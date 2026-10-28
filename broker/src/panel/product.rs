//! Read views that come from the product command line (`ols-cpanel ... --format=json`): `server.status`'s
//! extension (`status`), `generation.list` (`generation list`) and `doctor.report` (`doctor --read-only`).
//! Fixed argv only, run like engine.run (no shell, the fixed environment, own process group, killed with
//! everything it started at the limit), 30 s limit, output refused above MAX_OUTPUT. A reply is the
//! command's JSON object with its exit code; anything that is not one JSON object is COMMAND_FAILED.

use super::{now, Reply};
use crate::engine::command;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_OUTPUT: usize = 4 << 20;
/// Cache lifetimes: status is shown live (2 s, as the broker's own status), doctor is expensive (60 s).
pub const STATUS_CACHE: Duration = Duration::from_secs(2);
pub const DOCTOR_CACHE: Duration = Duration::from_secs(60);

pub const STATUS: &[&str] = &["status", "--format=json"];
pub const GENERATIONS: &[&str] = &["generation", "list", "--format=json"];
pub const DOCTOR: &[&str] = &["doctor", "--read-only", "--format=json"];

/// Runs `cli args...` and returns `{"observed_at", "source", "exit_code", "output"}`.
pub fn run(cli: &Path, args: &[&str]) -> Reply {
    run_for(cli, args, TIMEOUT)
}

/// `run` with its own time limit (the operations that talk to the mail system or the package manager).
pub fn run_for(cli: &Path, args: &[&str], timeout: Duration) -> Reply {
    let mut argv = vec![cli.display().to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let source = format!("ols-cpanel {}", args.join(" "));
    let out = match command::run(&argv, timeout, MAX_OUTPUT) {
        Ok(out) => out,
        Err(command::Failure::Timeout) => return Err(("TIMEOUT", format!("{source} did not finish within {} s", timeout.as_secs()))),
        Err(command::Failure::TooLarge) => return Err(("OUTPUT_TOO_LARGE", format!("{source} printed more than 4 MiB"))),
        Err(command::Failure::Spawn(message)) => return Err(("SPAWN_FAILED", message)),
    };
    match serde_json::from_slice::<Value>(&out.stdout) {
        Ok(output) if output.is_object() => Ok(json!({"observed_at": now(), "source": source, "exit_code": out.code, "output": output})),
        _ => Err(("COMMAND_FAILED", format!("{source} exited with {} without a JSON report", out.code))),
    }
}

/// One cached product command: concurrent callers wait for the running command instead of starting another.
pub struct Cached {
    args: &'static [&'static str],
    lifetime: Duration,
    last: Mutex<Option<(Instant, Value)>>,
}

impl Cached {
    pub fn new(args: &'static [&'static str], lifetime: Duration) -> Cached {
        Cached { args, lifetime, last: Mutex::new(None) }
    }

    /// Errors are not cached: the next request tries again.
    pub fn get(&self, cli: &Path) -> Reply {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, value)) = last.as_ref() {
            if at.elapsed() < self.lifetime {
                return Ok(value.clone());
            }
        }
        let value = run(cli, self.args)?;
        *last = Some((Instant::now(), value.clone()));
        Ok(value)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A stand-in for the product CLI: a script that answers per subcommand.
    pub fn fake_cli(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("ols-cpanel");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn json_reports_with_their_exit_code() {
        let temp = TempTree::new();
        let cli = fake_cli(temp.path(), r#"case "$1 $2 $3" in
"doctor --read-only --format=json") echo '{"supported": false}'; exit 2;;
"status --format=json ") echo '{"cut_over": true, "epoch": 4}';;
"generation list --format=json") echo 'not json'; exit 1;;
*) echo "unexpected $*" >&2; exit 64;;
esac"#);
        let doctor = run(&cli, DOCTOR).unwrap();
        assert_eq!((doctor["exit_code"].as_i64(), doctor["output"].clone()), (Some(2), json!({"supported": false})));
        assert_eq!(doctor["source"], json!("ols-cpanel doctor --read-only --format=json"));
        assert_eq!(run(&cli, STATUS).unwrap()["output"]["epoch"], json!(4));
        assert_eq!(run(&cli, GENERATIONS).unwrap_err().0, "COMMAND_FAILED");
        assert_eq!(run(&cli, &["other"]).unwrap_err().0, "COMMAND_FAILED");
        assert_eq!(run(&temp.path().join("missing"), STATUS).unwrap_err().0, "SPAWN_FAILED");
        // The fixed environment of engine.run, nothing of the broker's.
        let env = fake_cli(temp.path(), r#"printf '{"env": "%s"}' "$(env | sort | tr '\n' ' ')""#);
        let reply = run(&env, STATUS).unwrap();
        let mut vars: Vec<&str> = reply["output"]["env"].as_str().unwrap().split(' ')
            .filter(|v| !v.is_empty() && !["PWD=", "OLDPWD=", "SHLVL=", "_="].iter().any(|shell| v.starts_with(shell)))
            .collect();
        vars.sort();
        assert_eq!(vars, ["LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin"]);
    }

    #[test]
    fn successes_are_cached_failures_are_not() {
        let temp = TempTree::new();
        let counter = temp.path().join("count");
        let cli = fake_cli(temp.path(), &format!("echo x >> {0}; [ -f {0}.fail ] && exit 1; echo '{{\"n\": 1}}'", counter.display()));
        let cached = Cached::new(STATUS, Duration::from_secs(60));
        fs::write(format!("{}.fail", counter.display()), "").unwrap();
        assert!(cached.get(&cli).is_err());
        fs::remove_file(format!("{}.fail", counter.display())).unwrap();
        assert!(cached.get(&cli).is_ok());
        assert!(cached.get(&cli).is_ok());
        assert_eq!(fs::read_to_string(&counter).unwrap().lines().count(), 2);
        let fresh = Cached::new(STATUS, Duration::ZERO);
        fresh.get(&cli).unwrap();
        fresh.get(&cli).unwrap();
        assert_eq!(fs::read_to_string(&counter).unwrap().lines().count(), 4);
    }
}
