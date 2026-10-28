//! Product jobs behind `cap.execute` (docs/product-interfaces.md, "Admin socket: jobs for WHM"): one fixed
//! `ols-cpanel` argv per action, one job at a time (a second gets BUSY), each job a child process in its own
//! process group with stdout and stderr written straight to files under `jobs/<id>/` (0700), so a job does
//! not depend on the broker's pipes. A monitor thread waits for it, kills the whole group when its output
//! passes MAX_OUTPUT or it runs longer than TIMEOUT, and records the outcome.
//!
//! State on disk, so `job.status` survives a broker restart: `jobs/<id>/job.json` (the record, replaced
//! atomically), `output` (the command's stdout: its JSON report) and `log` (stderr: progress lines). At
//! start the broker recovers records left "running": a process that is gone is recorded as failed
//! ("interrupted"), one that still runs (same PID and start time) is watched until it ends, then recorded
//! as failed with an unknown exit status (the new broker is not its parent and cannot read it). With the
//! unit's default KillMode a broker stop also ends the job, so the first case is the expected one.
//! Every start and finish is appended to the broker's audit log.

use super::{audit, now, random_hex, read_bounded, Reply};
use crate::engine::command;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// stdout and stderr each; above it the job is killed and failed (output is never silently cut).
pub const MAX_OUTPUT: u64 = 1 << 20;
/// A cutover with many vhosts takes minutes; a job still running after an hour is stuck.
pub const TIMEOUT: Duration = Duration::from_secs(3600);
/// Job directories kept; older ones are removed when a new job starts.
pub const KEEP: usize = 200;
/// `job.list` length.
pub const LIST: usize = 50;
/// `job.status` log: the last lines of stderr, at most this many and from at most LOG_BYTES.
pub const LOG_LINES: usize = 200;
const LOG_BYTES: u64 = 64 << 10;
const MAX_RECORD: u64 = 64 << 10;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scope {
    /// The scope is the word "server".
    Server,
    /// The scope is a plan id (`plans/<id>.json`).
    Plan,
    /// LSCache purge: `server`, `account:<user>` or `domain:<domain>`.
    Cache,
    /// PHP restart: `server` or `account:<user>`.
    PhpRestart,
    /// OPcache installation: `server` or `version:ea-phpNN`.
    Opcache,
}

pub struct Action {
    pub name: &'static str,
    /// Arguments after the program; "--plan=" gets the plan id appended.
    pub args: &'static [&'static str],
    pub scope: Scope,
    /// Runs as a transient systemd unit outside the broker's own mount namespace (see `Launcher`).
    pub unit: bool,
}

/// How a `unit` action is started. The broker unit runs under ProtectSystem=full with a short ReadWritePaths list; the
/// WHM preparation jobs (`ols.plan`, `ols.plan_hybrid`) deploy the WHM and cPanel plugins into /usr/local/cpanel and
/// register them with cPanel's own tools, which write wherever cPanel keeps its plugin state. Widening the broker's
/// writable paths for that (and for whatever install_plugin writes beside them) would loosen the sandbox of every
/// other broker operation; instead only these two jobs run as a root transient unit `ols-cpanel-job-<id>` started
/// through PID 1 (D-Bus), so it does not inherit the broker's mount namespace, with explicit hardening that fits a
/// deployment (no extra privileges, kernel tunables and cgroups read-only, a private /tmp, the broker's UMask, a
/// runtime cap). The broker still watches the systemd-run client (`--wait --pipe`: its exit status is the job's) and
/// stops the unit when it must end the job.
#[derive(Clone)]
pub struct Launcher {
    pub systemd_run: PathBuf,
    pub systemctl: PathBuf,
}

impl Launcher {
    pub fn system() -> Launcher {
        Launcher { systemd_run: "/usr/bin/systemd-run".into(), systemctl: "/usr/bin/systemctl".into() }
    }
}

pub fn unit_name(id: &str) -> String {
    format!("ols-cpanel-job-{id}.service")
}

/// The systemd-run argv that runs `argv` as the job's transient unit.
pub fn unit_argv(launcher: &Launcher, id: &str, runtime_secs: u64, argv: &[String]) -> Vec<String> {
    let mut out = vec![launcher.systemd_run.display().to_string(), format!("--unit={}", unit_name(id)), "--wait".into(),
                       "--collect".into(), "--pipe".into(), "--quiet".into()];
    for (key, value) in command::ENV {
        out.push(format!("--setenv={key}={value}"));
    }
    for property in ["User=root", "WorkingDirectory=/", "UMask=0077", "NoNewPrivileges=yes", "ProtectKernelTunables=yes",
                     "ProtectControlGroups=yes", "RestrictRealtime=yes", "LockPersonality=yes", "PrivateTmp=yes",
                     "KillMode=control-group"] {
        out.push(format!("--property={property}"));
    }
    out.push(format!("--property=RuntimeMaxSec={runtime_secs}"));
    out.push("--".into());
    out.extend(argv.iter().cloned());
    out
}

/// The whole action table. A change here is a contract change (docs/product-interfaces.md).
pub const ACTIONS: &[Action] = &[
    Action { name: "ols.sync", args: &["sync", "--format=json"], scope: Scope::Server, unit: false },
    Action { name: "ols.rollback", args: &["rollback", "--format=json"], scope: Scope::Server, unit: false },
    Action { name: "ols.plan", args: &["install", "--prepare", "--format=json"], scope: Scope::Server, unit: true },
    Action { name: "ols.plan_hybrid", args: &["install", "--prepare", "--hybrid", "--format=json"], scope: Scope::Server, unit: true },
    Action { name: "ols.cutover", args: &["install", "--cutover", "--plan=", "--yes", "--format=json"], scope: Scope::Plan, unit: false },
    Action { name: "ols.apache_return", args: &["apache-return", "--execute", "--yes", "--format=json"], scope: Scope::Server, unit: false },
    Action { name: "ols.cache_purge", args: &["cache", "purge"], scope: Scope::Cache, unit: false },
    Action { name: "ols.php_restart", args: &["php", "restart"], scope: Scope::PhpRestart, unit: false },
    Action { name: "ols.opcache_install", args: &["php", "opcache", "install"], scope: Scope::Opcache, unit: false },
    Action { name: "ols.php_env_repair", args: &["php", "env", "repair", "--format=json"], scope: Scope::Server, unit: false },
    Action { name: "ols.support_bundle", args: &["support", "bundle", "--format=json"], scope: Scope::Server, unit: false },
    Action { name: "ols.support_bundle_raw", args: &["support", "bundle", "--no-anonymize", "--format=json"], scope: Scope::Server, unit: false },
];

pub fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}

pub fn valid_scope(action: &Action, scope: &str) -> bool {
    match action.scope {
        Scope::Server => scope == "server",
        // Never the word "server" and never something that reads like an option.
        Scope::Plan => scope != "server" && !scope.starts_with('-') && super::summary::valid_plan_id(scope),
        Scope::Cache | Scope::PhpRestart | Scope::Opcache => scope_flag(action, scope).is_some(),
    }
}

/// The option a scoped action gets for its scope (the actions whose argv ends in `<flag> --format=json`).
fn scope_flag(action: &Action, scope: &str) -> Option<String> {
    match action.scope {
        Scope::Cache => super::cache::purge_flag(scope),
        Scope::PhpRestart => super::php::restart_flag(scope),
        Scope::Opcache => super::php::opcache_flag(scope),
        Scope::Server | Scope::Plan => None,
    }
}

/// The fixed argv of an action (the scope is already checked by valid_scope).
pub fn argv(cli: &Path, action: &Action, scope: &str) -> Vec<String> {
    let mut argv = vec![cli.display().to_string()];
    argv.extend(action.args.iter().map(|a| if *a == "--plan=" { format!("--plan={scope}") } else { a.to_string() }));
    if matches!(action.scope, Scope::Cache | Scope::PhpRestart | Scope::Opcache) {
        // valid_scope has already accepted the scope, so the flag exists.
        argv.push(scope_flag(action, scope).unwrap_or_default());
        argv.push("--format=json".to_string());
    }
    argv
}

/// `j<unix seconds, 10 digits>-<8 hex>`: sorts by start time.
pub fn valid_job_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 20 && b[0] == b'j' && b[1..11].iter().all(u8::is_ascii_digit) && b[11] == b'-'
        && b[12..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    pub max_output: u64,
    pub poll: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { timeout: TIMEOUT, max_output: MAX_OUTPUT, poll: Duration::from_millis(200) }
    }
}

struct Inner {
    dir: PathBuf,
    cli: PathBuf,
    audit: PathBuf,
    limits: Limits,
    launcher: Option<Launcher>,
    /// The running job; held while a job is started, so two starts cannot both pass the check.
    running: Mutex<Option<String>>,
}

pub struct Jobs(Arc<Inner>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobArgs {
    job: String,
}

type Failure = (&'static str, String);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// (state, start time in clock ticks) of a process, from /proc/<pid>/stat.
fn process(pid: u32) -> Option<(char, u64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &text[text.rfind(')')? + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some((fields.first()?.chars().next()?, fields.get(19)?.parse().ok()?))
}

/// The same process (PID and start time) still runs (a zombie has ended).
fn alive(pid: u32, start: u64) -> bool {
    matches!(process(pid), Some((state, s)) if s == start && state != 'Z' && state != 'X')
}

fn size(path: &Path) -> u64 {
    fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn new_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// The last LOG_LINES lines of a log, printable (control characters other than tab become '?').
fn log_tail(path: &Path) -> Vec<String> {
    let Ok(mut file) = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) else { return Vec::new() };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let skip = len.saturating_sub(LOG_BYTES);
    let mut bytes = Vec::new();
    if file.seek(SeekFrom::Start(skip)).is_err() || file.take(LOG_BYTES).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if skip > 0 && !lines.is_empty() {
        lines.remove(0); // a partial first line
    }
    let start = lines.len().saturating_sub(LOG_LINES);
    lines[start..].iter().map(|l| l.chars().map(|c| if c.is_control() && c != '\t' { '?' } else { c }).collect()).collect()
}

enum Watched {
    Child(Child),
    /// A job of an earlier broker process: PID and start time.
    Orphan(u32, u64),
}

impl Inner {
    fn job_dir(&self, id: &str) -> PathBuf {
        self.dir.join(id)
    }

    fn read(&self, id: &str) -> Option<Value> {
        let bytes = read_bounded(&self.job_dir(id).join("job.json"), MAX_RECORD)?;
        serde_json::from_slice::<Value>(&bytes).ok().filter(Value::is_object)
    }

    fn write(&self, id: &str, record: &Value) -> Result<(), String> {
        crate::activator::generation::write_durable(&self.job_dir(id).join("job.json"), &record.to_string())
            .map_err(|e| format!("job record: {e:?}"))
    }

    /// Job ids on disk, oldest first.
    fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = fs::read_dir(&self.dir)
            .map(|entries| entries.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| valid_job_id(n)).collect())
            .unwrap_or_default();
        ids.sort();
        ids
    }

    /// The jobs directory, created 0700 when missing; a link or a file there is refused.
    fn ensure_dir(&self) -> Result<(), Failure> {
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(("INTERNAL", format!("{} is not a directory", self.dir.display()))),
            Err(_) => {
                fs::DirBuilder::new().mode(0o700).create(&self.dir).map_err(|e| ("INTERNAL", format!("{}: {e}", self.dir.display())))?;
                fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).map_err(|e| ("INTERNAL", e.to_string()))
            }
        }
    }

    fn prune(&self, keep: usize) {
        let ids = self.ids();
        let running = lock(&self.running).clone();
        for id in ids.iter().take(ids.len().saturating_sub(keep)) {
            if Some(id) != running.as_ref() {
                let _ = fs::remove_dir_all(self.job_dir(id));
            }
        }
    }

    /// Records the outcome, audits it and frees the slot.
    fn finish(&self, id: &str, exit_code: Option<i32>, reason: Option<String>) {
        let mut record = self.read(id).unwrap_or_else(|| json!({"job": id}));
        let state = if exit_code == Some(0) && reason.is_none() { "done" } else { "failed" };
        record["state"] = json!(state);
        record["finished"] = json!(now());
        record["exit_code"] = json!(exit_code);
        record["reason"] = json!(reason);
        if let Err(e) = self.write(id, &record) {
            eprintln!("{} job {id}: {e}", now());
        }
        let entry = json!({"time": now(), "event": "job_finish", "job": id, "action": record["action"], "state": state,
                           "exit_code": exit_code, "reason": record["reason"]});
        if let Err(e) = audit(&self.audit, &entry) {
            eprintln!("{} job {id}: audit: {e}", now());
        }
        let mut running = lock(&self.running);
        if running.as_deref() == Some(id) {
            *running = None;
        }
    }

    /// Ends the job: its process group and, for a `unit` job, the transient unit (the client's death alone leaves the
    /// unit running).
    fn kill(&self, id: &str, watched: &Watched) {
        if let Some(launcher) = &self.launcher {
            if self.read(id).map_or(false, |r| r["unit"] == json!(true)) {
                let _ = Command::new(&launcher.systemctl).args(["stop", &unit_name(id)]).env_clear().envs(command::ENV)
                    .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
            }
        }
        match watched {
            Watched::Child(child) => command::kill_group(child),
            Watched::Orphan(pid, start) => {
                if alive(*pid, *start) {
                    // SAFETY: the PID and start time were checked just before; the job leads its own group.
                    unsafe { libc::killpg(*pid as libc::pid_t, libc::SIGKILL) };
                }
            }
        }
    }

    /// Waits for the job and records it (runs on its own thread).
    fn monitor(&self, id: String, mut watched: Watched, started: Instant) {
        let dir = self.job_dir(&id);
        let limit = self.limits.max_output;
        let reason = loop {
            let ended = match &watched {
                Watched::Child(child) => command::exited(child),
                Watched::Orphan(pid, start) => !alive(*pid, *start),
            };
            if ended {
                break None;
            }
            if size(&dir.join("output")) > limit || size(&dir.join("log")) > limit {
                self.kill(&id, &watched);
                break Some(format!("output exceeds {} KiB; the job was stopped", limit >> 10));
            }
            if started.elapsed() > self.limits.timeout {
                self.kill(&id, &watched);
                break Some(format!("no result within {} s; the job was stopped", self.limits.timeout.as_secs()));
            }
            thread::sleep(self.limits.poll);
        };
        // A command that wrote past the limit and ended between two polls is not a success either.
        let reason = reason.or_else(|| (size(&dir.join("output")) > limit || size(&dir.join("log")) > limit)
            .then(|| format!("output exceeds {} KiB", limit >> 10)));
        let (code, reason) = match &mut watched {
            Watched::Child(child) => {
                // Also after a normal exit: nothing the command started outlives it holding the job's files.
                command::kill_group(child);
                let code = child.wait().ok().map(|s| s.code().unwrap_or_else(|| -s.signal().unwrap_or(0)));
                (code, reason)
            }
            Watched::Orphan(..) => (None, Some(reason.unwrap_or_else(|| {
                "the broker restarted while the job ran; its exit status is unknown".into()
            }))),
        };
        self.finish(&id, code, reason);
    }
}

impl Jobs {
    pub fn new(dir: PathBuf, cli: PathBuf, audit: PathBuf, limits: Limits) -> Jobs {
        Jobs::with_launcher(dir, cli, audit, limits, None)
    }

    /// With a launcher, the `unit` actions run as transient systemd units; without one every job is a plain child.
    pub fn with_launcher(dir: PathBuf, cli: PathBuf, audit: PathBuf, limits: Limits, launcher: Option<Launcher>) -> Jobs {
        Jobs(Arc::new(Inner { dir, cli, audit, limits, launcher, running: Mutex::new(None) }))
    }

    pub fn running(&self) -> Option<String> {
        lock(&self.0.running).clone()
    }

    /// At broker start: records left "running" by an earlier broker process.
    pub fn recover(&self) {
        for id in self.0.ids() {
            let Some(record) = self.0.read(&id) else { continue };
            if record["state"] != json!("running") {
                continue;
            }
            let pid = record["pid"].as_u64().and_then(|p| u32::try_from(p).ok());
            let start = record["pid_start"].as_u64();
            match (pid, start) {
                (Some(pid), Some(start)) if alive(pid, start) && lock(&self.0.running).is_none() => {
                    *lock(&self.0.running) = Some(id.clone());
                    let inner = Arc::clone(&self.0);
                    let started = Instant::now() - Duration::from_secs(now().saturating_sub(record["started"].as_u64().unwrap_or(0)));
                    thread::spawn(move || inner.monitor(id, Watched::Orphan(pid, start), started));
                }
                _ => self.0.finish(&id, None, Some("interrupted: the broker stopped while the job ran".into())),
            }
        }
    }

    /// Starts the action's command; returns the job id, or BUSY while another job runs.
    pub fn start(&self, action: &Action, scope: &str, principal: &str, digest: &str) -> Result<String, Failure> {
        if !valid_scope(action, scope) {
            return Err(("BAD_ARGS", "scope does not fit the action".into()));
        }
        let inner = &self.0;
        let mut running = lock(&inner.running);
        if let Some(current) = running.as_ref() {
            return Err(("BUSY", format!("job {current} is still running")));
        }
        inner.ensure_dir()?;
        drop(running);
        inner.prune(KEEP - 1);
        running = lock(&inner.running);
        if running.is_some() {
            return Err(("BUSY", "another job started".into()));
        }
        let id = format!("j{:010}-{}", now(), random_hex(4));
        let dir = inner.job_dir(&id);
        fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| ("INTERNAL", format!("{}: {e}", dir.display())))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| ("INTERNAL", e.to_string()))?;
        let argv = argv(&inner.cli, action, scope);
        let mut record = json!({"job": id, "action": action.name, "scope": scope, "principal": principal, "argv": argv,
                                "state": "running", "started": now(), "finished": null, "exit_code": null, "reason": null,
                                "pid": null, "pid_start": null, "unit": action.unit && inner.launcher.is_some()});
        inner.write(&id, &record).map_err(|e| ("INTERNAL", e))?;
        // No job without its audit record.
        audit(&inner.audit, &json!({"time": now(), "event": "job_start", "job": id, "action": action.name, "scope": scope,
                                    "principal": principal, "digest": digest}))
            .map_err(|e| ("INTERNAL", format!("audit log: {e}")))?;
        let files = new_file(&dir.join("output")).and_then(|out| Ok((out, new_file(&dir.join("log"))?)));
        let run_argv = match (&inner.launcher, action.unit) {
            (Some(launcher), true) => unit_argv(launcher, &id, inner.limits.timeout.as_secs().max(1), &argv),
            _ => argv.clone(),
        };
        let spawned = files.and_then(|(out, log)| {
            Command::new(&run_argv[0])
                .args(&run_argv[1..])
                .env_clear()
                .envs(command::ENV)
                .current_dir("/")
                .stdin(Stdio::null())
                .stdout(Stdio::from(out))
                .stderr(Stdio::from(log))
                .process_group(0)
                .spawn()
        });
        let child = match spawned {
            Ok(child) => child,
            Err(e) => {
                drop(running);
                let message = format!("{}: {e}", argv[0]);
                inner.finish(&id, None, Some(format!("not started: {message}")));
                return Err(("SPAWN_FAILED", message));
            }
        };
        record["pid"] = json!(child.id());
        record["pid_start"] = json!(process(child.id()).map(|(_, start)| start));
        if let Err(e) = inner.write(&id, &record) {
            eprintln!("{} job {id}: {e}", now());
        }
        *running = Some(id.clone());
        drop(running);
        let worker = Arc::clone(&self.0);
        let job = id.clone();
        thread::spawn(move || worker.monitor(job, Watched::Child(child), Instant::now()));
        Ok(id)
    }

    /// `job.list`: the newest LIST jobs.
    pub fn list(&self) -> Reply {
        let jobs: Vec<Value> = self.0.ids().iter().rev().take(LIST).filter_map(|id| self.0.read(id)).map(|r| {
            json!({"job": r["job"], "action": r["action"], "scope": r["scope"], "state": r["state"], "started": r["started"],
                   "finished": r["finished"], "exit_code": r["exit_code"]})
        }).collect();
        Ok(json!({"observed_at": now(), "running": self.running(), "jobs": jobs}))
    }

    /// `job.status {"job"}`: the record plus `output` (the command's JSON, null until it is complete JSON) and `log`.
    pub fn status(&self, args: Value) -> Reply {
        let a: JobArgs = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
        if !valid_job_id(&a.job) {
            return Err(("BAD_ARGS", "job must match j<10 digits>-<8 hex>".into()));
        }
        let record = self.0.read(&a.job).ok_or(("NOT_FOUND", "no such job".to_string()))?;
        let dir = self.0.job_dir(&a.job);
        let output = read_bounded(&dir.join("output"), self.0.limits.max_output)
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .unwrap_or(Value::Null);
        let mut out = json!({"observed_at": now(), "output": output, "log": log_tail(&dir.join("log"))});
        for key in ["job", "action", "scope", "principal", "state", "started", "finished", "exit_code", "reason"] {
            out[key] = record.get(key).cloned().unwrap_or(Value::Null);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;
    use crate::panel::product::tests::fake_cli;
    use std::os::unix::fs::MetadataExt;

    /// The fake product command: per subcommand a behaviour of a real job.
    const SCRIPT: &str = r#"case "$1" in
sync) echo "compiling" >&2; echo "activating" >&2; echo '{"result": "committed", "generation": "r20261022120000-a1b2c3"}';;
rollback) sleep 1; echo '{"result": "rolled back"}';;
apache-return) echo '{"result": "refused", "reason": "no backup"}'; exit 1;;
install) case "$2 $3" in
  "--cutover --plan="*) printf '{"argv": "%s"}' "$*";;
  "--prepare --hybrid") sleep 30;;
  *) head -c 100000 /dev/zero | tr '\0' x;;
  esac;;
*) sleep 30;;
esac"#;

    fn jobs(temp: &TempTree, limits: Limits) -> Jobs {
        let cli = fake_cli(temp.path(), SCRIPT);
        Jobs::new(temp.path().join("state/jobs"), cli, temp.path().join("state/broker-audit.log"), limits)
    }

    fn quick() -> Limits {
        Limits { timeout: Duration::from_secs(20), max_output: 4096, poll: Duration::from_millis(10) }
    }

    fn setup() -> TempTree {
        let temp = TempTree::new();
        fs::create_dir_all(temp.path().join("state")).unwrap();
        temp
    }

    fn wait(jobs: &Jobs) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while jobs.running().is_some() {
            assert!(Instant::now() < deadline, "job did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn status(jobs: &Jobs, id: &str) -> Value {
        jobs.status(json!({"job": id})).unwrap()
    }

    fn audit_lines(temp: &TempTree) -> Vec<Value> {
        fs::read_to_string(temp.path().join("state/broker-audit.log")).unwrap_or_default().lines()
            .map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn action_table() {
        let cli = Path::new("/usr/local/ols-cpanel/bin/ols-cpanel");
        let table: Vec<(&str, String)> = ACTIONS.iter()
            .map(|a| (a.name, argv(cli, a, if a.scope == Scope::Plan { "p20261022120000-a1b2c3" } else { "server" })[1..].join(" ")))
            .collect();
        assert_eq!(table, [
            ("ols.sync", "sync --format=json".to_string()),
            ("ols.rollback", "rollback --format=json".to_string()),
            ("ols.plan", "install --prepare --format=json".to_string()),
            ("ols.plan_hybrid", "install --prepare --hybrid --format=json".to_string()),
            ("ols.cutover", "install --cutover --plan=p20261022120000-a1b2c3 --yes --format=json".to_string()),
            ("ols.apache_return", "apache-return --execute --yes --format=json".to_string()),
            ("ols.cache_purge", "cache purge --all --format=json".to_string()),
            ("ols.php_restart", "php restart --all --format=json".to_string()),
            ("ols.opcache_install", "php opcache install --all --format=json".to_string()),
            ("ols.php_env_repair", "php env repair --format=json".to_string()),
            ("ols.support_bundle", "support bundle --format=json".to_string()),
            ("ols.support_bundle_raw", "support bundle --no-anonymize --format=json".to_string()),
        ]);
        let restart = action("ols.php_restart").unwrap();
        for (scope, flag) in [("server", "--all"), ("account:olscpa", "--account=olscpa")] {
            assert!(valid_scope(restart, scope), "{scope}");
            assert_eq!(argv(cli, restart, scope)[1..], ["php", "restart", flag, "--format=json"], "{scope}");
        }
        for bad in ["", "all", "--all", "account:", "account:A", "account:a b", "domain:a.test", "version:ea-php83", "server ", "plan:p1"] {
            assert!(!valid_scope(restart, bad), "{bad}");
        }
        let opcache = action("ols.opcache_install").unwrap();
        for (scope, flag) in [("server", "--all"), ("version:ea-php83", "--version=ea-php83")] {
            assert!(valid_scope(opcache, scope), "{scope}");
            assert_eq!(argv(cli, opcache, scope)[1..], ["php", "opcache", "install", flag, "--format=json"], "{scope}");
        }
        for bad in ["", "all", "version:", "version:ea-php8", "version:ea-php83 --all", "account:olscpa", "version:alt-php81", "server ", "plan:p1"] {
            assert!(!valid_scope(opcache, bad), "{bad}");
        }
        let purge = action("ols.cache_purge").unwrap();
        for (scope, flag) in [("server", "--all"), ("account:olscpa", "--account=olscpa"), ("domain:a.test", "--domain=a.test")] {
            assert!(valid_scope(purge, scope), "{scope}");
            assert_eq!(argv(cli, purge, scope)[1..], ["cache", "purge", flag, "--format=json"], "{scope}");
        }
        for bad in ["", "all", "--all", "account:", "account:A", "account:a b", "account:a/b", "account:../x", "domain:", "domain:a", "domain:a.test --all",
                    "domain:../a.test", "domain:a.test/x", "domain:A.test", "domain:a.test;id", "account:olscpa:x", "server ", "plan:p1"] {
            assert!(!valid_scope(purge, bad), "{bad}");
        }
        assert!(action("lab.audit_marker").is_none() && action("ols.restart").is_none());
        let cutover = action("ols.cutover").unwrap();
        assert!(valid_scope(cutover, "p20261022120000-a1b2c3"));
        for bad in ["server", "", "../p1", "p1 --force", "--yes", "p1;id", &"a".repeat(65)] {
            assert!(!valid_scope(cutover, bad), "{bad}");
        }
        assert!(valid_scope(action("ols.sync").unwrap(), "server") && !valid_scope(action("ols.sync").unwrap(), "p1"));
        assert!(valid_job_id("j1761134400-0a1b2c3d"));
        for bad in ["j176113440-0a1b2c3d", "j1761134400-0A1B2C3D", "x1761134400-0a1b2c3d", "j1761134400_0a1b2c3d", "../j1761134400-0a1b2c3"] {
            assert!(!valid_job_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_job_runs_to_completion() {
        let temp = setup();
        let jobs = jobs(&temp, quick());
        let id = jobs.start(action("ols.sync").unwrap(), "server", "root", &"ab".repeat(32)).unwrap();
        assert!(valid_job_id(&id));
        wait(&jobs);
        let out = status(&jobs, &id);
        assert_eq!((out["state"].as_str(), out["exit_code"].as_i64(), out["action"].as_str()), (Some("done"), Some(0), Some("ols.sync")));
        assert_eq!(out["output"], json!({"result": "committed", "generation": "r20261022120000-a1b2c3"}));
        assert_eq!(out["log"], json!(["compiling", "activating"]));
        assert!(out["finished"].as_u64() >= out["started"].as_u64() && out["reason"].is_null());
        // Private directories and files.
        let dir = temp.path().join("state/jobs");
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dir.join(&id)).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dir.join(&id).join("output")).unwrap().mode() & 0o777, 0o600);
        // Audit: start and finish.
        let audit = audit_lines(&temp);
        assert_eq!(audit.len(), 2);
        assert_eq!((audit[0]["event"].as_str(), audit[0]["job"].as_str(), audit[0]["principal"].as_str()),
                   (Some("job_start"), Some(id.as_str()), Some("root")));
        assert_eq!((audit[1]["event"].as_str(), audit[1]["state"].as_str()), (Some("job_finish"), Some("done")));
        // A failing command is a failed job with its exit code and report.
        let id = jobs.start(action("ols.apache_return").unwrap(), "server", "root", &"ab".repeat(32)).unwrap();
        wait(&jobs);
        let out = status(&jobs, &id);
        assert_eq!((out["state"].as_str(), out["exit_code"].as_i64()), (Some("failed"), Some(1)));
        assert_eq!(out["output"]["reason"], json!("no backup"));
        // The plan id reaches the command as one argument.
        let id = jobs.start(action("ols.cutover").unwrap(), "p20261022120000-a1b2c3", "root", &"ab".repeat(32)).unwrap();
        wait(&jobs);
        assert_eq!(status(&jobs, &id)["output"]["argv"], json!("install --cutover --plan=p20261022120000-a1b2c3 --yes --format=json"));
        assert_eq!(jobs.start(action("ols.cutover").unwrap(), "server", "root", "x").unwrap_err().0, "BAD_ARGS");
    }

    #[test]
    fn one_job_at_a_time() {
        let temp = setup();
        let jobs = jobs(&temp, quick());
        let first = jobs.start(action("ols.rollback").unwrap(), "server", "root", "d").unwrap();
        assert_eq!(jobs.running(), Some(first.clone()));
        assert_eq!(status(&jobs, &first)["state"], json!("running"));
        assert_eq!(status(&jobs, &first)["output"], Value::Null);
        let busy = jobs.start(action("ols.sync").unwrap(), "server", "root", "d").unwrap_err();
        assert_eq!(busy.0, "BUSY");
        let list = jobs.list().unwrap();
        assert_eq!((list["running"].as_str(), list["jobs"].as_array().unwrap().len()), (Some(first.as_str()), 1));
        wait(&jobs);
        assert_eq!(status(&jobs, &first)["output"], json!({"result": "rolled back"}));
        let second = jobs.start(action("ols.sync").unwrap(), "server", "root", "d").unwrap();
        wait(&jobs);
        let list = jobs.list().unwrap();
        assert_eq!(list["running"], Value::Null);
        let ids: Vec<&str> = list["jobs"].as_array().unwrap().iter().map(|j| j["job"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&first.as_str()) && ids.contains(&second.as_str()));
        assert_eq!(list["jobs"][0].as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
                   ["action", "exit_code", "finished", "job", "scope", "started", "state"]);
    }

    #[test]
    fn limits_stop_the_job() {
        let temp = setup();
        // Output above the limit: killed, failed, never a cut report.
        let jobs = jobs(&temp, quick());
        let id = jobs.start(action("ols.plan").unwrap(), "server", "root", "d").unwrap();
        wait(&jobs);
        let out = status(&jobs, &id);
        assert_eq!(out["state"], json!("failed"));
        assert!(out["reason"].as_str().unwrap().starts_with("output exceeds 4 KiB"), "{out}");
        assert_eq!(out["output"], Value::Null);
        // Time limit: the whole group is killed (exit status: minus the signal).
        let slow = Jobs::new(temp.path().join("state/jobs"), temp.path().join("ols-cpanel"), temp.path().join("state/broker-audit.log"),
                             Limits { timeout: Duration::from_millis(300), ..quick() });
        let started = Instant::now();
        let id = slow.start(action("ols.plan_hybrid").unwrap(), "server", "root", "d").unwrap();
        wait(&slow);
        assert!(started.elapsed() < Duration::from_secs(10));
        let out = slow.status(json!({"job": id})).unwrap();
        assert_eq!((out["state"].as_str(), out["exit_code"].as_i64()), (Some("failed"), Some(-9)));
        assert!(out["reason"].as_str().unwrap().starts_with("no result within"));
        // A command that cannot start.
        let missing = Jobs::new(temp.path().join("state/jobs"), temp.path().join("missing"), temp.path().join("state/broker-audit.log"), quick());
        assert_eq!(missing.start(action("ols.sync").unwrap(), "server", "root", "d").unwrap_err().0, "SPAWN_FAILED");
        assert!(missing.running().is_none());
        let failed = missing.list().unwrap()["jobs"][0].clone();
        assert_eq!(failed["state"], json!("failed"));
    }

    #[test]
    fn status_arguments() {
        let temp = setup();
        let jobs = jobs(&temp, quick());
        assert_eq!(jobs.status(json!({"job": "j1761134400-0a1b2c3d"})).unwrap_err().0, "NOT_FOUND");
        for bad in [json!({"job": "../etc"}), json!({"job": 1}), json!({}), json!({"job": "j1761134400-0a1b2c3d", "x": 1}), Value::Null] {
            assert_eq!(jobs.status(bad).unwrap_err().0, "BAD_ARGS");
        }
        assert_eq!(jobs.list().unwrap()["jobs"], json!([]));
    }

    fn record(dir: &Path, id: &str, state: &str, pid: Option<u32>, start: Option<u64>) {
        fs::create_dir_all(dir.join(id)).unwrap();
        fs::write(dir.join(id).join("job.json"), json!({"job": id, "action": "ols.sync", "scope": "server", "state": state,
            "started": now(), "finished": null, "exit_code": null, "pid": pid, "pid_start": start}).to_string()).unwrap();
    }

    #[test]
    fn records_survive_a_broker_restart() {
        let temp = setup();
        let dir = temp.path().join("state/jobs");
        // A job whose process is gone (the broker stopped with it): failed, interrupted.
        record(&dir, "j1761134400-00000001", "running", Some(u32::MAX - 1), Some(1));
        record(&dir, "j1761134400-00000002", "done", None, None);
        // A job that still runs: watched until it ends.
        let mut child = Command::new("/usr/bin/sleep").arg("1").process_group(0).spawn().unwrap();
        let start = process(child.id()).unwrap().1;
        record(&dir, "j1761134401-00000003", "running", Some(child.id()), Some(start));
        let reaper = thread::spawn(move || child.wait());
        let jobs = jobs(&temp, quick());
        jobs.recover();
        let gone = status(&jobs, "j1761134400-00000001");
        assert_eq!((gone["state"].as_str(), gone["exit_code"].clone()), (Some("failed"), Value::Null));
        assert!(gone["reason"].as_str().unwrap().starts_with("interrupted"));
        assert_eq!(status(&jobs, "j1761134400-00000002")["state"], json!("done"));
        assert_eq!(jobs.running().as_deref(), Some("j1761134401-00000003"));
        assert_eq!(jobs.start(action("ols.sync").unwrap(), "server", "root", "d").unwrap_err().0, "BUSY");
        reaper.join().unwrap().unwrap();
        wait(&jobs);
        let orphan = status(&jobs, "j1761134401-00000003");
        assert_eq!((orphan["state"].as_str(), orphan["exit_code"].clone()), (Some("failed"), Value::Null));
        assert!(orphan["reason"].as_str().unwrap().contains("exit status is unknown"));
        // Each recovered job has its finish audited.
        assert_eq!(audit_lines(&temp).iter().filter(|r| r["event"] == json!("job_finish")).count(), 2);
        // Old directories are pruned when a job starts; the newest stay.
        for n in 0..KEEP + 5 {
            record(&dir, &format!("j1700000000-{n:08x}"), "done", None, None);
        }
        jobs.start(action("ols.sync").unwrap(), "server", "root", "d").unwrap();
        wait(&jobs);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), KEEP);
        assert_eq!(jobs.list().unwrap()["jobs"].as_array().unwrap().len(), LIST);
    }

    #[test]
    fn log_tail_is_bounded_and_printable() {
        let temp = setup();
        let log = temp.path().join("log");
        let mut text = String::new();
        for n in 0..5000 {
            text.push_str(&format!("line {n} \x1b[31mred\x1b[0m\ttab\n"));
        }
        fs::write(&log, &text).unwrap();
        let tail = log_tail(&log);
        assert_eq!(tail.len(), LOG_LINES);
        assert_eq!(tail.last().unwrap(), "line 4999 ?[31mred?[0m\ttab");
        assert!(log_tail(&temp.path().join("missing")).is_empty());
    }

    /// RV-31 item 7: the preparation jobs run as transient units outside the broker's mount namespace; no other job does.
    #[test]
    fn preparation_jobs_run_as_transient_units() {
        let temp = setup();
        let dir = temp.path();
        let run = dir.join("systemd-run");
        let ctl = dir.join("systemctl");
        fs::write(&run, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {0}/run.args\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n", dir.display())).unwrap();
        fs::write(&ctl, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {0}/ctl.args\n", dir.display())).unwrap();
        for f in [&run, &ctl] {
            fs::set_permissions(f, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let launcher = Launcher { systemd_run: run, systemctl: ctl };
        let cli = fake_cli(dir, SCRIPT);
        let jobs = Jobs::with_launcher(dir.join("state/jobs"), cli.clone(), dir.join("state/broker-audit.log"),
                                       Limits { timeout: Duration::from_secs(20), ..quick() }, Some(launcher.clone()));
        // A non-unit job is a plain child.
        jobs.start(action("ols.sync").unwrap(), "server", "root", "d").unwrap();
        wait(&jobs);
        assert!(!dir.join("run.args").exists());
        // ols.plan (here: the fake's oversized output) is wrapped; the unit name carries the job id.
        let id = jobs.start(action("ols.plan").unwrap(), "server", "root", "d").unwrap();
        wait(&jobs);
        let args = fs::read_to_string(dir.join("run.args")).unwrap();
        let lines: Vec<&str> = args.lines().collect();
        assert_eq!(lines[0], format!("--unit=ols-cpanel-job-{id}.service"));
        for expected in ["--wait", "--collect", "--pipe", "--property=User=root", "--property=NoNewPrivileges=yes",
                         "--property=UMask=0077", "--property=RuntimeMaxSec=20", "--setenv=PATH=/usr/bin:/bin:/usr/sbin"] {
            assert!(lines.contains(&expected), "{expected} in {lines:?}");
        }
        let cut = lines.iter().position(|l| *l == "--").unwrap();
        assert_eq!(&lines[cut + 1..], [cli.display().to_string().as_str(), "install", "--prepare", "--format=json"]);
        assert_eq!(jobs.0.read(&id).unwrap()["unit"], json!(true));
        // A job that has to be ended also stops its unit.
        let slow = Jobs::with_launcher(dir.join("state/jobs"), cli, dir.join("state/broker-audit.log"),
                                       Limits { timeout: Duration::from_millis(300), ..quick() }, Some(launcher));
        let id = slow.start(action("ols.plan_hybrid").unwrap(), "server", "root", "d").unwrap();
        wait(&slow);
        let stopped = fs::read_to_string(dir.join("ctl.args")).unwrap();
        assert_eq!(stopped.lines().collect::<Vec<_>>(), ["stop", &format!("ols-cpanel-job-{id}.service")]);
    }
}
