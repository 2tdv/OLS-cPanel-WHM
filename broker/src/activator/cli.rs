//! Command line of ols-cpanel-activator. The activator commands are those of ols_generation.py, with
//! the same argument handling and the same JSON on stdout (`json.dumps(out, sort_keys=True)`):
//!
//!   stage <id> <src-dir> | validate <id> | activate <id> [--crash-after intent|switched|reloaded]
//!   | recover [--grace N] | status | restrict <reason> | enforce [--grace N] | health [--seconds N]
//!
//! plus `stage-validate [--binary B] <candidate>` (the command line of ols_stage_validate.py) and
//! `lint <file> [--no-policy]` (the command line of ols_config_lint.py). `--lab-root DIR` before the
//! command runs against DIR as the state directory with DIR/openlitespeed as the OLS binary and no
//! service, process or HTTP access at all; it is refused for root and exists for parity tests only.

use super::generation::{Activator, Error, Paths, CRASH_POINTS};
use super::lint;
use super::pyjson::{self, Ordered};
use super::pystr;
use super::runtime::{NullRuntime, Runtime, SystemRuntime};
use super::validate;
use serde_json::{json, Value};
use std::path::Path;

pub const USAGE: &str = "\
Generation activator (plan section 17): immutable generations, one atomic pointer, a durable journal,
validation binding and the restriction epoch. Run as root.

Commands: stage <id> <src-dir> | validate <id> | activate <id> [--crash-after STEP] | recover [--grace N]
          | status | restrict <reason> | enforce [--grace N] | health [--seconds N]
          | stage-validate [--binary B] <candidate> | lint <file> [--no-policy]";

fn lint_main(args: &[String]) -> i32 {
    let Some(file) = args.first() else {
        eprintln!("usage: ols-cpanel-activator lint <file> [--no-policy]");
        return 2;
    };
    let policy = !args[1..].iter().any(|a| a == "--no-policy");
    let text = match std::fs::read(file).map_err(|e| e.to_string()).and_then(|b| String::from_utf8(b).map_err(|e| e.to_string())) {
        Ok(text) => pystr::universal_newlines(&text),
        Err(e) => {
            eprintln!("ols-cpanel-activator lint: {file}: {e}");
            return 1;
        }
    };
    let problems = lint::lint(&text, policy);
    let valid = problems.is_empty();
    println!("{}", pyjson::dumps_ordered(&Ordered(vec![("valid", json!(valid)), ("errors", json!(problems))]), Some(2)));
    if valid {
        0
    } else {
        1
    }
}

fn arg<'a>(args: &'a [String], index: usize) -> Result<&'a str, Error> {
    args.get(index).map(String::as_str).ok_or_else(|| Error::Fatal("missing argument (IndexError: list index out of range)".into()))
}

/// `--grace N` anywhere after the command (default 0).
fn grace(args: &[String]) -> Result<f64, Error> {
    match args.iter().position(|a| a == "--grace") {
        None => Ok(0.0),
        Some(i) => args
            .get(i + 1)
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or_else(|| Error::Exit("--grace needs a non-negative number of seconds".into())),
    }
}

/// Largest `health --seconds` (the broker's engine.health accepts the same range).
pub const MAX_HEALTH_SECONDS: i64 = 60;

/// `--seconds N` anywhere after the command: a whole number 0..60, default 5 (ols_generation.py `health`).
pub fn seconds(args: &[String]) -> Result<f64, Error> {
    match args.iter().position(|a| a == "--seconds") {
        None => Ok(5.0),
        Some(i) => args
            .get(i + 1)
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| (0..=MAX_HEALTH_SECONDS).contains(v))
            .map(|v| v as f64)
            .ok_or_else(|| Error::Exit(format!("--seconds needs a whole number of seconds 0..{MAX_HEALTH_SECONDS}"))),
    }
}

fn dispatch<R: Runtime>(activator: &Activator<R>, args: &[String]) -> Result<Value, Error> {
    activator.ensure_dirs()?;
    let command = args.first().map(String::as_str).unwrap_or("");
    match command {
        "stage" => activator.stage(arg(args, 1)?, Path::new(arg(args, 2)?)),
        "validate" => activator.validate(arg(args, 1)?),
        "activate" => {
            let gen = arg(args, 1)?;
            // Exactly the Python parsing: the value is argv[4] only when argv[3] is "--crash-after".
            let crash = if args.len() > 3 && args[2] == "--crash-after" { Some(args[3].as_str()) } else { None };
            if let Some(point) = crash {
                if !CRASH_POINTS.contains(&point) {
                    return Err(Error::Exit("unknown crash point".into()));
                }
            }
            activator.activate(gen, crash)
        }
        "recover" => activator.recover(grace(args)?),
        "status" => activator.status(),
        "restrict" => {
            let reason = args[1..].join(" ");
            activator.restrict(if reason.is_empty() { "unspecified" } else { &reason })
        }
        "enforce" => Ok(json!({"result": activator.enforce(grace(args)?)?})),
        "health" => activator.health(seconds(args)?),
        _ => Err(Error::Exit(USAGE.into())),
    }
}

fn run<R: Runtime>(activator: Activator<R>, args: &[String]) -> i32 {
    match dispatch(&activator, args) {
        Ok(out) => {
            println!("{}", pyjson::dumps(&out, None));
            0
        }
        Err(Error::Crash) => 9,
        Err(Error::Exit(message)) => {
            eprintln!("{message}");
            1
        }
        Err(Error::Epoch(message)) => {
            eprintln!("ols-cpanel-activator: EpochError: {message}");
            1
        }
        Err(Error::Fatal(message)) => {
            eprintln!("ols-cpanel-activator: {message}");
            1
        }
    }
}

pub fn main(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("lint") => return lint_main(&args[1..]),
        Some("stage-validate") => return validate::main(&args[1..]),
        Some("--lab-root") => {
            let Some(root) = args.get(1) else {
                eprintln!("--lab-root needs a directory");
                return 2;
            };
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } == 0 {
                eprintln!("--lab-root is for unprivileged parity tests and is refused for root");
                return 2;
            }
            let root = Path::new(root);
            let paths = Paths::under(root, &super::generation::cat(root, "openlitespeed"));
            return run(Activator::new(paths, NullRuntime::new()), &args[2..]);
        }
        _ => {}
    }
    run(Activator::new(Paths::production(), SystemRuntime::new()), args)
}
