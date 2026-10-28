//! Execution of an allowlisted argv for `engine.run`: no shell, a fixed environment, stdin from
//! /dev/null, its own process group (so a timeout or an output overrun kills runuser's child too), a
//! time limit and an output limit that refuses instead of truncating.

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(120);
/// stdout and stderr together.
pub const MAX_OUTPUT: usize = 16 << 20;
pub const ENV: [(&str, &str); 3] = [("PATH", "/usr/bin:/bin:/usr/sbin"), ("LANG", "C"), ("LC_ALL", "C")];

#[derive(Debug, PartialEq)]
pub enum Failure {
    Spawn(String),
    Timeout,
    TooLarge,
}

#[derive(Debug)]
pub struct Output {
    /// The exit status, or minus the signal number (Python's returncode).
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Reads until EOF, or stops once the shared total passed `limit` (the caller then kills the group).
fn collect<R: Read>(mut pipe: R, total: &AtomicUsize, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&chunk[..n]);
                if total.fetch_add(n, Ordering::SeqCst) + n > limit {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    out
}

/// True once the child has exited; it stays a zombie (WNOWAIT), so its PID and process group cannot
/// be reused before the group is killed.
pub(crate) fn exited(child: &Child) -> bool {
    // SAFETY: a zeroed siginfo_t is a valid out-parameter for waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::waitid(libc::P_PID, child.id(), &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
    // SAFETY: waitid filled `info` (si_pid stays 0 while the child runs).
    rc != 0 || unsafe { info.si_pid() } != 0
}

pub(crate) fn kill_group(child: &Child) {
    // SAFETY: the group leader is our unreaped child, so the group ID is ours.
    unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
}

/// Also the activator's bounded subprocesses (systemctl, pgrep, pkill, curl, the staged validator).
pub fn run<S: AsRef<OsStr>>(argv: &[S], timeout: Duration, limit: usize) -> Result<Output, Failure> {
    let (program, args) = argv.split_first().ok_or_else(|| Failure::Spawn("empty argv".into()))?;
    let program = program.as_ref();
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(ENV)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| Failure::Spawn(format!("{}: {e}", std::path::Path::new(program).display())))?;
    let total = Arc::new(AtomicUsize::new(0));
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let (t1, t2) = (Arc::clone(&total), Arc::clone(&total));
    let out = thread::spawn(move || stdout.map(|p| collect(p, &t1, limit)).unwrap_or_default());
    let err = thread::spawn(move || stderr.map(|p| collect(p, &t2, limit)).unwrap_or_default());
    let deadline = Instant::now() + timeout;
    let failure = loop {
        if total.load(Ordering::SeqCst) > limit {
            break Some(Failure::TooLarge);
        }
        if exited(&child) {
            break None;
        }
        if Instant::now() >= deadline {
            break Some(Failure::Timeout);
        }
        thread::sleep(Duration::from_millis(5));
    };
    // Also after a normal exit: nothing the command started may outlive it or hold the pipes open.
    kill_group(&child);
    let status = child.wait();
    let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    if let Some(failure) = failure {
        return Err(failure);
    }
    if stdout.len() + stderr.len() > limit {
        return Err(Failure::TooLarge);
    }
    let status = status.map_err(|e| Failure::Spawn(e.to_string()))?;
    let code = status.code().unwrap_or_else(|| -status.signal().unwrap_or(0));
    Ok(Output { code, stdout, stderr })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn environment_is_exactly_the_fixed_one() {
        let out = run(&argv(&["/usr/bin/env"]), TIMEOUT, MAX_OUTPUT).unwrap();
        assert_eq!(out.code, 0);
        let mut lines: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(str::to_owned).collect();
        lines.sort();
        assert_eq!(lines, ["LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin"]);
    }

    #[test]
    fn exit_codes_and_streams() {
        let out = run(&argv(&["/usr/bin/ls", "/nonexistent-engine-test"]), TIMEOUT, MAX_OUTPUT).unwrap();
        assert_eq!(out.code, 2);
        assert!(out.stdout.is_empty() && !out.stderr.is_empty());
        // Arguments are passed as they are: no shell expands anything.
        let out = run(&argv(&["/usr/bin/printf", "%s", "$HOME;*`id`"]), TIMEOUT, MAX_OUTPUT).unwrap();
        assert_eq!(out.stdout, b"$HOME;*`id`");
    }

    #[test]
    fn missing_program_is_a_spawn_failure() {
        assert!(matches!(run(&argv(&["/nonexistent/program"]), TIMEOUT, MAX_OUTPUT), Err(Failure::Spawn(_))));
    }

    #[test]
    fn output_above_the_limit_is_refused() {
        let at = run(&argv(&["/usr/bin/head", "-c", "4096", "/dev/zero"]), TIMEOUT, 4096).unwrap();
        assert_eq!(at.stdout.len(), 4096);
        assert_eq!(run(&argv(&["/usr/bin/head", "-c", "4097", "/dev/zero"]), TIMEOUT, 4096).unwrap_err(), Failure::TooLarge);
        // An endless writer is killed instead of filling memory.
        let started = Instant::now();
        assert_eq!(run(&argv(&["/usr/bin/cat", "/dev/zero"]), TIMEOUT, 1 << 20).unwrap_err(), Failure::TooLarge);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn timeout_kills_the_command() {
        let started = Instant::now();
        assert_eq!(run(&argv(&["/usr/bin/sleep", "30"]), Duration::from_millis(300), MAX_OUTPUT).unwrap_err(), Failure::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
