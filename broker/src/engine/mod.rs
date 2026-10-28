//! The engine socket's operations (docs/product-interfaces.md, "Engine socket"): allowlisted cPanel
//! input reads for the configuration builder, generation apply through the activator (in-process),
//! status, enforcement, recovery and the event spool. The caller is root or the `olscpanel` reconciler;
//! the broker checks that before anything here runs.
//!
//! `engine.run` output: stdout and stderr are returned as JSON text. Valid UTF-8 is passed through
//! unchanged; only output that is not valid UTF-8 is decoded lossily (each invalid sequence becomes
//! U+FFFD), so callers comparing bytes must not rely on such output.

pub mod allowlist;
pub mod apply;
pub mod command;
pub mod events;
pub mod restrictions;

use crate::activator::generation::{cat, Activator, Paths};
use crate::activator::runtime::{Runtime, SystemRuntime};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

type Reply = Result<Value, (&'static str, String)>;

/// Upper bound of `grace` for enforce and recover (one day).
pub const MAX_GRACE: i64 = 86400;
/// HR-D11: a stale generation stops serving at most this long after the earliest restriction it lacks.
pub const ENFORCE_GRACE: f64 = 300.0;
/// The enforcement thread's round period (docs/product-interfaces.md, "Locks, deadlines and recovery").
pub const ENFORCE_PERIOD: f64 = 5.0;
/// From this long before a deadline the round awaits the activation lock (more than a round takes).
pub const ENFORCE_LEAD: f64 = 10.0;
/// A round's fold waits this long per intent for the lock; enforcement counts unfolded intents anyway.
pub const ROUND_FOLD_WAIT: f64 = 1.0;
/// `engine.restrictions_fold` waits this long per intent (longer than any bounded transaction holds the lock).
pub const FOLD_WAIT: f64 = 300.0;

/// What one round of the broker's enforcement thread did, and when the next one is due.
#[derive(Debug, PartialEq)]
pub struct Round {
    /// `{"folded", "epoch"}` of the fold, or its error.
    pub fold: Result<Value, String>,
    /// The enforcement result ("within-grace", "stopped", "stopped-without-lock", ...), or its error.
    pub enforced: Result<Option<&'static str>, String>,
    /// Seconds until the next round: ENFORCE_PERIOD, or less so that the round before a deadline starts awaiting
    /// the lock ENFORCE_LEAD seconds before it.
    pub wake: f64,
}

/// One enforcement round, independent of any reconciler (review RV-29, finding 3): fold the restriction intents
/// (a busy lock leaves them unfolded, and enforcement counts them from their time), then enforce with HR-D11's
/// grace, awaiting the activation lock at most until the deadline and stopping without it after.
///
/// Timing: a restriction lacked by the served generation since R has the deadline D = R + 300 (an intent counts
/// from its time, and folding keeps that time). Rounds are at most ENFORCE_PERIOD apart and never sleep past
/// D - ENFORCE_LEAD, so a round starts in [D - ENFORCE_LEAD - ENFORCE_PERIOD, D - ENFORCE_LEAD] (or the first round
/// after the restriction became visible, when that is later); it awaits the lock until D, enforces at D under the
/// lock, or at D stops OLS without it.
pub fn round<R: Runtime>(activator: &Activator<R>, folding: &Mutex<()>) -> Round {
    // Never queued behind engine.restrictions_fold (it may await the activation lock): that fold is running anyway.
    let fold = match folding.try_lock() {
        Ok(_fold) => restrictions::fold(activator, ROUND_FOLD_WAIT).map_err(|(code, message)| format!("{code}: {message}")),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            let _fold = poisoned.into_inner();
            restrictions::fold(activator, ROUND_FOLD_WAIT).map_err(|(code, message)| format!("{code}: {message}"))
        }
        Err(std::sync::TryLockError::WouldBlock) => Ok(json!({"folded": [], "epoch": null})),
    };
    let enforced = activator.enforce_ahead(ENFORCE_GRACE, ENFORCE_LEAD).map_err(|e| {
        let (code, message) = apply::activator_error(e);
        format!("{code}: {message}")
    });
    let wake = match &enforced {
        Ok((_, Some(due))) => (due - ENFORCE_LEAD - activator.rt.now()).clamp(0.1, ENFORCE_PERIOD),
        _ => ENFORCE_PERIOD,
    };
    Round { fold, enforced: enforced.map(|(result, _)| result), wake }
}

/// Every location the engine touches, injectable for tests.
pub struct Config {
    /// /var/lib/ols-cpanel: generations, journal, staging/, events/.
    pub state: PathBuf,
    pub ols_binary: PathBuf,
    /// The activator binary: its `stage-validate` is the validator recorded in validation records.
    pub activator: PathBuf,
    pub userdatadomains: PathBuf,
}

impl Config {
    pub fn production() -> Config {
        Config {
            state: PathBuf::from(crate::activator::generation::STATE),
            ols_binary: PathBuf::from(crate::activator::generation::BINARY),
            activator: PathBuf::from("/usr/local/ols-cpanel/libexec/ols-cpanel-activator"),
            userdatadomains: PathBuf::from("/etc/userdatadomains"),
        }
    }
}

pub struct Engine {
    pub config: Config,
    /// Serializes apply and events_done. enforce and recover only take the activator's own lock, so the
    /// enforcement loop is never queued behind a validation.
    mutations: Mutex<()>,
    /// Serializes folding (engine.restrictions_fold and the enforcement thread), never held while enforcing.
    folding: Mutex<()>,
}

/// A cPanel account name: what runuser may switch to (never an option, never root or nobody).
pub fn valid_user(value: &str) -> bool {
    let b = value.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
        && value != "root"
        && value != "nobody"
}

/// The builder's domain grammar (ServerConfigurationBuilder::DOMAIN): dot-separated labels of lowercase
/// letters, digits and inner hyphens, at least two labels. Stricter than the inventory's valid_domain.
pub fn valid_domain(value: &str) -> bool {
    let labels: Vec<&str> = value.split('.').collect();
    value.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A PHP installation under /opt/cpanel (ea-php83, alt-php74): `[a-z][a-z0-9-]*`.
pub fn valid_version(value: &str) -> bool {
    let b = value.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// For error messages: printable ASCII only, bounded.
pub fn printable(value: &str) -> String {
    value.chars().take(80).map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect()
}

/// The accounts of /etc/userdatadomains (`domain: user==owner==type==...`), read at request time.
pub fn accounts(path: &Path) -> HashSet<String> {
    let text = fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    text.lines()
        .filter_map(|line| line.split_once(": "))
        .filter_map(|(_, rest)| rest.split("==").next())
        .filter(|user| valid_user(user))
        .map(str::to_owned)
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    name: String,
    argv: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grace {
    grace: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seconds {
    seconds: i64,
}

/// `engine.health` seconds: 0..60, like `activator health --seconds N`.
fn health_seconds(args: Value) -> Result<f64, (&'static str, String)> {
    let a: Seconds = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    let max = crate::activator::cli::MAX_HEALTH_SECONDS;
    if !(0..=max).contains(&a.seconds) {
        return Err(("BAD_ARGS", format!("seconds must be 0..{max}")));
    }
    Ok(a.seconds as f64)
}

fn grace(args: Value) -> Result<f64, (&'static str, String)> {
    let a: Grace = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    if !(0..=MAX_GRACE).contains(&a.grace) {
        return Err(("BAD_ARGS", format!("grace must be 0..{MAX_GRACE} seconds")));
    }
    Ok(a.grace as f64)
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

impl Engine {
    pub fn new(config: Config) -> Engine {
        Engine { config, mutations: Mutex::new(()), folding: Mutex::new(()) }
    }

    fn activator(&self) -> Activator<SystemRuntime> {
        let mut activator = Activator::new(Paths::under(&self.config.state, &self.config.ols_binary), SystemRuntime::new());
        activator.validator = vec![OsString::from(&self.config.activator), OsString::from("stage-validate")];
        activator.validator_file = self.config.activator.clone();
        activator
    }

    fn serialized(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mutations.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn run(&self, args: Value) -> Reply {
        let a: Run = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
        if a.name.is_empty() || a.name.len() > 200 || !a.name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(("BAD_ARGS", "name must be 1-200 printable ASCII characters".into()));
        }
        if allowlist::allowed(&a.argv, &accounts(&self.config.userdatadomains)).is_none() {
            return Err(("FORBIDDEN", "argv is not in the engine.run allowlist".into()));
        }
        match command::run(&a.argv, command::TIMEOUT, command::MAX_OUTPUT) {
            Ok(out) => Ok(json!({"exit_code": out.code, "stdout": text(out.stdout), "stderr": text(out.stderr)})),
            Err(command::Failure::TooLarge) => Err(("OUTPUT_TOO_LARGE", "output exceeds 16 MiB".into())),
            Err(command::Failure::Timeout) => Err(("TIMEOUT", "command killed after 120 s".into())),
            Err(command::Failure::Spawn(message)) => Err(("SPAWN_FAILED", message)),
        }
    }

    pub fn apply(&self, args: Value) -> Reply {
        let a: apply::Apply = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
        let _serial = self.serialized();
        apply::apply(&self.activator(), &self.config.state.join("staging"), a)
    }

    pub fn status(&self) -> Reply {
        status_of(&self.activator())
    }

    pub fn enforce(&self, args: Value) -> Reply {
        let grace = grace(args)?;
        let activator = self.activator();
        activator.ensure_dirs().map_err(apply::activator_error)?;
        Ok(json!({"result": activator.enforce(grace).map_err(apply::activator_error)?}))
    }

    /// The active generation's vhost health (read-only: not serialized with apply, takes no lock).
    pub fn health(&self, args: Value) -> Reply {
        let seconds = health_seconds(args)?;
        health_of(&self.activator(), seconds)
    }

    pub fn recover(&self, args: Value) -> Reply {
        let grace = grace(args)?;
        let activator = self.activator();
        activator.ensure_dirs().map_err(apply::activator_error)?;
        activator.recover(grace).map_err(apply::activator_error)
    }

    pub fn events(&self) -> Reply {
        events::pending(&self.config.state.join("events"))
    }

    pub fn events_done(&self, args: Value) -> Reply {
        let _serial = self.serialized();
        events::done(&self.config.state.join("events"), args)
    }

    pub fn events_quarantine(&self, args: Value) -> Reply {
        let _serial = self.serialized();
        events::quarantine(&self.config.state.join("events"), args)
    }

    /// `engine.restrictions_fold`: `{"folded": [names], "epoch"}`.
    pub fn restrictions_fold(&self) -> Reply {
        let _fold = self.folding.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let activator = self.activator();
        activator.ensure_dirs().map_err(apply::activator_error)?;
        restrictions::fold(&activator, FOLD_WAIT)
    }

    /// One round of the broker's enforcement thread (main.rs runs it every ENFORCE_PERIOD at most).
    pub fn enforcement_round(&self) -> Round {
        let activator = self.activator();
        if let Err(e) = activator.ensure_dirs() {
            let (code, message) = apply::activator_error(e);
            return Round { fold: Err(format!("{code}: {message}")), enforced: Err(format!("{code}: {message}")), wake: ENFORCE_PERIOD };
        }
        round(&activator, &self.folding)
    }
}

/// `activator health --seconds N`: `{"generation", "failing": [{"vhost", "got"}]}`.
fn health_of<R: crate::activator::runtime::Runtime>(activator: &Activator<R>, seconds: f64) -> Reply {
    activator.ensure_dirs().map_err(apply::activator_error)?;
    activator.health(seconds).map_err(apply::activator_error)
}

/// `activator status` plus the active generation's SOURCE_SHA256 (stripped; null when missing).
fn status_of<R: crate::activator::runtime::Runtime>(activator: &Activator<R>) -> Reply {
    activator.ensure_dirs().map_err(apply::activator_error)?;
    let mut out = activator.status().map_err(apply::activator_error)?;
    let source = activator
        .pointer()
        .filter(|gen| !gen.is_empty())
        .and_then(|gen| fs::read(cat(&cat(&activator.paths.gen_root, &gen), "SOURCE_SHA256")).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|t| crate::activator::pystr::strip(&t).to_string());
    out["source_sha256"] = json!(source);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::{Mock, TempTree};

    fn engine(temp: &TempTree) -> Engine {
        let state = temp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let userdatadomains = temp.path().join("userdatadomains");
        fs::write(&userdatadomains, "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
                                     host.test: nobody==root==main==host.test==/var/www/html==1.2.3.4:80==1.2.3.4:443====0==\n").unwrap();
        Engine::new(Config { state: state.clone(), ols_binary: state.join("openlitespeed"), activator: PathBuf::from("/nonexistent"), userdatadomains })
    }

    #[test]
    fn grammars() {
        for good in ["a.test", "olscp-c.test", "x1.b-2.example.com", "svc.a.test"] {
            assert!(valid_domain(good), "{good}");
        }
        for bad in ["", "a", "a.", ".a", "a..b", "-a.test", "a-.test", "A.test", "a_b.test", "*.a.test", "a.test/x", "a.test\n"] {
            assert!(!valid_domain(bad), "{bad:?}");
        }
        for bad in ["", "root", "nobody", "-u", "_x", "Bob", "a.b", "a/b", &"a".repeat(33)] {
            assert!(!valid_user(bad), "{bad}");
        }
        assert!(valid_version("ea-php83") && valid_version("alt-php74") && !valid_version("8.3") && !valid_version("..") && !valid_version("Ea"));
    }

    #[test]
    fn accounts_come_from_userdatadomains() {
        let temp = TempTree::new();
        let e = engine(&temp);
        assert_eq!(accounts(&e.config.userdatadomains), ["olscpa".to_string()].into_iter().collect());
        assert!(accounts(&temp.path().join("missing")).is_empty());
    }

    #[test]
    fn run_checks_arguments_and_allowlist() {
        let temp = TempTree::new();
        let e = engine(&temp);
        let code = |args: Value| e.run(args).unwrap_err().0;
        assert_eq!(code(json!({"name": "x", "argv": ["/usr/bin/id"]})), "FORBIDDEN");
        assert_eq!(code(json!({"name": "x", "argv": ["/usr/sbin/runuser", "-u", "nobody", "--", "/usr/bin/cat", "/home/nobody/.htaccess"]})), "FORBIDDEN");
        assert_eq!(code(json!({"name": "x", "argv": ["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/cat", "/home/olscpb/.htaccess"]})), "FORBIDDEN");
        assert_eq!(code(json!({"name": "", "argv": ["/usr/bin/hostname", "-f"]})), "BAD_ARGS");
        assert_eq!(code(json!({"name": "a\nb", "argv": ["/usr/bin/hostname", "-f"]})), "BAD_ARGS");
        assert_eq!(code(json!({"name": "x", "argv": ["/usr/bin/hostname", "-f"], "env": {}})), "BAD_ARGS");
        assert_eq!(code(json!({"argv": ["/usr/bin/hostname", "-f"]})), "BAD_ARGS");
        assert_eq!(code(json!({"name": "x", "argv": "/usr/bin/hostname -f"})), "BAD_ARGS");
        // An allowlisted command runs (whatever its exit status in this environment).
        let out = e.run(json!({"name": "suspended-olscpa", "argv": ["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpa"]})).unwrap();
        assert!(out["exit_code"].is_i64() && out["stdout"] == json!("") && out["stderr"].is_string());
    }

    #[test]
    fn lossy_text_only_when_invalid() {
        assert_eq!(text(b"caf\xc3\xa9".to_vec()), "caf\u{e9}");
        assert_eq!(text(b"a\xffb".to_vec()), "a\u{fffd}b");
    }

    #[test]
    fn grace_is_bounded() {
        assert_eq!(grace(json!({"grace": 300})).unwrap(), 300.0);
        for bad in [json!({"grace": -1}), json!({"grace": 86401}), json!({"grace": 1.5}), json!({"grace": "1"}), json!({}),
                    json!({"grace": 1, "x": 2}), json!(null)] {
            assert_eq!(grace(bad).unwrap_err().0, "BAD_ARGS");
        }
    }

    #[test]
    fn health_seconds_are_bounded() {
        assert_eq!(health_seconds(json!({"seconds": 0})).unwrap(), 0.0);
        assert_eq!(health_seconds(json!({"seconds": 60})).unwrap(), 60.0);
        for bad in [json!({"seconds": -1}), json!({"seconds": 61}), json!({"seconds": 1.5}), json!({"seconds": "5"}), json!({}),
                    json!({"seconds": 5, "x": 1}), json!(null)] {
            assert_eq!(health_seconds(bad).unwrap_err().0, "BAD_ARGS");
        }
    }

    #[test]
    fn health_of_the_active_generation() {
        let temp = TempTree::new();
        let state = temp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let a = Activator::new(Paths::under(&state, &state.join("openlitespeed")), Mock::running(Some("r20261022120000-a1b2c3")));
        assert_eq!(health_of(&a, 5.0).unwrap(), json!({"generation": null, "failing": []}));
        let gen = a.paths.gen_root.join("r20261022120000-a1b2c3");
        fs::create_dir_all(&gen).unwrap();
        fs::write(gen.join("health.json"), r#"[{"vhost": "a.test", "host": "a.test", "url": "http://10.0.0.5:80/.ols-cpanel-generation/id"}]"#).unwrap();
        std::os::unix::fs::symlink(&gen, &a.paths.active).unwrap();
        assert_eq!(health_of(&a, 5.0).unwrap(), json!({"generation": "r20261022120000-a1b2c3", "failing": []}));
        a.rt.healthy.set(false);
        assert_eq!(health_of(&a, 0.0).unwrap(),
                   json!({"generation": "r20261022120000-a1b2c3", "failing": [{"vhost": "a.test", "got": "error: HTTP 404"}]}));
        // Through the engine (no OLS in the test environment): the bounded argument is checked first.
        let other = TempTree::new();
        let e = engine(&other);
        assert_eq!(e.health(json!({"seconds": 61})).unwrap_err().0, "BAD_ARGS");
        assert_eq!(e.health(json!({"seconds": 0})).unwrap(), json!({"generation": null, "failing": []}));
    }

    /// OLS serving "old" (epoch 0, the pointer), "new" (epoch 1) staged and validated, a restriction at `since`.
    fn stale_server(temp: &TempTree, since: Option<f64>) -> Activator<Mock> {
        let state = temp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("openlitespeed"), b"binary").unwrap();
        let a = Activator::new(Paths::under(&state, &state.join("openlitespeed")), Mock::running(Some("old")));
        a.ensure_dirs().unwrap();
        fs::write(&a.paths.epoch, r#"{"epoch": 0, "history": []}"#).unwrap();
        for (gen, epoch) in [("old", 0), ("new", 1)] {
            let dir = a.paths.gen_root.join(gen);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("EPOCH"), format!("{epoch}\n")).unwrap();
            fs::write(dir.join("health.json"), r#"[{"vhost": "a.test", "host": "a.test", "url": "http://10.0.0.5:80/.ols-cpanel-generation/id"}]"#).unwrap();
            let record = json!({"generation": gen, "valid": true, "tree_sha256": a.tree_sha256(gen).unwrap(),
                                "binary_sha256": crate::activator::generation::file_sha256(&a.paths.binary).unwrap()});
            fs::write(a.paths.validations.join(format!("{gen}.json")), record.to_string()).unwrap();
        }
        a.switch("old").unwrap();
        if let Some(since) = since {
            let now = a.rt.wall.get();
            a.rt.wall.set(since);
            a.restrict("Accounts::suspendacct bob").unwrap();
            a.rt.wall.set(now);
        }
        a
    }

    /// The activation lock held by another open file (a transaction in progress), released on drop.
    fn hold_lock(a: &Activator<Mock>) -> fs::File {
        let file = fs::OpenOptions::new().append(true).create(true).open(&a.paths.lock).unwrap();
        assert_eq!(unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) }, 0);
        file
    }

    fn no_fold() -> Result<Value, String> {
        Ok(json!({"folded": [], "epoch": null}))
    }

    #[test]
    fn enforcement_rounds_wake_before_the_deadline() {
        let temp = TempTree::new();
        // Nothing stale: the next round in one period.
        let a = stale_server(&temp, None);
        let folding = Mutex::new(());
        assert_eq!(round(&a, &folding), Round { fold: no_fold(), enforced: Ok(None), wake: ENFORCE_PERIOD });
        // A restriction 200 s ago: within grace, deadline far away.
        let temp = TempTree::new();
        let a = stale_server(&temp, Some(800.0));
        assert_eq!(round(&a, &folding), Round { fold: no_fold(), enforced: Ok(Some("within-grace")), wake: ENFORCE_PERIOD });
        // 288 s ago: the next round starts awaiting the lock ENFORCE_LEAD before the deadline (in 2 s).
        let temp = TempTree::new();
        let a = stale_server(&temp, Some(712.0));
        assert_eq!(round(&a, &folding), Round { fold: no_fold(), enforced: Ok(Some("within-grace")), wake: 2.0 });
        assert!(a.rt.calls().is_empty());
    }

    #[test]
    fn enforcement_stops_at_the_deadline_with_the_lock() {
        let temp = TempTree::new();
        // 295 s ago (deadline 1005): the lock is free, held until the deadline, then the stale generation stops.
        let a = stale_server(&temp, Some(705.0));
        let out = round(&a, &Mutex::new(()));
        assert_eq!(out.enforced, Ok(Some("stopped")));
        assert_eq!(a.rt.calls(), ["stop"]);
        assert!(a.rt.wall.get() >= 1005.0 && a.rt.wall.get() < 1005.5, "stopped at {}", a.rt.wall.get());
        assert_eq!(out.wake, ENFORCE_PERIOD);
    }

    #[test]
    fn enforcement_stops_without_the_lock_past_the_deadline() {
        let temp = TempTree::new();
        let a = stale_server(&temp, Some(705.0));
        let holder = hold_lock(&a);
        let out = round(&a, &Mutex::new(()));
        // The transaction keeps the lock past the deadline: stopped without it, at the deadline.
        assert_eq!(out.enforced, Ok(Some("stopped-without-lock")));
        assert_eq!(a.rt.calls(), ["stop"]);
        assert!(a.rt.wall.get() >= 1004.999 && a.rt.wall.get() < 1005.5, "stopped at {}", a.rt.wall.get());
        drop(holder);
        // The transaction ends: it finds OLS stopped. "old" is stale and never comes back; "new" may start.
        assert!(!a.ols_running());
        let out = a.recover(300.0).unwrap();
        assert_eq!(out["actions"], json!([]));
        assert_eq!(a.rt.calls(), ["stop"]);
        assert_eq!(a.reload(), 1, "the stale pointer is not started");
        assert_eq!(a.rt.calls(), ["stop"]);
    }

    #[test]
    fn unfolded_intents_count_from_their_time() {
        let temp = TempTree::new();
        let a = stale_server(&temp, None);
        fs::create_dir_all(&a.paths.restrictions).unwrap();
        let intent = "1729600000000000001-0123456789abcdef0123456789abcdef.json";
        fs::write(a.paths.restrictions.join(intent), r#"{"event": "Accounts::Remove", "reason": "Accounts::Remove bob", "time": 600, "user": "bob"}"#).unwrap();
        // Every generation lacks the intent; the deadline (900) has passed and a transaction holds the lock: the
        // round cannot fold it, and stops OLS without the lock at once.
        let holder = hold_lock(&a);
        let out = round(&a, &Mutex::new(()));
        assert!(out.fold.as_ref().unwrap_err().starts_with("ACTIVATOR: activation lock busy"), "{:?}", out.fold);
        assert_eq!(out.enforced, Ok(Some("stopped-without-lock")));
        // The transaction cannot restart anything while the intent is unfolded, not even the newest generation.
        assert_eq!(a.validation_problem("new").unwrap(), Some(format!("restriction intent {intent} not yet folded into the epoch")));
        a.switch("new").unwrap();
        assert_eq!(a.reload(), 1);
        drop(holder);
        assert_eq!(a.rt.calls(), ["stop"]);
        // The next round folds it with its own time (the deadline does not move); "new" (epoch 1) is current again.
        let out = round(&a, &Mutex::new(()));
        assert_eq!(out.fold, Ok(json!({"folded": [intent], "epoch": 1})));
        assert_eq!(out.enforced, Ok(None));
        let record: Value = serde_json::from_slice(&fs::read(&a.paths.epoch).unwrap()).unwrap();
        assert_eq!(record["history"][0]["time"], json!(600.0));
        assert_eq!(a.validation_problem("new").unwrap(), None);
        // A fold already running elsewhere: the round does not queue behind it.
        let folding = Mutex::new(());
        let _busy = folding.lock().unwrap();
        assert_eq!(round(&a, &folding).fold, no_fold());
    }

    #[test]
    fn enforce_never_waits_for_the_lock_without_bound() {
        // The one-shot enforce (activator CLI, engine.enforce) past the deadline with the lock held: one attempt,
        // then the stop without it.
        let temp = TempTree::new();
        let a = stale_server(&temp, Some(500.0));
        let _holder = hold_lock(&a);
        assert_eq!(a.enforce(300.0).unwrap(), Some("stopped-without-lock"));
        assert!(a.rt.clock.get() < 1.0);
        // Within grace it never touches the lock.
        let temp = TempTree::new();
        let a = stale_server(&temp, Some(900.0));
        let _holder = hold_lock(&a);
        assert_eq!(a.enforce(300.0).unwrap(), Some("within-grace"));
    }

    #[test]
    fn quarantine_and_fold_through_the_engine() {
        let temp = TempTree::new();
        let e = engine(&temp);
        assert_eq!(e.restrictions_fold().unwrap(), json!({"folded": [], "epoch": null}));
        assert_eq!(e.events_quarantine(json!({"names": ["x.json"]})).unwrap_err().0, "NOT_FOUND");
        let spool = e.config.state.join("events");
        fs::create_dir_all(&spool).unwrap();
        fs::write(spool.join("x.json"), "{}").unwrap();
        assert_eq!(e.events_quarantine(json!({"names": ["x.json"]})).unwrap(), json!({"quarantined": ["x.json"]}));
        assert!(spool.join("quarantine/x.json").is_file());
    }

    #[test]
    fn status_adds_the_active_source_digest() {
        let temp = TempTree::new();
        let state = temp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let a = Activator::new(Paths::under(&state, &state.join("openlitespeed")), Mock::new());
        let out = status_of(&a).unwrap();
        assert_eq!(out["source_sha256"], Value::Null);
        assert_eq!(out["pointer"], Value::Null);
        let gen = a.paths.gen_root.join("r20261022120000-a1b2c3");
        fs::create_dir_all(&gen).unwrap();
        std::os::unix::fs::symlink(&gen, &a.paths.active).unwrap();
        assert_eq!(status_of(&a).unwrap()["source_sha256"], Value::Null);
        fs::write(gen.join("SOURCE_SHA256"), format!("{}\n", "ab".repeat(32))).unwrap();
        let out = status_of(&a).unwrap();
        assert_eq!(out["source_sha256"], json!("ab".repeat(32)));
        assert_eq!(out["pointer"], json!("r20261022120000-a1b2c3"));
        assert!(out.get("coherent").is_some() && out.get("epoch").is_some());
    }
}
