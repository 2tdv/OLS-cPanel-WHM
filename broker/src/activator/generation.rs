//! Generation activation (plan section 17), ported from build/vm-qualification/ols_generation.py.
//!
//! Immutable generations live in GEN_ROOT/<id>/ and reference only their own absolute paths; one
//! pointer (ACTIVE, a symlink replaced by rename) selects the live one, and OLS's fixed main config is
//! a stable symlink to ACTIVE/httpd_config.conf. Every activation writes a durable journal:
//! intent -> switched -> reloaded -> committed | rolled_back | aborted. Each generation contains a
//! loopback-only marker vhost serving its own ID, so verification checks what OLS actually serves.
//! `recover` brings any interrupted transaction to a coherent state: pointer == served generation ==
//! the last committed (or newly verified) generation.
//! Activation requires a passing validation record of exactly this generation (tree digest) and this
//! OLS binary, and a generation commits only when the marker AND every vhost listed in its
//! health.json answer from this generation (review RV-02).
//! Restriction epoch (plan 14.4, review RV-05): every security-sensitive cPanel change raises a durable
//! epoch; each generation records the epoch it was compiled against (file EPOCH). No activation,
//! rollback or recovery ever selects a generation from an older epoch.
//!
//! Function names and control flow follow the Python tool one to one; where the Python would crash
//! with a traceback (exit status 1), this port returns `Error::Fatal` (also exit status 1).

use super::pyjson;
use super::pystr;
use super::runtime::Runtime;
use super::validate::{copytree, hex};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use crate::engine::command::{self, Failure};
use std::time::Duration;

pub const STATE: &str = "/var/lib/ols-cpanel";
pub const BINARY: &str = "/usr/local/lsws/bin/openlitespeed";
pub const MARKER_URL: &str = "http://127.0.0.1:8097/generation";
pub const CRASH_POINTS: [&str; 3] = ["intent", "switched", "reloaded"];
pub const FINAL: [&str; 8] = [
    "committed",
    "rolled_back",
    "aborted",
    "rollback_failed",
    "failed_no_previous",
    "rollback_refused_stale",
    "stopped_no_fresh_generation",
    "superseded",
];

/// Total deadline of one activator transaction (activate with its rollback, recover, enforce, health): every
/// wait for the marker and every health check shares what is left of it (review RV-29, finding 4).
pub const TRANSACTION_SECONDS: f64 = 120.0;
/// Of an activation's deadline, what the forward checks leave for the rollback should the generation fail.
pub const ROLLBACK_RESERVE: f64 = 50.0;
/// Every `systemctl reload|start` is killed after this long (and after 5 s once the deadline is spent).
pub const SYSTEMCTL_TIMEOUT: f64 = 30.0;
/// `systemctl stop` is the fail-closed action: it gets this long whatever is left of the deadline.
pub const STOP_TIMEOUT: f64 = 20.0;
/// The staged validator (its OLS binary test is itself bounded by 60 s).
pub const VALIDATE_TIMEOUT: Duration = Duration::from_secs(300);
/// What a health target "answers" when the transaction's deadline left no time to ask it (unhealthy).
pub const DEADLINE_EXCEEDED: &str = "error: deadline exceeded";
/// A restriction intent is a small JSON object (docs/product-interfaces.md, "Restriction intents").
pub const MAX_INTENT: u64 = 65536;

/// A restriction intent's file name (the spool name grammar `^[0-9]{1,24}-[0-9a-f]{32}\.json$`).
pub fn intent_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else { return false };
    let Some((time, id)) = stem.split_once('-') else { return false };
    (1..=24).contains(&time.len())
        && time.bytes().all(|b| b.is_ascii_digit())
        && id.len() == 32
        && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Oldest first: shorter names first, then byte order (the names start with the time in nanoseconds).
pub fn oldest_first(names: &mut [String]) {
    names.sort_by(|a, b| (a.len(), a.as_str()).cmp(&(b.len(), b.as_str())));
}

/// The enforcement decision for the served generation (made without the activation lock).
#[derive(Debug, PartialEq)]
pub enum Assessment {
    /// OLS is not running, or what it serves is current.
    Nothing,
    /// A stale generation serves, inside its grace: the deadline (wall clock) of its earliest unapplied restriction.
    Within(f64),
    /// A stale generation serves past its deadline (or without any grace); the served generation's ID.
    Due(Option<String>),
}

#[derive(Debug)]
pub enum Error {
    /// The restriction epoch record is damaged; nothing may be treated as current (fail closed).
    Epoch(String),
    /// Python SystemExit(message): the message on stderr, exit status 1.
    Exit(String),
    /// Any other failure (a Python traceback): exit status 1.
    Fatal(String),
    /// `--crash-after`: exit status 9 at once, nothing printed (Python os._exit(9)).
    Crash,
}

pub type Result<T> = std::result::Result<T, Error>;

fn fatal<E: std::fmt::Display>(what: impl AsRef<Path>) -> impl FnOnce(E) -> Error {
    let what = what.as_ref().display().to_string();
    move |e| Error::Fatal(format!("{what}: {e}"))
}

/// `base + "/" + rest` as a string, like the Python f-strings (an absolute `rest` stays below `base`).
pub fn cat(base: &Path, rest: &str) -> PathBuf {
    let mut joined = OsString::from(base.as_os_str());
    joined.push("/");
    joined.push(rest);
    PathBuf::from(joined)
}

pub struct Paths {
    pub state: PathBuf,
    pub gen_root: PathBuf,
    pub journal: PathBuf,
    pub validations: PathBuf,
    pub epoch: PathBuf,
    /// Independent high-water mark of the restriction epoch: losing epoch.json must not lose a restriction.
    pub epoch_high: PathBuf,
    pub binary: PathBuf,
    pub active: PathBuf,
    pub lock: PathBuf,
    /// The hook's durable restriction intents (`ols_events.RESTRICTIONS`).
    pub restrictions: PathBuf,
    pub marker_url: String,
}

impl Paths {
    pub fn production() -> Paths {
        Paths::under(Path::new(STATE), Path::new(BINARY))
    }

    pub fn under(state: &Path, binary: &Path) -> Paths {
        Paths {
            state: state.to_path_buf(),
            gen_root: cat(state, "generations"),
            journal: cat(state, "journal"),
            validations: cat(state, "validations"),
            epoch: cat(state, "epoch.json"),
            epoch_high: cat(state, "epoch.high"),
            binary: binary.to_path_buf(),
            active: cat(state, "active"),
            lock: cat(state, "activation.lock"),
            restrictions: cat(state, "restrictions"),
            marker_url: MARKER_URL.to_string(),
        }
    }
}

/// Python truthiness of a JSON value.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().map_or(true, |f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn some_truthy(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

/// `str(value)` for scalars (used where Python formats a JSON value into a path or message).
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) if n.is_f64() => pyjson::float_repr(n.as_f64().unwrap_or(f64::NAN)),
        other => other.to_string(),
    }
}

/// A numeric sort/seq key: missing -> default, bool -> 0/1, number -> value; anything else is the
/// TypeError a Python comparison would raise.
fn number(value: Option<&Value>, default: f64) -> Result<f64> {
    match value {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(if *b { 1.0 } else { 0.0 }),
        Some(Value::Number(n)) => Ok(n.as_f64().unwrap_or(default)),
        Some(other) => Err(Error::Fatal(format!("journal record has a non-numeric order key {other}"))),
    }
}

pub fn uuid_hex() -> String {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).expect("/dev/urandom is readable");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    hex(&bytes)
}

/// The bytes of a restriction intent (a regular file of at most MAX_INTENT bytes, never through a link), or None.
pub fn read_intent(path: &Path) -> Option<Vec<u8>> {
    // O_NONBLOCK keeps a planted FIFO from blocking the read.
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_INTENT + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= MAX_INTENT).then_some(bytes)
}

/// An intent's `time` (Unix seconds, a JSON number), when it has a usable one.
fn intent_time(path: &Path) -> Option<f64> {
    match serde_json::from_slice::<Value>(&read_intent(path)?).ok()? {
        Value::Object(map) => map.get("time").and_then(Value::as_f64).filter(|t| t.is_finite()),
        _ => None,
    }
}

pub fn fsync_dir(path: &Path) -> Result<()> {
    let dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)
        .map_err(fatal(path))?;
    dir.sync_all().map_err(fatal(path))
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Write to a unique temporary name, fsync, rename over `path`, fsync the directory.
pub fn write_durable(path: &Path, text: &str) -> Result<()> {
    let mut tmp = OsString::from(path.as_os_str());
    tmp.push(format!(".tmp-{}", uuid_hex()));
    let tmp = PathBuf::from(tmp);
    let mut file = fs::File::create(&tmp).map_err(fatal(&tmp))?;
    file.write_all(text.as_bytes()).map_err(fatal(&tmp))?;
    file.sync_all().map_err(fatal(&tmp))?;
    fs::rename(&tmp, path).map_err(fatal(path))?;
    fsync_dir(parent(path))
}

pub fn file_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(fatal(path))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer).map_err(fatal(path))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(hex(&digest.finalize()))
}

/// Exclusive activation lock (flock on activation.lock), released on drop.
pub struct Lock(#[allow(dead_code)] fs::File);

/// A transaction deadline in force until dropped; nested deadlines only ever shorten the outer one.
pub struct Deadline<'a> {
    cell: &'a std::cell::Cell<f64>,
    previous: f64,
}

impl Drop for Deadline<'_> {
    fn drop(&mut self) {
        self.cell.set(self.previous);
    }
}

/// os.walk(top) without following links, top-down: `visit(root, dirs, files)` runs before the
/// subdirectories are listed (as in Python, where the loop body runs before the walk descends);
/// unreadable directories are skipped like os.walk without onerror.
fn walk_visit(top: &str, visit: &mut dyn FnMut(&str, &[String], &[String]) -> Result<()>) -> Result<()> {
    let Ok(entries) = fs::read_dir(top) else {
        return Ok(());
    };
    let (mut dirs, mut files) = (Vec::new(), Vec::new());
    for entry in entries.filter_map(std::result::Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        // DirEntry.is_dir() follows a symbolic link; a link to a directory is listed but not entered.
        if fs::metadata(entry.path()).map(|m| m.is_dir()).unwrap_or(false) {
            dirs.push(name);
        } else {
            files.push(name);
        }
    }
    visit(top, &dirs, &files)?;
    for name in dirs {
        let path = pystr::join(top, &name);
        if !Path::new(&path).is_symlink() {
            walk_visit(&path, visit)?;
        }
    }
    Ok(())
}

/// All (root, dirs, files) of os.walk(top).
fn walk(top: &str) -> Vec<(String, Vec<String>, Vec<String>)> {
    let mut out = Vec::new();
    let _ = walk_visit(top, &mut |root, dirs, files| {
        out.push((root.to_string(), dirs.to_vec(), files.to_vec()));
        Ok(())
    });
    out
}

pub struct Activator<R: Runtime> {
    pub paths: Paths,
    pub rt: R,
    /// Validator command (program and leading arguments); the generation directory is appended.
    pub validator: Vec<OsString>,
    /// The file whose digest is recorded as validator_sha256.
    pub validator_file: PathBuf,
    /// The current transaction's deadline (monotonic seconds; infinite outside a transaction).
    deadline: std::cell::Cell<f64>,
}

impl<R: Runtime> Activator<R> {
    pub fn new(paths: Paths, rt: R) -> Activator<R> {
        Activator {
            paths,
            rt,
            validator: vec![OsString::from("/proc/self/exe"), OsString::from("stage-validate")],
            validator_file: PathBuf::from("/proc/self/exe"),
            deadline: std::cell::Cell::new(f64::INFINITY),
        }
    }

    /// A deadline `seconds` from now for everything until the guard is dropped (never later than one in force).
    pub fn deadline_in(&self, seconds: f64) -> Deadline<'_> {
        self.deadline_at(self.rt.monotonic() + seconds)
    }

    fn deadline_at(&self, at: f64) -> Deadline<'_> {
        let previous = self.deadline.get();
        self.deadline.set(previous.min(at));
        Deadline { cell: &self.deadline, previous }
    }

    /// What is left of the transaction's deadline, at most `cap` seconds, never negative.
    pub fn budget(&self, cap: f64) -> f64 {
        (self.deadline.get() - self.rt.monotonic()).min(cap).max(0.0)
    }

    /// The activation lock, waiting at most `seconds` (at least one attempt); None while another holder keeps it.
    pub fn lock_within(&self, seconds: f64) -> Result<Option<Lock>> {
        let file = fs::OpenOptions::new().append(true).create(true).open(&self.paths.lock).map_err(fatal(&self.paths.lock))?;
        let limit = self.rt.monotonic() + seconds.max(0.0);
        loop {
            // SAFETY: a valid open descriptor.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Some(Lock(file)));
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) {
                return Err(Error::Fatal(format!("{}: {error}", self.paths.lock.display())));
            }
            let left = limit - self.rt.monotonic();
            if left <= 0.0 {
                return Ok(None);
            }
            self.rt.sleep(Duration::from_secs_f64(left.clamp(0.001, 0.1)));
        }
    }

    /// The hook's restriction intents not yet folded into the epoch, oldest first, each with the time it counts
    /// from: its `time` when that is a finite number no later than the file's modification time, otherwise that
    /// modification time (a symbolic link's own). An intent is a restriction no generation has applied
    /// (docs/product-interfaces.md, "Restriction intents"). An unreadable directory is an error (fail closed).
    pub fn pending_intents(&self) -> std::result::Result<Vec<(String, f64)>, String> {
        let dir = &self.paths.restrictions;
        let entries = match fs::read_dir(dir) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("restriction intents unreadable: {e}")),
            Ok(entries) => entries,
        };
        let mut names: Vec<String> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("restriction intents unreadable: {e}"))?;
            if let Some(name) = entry.file_name().to_str().filter(|n| intent_name(n)) {
                names.push(name.to_string());
            }
        }
        oldest_first(&mut names);
        let mut out = Vec::new();
        for name in names {
            let path = cat(dir, &name);
            let Ok(meta) = fs::symlink_metadata(&path) else { continue }; // folded meanwhile
            let modified = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0.0, |d| d.as_secs_f64());
            let time = if meta.is_file() && meta.len() <= MAX_INTENT { intent_time(&path) } else { None };
            out.push((name, time.filter(|t| *t <= modified).unwrap_or(modified)));
        }
        Ok(out)
    }

    fn gen_dir(&self, gen: &str) -> PathBuf {
        cat(&self.paths.gen_root, gen)
    }

    pub fn lock(&self) -> Result<Lock> {
        let file = fs::OpenOptions::new().append(true).create(true).open(&self.paths.lock).map_err(fatal(&self.paths.lock))?;
        loop {
            // SAFETY: a valid open descriptor.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Lock(file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(Error::Fatal(format!("{}: {error}", self.paths.lock.display())));
            }
        }
    }

    /// Monotonic transaction order (never wall-clock time: review F-17..F-20); called under LOCK.
    pub fn next_seq(&self) -> Result<Value> {
        let mut highest = 0.0f64;
        let mut integral = true;
        for tx in self.read_journal()? {
            let seq = tx.get("seq");
            if matches!(seq, Some(Value::Number(n)) if n.is_f64()) {
                integral = false;
            }
            highest = highest.max(number(seq, 0.0)?);
        }
        Ok(if integral { json!(highest as i64 + 1) } else { json!(highest + 1.0) })
    }

    pub fn journal(&self, tx: &mut Map<String, Value>, fields: Vec<(&str, Value)>) -> Result<()> {
        let state = fields.iter().find(|(k, _)| *k == "state").map(|(_, v)| v.clone()).unwrap_or(Value::Null);
        for (key, value) in fields {
            tx.insert(key.to_string(), value);
        }
        tx.insert("updated".into(), json!(self.rt.now()));
        match tx.entry("history").or_insert_with(|| json!([])) {
            Value::Array(history) => history.push(state),
            _ => return Err(Error::Fatal("journal record history is not a list".into())),
        }
        let id = py_str(tx.get("id").unwrap_or(&Value::Null));
        write_durable(&cat(&self.paths.journal, &format!("{id}.json")), &pyjson::dumps(&Value::Object(tx.clone()), None))
    }

    pub fn pointer(&self) -> Option<String> {
        fs::read_link(&self.paths.active).ok().map(|target| pystr::basename(&target.to_string_lossy()))
    }

    pub fn served(&self) -> Option<String> {
        self.rt.marker(&self.paths.marker_url, Duration::from_secs(1))
    }

    /// Digest of every file and symlink in the generation, by relative path (symbolic links to
    /// directories are listed by os.walk as directories and are therefore not covered).
    pub fn tree_sha256(&self, gen: &str) -> Result<String> {
        let base = self.gen_dir(gen).to_string_lossy().into_owned();
        let mut tree = walk(&base);
        tree.sort_by(|a, b| a.0.cmp(&b.0));
        let mut digest = Sha256::new();
        for (root, _, mut files) in tree {
            files.sort();
            for name in files {
                let path = pystr::join(&root, &name);
                let rel = path[base.len()..].trim_start_matches('/').to_string();
                let link = Path::new(&path).is_symlink();
                let value = if link {
                    let target = fs::read_link(&path).map_err(fatal(&path))?;
                    let mut bytes = b"link:".to_vec();
                    bytes.extend_from_slice(target.as_os_str().as_bytes());
                    bytes
                } else {
                    file_sha256(Path::new(&path))?.into_bytes()
                };
                digest.update(rel.as_bytes());
                digest.update(b"\0");
                digest.update(&value);
                digest.update(b"\n");
            }
        }
        Ok(hex(&digest.finalize()))
    }

    fn generations_with_epoch(&self) -> std::result::Result<Vec<String>, String> {
        let names: Vec<String> = match fs::read_dir(&self.paths.gen_root) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("generations unreadable: {e}")),
            Ok(entries) => entries.filter_map(std::result::Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect(),
        };
        // An unknown epoch (-1) counts: fail closed.
        Ok(names.into_iter().filter(|g| self.generation_epoch(g) != 0).collect())
    }

    /// The restriction epoch. A missing record means epoch 0 only on a fresh installation; a damaged
    /// record, or a missing one while generations of a later epoch exist, is an error (never reset).
    pub fn current_epoch(&self) -> std::result::Result<i64, String> {
        let text = match fs::read(&self.paths.epoch) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if self.paths.epoch_high.exists() || !self.generations_with_epoch()?.is_empty() {
                    return Err("epoch record missing although a restriction was recorded".into());
                }
                return Ok(0);
            }
            Err(e) => return Err(format!("epoch record unreadable: {e}")),
            Ok(bytes) => String::from_utf8(bytes).map_err(|e| format!("epoch record unreadable: {e}"))?,
        };
        let record: Value = serde_json::from_str(&text).map_err(|e| format!("epoch record unreadable: {e}"))?;
        let value = match &record {
            Value::Object(map) => map.get("epoch").ok_or("epoch record unreadable: 'epoch'")?,
            _ => return Err("epoch record unreadable: not an object".into()),
        };
        let value = match value {
            Value::Number(n) if !n.is_f64() => n.as_i64().ok_or("epoch record malformed")?,
            _ => return Err("epoch record malformed".into()),
        };
        if value < 0 {
            return Err("epoch record malformed".into());
        }
        let high = match fs::read(&self.paths.epoch_high) {
            Err(e) if e.kind() == ErrorKind::NotFound => 0,
            Err(e) => return Err(format!("epoch high-water mark unreadable: {e}")),
            Ok(bytes) => String::from_utf8(bytes)
                .ok()
                .and_then(|t| pystr::int(&t))
                .ok_or("epoch high-water mark unreadable: invalid literal")?,
        };
        if high > value {
            return Err("epoch record older than its high-water mark".into());
        }
        Ok(value)
    }

    /// The epoch a generation was compiled against; -1 (unknown) is never newer than any epoch.
    pub fn generation_epoch(&self, gen: &str) -> i64 {
        fs::read(cat(&self.gen_dir(gen), "EPOCH"))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| pystr::int(&text))
            .unwrap_or(-1)
    }

    /// A generation older than the restriction epoch; while an unfolded restriction intent exists (or the intents
    /// cannot be read), every generation is stale.
    pub fn stale(&self, gen: Option<&str>) -> bool {
        match gen {
            None => false,
            Some(_) if self.pending_intents().map_or(true, |intents| !intents.is_empty()) => true,
            Some(gen) => match self.current_epoch() {
                Ok(epoch) => self.generation_epoch(gen) < epoch,
                Err(_) => true, // unknown restrictions: nothing is current
            },
        }
    }

    pub fn epoch_or_none(&self) -> Option<i64> {
        self.current_epoch().ok()
    }

    /// Raise the restriction epoch durably before a security-sensitive change is acknowledged.
    pub fn restrict(&self, reason: &str) -> Result<Value> {
        let _lock = self.lock()?;
        self.restrict_locked(reason, None)
    }

    /// Folding a restriction intent (the broker): `restrict` with the history time of the intent (never later than
    /// now), so folding never moves the enforcement deadline; waits at most `wait` seconds for the lock (None
    /// when another holder keeps it).
    pub fn restrict_since(&self, reason: &str, since: f64, wait: f64) -> Result<Option<Value>> {
        let Some(_lock) = self.lock_within(wait)? else { return Ok(None) };
        self.restrict_locked(reason, Some(since)).map(Some)
    }

    fn restrict_locked(&self, reason: &str, since: Option<f64>) -> Result<Value> {
        let epoch = self.current_epoch().map_err(Error::Epoch)?; // never restart the counter
        let mut record = match fs::read(&self.paths.epoch) {
            Err(e) if e.kind() == ErrorKind::NotFound => json!({"epoch": 0, "history": []}),
            Err(e) => return Err(fatal(&self.paths.epoch)(e)),
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(fatal(&self.paths.epoch))?,
        };
        let reason = pystr::head(reason, 200);
        let next = epoch + 1;
        let time = since.map_or_else(|| self.rt.now(), |since| since.min(self.rt.now()));
        let map = record.as_object_mut().ok_or_else(|| Error::Fatal("epoch record is not an object".into()))?;
        map.insert("epoch".into(), json!(next));
        match map.get_mut("history") {
            Some(Value::Array(history)) => history.push(json!({"epoch": next, "reason": reason, "time": time})),
            _ => return Err(Error::Fatal("epoch record has no history list".into())),
        }
        // High-water mark first: a lost epoch.json can never read as older.
        write_durable(&self.paths.epoch_high, &format!("{next}\n"))?;
        write_durable(&self.paths.epoch, &pyjson::dumps(&record, None))?;
        Ok(json!({"epoch": next, "reason": reason}))
    }

    /// Vhosts the generation must serve: [{"vhost", "host", "url"}]; the body must be "<gen> <vhost>".
    pub fn health_targets(&self, gen: &str) -> Option<Vec<Value>> {
        let bytes = fs::read(cat(&self.gen_dir(gen), "health.json")).ok()?;
        match serde_json::from_slice::<Value>(&bytes).ok()? {
            Value::Array(targets) if !targets.is_empty() => Some(targets),
            _ => None,
        }
    }

    /// Every listed vhost answers its health path with this generation's ID; returns the failures. Retried for
    /// `seconds`, within the transaction's deadline: each attempt gets at most 2 s of what is left, and once
    /// nothing is left the remaining targets are not asked and count as failing (DEADLINE_EXCEEDED).
    pub fn vhost_health(&self, gen: &str, targets: &[Value], seconds: f64) -> Result<Vec<Value>> {
        let deadline = self.rt.monotonic() + self.budget(seconds);
        loop {
            let mut failing = Vec::new();
            for target in targets {
                let field = |key: &str| target.get(key).ok_or_else(|| Error::Fatal(format!("health target lacks {key:?}")));
                let url = field("url")?.as_str().ok_or_else(|| Error::Fatal("health target url is not a string".into()))?;
                let host = field("host")?.as_str().ok_or_else(|| Error::Fatal("health target host is not a string".into()))?;
                let vhost = field("vhost")?;
                let left = self.budget(2.0);
                let body = if left > 0.0 { self.rt.health(url, host, Duration::from_secs_f64(left)) } else { DEADLINE_EXCEEDED.to_string() };
                if body != format!("{gen} {}", py_str(vhost)) {
                    failing.push(json!({"vhost": vhost, "got": pystr::head(&body, 120)}));
                }
            }
            if failing.is_empty() || self.rt.monotonic() > deadline || self.budget(1.0) <= 0.0 {
                return Ok(failing);
            }
            self.rt.sleep(Duration::from_millis(500));
        }
    }

    /// `health [--seconds N]`: the active generation's vhost health (what the reconciler checks before
    /// keeping an unchanged generation): `{"generation": pointer or null, "failing": [{"vhost", "got"}]}`.
    pub fn health(&self, seconds: f64) -> Result<Value> {
        let Some(current) = self.pointer() else { return Ok(json!({"generation": null, "failing": []})) };
        let _deadline = self.deadline_in(TRANSACTION_SECONDS);
        let targets = self.health_targets(&current).unwrap_or_default();
        let failing = self.vhost_health(&current, &targets, seconds)?;
        Ok(json!({"generation": current, "failing": failing}))
    }

    /// Atomic replacement of the single pointer.
    pub fn switch(&self, gen: &str) -> Result<()> {
        let tmp = cat(&self.paths.state, &format!("active.new-{}", uuid_hex()));
        std::os::unix::fs::symlink(self.gen_dir(gen), &tmp).map_err(fatal(&tmp))?;
        fs::rename(&tmp, &self.paths.active).map_err(fatal(&self.paths.active))?;
        fsync_dir(&self.paths.state)
    }

    pub fn running(&self) -> bool {
        self.rt.service_active()
    }

    /// Graceful restart (SIGUSR1 through lswsctrl) when running, start otherwise; bounded by what is left of the
    /// transaction (at least 5 s, at most SYSTEMCTL_TIMEOUT). Never of a stale generation: a transaction that
    /// finds OLS stopped by enforcement (an intent or a restriction past its deadline) does not bring back what
    /// the restriction removed; it returns 1 without starting anything (review RV-29, finding 3).
    pub fn reload(&self) -> i32 {
        if self.stale(some_truthy(&self.pointer())) {
            return 1;
        }
        let timeout = Duration::from_secs_f64(self.budget(SYSTEMCTL_TIMEOUT).max(5.0));
        if self.running() {
            self.rt.systemctl("reload", timeout)
        } else {
            self.rt.systemctl("start", timeout)
        }
    }

    /// The marker answers `gen` within `seconds` (and within the transaction's deadline).
    pub fn wait_for(&self, gen: &str, seconds: f64) -> bool {
        let deadline = self.rt.monotonic() + self.budget(seconds);
        while self.rt.monotonic() < deadline {
            if self.served().as_deref() == Some(gen) {
                return true;
            }
            self.rt.sleep(Duration::from_millis(250));
        }
        false
    }

    fn read_journal(&self) -> Result<Vec<Map<String, Value>>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.paths.journal).map_err(fatal(&self.paths.journal))? {
            let entry = entry.map_err(fatal(&self.paths.journal))?;
            let name = entry.file_name();
            if !name.as_bytes().ends_with(b".json") {
                continue;
            }
            let path = entry.path();
            let bytes = fs::read(&path).map_err(fatal(&path))?;
            match serde_json::from_slice::<Value>(&bytes).map_err(fatal(&path))? {
                Value::Object(map) => records.push(map),
                _ => return Err(Error::Fatal(format!("{}: journal record is not an object", path.display()))),
            }
        }
        Ok(records)
    }

    /// All journal records in transaction order (seq, then start time; stable for ties).
    pub fn transactions(&self) -> Result<Vec<Map<String, Value>>> {
        let records = self.read_journal()?;
        let mut keyed = Vec::with_capacity(records.len());
        for tx in records {
            let key = (number(tx.get("seq"), 0.0)?, number(tx.get("started"), 0.0)?);
            keyed.push((key, tx));
        }
        keyed.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        Ok(keyed.into_iter().map(|(_, tx)| tx).collect())
    }

    fn tx_new(tx: &Map<String, Value>) -> Result<String> {
        match tx.get("new") {
            Some(Value::String(gen)) => Ok(gen.clone()),
            Some(other) => Ok(py_str(other)),
            None => Err(Error::Fatal("journal record lacks 'new'".into())),
        }
    }

    fn tx_id(tx: &Map<String, Value>) -> Value {
        tx.get("id").cloned().unwrap_or(Value::Null)
    }

    /// The generation of the last committed transaction.
    pub fn committed(&self) -> Result<Option<String>> {
        match self.transactions()?.iter().rev().find(|tx| tx.get("state") == Some(&json!("committed"))) {
            Some(tx) => Ok(Some(Self::tx_new(tx)?)),
            None => Ok(None),
        }
    }

    pub fn stage(&self, gen: &str, src: &Path) -> Result<Value> {
        let target = self.gen_dir(gen);
        if target.exists() {
            return Err(Error::Exit(format!("generation {gen} exists (generations are immutable)")));
        }
        let tmp = cat(&self.paths.gen_root, &format!(".staging-{gen}"));
        copytree(src, &tmp).map_err(Error::Fatal)?;
        let mut files = Map::new();
        let tmp_s = tmp.to_string_lossy().into_owned();
        walk_visit(&tmp_s, &mut |root, dirs, names| {
            for name in names {
                let path = pystr::join(root, name);
                let mut handle = fs::File::open(&path).map_err(fatal(&path))?;
                let mut bytes = Vec::new();
                handle.read_to_end(&mut bytes).map_err(fatal(&path))?;
                let rel = path[tmp_s.len()..].trim_start_matches('/').to_string();
                files.insert(rel, json!(hex(&Sha256::digest(&bytes))));
                handle.sync_all().map_err(fatal(&path))?;
                // OLS workers (nobody) read the marker; no secrets live here.
                fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).map_err(fatal(&path))?;
            }
            for name in dirs {
                let path = pystr::join(root, name);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(fatal(&path))?;
            }
            fsync_dir(Path::new(root))
        })?;
        let count = files.len();
        let manifest = cat(&tmp, "MANIFEST.json");
        let mut handle = fs::File::create(&manifest).map_err(fatal(&manifest))?;
        let text = pyjson::dumps(&json!({"generation": gen, "files": files}), None);
        handle.write_all(text.as_bytes()).map_err(fatal(&manifest))?;
        handle.sync_all().map_err(fatal(&manifest))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(fatal(&tmp))?;
        fs::rename(&tmp, &target).map_err(fatal(&target))?;
        fsync_dir(&self.paths.gen_root)?;
        Ok(json!({"generation": gen, "files": count}))
    }

    /// Validate the staged tree and record the verdict for exactly this tree and binary.
    pub fn validate(&self, gen: &str) -> Result<Value> {
        let tree = self.tree_sha256(gen)?;
        if self.validator.is_empty() {
            return Err(Error::Fatal("no validator".into()));
        }
        let mut argv = self.validator.clone();
        argv.push(self.gen_dir(gen).into_os_string());
        // Bounded like every activator subprocess: its own process group, killed with it at the limit.
        let output = match command::run(&argv, VALIDATE_TIMEOUT, command::MAX_OUTPUT) {
            Ok(output) => output,
            Err(Failure::Spawn(message)) => return Err(Error::Fatal(message)),
            Err(failure) => command::Output {
                code: -9,
                stdout: Vec::new(),
                stderr: format!("validator killed: {}", if failure == Failure::Timeout { "time limit" } else { "output limit" }).into_bytes(),
            },
        };
        let code = output.code;
        let valid = code == 0 && self.tree_sha256(gen)? == tree;
        let record = json!({
            "generation": gen, "valid": valid, "exit_code": code, "tree_sha256": tree,
            "binary_sha256": file_sha256(&self.paths.binary)?, "validator_sha256": file_sha256(&self.validator_file)?,
            "health_targets": self.health_targets(gen).map_or(0, |t| t.len()), "time": self.rt.now(),
        });
        write_durable(&cat(&self.paths.validations, &format!("{gen}.json")), &pyjson::dumps(&record, None))?;
        let mut out = record.as_object().cloned().unwrap_or_default();
        let stdout = pystr::universal_newlines(&String::from_utf8_lossy(&output.stdout));
        let stderr = pystr::universal_newlines(&String::from_utf8_lossy(&output.stderr));
        out.insert("report".into(), json!(pystr::tail(&stdout, 2000)));
        // The validator's findings come before its output tail, so the report's tail alone loses the cause of a
        // refusal (a second server, 2026-10-28): they are carried whole.
        if let Ok(Value::Object(report)) = serde_json::from_str::<Value>(&stdout) {
            if let Some(Value::Array(found)) = report.get("findings") {
                out.insert("findings".into(), json!(found));
            }
        }
        out.insert("stderr".into(), json!(pystr::tail(&stderr, 1000)));
        Ok(Value::Object(out))
    }

    /// Why this generation may not be activated, or None (review RV-02).
    pub fn validation_problem(&self, gen: &str) -> Result<Option<String>> {
        let record = fs::read(cat(&self.paths.validations, &format!("{gen}.json")))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        // A record that is not an object crashes the Python here; it never binds (fail closed).
        let Some(Value::Object(record)) = record else {
            return Ok(Some("not validated".into()));
        };
        if !truthy(record.get("valid")) {
            return Ok(Some("validation failed".into()));
        }
        if record.get("tree_sha256") != Some(&json!(self.tree_sha256(gen)?)) {
            return Ok(Some("generation changed after validation".into()));
        }
        if record.get("binary_sha256") != Some(&json!(file_sha256(&self.paths.binary)?)) {
            return Ok(Some("OLS binary changed after validation".into()));
        }
        if self.health_targets(gen).is_none() {
            return Ok(Some("no vhost health targets".into()));
        }
        if self.stale(Some(gen)) {
            match self.pending_intents() {
                Err(message) => return Ok(Some(message)),
                Ok(intents) if !intents.is_empty() => {
                    return Ok(Some(format!("restriction intent {} not yet folded into the epoch", intents[0].0)));
                }
                Ok(_) => {}
            }
            let epoch = self.epoch_or_none().map_or_else(|| "None".to_string(), |e| e.to_string());
            return Ok(Some(format!("generation epoch {} predates restriction epoch {epoch}", self.generation_epoch(gen))));
        }
        Ok(None)
    }

    pub fn activate(&self, gen: &str, crash_after: Option<&str>) -> Result<Value> {
        let _lock = self.lock()?;
        let _deadline = self.deadline_in(TRANSACTION_SECONDS);
        self.recover_locked()?; // never start a transaction over an interrupted one (review finding 8)
        if let Some(problem) = self.validation_problem(gen)? {
            return Ok(json!({"result": "refused", "generation": gen, "reason": problem}));
        }
        let previous = self.pointer();
        let mut tx = Map::new();
        tx.insert("id".into(), json!(uuid_hex()));
        tx.insert("seq".into(), self.next_seq()?);
        tx.insert("new".into(), json!(gen));
        tx.insert("previous".into(), json!(previous));
        tx.insert("started".into(), json!(self.rt.now()));
        self.journal(&mut tx, vec![("state", json!("intent"))])?;
        if crash_after == Some("intent") {
            return Err(Error::Crash);
        }
        self.switch(gen)?;
        self.journal(&mut tx, vec![("state", json!("switched"))])?;
        if crash_after == Some("switched") {
            return Err(Error::Crash);
        }
        // The forward checks leave ROLLBACK_RESERVE of the deadline to the rollback.
        let forward = self.deadline_at(self.deadline.get() - ROLLBACK_RESERVE);
        let code = self.reload();
        self.journal(&mut tx, vec![("state", json!("reloaded")), ("reload_exit", json!(code))])?;
        if crash_after == Some("reloaded") {
            return Err(Error::Crash);
        }
        let id = Self::tx_id(&tx);
        if self.wait_for(gen, 20.0) {
            // Python iterates health_targets(gen) directly: a vanished health.json is a crash there.
            let targets = self.health_targets(gen).ok_or_else(|| Error::Fatal(format!("{gen}: health.json vanished")))?;
            let failing = self.vhost_health(gen, &targets, 20.0)?;
            if failing.is_empty() {
                self.journal(&mut tx, vec![("state", json!("committed"))])?;
                return Ok(json!({"tx": id, "result": "committed", "generation": gen}));
            }
            drop(forward);
            self.journal(&mut tx, vec![("state", json!("unhealthy")), ("failing", json!(failing))])?;
            let mut out = Map::new();
            out.insert("tx".into(), id);
            out.insert("failing".into(), json!(failing));
            out.extend(self.rollback(&mut tx)?);
            return Ok(Value::Object(out));
        }
        drop(forward);
        let mut out = Map::new();
        out.insert("tx".into(), id);
        out.insert("reason".into(), json!(format!("OpenLiteSpeed did not serve generation {gen} on {} within 20 s", self.paths.marker_url)));
        out.extend(self.rollback(&mut tx)?);
        Ok(Value::Object(out))
    }

    /// The rollback target: the previous generation, else the newest committed one, never one from an
    /// older restriction epoch and never the failing generation itself. Validation binding (same tree
    /// and OLS binary) and the current epoch are both required (review 2, item 4).
    pub fn fresh_target(&self, tx: &Map<String, Value>) -> Result<Option<String>> {
        let new = Self::tx_new(tx)?;
        let mut candidates: Vec<Option<String>> = vec![match tx.get("previous") {
            Some(Value::String(g)) => Some(g.clone()),
            Some(Value::Null) | None => None,
            Some(other) => truthy(Some(other)).then(|| py_str(other)),
        }];
        for t in self.transactions()?.iter().rev() {
            if t.get("state") == Some(&json!("committed")) {
                candidates.push(Some(Self::tx_new(t)?));
            }
        }
        for candidate in candidates.into_iter().flatten() {
            if !candidate.is_empty() && candidate != new && self.validation_problem(&candidate)?.is_none() {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    pub fn rollback(&self, tx: &mut Map<String, Value>) -> Result<Map<String, Value>> {
        let new = Self::tx_new(tx)?;
        let target = self.fresh_target(tx)?;
        let as_map = |value: Value| value.as_object().cloned().unwrap_or_default();
        if target.is_none() && !(truthy(tx.get("previous")) || self.committed()?.map_or(false, |c| !c.is_empty())) {
            self.journal(tx, vec![("state", json!("failed_no_previous"))])?;
            return Ok(as_map(json!({"result": "failed_no_previous"})));
        }
        let Some(target) = target else {
            if self.validation_problem(&new)?.is_none() && self.served().as_deref() == Some(new.as_str()) {
                // Older generations would revive privileges a newer restriction removed: keep the new one
                // (compiled with the current restrictions, and actually serving) and alert.
                self.journal(tx, vec![("state", json!("rollback_refused_stale")), ("epoch", json!(self.epoch_or_none()))])?;
                return Ok(as_map(json!({"result": "rollback_refused_stale", "generation": new})));
            }
            // Nothing current is serving (e.g. the reload failed and the old process lives on): stop
            // serving rather than serve stale rights, and verify the stop (review finding 3).
            let stopped = self.stop_serving();
            self.journal(tx, vec![
                ("state", json!("stopped_no_fresh_generation")),
                ("epoch", json!(self.epoch_or_none())),
                ("stopped", json!(stopped)),
            ])?;
            return Ok(as_map(json!({"result": "stopped_no_fresh_generation", "stopped": stopped})));
        };
        self.switch(&target)?;
        self.reload();
        let ok = self.wait_for(&target, 20.0) && {
            let targets = self.health_targets(&target).ok_or_else(|| Error::Fatal(format!("{target}: health.json vanished")))?;
            self.vhost_health(&target, &targets, 20.0)?.is_empty()
        };
        if !ok {
            let stopped = self.stop_serving(); // neither the new nor the previous generation serves correctly
            self.journal(tx, vec![("state", json!("rollback_failed")), ("restored", json!(target)), ("stopped", json!(stopped))])?;
            return Ok(as_map(json!({"result": "rollback_failed", "generation": target, "stopped": stopped})));
        }
        self.journal(tx, vec![("state", json!("rolled_back")), ("restored", json!(target))])?;
        Ok(as_map(json!({"result": "rolled_back", "generation": target})))
    }

    /// Any OLS main or worker process, whatever the marker says.
    pub fn ols_running(&self) -> bool {
        self.rt.ols_process() || self.running()
    }

    /// Stop OLS and confirm that no OLS process is left (an unreachable marker proves nothing).
    /// Bounded whatever is left of a transaction: systemctl stop STOP_TIMEOUT, then at most 20 s for the processes
    /// to exit, then the kill.
    pub fn stop_serving(&self) -> bool {
        self.rt.systemctl("stop", Duration::from_secs_f64(STOP_TIMEOUT));
        let until = self.rt.monotonic() + 20.0;
        for _ in 0..40 {
            if !self.ols_running() {
                return true;
            }
            if self.rt.monotonic() >= until {
                break;
            }
            self.rt.sleep(Duration::from_millis(500));
        }
        self.rt.kill_ols();
        self.rt.sleep(Duration::from_secs(1));
        !self.ols_running()
    }

    /// Time of the earliest restriction newer than `epoch` (what a generation of that epoch still
    /// lacks), or None when unknown; later restrictions never move this deadline (review 2, item 7). Unfolded
    /// restriction intents count from their time (an intent is lacked by every generation).
    pub fn first_unapplied_restriction(&self, epoch: i64) -> Option<f64> {
        let intents: Vec<f64> = self.pending_intents().ok()?.into_iter().map(|(_, time)| time).collect();
        let record: Value = match fs::read(&self.paths.epoch) {
            // A fresh installation: no restriction recorded in the epoch yet.
            Err(e) if e.kind() == ErrorKind::NotFound => json!({"history": []}),
            Err(_) => return None,
            Ok(bytes) => serde_json::from_slice(&bytes).ok()?,
        };
        // A record that is not an object, or history entries that are not objects, crash the Python
        // (AttributeError); here they are unknown, which grants no grace (fail closed).
        let history = match record.as_object()?.get("history") {
            Some(Value::Array(entries)) => entries.clone(),
            value if !truthy(value) => Vec::new(),
            _ => return None,
        };
        let mut times = intents;
        for entry in &history {
            let entry = entry.as_object()?;
            // type(h.get("epoch")) is int and h["epoch"] > epoch (booleans and floats never count)
            let newer = match entry.get("epoch") {
                Some(Value::Number(n)) if !n.is_f64() => n.as_i64().map_or(true, |e| e > epoch),
                _ => false,
            };
            if !newer {
                continue;
            }
            let time = match entry.get("time")? {
                Value::Number(t) => t.as_f64()?,
                Value::String(s) => pystr::float(s)?,
                Value::Bool(b) => f64::from(u8::from(*b)),
                _ => return None,
            };
            times.push(time);
        }
        times.into_iter().reduce(|a, b| if b < a { b } else { a })
    }

    /// Under LOCK: never keep serving a generation older than the restriction epoch for longer than
    /// `grace` seconds after the earliest restriction it lacks (HR-D11: 300 s). An unknown runtime (OLS
    /// running, marker silent) or an unknown epoch gets no grace.
    ///
    /// The lock is never awaited without bound (review RV-29, findings 3 and 4): the decision is made without
    /// it, and only a stale generation past its deadline needs it; see `enforce_ahead`.
    pub fn enforce(&self, grace: f64) -> Result<Option<&'static str>> {
        self.enforce_ahead(grace, 0.0).map(|(result, _)| result)
    }

    /// Enforcement with a bounded lock wait. Within grace, more than `lead` seconds before the deadline:
    /// "within-grace" and that deadline. Otherwise the activation lock is awaited at most until the deadline
    /// (once, at once, when it has passed); held early, it is kept until the deadline and `enforce_locked` decides
    /// then. Still held by a transaction at the deadline: the stale generation is stopped without the lock
    /// ("stopped-without-lock"); that transaction finds OLS stopped and never starts a stale generation (`reload`).
    pub fn enforce_ahead(&self, grace: f64, lead: f64) -> Result<(Option<&'static str>, Option<f64>)> {
        let due = match self.assess(grace) {
            Assessment::Nothing => return Ok((None, None)),
            Assessment::Within(due) if due - self.rt.now() > lead => return Ok((Some("within-grace"), Some(due))),
            Assessment::Within(due) => due,
            Assessment::Due(_) => self.rt.now(),
        };
        // Once the clock has reached `due`, a deadline no later than it counts as passed (whatever the rounding).
        match self.lock_within(due - self.rt.now())? {
            Some(_lock) => {
                let _deadline = self.deadline_in(TRANSACTION_SECONDS);
                let early = due - self.rt.now();
                if early > 0.0 {
                    self.rt.sleep(Duration::from_secs_f64(early));
                }
                Ok((self.enforce_locked_at(grace, due)?, None))
            }
            None => Ok(match self.assess_at(grace, due) {
                Assessment::Due(_) => (Some(if self.stop_serving() { "stopped-without-lock" } else { "stop-failed" }), None),
                Assessment::Within(due) => (Some("within-grace"), Some(due)),
                Assessment::Nothing => (None, None),
            }),
        }
    }

    /// The enforcement decision (`_enforce_locked` up to its action), without the lock.
    pub fn assess(&self, grace: f64) -> Assessment {
        self.assess_at(grace, f64::NEG_INFINITY)
    }

    /// `assess`, with every deadline no later than `reached` counted as passed.
    fn assess_at(&self, grace: f64, reached: f64) -> Assessment {
        if !self.ols_running() {
            return Assessment::Nothing;
        }
        let live = self.served();
        let unknown_epoch = self.epoch_or_none().is_none();
        let live_epoch = match &live {
            None => {
                // Running but the marker does not answer: what serves is unknown. Only a current pointer is trusted.
                let current = self.pointer();
                if some_truthy(&current).is_some() && !self.stale(current.as_deref()) {
                    return Assessment::Nothing;
                }
                some_truthy(&current).map_or(-1, |c| self.generation_epoch(c))
            }
            Some(live_gen) => {
                if !self.stale(Some(live_gen)) {
                    return Assessment::Nothing;
                }
                self.generation_epoch(live_gen)
            }
        };
        let since = if unknown_epoch { None } else { self.first_unapplied_restriction(live_epoch) };
        if grace != 0.0 {
            if let Some(since) = since {
                if self.rt.now() - since < grace && since + grace > reached {
                    return Assessment::Within(since + grace);
                }
            }
        }
        Assessment::Due(live)
    }

    pub fn enforce_locked(&self, grace: f64) -> Result<Option<&'static str>> {
        self.enforce_locked_at(grace, f64::NEG_INFINITY)
    }

    fn enforce_locked_at(&self, grace: f64, reached: f64) -> Result<Option<&'static str>> {
        let live = match self.assess_at(grace, reached) {
            Assessment::Nothing => return Ok(None),
            Assessment::Within(_) => return Ok(Some("within-grace")),
            Assessment::Due(live) => live,
        };
        let current = self.pointer();
        if let Some(current_gen) = some_truthy(&current) {
            if current != live && !self.stale(Some(current_gen)) && self.validation_problem(current_gen)?.is_none() {
                self.reload();
                if self.wait_for(current_gen, 20.0)
                    && self.vhost_health(current_gen, &self.health_targets(current_gen).unwrap_or_default(), 20.0)?.is_empty()
                {
                    return Ok(Some("reloaded-current"));
                }
            }
        }
        Ok(Some(if self.stop_serving() { "stopped" } else { "stop-failed" }))
    }

    /// Finish or undo every interrupted transaction, then enforce the restriction epoch (with `grace`
    /// seconds since the earliest unapplied restriction: 0 for boot/operator recovery, HR-D11's 300 s
    /// when the reconciler is about to activate a replacement).
    pub fn recover(&self, grace: f64) -> Result<Value> {
        let lock = self.lock()?;
        let _deadline = self.deadline_in(TRANSACTION_SECONDS);
        let recovered = self.recover_locked();
        let enforced = self.enforce_locked(grace);
        let mut actions = match recovered {
            Ok(actions) => actions,
            Err(Error::Epoch(message)) => vec![json!({"action": "recover", "error": message})],
            Err(other) => {
                enforced?;
                return Err(other);
            }
        };
        if let Some(result) = enforced? {
            actions.push(json!({"action": "enforce", "result": result}));
        }
        drop(lock);
        let mut out = self.status()?.as_object().cloned().unwrap_or_default();
        out.insert("actions".into(), Value::Array(actions));
        Ok(Value::Object(out))
    }

    /// Recovery body; the caller holds LOCK.
    pub fn recover_locked(&self) -> Result<Vec<Value>> {
        let mut actions = Vec::new();
        let mut history = self.transactions()?;
        for position in 0..history.len() {
            let state = history[position].get("state").cloned();
            if matches!(&state, Some(Value::String(s)) if FINAL.contains(&s.as_str())) {
                continue;
            }
            let id = Self::tx_id(&history[position]);
            if history[position + 1..].iter().any(|later| later.get("state") == Some(&json!("committed"))) {
                // A later activation committed after this one was interrupted: it owns the pointer now.
                self.journal(&mut history[position], vec![("state", json!("superseded"))])?;
                actions.push(json!({"tx": id, "action": "superseded"}));
                continue;
            }
            let new = Self::tx_new(&history[position])?;
            if self.stale(Some(&new)) && self.pointer().as_deref() == Some(new.as_str()) {
                // Interrupted activation of a generation a newer restriction made stale: undo it.
                let result = self.rollback(&mut history[position])?;
                actions.push(json!({"tx": id, "action": result.get("result")}));
                continue;
            }
            if state == Some(json!("intent")) && self.pointer().as_deref() != Some(new.as_str()) {
                self.journal(&mut history[position], vec![("state", json!("aborted"))])?; // the pointer never moved
                actions.push(json!({"tx": id, "action": "aborted"}));
                continue;
            }
            // The pointer moved to a staged generation: complete forward only if its validation still
            // binds (same tree and OLS binary, review finding 9) and it serves; otherwise roll back.
            if self.validation_problem(&new)?.is_some() {
                let result = self.rollback(&mut history[position])?;
                actions.push(json!({"tx": id, "action": result.get("result"), "reason": "validation no longer binds"}));
                continue;
            }
            if self.served().as_deref() != Some(new.as_str()) {
                self.reload();
            }
            let targets = self.health_targets(&new);
            let healthy = self.wait_for(&new, 20.0)
                && match &targets {
                    Some(targets) => self.vhost_health(&new, targets, 20.0)?.is_empty(),
                    None => false,
                };
            if healthy {
                self.journal(&mut history[position], vec![("state", json!("committed")), ("recovered", json!(true))])?;
                actions.push(json!({"tx": id, "action": "completed"}));
            } else {
                let result = self.rollback(&mut history[position])?;
                actions.push(json!({"tx": id, "action": result.get("result")}));
            }
        }
        // Coherence: what the pointer selects is what OLS serves, but never by (re)starting a generation
        // that a newer restriction made stale: that stays stopped until a current one is activated.
        let current = self.pointer();
        if let Some(current_gen) = some_truthy(&current) {
            if !self.stale(Some(current_gen))
                && self.served().as_deref() != Some(current_gen)
                && self.validation_problem(current_gen)?.is_none()
            {
                self.reload();
                self.wait_for(current_gen, 20.0);
            }
        }
        Ok(actions)
    }

    pub fn status(&self) -> Result<Value> {
        let current = self.pointer();
        let live = self.served();
        let epoch = self.epoch_or_none();
        let active_epoch = some_truthy(&current).map(|c| self.generation_epoch(c));
        let committed = self.committed()?;
        let coherent = current.is_some()
            && current == live
            && live == committed
            && epoch.is_some()
            && matches!((active_epoch, epoch), (Some(a), Some(e)) if a >= e);
        Ok(json!({"pointer": current, "served": live, "committed": committed, "epoch": epoch,
                  "active_epoch": active_epoch, "coherent": coherent}))
    }

    /// The state directories every command creates first (Python main()).
    /// The modes are set explicitly: the creating process may run with a restrictive umask (the broker unit has
    /// UMask=0077), and OLS's workers, which are not root, must traverse the generations directory to read the
    /// configuration and the marker (lab 2026-10-28: a fresh install created it 0700 and the cutover's marker was
    /// never served). A generations directory that others cannot traverse is repaired to 0755.
    pub fn ensure_dirs(&self) -> Result<()> {
        for (path, mode) in [(&self.paths.gen_root, 0o755), (&self.paths.journal, 0o700), (&self.paths.validations, 0o700)] {
            if path.is_dir() {
                if mode == 0o755 {
                    let meta = fs::symlink_metadata(path).map_err(fatal(path))?;
                    if meta.file_type().is_dir() && meta.permissions().mode() & 0o005 != 0o005 {
                        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(fatal(path))?;
                    }
                }
                continue;
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(fatal(parent))?;
            }
            match fs::DirBuilder::new().mode(mode).create(path) {
                Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(fatal(path))?,
                Err(e) if e.kind() == ErrorKind::AlreadyExists && path.is_dir() => {}
                Err(e) => return Err(fatal(path)(e)),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
