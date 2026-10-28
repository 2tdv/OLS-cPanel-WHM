//! G0-B candidate validation, ported from build/vm-qualification/ols_stage_validate.py: test a staged
//! OLS configuration tree with the installed binary inside private mount and network namespaces
//! (by executing /usr/bin/unshare exactly like the Python tool), so live PID, socket, shm and
//! listener state is never touched. Not an activation step and not a G0 certificate.

use super::lint;
use super::pyjson::{self, Ordered};
use super::pystr;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const BINARY: &str = "/usr/local/lsws/bin/openlitespeed";
pub const LIVE_ROOT: &str = "/usr/local/lsws";
/// Read-only support the binary resolves relative to the server root.
pub const SHARED: [&str; 4] = ["modules", "share", "lsrecaptcha", "lsns"];
pub const WRITABLE: [&str; 8] = ["logs", "tmp", "cachedata", "autoupdate", "cgid", "admin/tmp", "admin/logs", "admin/cgid"];
/// Private /tmp and /dev/shm; DEFAULT_TMP_DIR must exist for the test log. Every directory holding a
/// log the candidate names is replaced by a private tmpfs too: "-t" opens access and error logs for
/// writing, which would touch live log files and block forever on the log shipper's FIFOs when
/// nothing reads them. OLS patch 0009 keeps its runtime state in /run/ols-cpanel/lshttpd: a private
/// /run hides the live one. Identical to INNER in the Python tool.
pub const INNER: &str = concat!(
    "set -e; mount -t tmpfs -o mode=1777 tmpfs /tmp; mount -t tmpfs -o mode=1777 tmpfs /dev/shm; ",
    "mount -t tmpfs -o mode=0755 tmpfs /run; mkdir -p /run/ols-cpanel/lshttpd /run/ols-cpanel/status /run/ols-cpanel/shm /run/ols-cpanel/logs /tmp/lshttpd; ",
    "for d in \"$@\"; do case \"$d\" in m:*) mount -t tmpfs -o mode=0755 tmpfs \"${d#m:}\" ;; ",
    "d:*) mkdir -p \"${d#d:}\" ;; esac; done; exec \"$0\" -t"
);
const TIMEOUT: Duration = Duration::from_secs(60);
const USAGE: &str = "usage: ols-cpanel-activator stage-validate [-h] [--binary BINARY] candidate";

/// Case-insensitive comparison as Python `re.IGNORECASE` performs it for the ASCII letters of the
/// FAILURE patterns (simple lowercase plus the special folds of dotted/dotless i, long s, Kelvin).
fn fold(c: char) -> char {
    match c {
        '\u{130}' | '\u{131}' => 'i',
        '\u{17f}' => 's',
        '\u{212a}' => 'k',
        _ => {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(single), None) => single,
                _ => c,
            }
        }
    }
}

const FAILURE: [&str; 7] =
    ["[error]", "not support [", "failed to ", "can not ", "cannot ", "is not accessible", "configuration failed"];

/// Python FAILURE regex: `\[ERROR\]|Not support \[|failed to |Can not |Cannot |is not accessible|configuration failed`, IGNORECASE.
pub fn is_failure(line: &str) -> bool {
    let folded: Vec<char> = line.chars().map(fold).collect();
    FAILURE.iter().any(|pattern| {
        let needle: Vec<char> = pattern.chars().collect();
        folded.windows(needle.len()).any(|window| window == needle.as_slice())
    })
}

fn digits(chars: &[char], at: usize) -> Option<usize> {
    let end = at + chars[at..].iter().take_while(|c| c.is_ascii_digit()).count();
    (end > at).then_some(end)
}

fn literal(chars: &[char], at: usize, text: &str) -> Option<usize> {
    let needle: Vec<char> = text.chars().collect();
    (chars.len() >= at + needle.len() && chars[at..at + needle.len()] == needle[..]).then_some(at + needle.len())
}

fn benign_tail(chars: &[char], at: usize) -> bool {
    // `\S+ is \d+, smaller than minimum requirement \d+, use server [ug]id!$`
    let end = at + chars[at..].iter().take_while(|c| !pystr::is_space(**c)).count();
    if end == at {
        return false;
    }
    let step = literal(chars, end, " is ")
        .and_then(|i| digits(chars, i))
        .and_then(|i| literal(chars, i, ", smaller than minimum requirement "))
        .and_then(|i| digits(chars, i))
        .and_then(|i| literal(chars, i, ", use server "));
    match step {
        Some(i) => matches!(chars.get(i), Some('u') | Some('g')) && literal(chars, i + 1, "id!") == Some(chars.len()),
        None => false,
    }
}

/// Python BENIGN_WARN (search on the stripped line):
/// `\[WARN\].* (?:Uid|Gid) of \S+ is \d+, smaller than minimum requirement \d+, use server [ug]id!$`.
/// `\d` is ASCII here (Python: any Unicode decimal digit); fewer benign matches only fail closed.
pub fn is_benign_warn(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let Some(warn) = chars.windows(6).position(|w| w.iter().collect::<String>() == "[WARN]") else {
        return false;
    };
    (warn + 6..chars.len()).any(|p| {
        (literal(&chars, p, " Uid of ").is_some() || literal(&chars, p, " Gid of ").is_some()) && benign_tail(&chars, p + 8)
    })
}

/// Fail closed (review F-02): OLS skips a broken vhost with only a warning and keeps serving the rest,
/// so every [WARN] is a finding unless it is one of the reviewed, harmless messages.
pub fn findings(text: &str) -> Vec<String> {
    pystr::splitlines(text)
        .into_iter()
        .filter(|line| is_failure(line) || (line.contains("[WARN]") && !is_benign_warn(pystr::strip(line))))
        .map(|line| pystr::strip(line).to_string())
        .collect()
}

/// `verdict(exit_code, text)`: (findings[:50], valid).
pub fn verdict(exit_code: i32, text: &str) -> (Vec<String>, bool) {
    let mut found = findings(text);
    let valid = exit_code == 0 && found.is_empty();
    found.truncate(50);
    (found, valid)
}

fn log_paths(text: &str) -> Vec<String> {
    // re.findall(r"^\s*(?:accesslog|errorlog)\s+(/\S+)", text, re.MULTILINE)
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut pos = 0;
    while pos <= chars.len() {
        if pos == 0 || chars[pos - 1] == '\n' {
            let mut i = pos + chars[pos..].iter().take_while(|c| pystr::is_space(**c)).count();
            if let Some(after) = literal(&chars, i, "accesslog").or_else(|| literal(&chars, i, "errorlog")) {
                let gap = chars[after..].iter().take_while(|c| pystr::is_space(**c)).count();
                i = after + gap;
                if gap > 0 && chars.get(i) == Some(&'/') {
                    let end = i + chars[i..].iter().take_while(|c| !pystr::is_space(**c)).count();
                    found.push(chars[i..end].iter().collect());
                    pos = end;
                    continue;
                }
            }
        }
        pos += 1;
    }
    found
}

fn read_text(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    String::from_utf8(bytes).map(|t| pystr::universal_newlines(&t)).map_err(|_| format!("{}: not UTF-8", path.display()))
}

/// `sorted(candidate.glob("vhosts/*/vhconf.conf"))`.
pub fn vhconf_files(candidate: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(candidate.join("vhosts"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .map(|path| path.join("vhconf.conf"))
                .filter(|path| path.exists())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// Namespace setup for every access/error log directory the candidate configures: "m:<dir>" mounts a
/// private tmpfs, "d:<dir>" creates a directory inside one. A directory that does not exist yet is
/// created under a tmpfs mounted on its nearest existing ancestor, so nothing is ever created or
/// opened on the live filesystem.
pub fn log_dirs(candidate: &Path) -> Result<Vec<String>, String> {
    let mut texts = vec![read_text(&candidate.join("httpd_config.conf"))?];
    for path in vhconf_files(candidate) {
        texts.push(read_text(&path)?);
    }
    let mut dirs: Vec<String> = texts
        .iter()
        .flat_map(|text| log_paths(text))
        .filter(|path| !path.contains('$'))
        .map(|path| pystr::dirname(&path))
        .collect();
    dirs.sort();
    dirs.dedup();
    let (mut mounts, mut creates) = (Vec::<String>::new(), Vec::<String>::new());
    for d in dirs {
        if d.starts_with("/run/") {
            creates.push(d); // /run is already a private tmpfs in the namespace
            continue;
        }
        if d.starts_with("/tmp") || d.starts_with("/dev/shm") || d == "/" {
            continue;
        }
        let mut anchor = d.clone();
        while !Path::new(&anchor).is_dir() {
            anchor = pystr::dirname(&anchor);
        }
        if anchor == "/" || anchor.starts_with("/tmp") || anchor.starts_with("/dev/shm") {
            continue; // nothing safe to mount over; "-t" reports the missing directory
        }
        if anchor != d {
            creates.push(d);
        }
        mounts.push(anchor);
    }
    mounts.sort();
    mounts.dedup();
    creates.sort();
    creates.dedup();
    // A mount over an ancestor hides any deeper mount point, so keep only the outermost mounts.
    let outer: Vec<String> = mounts
        .iter()
        .filter(|m| !mounts.iter().any(|o| *m != o && m.starts_with(&format!("{}/", o.trim_end_matches('/')))))
        .cloned()
        .collect();
    Ok(outer.iter().map(|m| format!("m:{m}")).chain(creates.iter().map(|d| format!("d:{d}"))).collect())
}

fn set_times(path: &Path, meta: &fs::Metadata) {
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let timespec = |sec: i64, nsec: i64| {
        // SAFETY: timespec is plain data; zeroing also covers private padding fields on some targets.
        let mut value: libc::timespec = unsafe { std::mem::zeroed() };
        value.tv_sec = sec as _;
        value.tv_nsec = nsec as _;
        value
    };
    let times = [timespec(meta.atime(), meta.atime_nsec()), timespec(meta.mtime(), meta.mtime_nsec())];
    // SAFETY: valid NUL-terminated path and a two-element timespec array.
    unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
}

/// `shutil.copytree(src, dst)` with its defaults: symbolic links are followed (contents copied),
/// files are copied with their mode and times (copy2), directory modes and times are copied, a
/// dangling link fails the copy after everything else was copied. Extended attributes are not copied.
pub fn copytree(src: &Path, dst: &Path) -> Result<(), String> {
    let entries: Vec<fs::DirEntry> = fs::read_dir(src)
        .map_err(|e| format!("{}: {e}", src.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", src.display()))?;
    if dst.exists() || dst.is_symlink() {
        return Err(format!("{}: File exists", dst.display()));
    }
    fs::create_dir_all(dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    let mut errors = Vec::new();
    for entry in entries {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        match fs::metadata(&from) {
            Err(e) => errors.push(format!("{}: {e}", from.display())),
            Ok(meta) if meta.is_dir() => {
                if let Err(e) = copytree(&from, &to) {
                    errors.push(e);
                }
            }
            Ok(meta) => match fs::copy(&from, &to) {
                Ok(_) => set_times(&to, &meta),
                Err(e) => errors.push(format!("{}: {e}", from.display())),
            },
        }
    }
    if let Ok(meta) = fs::metadata(src) {
        let _ = fs::set_permissions(dst, fs::Permissions::from_mode(meta.mode() & 0o7777));
        set_times(dst, &meta);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// The private server root the binary tests: the candidate as conf/, writable runtime directories,
/// read-only support linked from the live root, mime.properties copied when the candidate has none.
pub fn stage(candidate: &Path, root: &Path, live: &Path) -> Result<(), String> {
    for name in WRITABLE {
        fs::create_dir_all(root.join(name)).map_err(|e| format!("{name}: {e}"))?;
    }
    copytree(candidate, &root.join("conf"))?;
    let admin = candidate.join("admin_config.conf");
    fs::create_dir(root.join("admin/conf")).map_err(|e| format!("admin/conf: {e}"))?;
    if admin.is_file() {
        let target = root.join("admin/conf/admin_config.conf");
        fs::copy(&admin, &target).map_err(|e| format!("admin_config.conf: {e}"))?;
        if let Ok(meta) = fs::metadata(&admin) {
            set_times(&target, &meta);
        }
    }
    for name in SHARED {
        if live.join(name).exists() {
            std::os::unix::fs::symlink(live.join(name), root.join(name)).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    let mime = root.join("conf/mime.properties");
    if !mime.exists() {
        let source = live.join("conf/mime.properties");
        fs::copy(&source, &mime).map_err(|e| format!("{}: {e}", source.display()))?;
        if let Ok(meta) = fs::metadata(&source) {
            set_times(&mime, &meta);
        }
    }
    Ok(())
}

fn rglob(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        out.push(path.clone());
        let is_link = entry.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        if !is_link && path.is_dir() {
            rglob(&path, out);
        }
    }
}

/// Digest of every regular file below `path` (full path, NUL, contents), in pathlib order.
pub fn tree_digest(path: &Path) -> String {
    let mut items = Vec::new();
    rglob(path, &mut items);
    items.sort(); // Path ordering is by component, like pathlib's
    let mut digest = Sha256::new();
    for item in items {
        if item.is_file() && !item.is_symlink() {
            digest.update(item.as_os_str().as_bytes());
            digest.update(b"\0");
            if let Ok(bytes) = fs::read(&item) {
                digest.update(bytes);
            }
        }
    }
    hex(&digest.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// pathlib `resolve()` (non-strict): symbolic links of the existing prefix resolved, the rest appended.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")).join(path)
    };
    if let Ok(real) = fs::canonicalize(&absolute) {
        return real;
    }
    let mut result = PathBuf::from("/");
    let mut missing = false;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(name) => {
                result.push(name);
                if !missing {
                    match fs::canonicalize(&result) {
                        Ok(real) => result = real,
                        Err(_) => missing = true,
                    }
                }
            }
        }
    }
    result
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.code().unwrap_or_else(|| -status.signal().unwrap_or(0))
}

fn run_namespaced(binary: &Path, root: &Path, dirs: &[String]) -> Result<Run, String> {
    let mut child = Command::new("/usr/bin/unshare")
        .args(["--mount", "--net", "--propagation", "private", "/bin/sh", "-c", INNER])
        .arg(binary)
        .args(dirs)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("LSWS_HOME", root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own process group: at the time limit the whole tree (unshare, sh, OLS) is killed.
        .process_group(0)
        .spawn()
        .map_err(|e| format!("/usr/bin/unshare: {e}"))?;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let out_thread = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = out.read_to_end(&mut buffer);
        buffer
    });
    let err_thread = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = err.read_to_end(&mut buffer);
        buffer
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > TIMEOUT {
            // SAFETY: the group leader is our unreaped child, so the group ID is ours.
            unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("binary test timed out after {} seconds", TIMEOUT.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok(Run {
        code: exit_code(status),
        stdout: pystr::universal_newlines(&String::from_utf8_lossy(&stdout)),
        stderr: pystr::universal_newlines(&String::from_utf8_lossy(&stderr)),
    })
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 6];
    if let Ok(mut urandom) = fs::File::open("/dev/urandom") {
        let _ = urandom.read_exact(&mut bytes);
    }
    hex(&bytes)
}

/// `tempfile.TemporaryDirectory(prefix="ols-stage-", dir="/var/tmp")`: mode 0700, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<TempDir, String> {
        for _ in 0..100 {
            let path = PathBuf::from(format!("/var/tmp/ols-stage-{}", random_suffix()));
            let mut builder = fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            match builder.create(&path) {
                Ok(()) => return Ok(TempDir(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Err("no temporary directory name available".into())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn usage_error(message: &str) -> i32 {
    eprintln!("{USAGE}\nols-cpanel-activator stage-validate: error: {message}");
    2
}

/// `stage-validate [--binary B] candidate`: the command line of ols_stage_validate.py. Prints the
/// JSON report (indent 2, Python key order) and returns the exit code (0 valid, 1 invalid, 2 usage).
pub fn main(args: &[String]) -> i32 {
    let mut binary = BINARY.to_string();
    let mut candidate = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-h" || arg == "--help" {
            println!("{USAGE}");
            return 0;
        } else if arg == "--binary" {
            match iter.next() {
                Some(value) => binary = value.clone(),
                None => return usage_error("argument --binary: expected one argument"),
            }
        } else if let Some(value) = arg.strip_prefix("--binary=") {
            binary = value.to_string();
        } else if arg.starts_with('-') && arg.len() > 1 || candidate.is_some() {
            return usage_error(&format!("unrecognized arguments: {arg}"));
        } else {
            candidate = Some(PathBuf::from(arg));
        }
    }
    let Some(candidate) = candidate else {
        return usage_error("the following arguments are required: candidate");
    };
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return usage_error("Run as root (sudo): namespaces and tmpfs mounts are required");
    }
    let binary = resolve(Path::new(&binary));
    if binary.starts_with("/tmp") || binary.starts_with("/dev/shm") {
        return usage_error("binary must not live under /tmp or /dev/shm: they are replaced by private tmpfs mounts");
    }
    let candidate = resolve(&candidate);
    if !candidate.join("httpd_config.conf").is_file() {
        return usage_error("candidate must contain httpd_config.conf");
    }
    match validate_candidate(&candidate, &binary) {
        Ok((report, ok)) => {
            println!("{report}");
            if ok {
                0
            } else {
                1
            }
        }
        Err(message) => {
            eprintln!("ols-cpanel-activator stage-validate: {message}");
            1
        }
    }
}

fn validate_candidate(candidate: &Path, binary: &Path) -> Result<(String, bool), String> {
    // Structural/product-policy lint first: the binary test does not validate listeners.
    let mut lint_errors = lint::lint(&read_text(&candidate.join("httpd_config.conf"))?, true);
    for vhconf in vhconf_files(candidate) {
        let name = vhconf.parent().and_then(Path::file_name).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        lint_errors.extend(lint::lint(&read_text(&vhconf)?, false).into_iter().map(|e| format!("{name}: {e}")));
    }
    if !lint_errors.is_empty() {
        let report = Ordered(vec![
            ("exit_code", Value::Null),
            ("findings", json!(lint_errors)),
            ("valid", json!(false)),
            ("stage", json!("lint")),
            ("live_conf_unchanged", json!(true)),
        ]);
        return Ok((pyjson::dumps_ordered(&report, Some(2)), false));
    }
    let live_conf = Path::new(LIVE_ROOT).join("conf");
    let before = live_conf.is_dir().then(|| tree_digest(&live_conf));
    let (run, text) = {
        let temp = TempDir::new()?;
        let root = temp.0.join("root");
        stage(candidate, &root, Path::new(LIVE_ROOT))?;
        let run = run_namespaced(binary, &root, &log_dirs(candidate)?)?;
        let log = root.join("logs/error.log");
        let log_text = if log.is_file() {
            fs::read(&log).map(|b| pystr::universal_newlines(&String::from_utf8_lossy(&b))).unwrap_or_default()
        } else {
            String::new()
        };
        let text = format!("{}{}{}", run.stdout, run.stderr, log_text);
        (run, text)
    };
    let (found, valid) = verdict(run.code, &text);
    let lines = pystr::splitlines(&text);
    let tail: Vec<&str> = lines[lines.len().saturating_sub(15)..].to_vec();
    let unchanged = before == live_conf.is_dir().then(|| tree_digest(&live_conf));
    let report = Ordered(vec![
        ("exit_code", json!(run.code)),
        ("findings", json!(found)),
        ("valid", json!(valid)),
        ("output_tail", json!(tail)),
        ("live_conf_unchanged", json!(unchanged)),
    ]);
    Ok((pyjson::dumps_ordered(&report, Some(2)), valid && unchanged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;

    #[test]
    fn verdict_rules_match_the_python_validator() {
        assert!(verdict(0, "[OK] Configuration test passed.\n").1);
        for (code, text) in [
            (1, "[OK]"),
            (0, "[ERROR] [PlainConf] parseline found more '}'"),
            (0, "2026 [WARN] [PlainConf] Not support [thisisnotadirective 1] in file x:3"),
            (0, "[ERROR] [config:server:listener] failed to start listener on address bad"),
            (0, "Can not set address bogus to webAdmin!"),
            (0, "[WARN] [1] Path for vhost root is not accessible: /var/lib/x/"),
            (0, "[WARN] [139358] [config:server:vhosts:vhost:olscp-gen] configuration failed!"),
            (0, "[WARN] [1] some new warning nobody reviewed"),
            (0, "[error] lowercase is still an error"),
            (0, "CANNOT open"),
            (0, "x i\u{17f} not acce\u{17f}\u{17f}ible"),
            (0, "[WARN] [1] [x] Uid of /a is 0, smaller than minimum requirement 11, use server uid! trailing"),
            (0, "[WARN] [1] [x] Uid of /a is x, smaller than minimum requirement 11, use server uid!"),
        ] {
            assert!(!verdict(code, text).1, "{text}");
        }
        assert!(verdict(0, "[INFO] No lsadm account, keep configuration directory ownership.").1);
        assert!(verdict(0, "2026 [WARN] [1] [config:server:vhosts:vhost:p] Uid of /var/www/html/ is 0, smaller than \
                             minimum requirement 11, use server uid!").1);
        assert!(verdict(0, "  [WARN] [1] Gid of /x is 0, smaller than minimum requirement 11, use server gid!  \r\n").1);
        let (found, valid) = verdict(0, &"[ERROR] x\n".repeat(60));
        assert!(!valid && found.len() == 50 && found[0] == "[ERROR] x");
    }

    #[test]
    fn log_directories_are_isolated() {
        let temp = TempTree::new_in(Path::new("/var/tmp")); // /tmp is already private in the namespace
        let cand = temp.path().join("cand");
        let logs = temp.path().join("live-logs");
        fs::create_dir_all(cand.join("vhosts/a")).unwrap();
        fs::create_dir(&logs).unwrap();
        let logs_s = logs.to_str().unwrap();
        fs::write(cand.join("httpd_config.conf"), format!("errorlog {logs_s}/error.log {{\n}}\naccesslog $SERVER_ROOT/logs/x.log {{\n}}\n")).unwrap();
        fs::write(cand.join("vhosts/a/vhconf.conf"), format!("accesslog {logs_s}/access.fifo {{\n}}\naccesslog /nonexistent/dir/x {{\n}}\n")).unwrap();
        assert_eq!(log_dirs(&cand).unwrap(), vec![format!("m:{logs_s}")]);
        fs::write(cand.join("vhosts/a/vhconf.conf"), format!("accesslog {logs_s}/run/ols/logs/access.fifo {{\n}}\n")).unwrap();
        assert_eq!(log_dirs(&cand).unwrap(), vec![format!("m:{logs_s}"), format!("d:{logs_s}/run/ols/logs")]);
        fs::write(cand.join("httpd_config.conf"), "accesslog /run/ols-cpanel/logs/access.fifo {\n}\n").unwrap();
        fs::remove_file(cand.join("vhosts/a/vhconf.conf")).unwrap();
        assert_eq!(log_dirs(&cand).unwrap(), vec!["d:/run/ols-cpanel/logs".to_string()]);
        assert!(INNER.contains("m:*) mount -t tmpfs") && INNER.contains("d:*) mkdir -p"));
        assert!(INNER.contains("mount -t tmpfs -o mode=0755 tmpfs /run;") && INNER.contains("/run/ols-cpanel/lshttpd"));
    }

    #[test]
    fn log_line_regex_semantics() {
        assert_eq!(log_paths("  errorlog /a/b {\n accesslog\t/c/d\naccesslogs /e\nx accesslog /f\n"), vec!["/a/b", "/c/d"]);
        assert_eq!(log_paths("\n\n   \n accesslog /x/y"), vec!["/x/y"]);
        assert_eq!(log_paths("accesslog\n/z/w"), vec!["/z/w"]); // \s+ spans a line break, as in Python
    }

    #[test]
    fn staging_layout() {
        let temp = TempTree::new();
        let live = temp.path().join("live");
        for name in ["modules", "share", "conf"] {
            fs::create_dir_all(live.join(name)).unwrap();
        }
        fs::write(live.join("conf/mime.properties"), "html = text/html\n").unwrap();
        let candidate = temp.path().join("candidate");
        fs::create_dir_all(candidate.join("vhosts/lab")).unwrap();
        fs::write(candidate.join("httpd_config.conf"), "serverName x\n").unwrap();
        fs::write(candidate.join("vhosts/lab/vhconf.conf"), "docRoot $VH_ROOT/html/\n").unwrap();
        fs::write(candidate.join("admin_config.conf"), "listener a {\n}\n").unwrap();
        let root = temp.path().join("root");
        stage(&candidate, &root, &live).unwrap();
        assert_eq!(fs::read_to_string(root.join("conf/httpd_config.conf")).unwrap(), "serverName x\n");
        assert!(root.join("conf/vhosts/lab/vhconf.conf").is_file());
        assert!(root.join("conf/mime.properties").is_file() && root.join("admin/conf/admin_config.conf").is_file());
        assert!(root.join("modules").is_symlink() && fs::canonicalize(root.join("modules")).unwrap() == fs::canonicalize(live.join("modules")).unwrap());
        assert!(!root.join("lsns").exists());
        assert!(WRITABLE.iter().all(|name| root.join(name).is_dir()));
        let digest = tree_digest(&live);
        fs::write(live.join("conf/new"), "x").unwrap();
        assert_ne!(tree_digest(&live), digest);
    }

    #[test]
    fn non_root_is_refused_before_anything() {
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(main(&["/nonexistent".to_string()]), 2);
        }
        assert_eq!(main(&[]), 2);
    }
}
