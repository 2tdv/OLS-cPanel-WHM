//! The tenant `.htaccess` watch (CMP-02; docs/product-interfaces.md, "Fast .htaccess changes"), run as
//! `ols-cpanel-broker --htaccess-watch=DIR` by `ols-cpanel-htaccess-watch.service` (root). It never serves a socket and
//! never opens, reads or follows a tenant file: it puts one fanotify filesystem mark on every filesystem that holds cPanel
//! homes (`/home` and `/home*`) and reads only the event records, whose last component name it compares with `.htaccess`.
//! A matching event (a file created, written and closed, renamed in or out, deleted, or its mode or owner changed), or a
//! lost-events overflow, is debounced (QUIET after the last one, at most MAX_DELAY after the first) and then "nudges" the
//! reconciler: DIR/htaccess.nudge gets a new token. The reconciler polls that token every second and runs a pass at once;
//! the pass still takes the input digest (RV-48) and compiles only when it changed, so a nudge never bypasses the
//! translation or the fail-closed review, and a burst of edits gives one pass.
//!
//! One mark per filesystem instead of one inotify watch per directory: about 36,000 directories under 25 lab document roots
//! already use 64% of the default `fs.inotify.max_user_watches` (56,567 with 7 GiB of RAM), so per-directory watches cannot
//! scale to 1,000 accounts; a filesystem mark has no such limit and sees new directories by construction. What the watch
//! cannot see (a whole directory tree renamed into a document root, a filesystem that refuses the mark, an event lost
//! while the service was down) is left to the reconciler's periodic digest (60 s) and the forced compile (15 minutes).
//! When fanotify is unavailable (old kernel, no CAP_SYS_ADMIN, no mark accepted) the service stays up idle and says so in
//! DIR/status.json; the reconciler then works exactly as before.

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The token file the reconciler polls (`Events\HtaccessNudge`).
pub const NUDGE_FILE: &str = "htaccess.nudge";
/// What the watch covers, for the operator and the lab probe.
pub const STATUS_FILE: &str = "status.json";
/// Quiet time after the last matching event before the nudge: an editor that writes several times gives one nudge.
pub const QUIET: Duration = Duration::from_secs(1);
/// Longest delay of a nudge after the first matching event, so that a continuous stream of writes cannot postpone it.
pub const MAX_DELAY: Duration = Duration::from_secs(4);
/// The file name the watch reports; any other name is ignored.
pub const NAME: &[u8] = b".htaccess";
/// Directory entry events (no FAN_ONDIR: only non-directory children), attribute changes and closes after a write. No
/// FAN_MODIFY: one event per close instead of one per write() keeps the event rate of a whole filesystem low.
pub const MASK: u64 = libc::FAN_CREATE
    | libc::FAN_DELETE
    | libc::FAN_MOVED_FROM
    | libc::FAN_MOVED_TO
    | libc::FAN_ATTRIB
    | libc::FAN_CLOSE_WRITE;
/// Re-check the home mounts (a new /homeN, a mark that failed) this often while idle.
const REMARK: Duration = Duration::from_secs(300);
const METADATA_LEN: usize = 24;

/// What one read of the fanotify queue held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Events on a file named `.htaccess`.
    pub matched: usize,
    /// Every other event.
    pub other: usize,
    /// The kernel dropped events (queue full): the caller must assume a change.
    pub overflow: bool,
    /// A record that does not parse: the caller must assume a change.
    pub malformed: bool,
    /// Event file descriptors to close (never set in FID mode; closed anyway if the kernel sends one).
    pub fds: Vec<i32>,
}

impl Scan {
    /// Whether this read must lead to a nudge.
    pub fn changed(&self) -> bool {
        self.matched > 0 || self.overflow || self.malformed
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|s| u16::from_ne_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8).map(|s| u64::from_ne_bytes(s.try_into().unwrap()))
}

/// Parses the events of one read (`struct fanotify_event_metadata` followed by info records; FAN_REPORT_DFID_NAME puts
/// the parent directory's handle and the entry name in a DFID_NAME record). Only the name is used: nothing is resolved,
/// opened or followed, so a symlink named `.htaccess` is a change (the compile reports it as a blocker) and a symlink
/// to a directory is never walked.
pub fn scan(buf: &[u8]) -> Scan {
    let mut out = Scan::default();
    let mut at = 0;
    while at < buf.len() {
        let (Some(len), Some(meta_len), Some(mask), Some(fd)) =
            (u32_at(buf, at), u16_at(buf, at + 6), u64_at(buf, at + 8), u32_at(buf, at + 16))
        else {
            out.malformed = true;
            break;
        };
        let (len, meta_len) = (len as usize, meta_len as usize);
        if buf[at + 4] != libc::FANOTIFY_METADATA_VERSION || meta_len < METADATA_LEN || len < meta_len || at + len > buf.len() {
            out.malformed = true;
            break;
        }
        let fd = fd as i32;
        if fd >= 0 {
            out.fds.push(fd);
        }
        if mask & libc::FAN_Q_OVERFLOW != 0 {
            out.overflow = true;
        } else if names(&buf[at + meta_len..at + len]).iter().any(|n| *n == NAME) {
            out.matched += 1;
        } else {
            out.other += 1;
        }
        at += len;
    }
    out
}

/// The entry names of an event's info records (DFID_NAME only).
fn names(mut info: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while info.len() >= 4 {
        let kind = info[0];
        let len = u16_at(info, 2).unwrap_or(0) as usize;
        if len < 4 || len > info.len() {
            break;
        }
        let record = &info[..len];
        // header (4), fsid (8), struct file_handle: handle_bytes (4), handle_type (4), f_handle[handle_bytes], then the name.
        if kind == libc::FAN_EVENT_INFO_TYPE_DFID_NAME {
            if let Some(bytes) = u32_at(record, 12) {
                let start = 20usize.saturating_add(bytes as usize);
                if let Some(rest) = record.get(start..) {
                    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
                    out.push(&rest[..end]);
                }
            }
        }
        info = &info[len..];
    }
    out
}

/// Debounce of matching events: due QUIET after the last one, or MAX_DELAY after the first.
#[derive(Debug, Default)]
pub struct Debounce {
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Debounce {
    pub fn note(&mut self, now: Instant) {
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    /// Time until the nudge is due (zero when due), or None when nothing is pending.
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        let (first, last) = (self.first?, self.last?);
        let due = (last + QUIET).min(first + MAX_DELAY);
        Some(due.saturating_duration_since(now))
    }

    /// Whether the nudge is due now; resets the pending state when it is.
    pub fn take(&mut self, now: Instant) -> bool {
        if self.wait(now) == Some(Duration::ZERO) {
            *self = Debounce::default();
            true
        } else {
            false
        }
    }
}

/// The roots whose filesystems hold cPanel homes: `/home` and every `/home*` directory of `/` (cPanel's HOMEMATCH),
/// never through a symlink.
pub fn home_roots(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let valid = name.starts_with("home") && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if valid && entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                out.push(root.join(&name).to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}

/// The status record: what is watched and what is not, with counters.
pub fn status_json(watching: &[String], unwatched: &[(String, String)], reason: Option<&str>, counters: [u64; 4]) -> String {
    serde_json::json!({
        "watching": !watching.is_empty(),
        "filesystems": watching,
        "unwatched": unwatched.iter().map(|(root, error)| serde_json::json!({"root": root, "error": error})).collect::<Vec<_>>(),
        "reason": reason,
        "events": counters[0], "matched": counters[1], "overflows": counters[2], "nudges": counters[3],
        "quiet_ms": QUIET.as_millis() as u64, "max_delay_ms": MAX_DELAY.as_millis() as u64,
        "updated": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    })
    .to_string()
}

/// Writes DIR/name atomically, world-readable (the reconciler runs as `olscpanel`).
pub fn publish(dir: &Path, name: &str, text: &str) -> std::io::Result<()> {
    let temp = dir.join(format!(".{name}.tmp"));
    let mut file = fs::File::create(&temp)?;
    file.write_all(text.as_bytes())?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    drop(file);
    fs::rename(&temp, dir.join(name))
}

/// A token unique to this process and nudge: "<process start ns>-<sequence> <unix seconds>".
pub fn token(start: u128, sequence: u64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{start}-{sequence} {now}\n")
}

fn errno_text() -> String {
    std::io::Error::last_os_error().to_string()
}

struct Marks {
    watching: Vec<String>,
    unwatched: Vec<(String, String)>,
    devices: Vec<u64>,
}

fn mark(fd: i32, marks: &mut Marks) {
    marks.unwatched.clear();
    for root in home_roots(Path::new("/")) {
        let Ok(meta) = fs::symlink_metadata(&root) else { continue };
        if marks.devices.contains(&meta.dev()) {
            continue;
        }
        let path = CString::new(root.clone()).expect("no NUL in a home root");
        let flags = libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM | libc::FAN_MARK_DONT_FOLLOW;
        // The raw system call: the static (musl) build's libc has no fanotify_mark wrapper. x86_64 passes the 64-bit mask
        // in one register.
        let done = unsafe { libc::syscall(libc::SYS_fanotify_mark, fd, flags, MASK, libc::AT_FDCWD, path.as_ptr()) };
        if done == 0 {
            marks.devices.push(meta.dev());
            marks.watching.push(root);
        } else {
            marks.unwatched.push((root, errno_text()));
        }
    }
}

fn idle(dir: &Path, reason: &str) -> ! {
    eprintln!("htaccess watch unavailable: {reason}; the reconciler's periodic digest applies .htaccess changes");
    let _ = publish(dir, STATUS_FILE, &status_json(&[], &[], Some(reason), [0; 4]));
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// The service: never returns while it can watch; idles (status "watching": false) when it cannot.
pub fn run(dir: &Path) -> i32 {
    if !dir.is_dir() {
        eprintln!("htaccess watch: {} is not a directory", dir.display());
        return 2;
    }
    let start = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let init = libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_REPORT_DFID_NAME;
    let fd = unsafe { libc::fanotify_init(init, (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as u32) };
    if fd < 0 {
        idle(dir, &format!("fanotify_init: {}", errno_text()));
    }
    let mut marks = Marks { watching: Vec::new(), unwatched: Vec::new(), devices: Vec::new() };
    mark(fd, &mut marks);
    if marks.watching.is_empty() {
        let why = marks.unwatched.iter().map(|(r, e)| format!("{r}: {e}")).collect::<Vec<_>>().join("; ");
        idle(dir, &format!("no home filesystem accepted the mark ({why})"));
    }
    // Events may have been missed while the service was down: the first token makes the reconciler take a digest.
    let mut sequence = 0u64;
    let mut counters = [0u64; 4];
    let _ = publish(dir, NUDGE_FILE, &token(start, sequence));
    let _ = publish(dir, STATUS_FILE, &status_json(&marks.watching, &marks.unwatched, None, counters));
    let mut debounce = Debounce::default();
    let mut buf = vec![0u8; 64 * 1024];
    let mut remarked = Instant::now();
    let mut reported = Instant::now();
    loop {
        let now = Instant::now();
        let timeout = debounce.wait(now).unwrap_or(Duration::from_secs(60));
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, timeout.as_millis().min(60_000) as i32 + 1) };
        if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            eprintln!("htaccess watch: poll: {}", errno_text());
            return 1;
        }
        loop {
            let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if read <= 0 {
                break;
            }
            let found = scan(&buf[..read as usize]);
            for event_fd in &found.fds {
                unsafe { libc::close(*event_fd) };
            }
            counters[0] += (found.matched + found.other) as u64;
            counters[1] += found.matched as u64;
            counters[2] += found.overflow as u64;
            if found.changed() {
                debounce.note(Instant::now());
            }
        }
        let now = Instant::now();
        if debounce.take(now) {
            sequence += 1;
            counters[3] += 1;
            if let Err(error) = publish(dir, NUDGE_FILE, &token(start, sequence)) {
                eprintln!("htaccess watch: cannot write the nudge: {error}");
            }
        }
        if now.duration_since(remarked) >= REMARK {
            mark(fd, &mut marks);
            remarked = now;
        }
        if now.duration_since(reported) >= Duration::from_secs(60) {
            let _ = publish(dir, STATUS_FILE, &status_json(&marks.watching, &marks.unwatched, None, counters));
            reported = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One event record as the kernel lays it out: metadata, then a DFID_NAME record with an 8-byte handle and the name.
    fn event(mask: u64, name: Option<&[u8]>) -> Vec<u8> {
        let mut info = Vec::new();
        if let Some(name) = name {
            let mut record = vec![libc::FAN_EVENT_INFO_TYPE_DFID_NAME, 0, 0, 0];
            record.extend_from_slice(&[7u8; 8]); // fsid
            record.extend_from_slice(&8u32.to_ne_bytes()); // handle_bytes
            record.extend_from_slice(&1i32.to_ne_bytes()); // handle_type
            record.extend_from_slice(&[9u8; 8]); // f_handle
            record.extend_from_slice(name);
            record.push(0);
            while record.len() % 4 != 0 {
                record.push(0);
            }
            let len = record.len() as u16;
            record[2..4].copy_from_slice(&len.to_ne_bytes());
            info = record;
        }
        let len = (METADATA_LEN + info.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_ne_bytes());
        out.push(libc::FANOTIFY_METADATA_VERSION);
        out.push(0);
        out.extend_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&(-1i32).to_ne_bytes()); // FAN_NOFD
        out.extend_from_slice(&1234i32.to_ne_bytes());
        out.extend_from_slice(&info);
        out
    }

    #[test]
    fn only_htaccess_names_match() {
        let mut buf = event(libc::FAN_CLOSE_WRITE, Some(b".htaccess"));
        buf.extend(event(libc::FAN_CLOSE_WRITE, Some(b"index.php")));
        buf.extend(event(libc::FAN_CREATE, Some(b".htaccess.bak")));
        buf.extend(event(libc::FAN_MOVED_TO, Some(b".htaccess")));
        buf.extend(event(libc::FAN_DELETE, Some(b".htaccess")));
        buf.extend(event(libc::FAN_ATTRIB, Some(b"x.htaccess")));
        let found = scan(&buf);
        assert_eq!((found.matched, found.other, found.overflow, found.malformed), (3, 3, false, false));
        assert!(found.changed() && found.fds.is_empty());
    }

    #[test]
    fn unrelated_events_do_not_change() {
        let buf: Vec<u8> = (0..100).flat_map(|i| event(libc::FAN_CLOSE_WRITE, Some(format!("sess_{i}").as_bytes()))).collect();
        let found = scan(&buf);
        assert_eq!((found.matched, found.other), (0, 100));
        assert!(!found.changed());
    }

    #[test]
    fn a_new_directory_with_an_htaccess_is_seen_by_the_file_event() {
        // mkdir is not reported (no FAN_ONDIR); the .htaccess created inside it is, on the same filesystem mark.
        let found = scan(&event(libc::FAN_CREATE, Some(b".htaccess")));
        assert_eq!(found.matched, 1);
    }

    #[test]
    fn a_symlink_named_htaccess_is_a_change_and_nothing_is_followed() {
        // The kernel reports the creation of the link itself (a non-directory entry); the watch never resolves it,
        // and the compile reports a symlinked .htaccess as a blocker (the site stays on Apache).
        let found = scan(&event(libc::FAN_CREATE, Some(b".htaccess")));
        assert!(found.changed());
        // A symlinked directory is an entry named after the link, never walked.
        assert!(!scan(&event(libc::FAN_CREATE, Some(b"linked-dir"))).changed());
    }

    #[test]
    fn overflow_and_malformed_records_are_changes() {
        let found = scan(&event(libc::FAN_Q_OVERFLOW, None));
        assert!(found.overflow && found.changed());
        let mut cut = event(libc::FAN_CLOSE_WRITE, Some(b"a"));
        cut.truncate(30);
        assert!(scan(&cut).malformed);
        let mut version = event(libc::FAN_CLOSE_WRITE, Some(b"a"));
        version[4] = 99;
        assert!(scan(&version).changed());
        // A record whose name runs past its length is ignored, never read out of bounds.
        let mut long = event(libc::FAN_CLOSE_WRITE, Some(b".htaccess"));
        long[24 + 12..24 + 16].copy_from_slice(&1000u32.to_ne_bytes());
        assert_eq!(scan(&long).matched, 0);
        assert!(!scan(&[]).changed());
    }

    #[test]
    fn debounce_waits_for_quiet_and_caps_the_delay() {
        let t0 = Instant::now();
        let mut d = Debounce::default();
        assert_eq!(d.wait(t0), None);
        assert!(!d.take(t0));
        // 20 edits in 2 s: no nudge until 1 s after the last, then exactly one.
        for i in 0..20 {
            d.note(t0 + Duration::from_millis(100 * i));
            assert!(!d.take(t0 + Duration::from_millis(100 * i + 50)));
        }
        assert!(!d.take(t0 + Duration::from_millis(2800)));
        assert!(d.take(t0 + Duration::from_millis(2900)));
        assert!(!d.take(t0 + Duration::from_millis(5000)));
        // A continuous stream is nudged MAX_DELAY after its first event.
        let mut d = Debounce::default();
        let mut nudges = 0;
        for i in 0..100 {
            let now = t0 + Duration::from_millis(200 * i);
            d.note(now);
            if d.take(now) {
                nudges += 1;
            }
        }
        assert_eq!(nudges, 4, "20 s of writes every 200 ms: one nudge every {} s", MAX_DELAY.as_secs());
        // A single edit: one second.
        let mut d = Debounce::default();
        d.note(t0);
        assert_eq!(d.wait(t0), Some(QUIET));
    }

    #[test]
    fn home_roots_are_home_directories_only() {
        let dir = std::env::temp_dir().join(format!("ols-watch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for d in ["home", "home2", "homex", "var", "home bad"] {
            fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(dir.join("var"), dir.join("home3")).unwrap();
        fs::write(dir.join("homefile"), b"").unwrap();
        let roots = home_roots(&dir);
        let names: Vec<_> = roots.iter().map(|r| r.rsplit('/').next().unwrap().to_string()).collect();
        assert_eq!(names, ["home", "home2", "homex"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nudge_and_status_files_are_published_readable() {
        let dir = std::env::temp_dir().join(format!("ols-watch-pub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let first = token(42, 0);
        let second = token(42, 1);
        assert!(first.starts_with("42-0 ") && second.starts_with("42-1 ") && first != second);
        publish(&dir, NUDGE_FILE, &second).unwrap();
        let meta = fs::metadata(dir.join(NUDGE_FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        assert_eq!(fs::read_to_string(dir.join(NUDGE_FILE)).unwrap(), second);
        let status: serde_json::Value =
            serde_json::from_str(&status_json(&[], &[("/home2".into(), "EXDEV".into())], Some("fanotify_init: EPERM"), [5, 1, 0, 1])).unwrap();
        assert_eq!(status["watching"], false);
        assert_eq!(status["unwatched"][0]["root"], "/home2");
        assert_eq!(status["reason"], "fanotify_init: EPERM");
        fs::remove_dir_all(&dir).unwrap();
    }
}
