//! Account tools (FV-08, docs/product-interfaces.md "Account tools"): the tenant operations `tenant.logs`,
//! `tenant.php_errors` and `tenant.perf`. Every one is scoped to the caller: the account is the SO_PEERCRED identity
//! passed in by the dispatcher, a domain in the request must be one of that account's own rows of
//! /etc/userdatadomains, and every file name is built from such a row (a validated host name), never from request text.
//!
//! Logs. Access logs are cPanel's domlogs (`<domlogs>/<domain>` and `<domain>-ssl_log`, filled by the log shipper), the
//! error log is the OLS vhost's own `<error_logs>/<vhost>-error.log`; both are per domain or vhost, so another account's
//! requests never appear in them. Root reads them without following a link at the last component, takes at most a
//! window from the end, and returns only redacted lines (`redact`). The docroot `error_log` the site's PHP writes is the
//! account's own file and is read as the account (`runuser -u <user> -- tail`), so a link planted in the home cannot
//! lead root anywhere.
//!
//! Bounds. A window is at most 4 MiB, but it may hold millions of (empty) lines, so a view looks at no more than
//! MAX_SCAN_LINES of the newest lines (MAX_SCAN_DOWNLOAD for a download), borrows them from the window, redacts them
//! one at a time and keeps only what is returned (the requested number of lines, or the matches of a download).
//!
//! Ownership epoch. A domain log belongs to whoever owned the domain when a line was written. The product keeps
//! `<state>/domain-owners.json` (root 0600, src/ObjectCache/DomainOwners.php, maintained by the reconcile pass from
//! /etc/userdatadomains): per domain its current owner and `since`, the second the owner took it (0 for domains that
//! existed when the file was first created). A tenant log read needs the domain in that file with the caller as owner
//! (otherwise NOT_FOUND, as for a foreign domain) and returns only lines whose own timestamp is not before `since`
//! (Apache `[28/Oct/2026:04:16:04 +0000]`, OLS `2026-10-28 04:30:39.432908` in local time, PHP `[28-Oct-2026 04:30:39 UTC]`);
//! a line without a timestamp follows the decision of the line before it, and, with `since` above 0, lines before the
//! first timestamp are dropped. So a domain that moves from one live account to another does not show the earlier
//! owner's requests or PHP error details to the new one.
//!
//! Stale logs. Independently, a log whose last write is older than the account's creation (cPanel's STARTDATE) cannot
//! hold the account's requests: it belongs to an earlier owner of the name and is answered as missing (`stale`; it also
//! covers an account re-created between two reconcile passes, which the epoch file would see as the same owner). The
//! reconciler also removes OLS vhost error logs of vhosts that no longer exist (src/ObjectCache/AccountRemoval) and
//! cPanel removes domlogs when it terminates an account (Whostmgr::Accounts::Remove::Cleanup, _apache_domlogs).
//!
//! Performance checks fetch the domain's front page twice over HTTPS from this server, against the address cPanel lists
//! for the domain, with the right Host and SNI (curl `--resolve`), and report what a visitor gets.

use super::{cache, now, redact, summary, Config, Reply};
use crate::engine::command;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_LINES: u64 = 200;
pub const MAX_LINES: u64 = 500;
/// How much of the end of a log is looked at (view, search and error groups).
pub const WINDOW: u64 = 4 << 20;
/// The largest download (redacted text).
pub const DOWNLOAD: u64 = 1 << 20;
pub const MAX_SEARCH: usize = 100;
/// The newest lines of a window that are looked at.
pub const MAX_SCAN_LINES: usize = 20_000;
pub const MAX_SCAN_DOWNLOAD: usize = 100_000;
pub const MAX_GROUPS: usize = 50;
const MAX_SIGNATURES: usize = 2000;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const CHECK_TIMEOUT: Duration = Duration::from_secs(12);
/// One performance check per account in this time.
pub const PERF_INTERVAL: Duration = Duration::from_secs(15);

type Fail = (&'static str, String);

/// The caller's own row for `domain`.
fn own_row(config: &Config, user: &str, domain: &str) -> Result<Value, Fail> {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    if !cache::domain_ok(domain) {
        return Err(("BAD_ARGS", "domain must be a domain name".into()));
    }
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    rows.into_iter().find(|r| r["domain"] == json!(domain) && r["user"] == json!(user))
        .ok_or(("NOT_FOUND", "that is not one of your domains".to_string()))
}

/// The vhost of a row, which must itself be one of the caller's own domains (the parent of an addon or parked domain).
fn own_vhost(config: &Config, user: &str, row: &Value) -> Result<String, Fail> {
    let vhost = summary::vhost_of(row).to_string();
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    rows.iter().any(|r| r["domain"] == json!(vhost) && r["user"] == json!(user))
        .then_some(vhost).ok_or(("NOT_FOUND", "the site of that domain is not one of your domains".to_string()))
}

/// The end of a regular file (at most `window` bytes) and whether bytes before it were left out; None when it does not exist.
fn tail(path: &Path, window: u64) -> Result<Option<(Vec<u8>, bool)>, Fail> {
    let unreadable = || ("UNREADABLE", "the log cannot be read".to_string());
    let mut file = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unreadable()),
    };
    let meta = file.metadata().map_err(|_| unreadable())?;
    if !meta.is_file() {
        return Err(unreadable());
    }
    let start = meta.len().saturating_sub(window);
    file.seek(SeekFrom::Start(start)).map_err(|_| unreadable())?;
    let mut bytes = Vec::new();
    file.take(window).read_to_end(&mut bytes).map_err(|_| unreadable())?;
    Ok(Some((bytes, start > 0)))
}

/// At most `max` of the newest complete lines of a window, borrowed from it, oldest first, and whether older lines
/// in the window were left out. A first line cut by the window's start is dropped, a trailing newline adds nothing.
fn last_lines(text: &str, cut_start: bool, max: usize) -> (Vec<&str>, bool) {
    if text.is_empty() {
        return (vec![], false);
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut lines: Vec<&str> = body.rsplit('\n').take(max + 1).collect();
    lines.reverse();
    let mut left_out = false;
    if lines.len() > max {
        lines.remove(0);
        left_out = true;
    } else if cut_start && !lines.is_empty() {
        lines.remove(0);
    }
    (lines.into_iter().map(|l| l.trim_end_matches('\r')).collect(), left_out)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LogArgs {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    lines: Option<u64>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    download: Option<bool>,
}

/// The ownership epoch file (see the module documentation).
const OWNERS_FILE: &str = "domain-owners.json";
const OWNERS_MAX: u64 = 16 << 20;

/// `since` of `domain` when `user` owns it according to the ownership epoch file; NOT_FOUND when the file or the domain
/// is missing or the owner is someone else.
fn epoch(config: &Config, user: &str, domain: &str) -> Result<u64, Fail> {
    let not_yours = || ("NOT_FOUND", "that is not one of your domains".to_string());
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(config.state.join(OWNERS_FILE)).map_err(|_| not_yours())?;
    let mut bytes = Vec::new();
    file.take(OWNERS_MAX + 1).read_to_end(&mut bytes).map_err(|_| not_yours())?;
    if bytes.len() as u64 > OWNERS_MAX {
        return Err(not_yours());
    }
    owner_since(&bytes, user, domain).ok_or_else(not_yours)
}

fn owner_since(bytes: &[u8], user: &str, domain: &str) -> Option<u64> {
    let data: Value = serde_json::from_slice(bytes).ok()?;
    let entry = data.get(domain)?;
    if entry["owner"] == json!(user) { entry["since"].as_u64() } else { None }
}

fn month(name: &str) -> Option<u32> {
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter()
        .position(|m| m.eq_ignore_ascii_case(name)).map(|i| i as u32 + 1)
}

/// Seconds since the epoch of a civil UTC date and time.
fn civil_utc(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> Option<i64> {
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh as i64 * 3600 + mm as i64 * 60 + ss as i64)
}

fn num(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(b.iter().fold(0u32, |n, d| n * 10 + (d - b'0') as u32))
}

/// The time a log line was written at, from its own timestamp: Apache `[28/Oct/2026:04:16:04 +0000]` (anywhere in the
/// line), OLS `2026-10-28 04:30:39.432908` (at the start, local time) or PHP `[28-Oct-2026 04:30:39 UTC]` (UTC only).
fn line_time(line: &str) -> Option<u64> {
    let b = line.as_bytes();
    if b.len() >= 19 && b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':' {
        let (y, mo, d) = (num(&b[0..4])?, num(&b[5..7])?, num(&b[8..10])?);
        let (hh, mi, ss) = (num(&b[11..13])?, num(&b[14..16])?, num(&b[17..19])?);
        civil_utc(y as i64, mo, d, hh, mi, ss)?;
        // SAFETY: mktime only reads and normalises the zeroed struct that is filled in here.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = y as i32 - 1900;
        tm.tm_mon = mo as i32 - 1;
        tm.tm_mday = d as i32;
        tm.tm_hour = hh as i32;
        tm.tm_min = mi as i32;
        tm.tm_sec = ss.min(59) as i32;
        tm.tm_isdst = -1;
        let t = unsafe { libc::mktime(&mut tm) };
        return if t >= 0 { Some(t as u64) } else { None };
    }
    let mut from = 0;
    while let Some(at) = line[from..].find('[') {
        let rest = &line[from + at + 1..];
        let rb = rest.as_bytes();
        // [dd/Mon/yyyy:hh:mm:ss +zzzz]
        if rb.len() >= 26 && rb[2] == b'/' && rb[6] == b'/' && rb[11] == b':' && rb[14] == b':' && rb[17] == b':' && rb[20] == b' '
            && (rb[21] == b'+' || rb[21] == b'-') {
            if let (Some(d), Some(mo), Some(y), Some(hh), Some(mi), Some(ss), Some(zh), Some(zm)) = (
                num(&rb[0..2]), rest.get(3..6).and_then(month), num(&rb[7..11]), num(&rb[12..14]), num(&rb[15..17]),
                num(&rb[18..20]), num(&rb[22..24]), num(&rb[24..26])) {
                let offset = (zh as i64 * 3600 + zm as i64 * 60) * if rb[21] == b'-' { -1 } else { 1 };
                return civil_utc(y as i64, mo, d, hh, mi, ss).map(|t| (t - offset).max(0) as u64);
            }
        }
        // [dd-Mon-yyyy hh:mm:ss UTC]
        if rb.len() >= 24 && rb[2] == b'-' && rb[6] == b'-' && rb[11] == b' ' && rb[14] == b':' && rb[17] == b':' && rb[20] == b' '
            && &rb[21..24] == b"UTC" {
            if let (Some(d), Some(mo), Some(y), Some(hh), Some(mi), Some(ss)) = (
                num(&rb[0..2]), rest.get(3..6).and_then(month), num(&rb[7..11]), num(&rb[12..14]), num(&rb[15..17]), num(&rb[18..20])) {
                return civil_utc(y as i64, mo, d, hh, mi, ss).map(|t| t.max(0) as u64);
            }
        }
        from += at + 1;
    }
    None
}

/// The lines written at or after `since`, in order. `since` 0 keeps every line. A line without a timestamp follows the
/// decision of the line before it (a continuation); before the first timestamp it is dropped.
fn since_lines(lines: Vec<&str>, since: u64) -> Vec<&str> {
    if since == 0 {
        return lines;
    }
    let mut keep = false;
    lines.into_iter().filter(|l| {
        if let Some(t) = line_time(l) {
            keep = t >= since;
        }
        keep
    }).collect()
}

/// Whether the log was last written before the account was created (so it cannot be the account's own; the ownership
/// epoch cannot tell an account re-created between two reconcile passes from the same owner).
fn stale(config: &Config, user: &str, path: &Path) -> bool {
    let Some(start) = super::requests::start_date(config, user) else { return false };
    fs::symlink_metadata(path).map_or(false, |m| m.is_file() && (m.mtime().max(0) as u64) < start)
}

/// `tenant.logs {domain, kind: "access"|"access_http"|"error", lines?: 1..500, search?: text, download?: bool}`.
pub fn tenant_logs(config: &Config, user: &str, args: Value) -> Reply {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let a: LogArgs = cache::parse(args)?;
    let lines = a.lines.unwrap_or(DEFAULT_LINES);
    if !(1..=MAX_LINES).contains(&lines) {
        return Err(("BAD_ARGS", format!("lines must be 1..{MAX_LINES}")));
    }
    let search = match a.search.as_deref() {
        None | Some("") => None,
        Some(s) if s.chars().count() <= MAX_SEARCH && !s.chars().any(|c| c.is_control()) => Some(s),
        Some(_) => return Err(("BAD_ARGS", format!("search must be at most {MAX_SEARCH} printable characters"))),
    };
    let row = own_row(config, user, &a.domain)?;
    let domain = a.domain.as_str();
    let mut since = epoch(config, user, domain)?;
    let (dir, file) = match a.kind.as_str() {
        "access" => (&config.domlogs, format!("{domain}-ssl_log")),
        "access_http" => (&config.domlogs, domain.to_string()),
        "error" => {
            let vhost = own_vhost(config, user, &row)?;
            since = since.max(epoch(config, user, &vhost)?);
            (&config.error_logs, format!("{vhost}-error.log"))
        }
        _ => return Err(("BAD_ARGS", "kind must be access, access_http or error".into())),
    };
    let download = a.download.unwrap_or(false);
    let window = if download { DOWNLOAD } else { WINDOW };
    let mut out = json!({"user": user, "domain": domain, "kind": a.kind, "file": file, "observed_at": now(), "search": search,
                         "download": download, "exists": false, "lines": [], "count": 0, "window_truncated": false});
    if stale(config, user, &dir.join(&file)) {
        return Ok(out);
    }
    let Some((bytes, cut)) = tail(&dir.join(&file), window)? else { return Ok(out) };
    let text = String::from_utf8_lossy(&bytes);
    let (newest, left_out) = last_lines(&text, cut, if download { MAX_SCAN_DOWNLOAD } else { MAX_SCAN_LINES });
    let newest = since_lines(newest, since);
    // The search runs over the redacted text, so it cannot be used to probe a removed value. Lines are redacted one at
    // a time, newest first, and only the lines that are returned are kept.
    let mut kept: Vec<String> = Vec::new();
    let mut size = 0usize;
    for line in newest.iter().rev() {
        let line = redact::redact(line);
        if !search.map_or(true, |s| line.contains(s)) {
            continue;
        }
        size += line.len() + 1;
        kept.push(line);
        if (!download && kept.len() >= lines as usize) || size >= 2 * DOWNLOAD as usize {
            break;
        }
    }
    kept.reverse();
    out["exists"] = json!(true);
    out["window_truncated"] = json!(cut || left_out);
    if download {
        let mut text = kept.join("\n");
        text.push('\n');
        out["count"] = json!(kept.len());
        out["bytes"] = json!(text.len());
        out["text"] = json!(text);
        return Ok(out);
    }
    out["count"] = json!(kept.len());
    out["lines"] = json!(kept);
    Ok(out)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DomainArgs {
    #[serde(default)]
    domain: String,
}

/// The timestamp a log line starts with, as written: `[28-Oct-2026 10:00:00 UTC]` or `2026-10-28 10:00:00`.
fn stamp(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix('[') {
        return rest.find(']').filter(|n| *n <= 40).map(|n| rest[..n].to_string());
    }
    let head: String = line.chars().take(19).collect();
    let b = head.as_bytes();
    let shaped = b.len() == 19 && b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':';
    shaped.then_some(head)
}

/// `("Warning", "Undefined variable $x in /a.php on line 3")` of a PHP error line.
fn php_message(line: &str) -> Option<(String, String)> {
    let at = line.find("PHP ")?;
    let rest = &line[at + 4..];
    let colon = rest.find(':')?;
    let level = rest[..colon].trim();
    if level.is_empty() || level.len() > 30 || !level.chars().all(|c| c.is_ascii_alphabetic() || c == ' ') {
        return None;
    }
    let message = rest[colon + 1..].split_whitespace().collect::<Vec<_>>().join(" ");
    (!message.is_empty()).then(|| (level.to_string(), message))
}

/// Long digit runs (identifiers, times) do not make two messages different; the line number stays.
fn signature(level: &str, message: &str) -> String {
    let mut out = format!("{level}: ");
    let chars: Vec<char> = message.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i - start >= 6 {
                out.push('N');
            } else {
                out.extend(&chars[start..i]);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

struct Group {
    level: String,
    message: String,
    count: u64,
    first_seen: Option<String>,
    last_seen: Option<String>,
    sources: Vec<&'static str>,
}

/// Groups the PHP error lines of `sources` (the text of a window and whether it was cut at its start) by message
/// signature. Only the newest MAX_SCAN_LINES lines of each source are looked at, borrowed and redacted one at a time;
/// the groups are bounded (MAX_SIGNATURES, 300 characters of message), so memory use does not depend on the log.
fn group_errors(sources: &[(&'static str, String, bool)]) -> Value {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Group> = HashMap::new();
    let (mut scanned, mut php, mut dropped) = (0u64, 0u64, 0u64);
    for (source, text, cut) in sources {
        let (lines, _) = last_lines(text, *cut, MAX_SCAN_LINES);
        for raw in lines {
            scanned += 1;
            // Only a line that can hold a PHP message is redacted; an empty or unrelated one costs nothing.
            if !raw.contains("PHP ") {
                continue;
            }
            let redacted = redact::redact(raw);
            let line = redacted.as_str();
            let Some((level, message)) = php_message(line) else { continue };
            php += 1;
            let sig = signature(&level, &message);
            let at = stamp(line);
            if !groups.contains_key(&sig) {
                if groups.len() >= MAX_SIGNATURES {
                    dropped += 1;
                    continue;
                }
                order.push(sig.clone());
                groups.insert(sig.clone(), Group { level, message: message.chars().take(300).collect(), count: 0,
                                                  first_seen: at.clone(), last_seen: None, sources: vec![] });
            }
            let g = groups.get_mut(&sig).expect("group inserted above");
            g.count += 1;
            if at.is_some() {
                g.last_seen = at;
            }
            if !g.sources.contains(source) {
                g.sources.push(source);
            }
        }
    }
    let mut list: Vec<&Group> = order.iter().filter_map(|s| groups.get(s)).collect();
    list.sort_by(|a, b| b.count.cmp(&a.count));
    let total = list.len();
    let rows: Vec<Value> = list.into_iter().take(MAX_GROUPS).map(|g| json!({
        "level": g.level, "message": g.message, "count": g.count, "first_seen": g.first_seen,
        "last_seen": g.last_seen.clone().or_else(|| g.first_seen.clone()), "sources": g.sources})).collect();
    json!({"scanned_lines": scanned, "php_lines": php, "groups_total": total, "groups_dropped_lines": dropped, "groups": rows})
}

/// The end of the account's own file, read as the account.
fn read_as_user(config: &Config, user: &str, path: &str) -> Option<(Vec<u8>, bool)> {
    let argv = [config.runuser.display().to_string(), "-u".into(), user.to_string(), "--".into(), config.tail.display().to_string(),
                "-c".into(), WINDOW.to_string(), "--".into(), path.to_string()];
    let out = command::run(&argv, READ_TIMEOUT, WINDOW as usize + (64 << 10)).ok()?;
    (out.code == 0).then(|| (out.stdout.clone(), out.stdout.len() as u64 >= WINDOW))
}

/// `tenant.php_errors {domain}`: the site's PHP errors grouped by message, from its OLS vhost error log and the
/// `error_log` in its document root.
pub fn tenant_php_errors(config: &Config, user: &str, args: Value) -> Reply {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let a: DomainArgs = cache::parse(args)?;
    let row = own_row(config, user, &a.domain)?;
    let vhost = own_vhost(config, user, &row)?;
    let since = epoch(config, user, &a.domain)?.max(epoch(config, user, &vhost)?);
    let mut sources: Vec<(&'static str, String, bool)> = Vec::new();
    let vhost_log = config.error_logs.join(format!("{vhost}-error.log"));
    if !stale(config, user, &vhost_log) {
        if let Some((bytes, cut)) = tail(&vhost_log, WINDOW)? {
            let text = String::from_utf8_lossy(&bytes);
            let (lines, _) = last_lines(&text, cut, MAX_SCAN_LINES);
            let kept = since_lines(lines, since);
            let joined = if kept.is_empty() { String::new() } else { kept.join("\n") + "\n" };
            sources.push(("vhost_error_log", joined, false));
        }
    }
    let docroot = row["docroot"].as_str().unwrap_or("");
    if let Some((bytes, cut)) = read_as_user(config, user, &format!("{}/error_log", docroot.trim_end_matches('/'))) {
        sources.push(("docroot_error_log", String::from_utf8_lossy(&bytes).into_owned(), cut));
    }
    let mut report = group_errors(&sources);
    report["user"] = json!(user);
    report["domain"] = json!(a.domain);
    report["observed_at"] = json!(now());
    report["sources"] = json!(sources.iter().map(|s| s.0).collect::<Vec<_>>());
    Ok(report)
}

/// The vhost address cPanel lists for the domain (`ip:443`), as curl wants it in `--resolve`.
fn address(config: &Config, domain: &str) -> Option<String> {
    let text = fs::read_to_string(&config.userdatadomains).ok()?;
    let line = text.lines().find(|l| l.split_once(": ").map_or(false, |(d, _)| d == domain))?;
    let fields: Vec<&str> = line.split_once(": ")?.1.split("==").collect();
    let ip = fields.get(6)?.rsplit_once(':')?.0;
    let v4 = ip.split('.').count() == 4 && ip.split('.').all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()));
    let v6 = ip.contains(':') && ip.len() <= 45 && ip.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    (v4 || v6).then(|| if v6 { format!("[{ip}]") } else { ip.to_string() })
}

/// "/<folder>/" for at most two folders directly under the domain's document root that hold a wp-config.php, found
/// as the account (`runuser -u <user> -- find`, which follows no link), sorted. Nothing when the search fails.
fn wordpress_folders(config: &Config, user: &str, row: &Value) -> Vec<String> {
    let Some(docroot) = row["docroot"].as_str() else { return Vec::new() };
    let argv = [config.runuser.display().to_string(), "-u".into(), user.to_string(), "--".into(), config.find.display().to_string(),
        docroot.to_string(), "-mindepth".into(), "2".into(), "-maxdepth".into(), "2".into(), "-name".into(), "wp-config.php".into(),
        "-type".into(), "f".into()];
    let Ok(out) = command::run(&argv, CHECK_TIMEOUT, 64 << 10) else { return Vec::new() };
    let prefix = format!("{}/", docroot.trim_end_matches('/'));
    let mut found: Vec<String> = String::from_utf8_lossy(&out.stdout).lines()
        .filter_map(|l| l.strip_prefix(&prefix)?.strip_suffix("/wp-config.php").map(str::to_string))
        .filter(|d| !d.is_empty() && d.len() <= 64 && d.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) && !d.starts_with('.'))
        .map(|d| format!("/{d}/")).collect();
    found.sort();
    found.truncate(2);
    found
}

struct Fetch {
    status: u16,
    time_ms: u64,
    verify: i64,
    http_version: String,
    headers: Vec<(String, String)>,
}

impl Fetch {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

fn fetch(config: &Config, domain: &str, ip: &str, path: &str) -> Result<Fetch, Fail> {
    let argv: Vec<String> = vec![config.curl.display().to_string(), "-sS".into(), "-o".into(), "/dev/null".into(), "-D".into(), "-".into(),
        "--max-time".into(), "8".into(), "--connect-timeout".into(), "3".into(), "--resolve".into(), format!("{domain}:443:{ip}"),
        "-H".into(), "Accept-Encoding: gzip, br".into(), "-H".into(), "User-Agent: ols-cpanel-check".into(), "-w".into(),
        "\n@@%{http_code} %{time_total} %{ssl_verify_result} %{http_version}\n".into(), format!("https://{domain}{path}")];
    let out = command::run(&argv, CHECK_TIMEOUT, 256 << 10).map_err(|_| ("TIMEOUT", "the check did not finish in time".to_string()))?;
    if out.code != 0 {
        let why = match out.code {
            6 | 7 => "the server did not answer on the domain's address",
            28 => "the site did not answer within 8 seconds",
            35 | 51 | 58 | 60 | 77 => "the TLS handshake or certificate check failed",
            _ => "the request failed",
        };
        return Err(("UNREACHABLE", why.to_string()));
    }
    parse_fetch(&String::from_utf8_lossy(&out.stdout))
}

fn parse_fetch(text: &str) -> Result<Fetch, Fail> {
    let bad = || ("COMMAND_FAILED", "unexpected answer of the check".to_string());
    let (head, tail) = text.rsplit_once("@@").ok_or_else(bad)?;
    let f: Vec<&str> = tail.split_whitespace().collect();
    if f.len() != 4 {
        return Err(bad());
    }
    let block = head.trim_end().rsplit("\r\n\r\n").next().unwrap_or("");
    let headers = block.lines().skip(1).filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), redact::clean(v.trim()))).collect();
    Ok(Fetch {
        status: f[0].parse().map_err(|_| bad())?,
        time_ms: (f[1].parse::<f64>().map_err(|_| bad())? * 1000.0) as u64,
        verify: f[2].parse().map_err(|_| bad())?,
        http_version: f[3].chars().take(8).collect(),
        headers,
    })
}

/// `tenant.perf {domain}`: compression, cache headers and LSCache, HTTP/3 and TLS for one of the caller's domains.
pub fn tenant_perf(config: &Config, limiter: &cache::TenantPurges, user: &str, args: Value) -> Reply {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let a: DomainArgs = cache::parse(args)?;
    let row = own_row(config, user, &a.domain)?;
    let ip = address(config, &a.domain).ok_or(("REFUSED", "cPanel lists no usable address for this domain".to_string()))?;
    if let Err(wait) = limiter.admit(user) {
        return Err(("RATE_LIMITED", format!("a performance check is allowed every {} s; try again in {wait} s", limiter.interval_secs())));
    }
    // The configured access log format (CpanelSurface::ACCESS_FORMAT) has no request time field.
    let slow = json!({"available": false, "reason": "The access log format does not record how long a request took, so slow URLs cannot be listed."});
    let first = match fetch(config, &a.domain, &ip, "/") {
        Ok(f) => f,
        Err(("UNREACHABLE", why)) => {
            return Ok(json!({"user": user, "domain": a.domain, "observed_at": now(), "reachable": false, "error": why, "slow_urls": slow}));
        }
        Err(e) => return Err(e),
    };
    let second = fetch(config, &a.domain, &ip, "/")?;
    let html = first.header("content-type").map_or(false, |t| t.to_ascii_lowercase().starts_with("text/html"));
    let encoding = first.header("content-encoding").map(str::to_ascii_lowercase);
    let compression = match (&encoding, html) {
        (Some(e), _) if ["gzip", "br", "zstd", "deflate"].contains(&e.as_str()) => "on",
        (_, false) => "not_html",
        _ => "off",
    };
    let lscache = |f: &Fetch| f.header("x-litespeed-cache").map(str::to_ascii_lowercase);
    let cache_state = match (lscache(&second), lscache(&first)) {
        (Some(s), _) if s.contains("hit") => "hit",
        (Some(_), _) | (_, Some(_)) => "miss",
        _ => "none",
    };
    let alt = second.header("alt-svc").or(first.header("alt-svc"));
    // A front page without LSCache is often not the site itself (WordPress in a subfolder such as /wp/): check up to
    // two WordPress folders directly under the document root, found as the account, so the owner sees where the
    // page cache works (lab 2026-10-28: the check said "no page cache" while /wp/ was served from the cache).
    let mut subsites = Vec::new();
    if cache_state == "none" {
        for path in wordpress_folders(config, user, &row) {
            let state = match (fetch(config, &a.domain, &ip, &path), fetch(config, &a.domain, &ip, &path)) {
                (Ok(f1), Ok(f2)) => match (lscache(&f2), lscache(&f1)) {
                    (Some(s), _) if s.contains("hit") => "hit",
                    (Some(_), _) | (_, Some(_)) => "miss",
                    _ => "none",
                },
                _ => "unreachable",
            };
            subsites.push(json!({"path": path, "state": state}));
        }
    }
    Ok(json!({
        "user": user, "domain": a.domain, "observed_at": now(), "reachable": true,
        "status": first.status, "http_version": first.http_version, "server": first.header("server"),
        "time_first_ms": first.time_ms, "time_second_ms": second.time_ms,
        "tls": {"verified": first.verify == 0, "verify_code": first.verify},
        "compression": {"state": compression, "encoding": encoding, "html": html},
        "cache": {"state": cache_state, "litespeed": lscache(&second), "cache_control": second.header("cache-control"),
                  "expires": second.header("expires"), "etag": second.header("etag").is_some(),
                  "last_modified": second.header("last-modified")},
        "http3": {"advertised": alt.map_or(false, |v| v.contains("h3")), "alt_svc": alt},
        "cache_subsites": subsites,
        "slow_urls": slow,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::summary::tests::{fixture, Fixture};
    use std::os::unix::fs::PermissionsExt;

    fn code(r: Reply) -> &'static str {
        r.err().map(|e| e.0).unwrap_or("ok")
    }

    fn script(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A tree with log directories; the fake `runuser -u USER -- CMD...` runs CMD as the test user.
    fn setup() -> Fixture {
        let mut f = fixture();
        let root = f.temp.path().to_path_buf();
        f.config.domlogs = root.join("domlogs");
        f.config.error_logs = root.join("vhostlogs");
        for d in [&f.config.domlogs, &f.config.error_logs] {
            fs::create_dir_all(d).unwrap();
        }
        f.config.runuser = root.join("fake-runuser");
        script(&f.config.runuser, "[ \"$1\" = -u ] && [ \"$3\" = -- ] || exit 9\nshift 3\nexec \"$@\"");
        f.config.tail = "/usr/bin/tail".into();
        // The ownership epoch file as the first reconcile pass writes it: every current domain, since 0.
        let (rows, _) = super::super::domain_rows(&f.config.userdatadomains);
        let owners: serde_json::Map<String, Value> = rows.iter()
            .map(|r| (r["domain"].as_str().unwrap().to_string(), json!({"owner": r["user"], "since": 0}))).collect();
        write(&f.config.state.join(OWNERS_FILE), &Value::Object(owners).to_string());
        f
    }

    fn owners(c: &Config, entries: &[(&str, &str, u64)]) {
        let map: serde_json::Map<String, Value> = entries.iter().map(|(d, u, s)| (d.to_string(), json!({"owner": u, "since": s}))).collect();
        write(&c.state.join(OWNERS_FILE), &Value::Object(map).to_string());
    }

    fn write(path: &Path, text: &str) {
        fs::write(path, text).unwrap();
    }

    #[test]
    fn logs_are_the_callers_own_bounded_and_redacted() {
        let f = setup();
        let c = &f.config;
        let access: String = (1..=600).map(|i| format!("a.test:443 1.2.3.4 - - [t] \"GET /p{i}?password=s3cret{i}&n={i} HTTP/2.0\" 200 5\n")).collect();
        write(&c.domlogs.join("a.test-ssl_log"), &access);
        write(&c.domlogs.join("b.test-ssl_log"), "b.test:443 9.9.9.9 \"GET /private-b\" 200 5\n");
        write(&c.error_logs.join("a.test-error.log"), "2026-10-28 10:00:00.1 [NOTICE] Authorization: Bearer abcdefghijklmnopqrs\n2026-10-28 10:00:01.1 [ERROR] x\n");
        let view = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "lines": 5})).unwrap();
        let lines = view["lines"].as_array().unwrap();
        assert_eq!(lines.len(), 5);
        assert!(lines[4].as_str().unwrap().contains("/p600?password=[redacted]&n=600"), "{}", lines[4]);
        assert!(!view.to_string().contains("s3cret") && !view.to_string().contains("private-b"));
        // Defaults and the upper bound.
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"})).unwrap()["lines"].as_array().unwrap().len(), 200);
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "lines": 500})).unwrap()["count"], json!(500));
        for bad in [json!({"domain": "a.test", "kind": "access", "lines": 501}), json!({"domain": "a.test", "kind": "access", "lines": 0}),
                    json!({"domain": "a.test", "kind": "x"}), json!({"domain": "a.test", "kind": "access", "search": "x".repeat(101)}),
                    json!({"domain": "a.test", "kind": "access", "search": "a\nb"}), json!({"domain": "a.test", "kind": "access", "user": "olscpb"}),
                    json!({"kind": "access"}), json!({"domain": "../b.test", "kind": "access"}), json!({"domain": "a.test/../b.test", "kind": "access"})] {
            assert_eq!(code(tenant_logs(c, "olscpa", bad.clone())), "BAD_ARGS", "{bad}");
        }
        // The error log is redacted too.
        let err = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "error"})).unwrap();
        assert!(err["lines"][0].as_str().unwrap().ends_with("[redacted]") && !err.to_string().contains("abcdefghijklmnopqrs"));
        // Missing file: an empty answer, not an error.
        let none = tenant_logs(c, "olscpa", json!({"domain": "shop.a.test", "kind": "access_http"})).unwrap();
        assert_eq!((none["exists"].clone(), none["count"].clone()), (json!(false), json!(0)));
    }

    #[test]
    fn logs_refuse_other_accounts_domains_and_forged_identities() {
        let f = setup();
        let c = &f.config;
        write(&c.domlogs.join("b.test-ssl_log"), "b.test:443 1.1.1.1 \"GET /x\" 200 5\n");
        write(&c.error_logs.join("b.test-error.log"), "2026 b secret line\n");
        for kind in ["access", "access_http", "error"] {
            assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "b.test", "kind": kind}))), "NOT_FOUND", "{kind}");
            assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "ghost.test", "kind": kind}))), "NOT_FOUND");
            assert!(tenant_logs(c, "olscpb", json!({"domain": "b.test", "kind": kind})).is_ok());
        }
        assert_eq!(code(tenant_php_errors(c, "olscpa", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert_eq!(code(tenant_perf(c, &cache::TenantPurges::new(Duration::ZERO), "olscpa", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert_eq!(code(tenant_logs(c, "", json!({"domain": "a.test", "kind": "access"}))), "FORBIDDEN");
        assert_eq!(code(tenant_logs(c, "Bad Name", json!({"domain": "a.test", "kind": "access"}))), "FORBIDDEN");
        // An addon domain is served by its parent's vhost, which the caller owns.
        write(&c.error_logs.join("addon.a.test-error.log"), "x\n");
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "addon.test", "kind": "error"})).unwrap()["file"], json!("addon.a.test-error.log"));
        // A parent that is another account's vhost is refused.
        fs::write(&c.userdatadomains, "evil.test: olscpa==root==addon==b.test==/home/olscpa/e==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
            b.test: olscpb==root==main==b.test==/home/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n").unwrap();
        assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "evil.test", "kind": "error"}))), "NOT_FOUND");
    }

    #[test]
    fn links_are_never_followed_and_search_is_over_redacted_text() {
        let f = setup();
        let c = &f.config;
        let secret = f.temp.path().join("secret");
        write(&secret, "SECRETDATA\n");
        std::os::unix::fs::symlink(&secret, c.domlogs.join("a.test-ssl_log")).unwrap();
        assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"}))), "UNREADABLE");
        fs::remove_file(c.domlogs.join("a.test-ssl_log")).unwrap();
        fs::create_dir(c.domlogs.join("a.test-ssl_log")).unwrap();
        assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"}))), "UNREADABLE");
        fs::remove_dir(c.domlogs.join("a.test-ssl_log")).unwrap();
        write(&c.domlogs.join("a.test-ssl_log"), "GET /a?token=hidden123 200\nGET /b 404\nGET /c?x=1 200\n");
        // Fixed-string search; the hidden value cannot be found.
        let hit = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "search": " 404"})).unwrap();
        assert_eq!(hit["lines"], json!(["GET /b 404"]));
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "search": "hidden123"})).unwrap()["count"], json!(0));
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "search": "?x=1"})).unwrap()["count"], json!(1));
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "search": ".*"})).unwrap()["count"], json!(0));
    }

    #[test]
    fn window_and_download_are_bounded() {
        let f = setup();
        let c = &f.config;
        let line = format!("{}\n", "x".repeat(99));
        write(&c.domlogs.join("a.test-ssl_log"), &line.repeat(50_000));
        let view = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "search": "x"})).unwrap();
        assert_eq!(view["window_truncated"], json!(true));
        let dl = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access", "download": true})).unwrap();
        let bytes = dl["bytes"].as_u64().unwrap();
        assert!(bytes <= DOWNLOAD && bytes > DOWNLOAD - 200 && dl["text"].as_str().unwrap().len() as u64 == bytes, "{bytes}");
        assert!(dl["lines"].as_array().unwrap().is_empty());
        // A line over the limit is cut.
        write(&c.domlogs.join("a.test"), &format!("{}\n", "y".repeat(10_000)));
        let long = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access_http"})).unwrap();
        assert_eq!(long["lines"][0].as_str().unwrap().len(), redact::MAX_LINE);
    }

    #[test]
    fn php_errors_are_grouped_by_message() {
        let f = setup();
        let c = &f.config;
        write(&c.error_logs.join("a.test-error.log"),
            "2026-10-28 10:00:00.100 [STDERR] PHP Warning:  Undefined variable $x in /home/olscpa/public_html/a.php on line 5\n\
             2026-10-28 10:00:01.100 [NOTICE] unrelated\n\
             2026-10-28 10:05:00.100 [STDERR] PHP Warning:  Undefined variable $x in /home/olscpa/public_html/a.php on line 5\n\
             2026-10-28 10:06:00.100 [STDERR] PHP Fatal error:  Uncaught Error: x in /home/olscpa/public_html/b.php:9 password=hunter2\n");
        let docroot = f.temp.path().join("public_html");
        fs::create_dir_all(&docroot).unwrap();
        fs::write(&c.userdatadomains, format!("a.test: olscpa==root==main==a.test=={}==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n", docroot.display())).unwrap();
        write(&docroot.join("error_log"),
            "[28-Oct-2026 11:00:00 UTC] PHP Warning:  Undefined variable $x in /home/olscpa/public_html/a.php on line 5\n\
             [28-Oct-2026 11:00:01 UTC] PHP Stack trace:\n[28-Oct-2026 11:00:01 UTC] PHP   1. {main}() /a.php:0\n\
             [28-Oct-2026 11:30:00 UTC] PHP Deprecated:  Function x() is deprecated in /h/c.php on line 123456789\n");
        let r = tenant_php_errors(c, "olscpa", json!({"domain": "a.test"})).unwrap();
        assert_eq!(r["sources"], json!(["vhost_error_log", "docroot_error_log"]));
        assert_eq!((r["php_lines"].clone(), r["groups_total"].clone()), (json!(5), json!(3)));
        let g = &r["groups"][0];
        assert_eq!((g["count"].clone(), g["level"].clone()), (json!(3), json!("Warning")));
        assert_eq!((g["first_seen"].clone(), g["last_seen"].clone()), (json!("2026-10-28 10:00:00"), json!("28-Oct-2026 11:00:00 UTC")));
        assert_eq!(g["sources"], json!(["vhost_error_log", "docroot_error_log"]));
        assert!(!r.to_string().contains("hunter2") && r.to_string().contains("password=[redacted]"));
        assert_eq!(code(tenant_php_errors(c, "olscpa", json!({"domain": "a.test", "x": 1}))), "BAD_ARGS");
        // A docroot error_log that is a link to a file the account cannot read gives nothing (here: a missing target).
        fs::remove_file(docroot.join("error_log")).unwrap();
        std::os::unix::fs::symlink(f.temp.path().join("missing"), docroot.join("error_log")).unwrap();
        let none = tenant_php_errors(c, "olscpa", json!({"domain": "a.test"})).unwrap();
        assert_eq!(none["sources"], json!(["vhost_error_log"]));
    }

    // 2026-10-28 04:16:04 UTC
    const T0: u64 = 1_793_160_964;

    #[test]
    fn line_times_of_the_three_formats() {
        assert_eq!(line_time("a.test:443 1.2.3.4 - - [28/Oct/2026:04:16:04 +0000] \"GET / HTTP/2.0\" 200 5"), Some(T0));
        assert_eq!(line_time("1.2.3.4 - - [28/Oct/2026:06:16:04 +0200] \"GET /?x=[1] HTTP/2.0\" 200 5"), Some(T0));
        assert_eq!(line_time("[28-Oct-2026 04:16:04 UTC] PHP Warning:  x"), Some(T0));
        let ols = line_time("2026-10-28 04:30:39.432908 [NOTICE] x").unwrap();
        // Local time: within one day of the UTC reading whatever the zone of the test host.
        assert!(ols.abs_diff(T0 + 14 * 60 + 35) <= 86400);
        assert_eq!(line_time("    continuation of a trace"), None);
        assert_eq!(line_time("[t] \"GET /\""), None);
        assert_eq!(line_time("[99/Foo/2026:04:16:04 +0000]"), None);
    }

    #[test]
    fn since_lines_filters_by_the_lines_own_time() {
        let lines = vec!["orphan before any time", "1.1.1.1 [28/Oct/2026:04:00:00 +0000] \"GET /old\"", "  old continuation",
                         "1.1.1.1 [28/Oct/2026:04:16:04 +0000] \"GET /edge\"", "  new continuation",
                         "1.1.1.1 [28/Oct/2026:05:00:00 +0000] \"GET /new\""];
        assert_eq!(since_lines(lines.clone(), 0), lines);
        assert_eq!(since_lines(lines.clone(), T0), vec![lines[3], lines[4], lines[5]]);
        assert_eq!(since_lines(lines.clone(), T0 + 1), vec![lines[5]]);
        let ols = vec!["2020-01-01 00:00:00.1 [ERROR] old", "trace of old", "2037-01-01 00:00:00.1 [ERROR] new", "trace of new"];
        assert_eq!(since_lines(ols.clone(), T0), vec![ols[2], ols[3]]);
    }

    #[test]
    fn a_moved_domain_shows_only_the_new_owners_period() {
        let f = setup();
        let c = &f.config;
        write(&c.domlogs.join("a.test-ssl_log"), "a.test:443 1.1.1.1 - - [28/Oct/2026:04:00:00 +0000] \"GET /secret-of-previous-owner\" 200 5\n\
            a.test:443 1.1.1.1 - - [28/Oct/2026:05:00:00 +0000] \"GET /mine\" 200 5\n");
        write(&c.error_logs.join("a.test-error.log"), "[28-Oct-2026 04:00:00 UTC] PHP Warning:  old problem in /home/other/a.php on line 1\n\
            [28-Oct-2026 05:00:00 UTC] PHP Warning:  new problem in /home/olscpa/a.php on line 2\n");
        owners(c, &[("a.test", "olscpa", T0), ("b.test", "olscpb", 0)]);
        let view = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"})).unwrap();
        assert_eq!(view["count"], json!(1));
        assert!(view["lines"][0].as_str().unwrap().contains("/mine") && !view.to_string().contains("secret-of-previous-owner"));
        let err = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "error", "download": true})).unwrap();
        assert!(!err["text"].as_str().unwrap().contains("old problem") && err["text"].as_str().unwrap().contains("new problem"));
        let groups = tenant_php_errors(c, "olscpa", json!({"domain": "a.test"})).unwrap();
        assert_eq!((groups["php_lines"].clone(), groups["groups"][0]["message"].as_str().unwrap().starts_with("new problem")), (json!(1), true));
        // since 0 keeps everything.
        owners(c, &[("a.test", "olscpa", 0)]);
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"})).unwrap()["count"], json!(2));
        // The epoch of the vhost counts for a domain served by it (an addon domain of a moved parent).
        owners(c, &[("addon.test", "olscpa", 0), ("addon.a.test", "olscpa", T0 + 1000)]);
        write(&c.error_logs.join("addon.a.test-error.log"), "2020-01-01 00:00:00.1 [ERROR] ancient\n");
        assert_eq!(tenant_logs(c, "olscpa", json!({"domain": "addon.test", "kind": "error"})).unwrap()["count"], json!(0));
    }

    #[test]
    fn logs_of_a_domain_not_owned_in_the_epoch_file_are_refused() {
        let f = setup();
        let c = &f.config;
        write(&c.domlogs.join("a.test-ssl_log"), "x\n");
        // Owner differs (the table says olscpa, the epoch file already has the new owner), or the domain or the file is missing.
        owners(c, &[("a.test", "olscpb", 0)]);
        for kind in ["access", "access_http", "error"] {
            assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": kind}))), "NOT_FOUND", "{kind}");
        }
        assert_eq!(code(tenant_php_errors(c, "olscpa", json!({"domain": "a.test"}))), "NOT_FOUND");
        owners(c, &[("b.test", "olscpb", 0)]);
        assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"}))), "NOT_FOUND");
        fs::remove_file(c.state.join(OWNERS_FILE)).unwrap();
        assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"}))), "NOT_FOUND");
        write(&c.state.join(OWNERS_FILE), "not json");
        assert_eq!(code(tenant_php_errors(c, "olscpa", json!({"domain": "a.test"}))), "NOT_FOUND");
        // A link in place of the file is not followed.
        fs::remove_file(c.state.join(OWNERS_FILE)).unwrap();
        owners(c, &[("a.test", "olscpa", 0)]);
        let real = c.state.join("real.json");
        fs::rename(c.state.join(OWNERS_FILE), &real).unwrap();
        std::os::unix::fs::symlink(&real, c.state.join(OWNERS_FILE)).unwrap();
        assert_eq!(code(tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "access"}))), "NOT_FOUND");
    }

    #[test]
    fn signatures_collapse_long_numbers_only() {
        assert_eq!(signature("Warning", "id 1234567 at line 12"), "Warning: id N at line 12");
        assert_eq!(php_message("x PHP Fatal error:  Boom in /a.php:3").unwrap().0, "Fatal error");
        assert!(php_message("PHP   1. {main}()").is_none() && php_message("PHP Stack trace:").is_none());
        assert_eq!(stamp("[28-Oct-2026 11:00:00 UTC] PHP x").unwrap(), "28-Oct-2026 11:00:00 UTC");
        assert!(stamp("no stamp").is_none());
    }

    const CURL: &str = r#"case "$*" in
*unreachable.test*) exit 7;;
esac
n=0; [ -f "$0.n" ] && n=$(cat "$0.n"); n=$((n+1)); echo $n > "$0.n"
printf 'HTTP/2 200 \r\ncontent-type: text/html; charset=UTF-8\r\ncontent-encoding: br\r\nalt-svc: h3=":443"; ma=86400\r\n'
if [ $n -ge 2 ]; then printf 'x-litespeed-cache: hit\r\ncache-control: public, max-age=3600\r\netag: "abc"\r\n'; else printf 'x-litespeed-cache: miss\r\n'; fi
printf '\r\n\n@@200 0.250 0 2\n'
echo "$*" > "$0.argv""#;

    #[test]
    fn performance_checks_run_against_the_own_address() {
        let mut f = setup();
        f.config.curl = f.temp.path().join("curl");
        script(&f.config.curl, CURL);
        let free = cache::TenantPurges::new(Duration::ZERO);
        let r = tenant_perf(&f.config, &free, "olscpa", json!({"domain": "a.test"})).unwrap();
        assert_eq!(r["compression"]["state"], json!("on"));
        assert_eq!((r["cache"]["state"].clone(), r["cache"]["cache_control"].clone()), (json!("hit"), json!("public, max-age=3600")));
        assert_eq!(r["http3"]["advertised"], json!(true));
        assert_eq!((r["tls"]["verified"].clone(), r["http_version"].clone(), r["time_first_ms"].clone()), (json!(true), json!("2"), json!(250)));
        assert_eq!(r["slow_urls"]["available"], json!(false));
        let argv = fs::read_to_string(format!("{}.argv", f.config.curl.display())).unwrap();
        assert!(argv.contains("--resolve a.test:443:1.2.3.4") && argv.contains("https://a.test/"), "{argv}");
        // Scope, bounds and refusals.
        assert_eq!(code(tenant_perf(&f.config, &free, "olscpa", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert_eq!(code(tenant_perf(&f.config, &free, "olscpa", json!({"domain": "a.test", "ip": "127.0.0.1"}))), "BAD_ARGS");
        assert_eq!(code(tenant_perf(&f.config, &free, "olscpa", json!({"domain": "a.test; id"}))), "BAD_ARGS");
        let limited = cache::TenantPurges::new(Duration::from_secs(60));
        assert!(tenant_perf(&f.config, &limited, "olscpa", json!({"domain": "a.test"})).is_ok());
        assert_eq!(code(tenant_perf(&f.config, &limited, "olscpa", json!({"domain": "a.test"}))), "RATE_LIMITED");
        // An unreachable site is a result, not an error; an unusable address is refused.
        fs::write(&f.config.userdatadomains, "unreachable.test: olscpa==root==main==unreachable.test==/home/olscpa/p==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
            bad.test: olscpa==root==main==bad.test==/home/olscpa/p==1.2.3.4:80==not-an-ip:443====0==ea-php83\n").unwrap();
        let down = tenant_perf(&f.config, &free, "olscpa", json!({"domain": "unreachable.test"})).unwrap();
        assert_eq!(down["reachable"], json!(false));
        assert_eq!(code(tenant_perf(&f.config, &free, "olscpa", json!({"domain": "bad.test"}))), "REFUSED");
        assert_eq!(r["cache_subsites"], json!([]), "a cached front page needs no folder search");
    }

    #[test]
    fn an_uncached_front_page_checks_the_wordpress_folders() {
        let mut f = setup();
        f.config.curl = f.temp.path().join("curl");
        // The front page has no LSCache header; /wp/ is served from the cache on the second request.
        script(&f.config.curl, r#"printf 'HTTP/2 200 \r\ncontent-type: text/html\r\n'
case "$*" in *https://a.test/wp/*) n=0; [ -f "$0.n" ] && n=$(cat "$0.n"); n=$((n+1)); echo $n > "$0.n"
  if [ $n -ge 2 ]; then printf 'x-litespeed-cache: hit\r\n'; else printf 'x-litespeed-cache: miss\r\n'; fi;; esac
printf '\r\n\n@@200 0.050 0 2\n'"#);
        // find runs as the account (fake runuser) and lists wp-config.php files two levels down only.
        let root = f.temp.path().join("site");
        for d in ["wp", "blog", ".hidden", "deep/x"] {
            fs::create_dir_all(root.join(d)).unwrap();
            fs::write(root.join(d).join("wp-config.php"), "<?php").unwrap();
        }
        fs::create_dir_all(root.join("plain")).unwrap();
        fs::write(&f.config.userdatadomains, format!("a.test: olscpa==root==main==a.test=={}==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n", root.display())).unwrap();
        f.config.find = "/usr/bin/find".into();
        let free = cache::TenantPurges::new(Duration::ZERO);
        let r = tenant_perf(&f.config, &free, "olscpa", json!({"domain": "a.test"})).unwrap();
        assert_eq!(r["cache"]["state"], json!("none"));
        assert_eq!(r["cache_subsites"], json!([{"path": "/blog/", "state": "none"}, {"path": "/wp/", "state": "hit"}]));
    }

    #[test]
    fn curl_output_parsing() {
        let f = parse_fetch("HTTP/1.1 301 Moved\r\nLocation: /x\r\nServer: OLS\r\n\r\nHTTP/2 200 \r\nContent-Type: text/html\r\n\r\n\n@@200 0.5 60 2\n").unwrap();
        assert_eq!((f.status, f.verify, f.header("content-type")), (200, 60, Some("text/html")));
        assert!(f.header("location").is_none());
        assert!(parse_fetch("garbage").is_err() && parse_fetch("x@@1 2 3").is_err());
    }

    #[test]
    fn a_window_of_only_newlines_is_bounded() {
        let f = setup();
        let c = &f.config;
        // 4 MiB of empty lines: millions of lines must not be materialized.
        write(&c.error_logs.join("a.test-error.log"), &"\n".repeat(WINDOW as usize));
        let view = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "error", "lines": 7})).unwrap();
        assert_eq!((view["count"].clone(), view["window_truncated"].clone()), (json!(7), json!(true)));
        let found = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "error", "search": "needle"})).unwrap();
        assert_eq!(found["count"], json!(0));
        let report = tenant_php_errors(c, "olscpa", json!({"domain": "a.test"})).unwrap();
        assert_eq!(report["scanned_lines"], json!(MAX_SCAN_LINES));
        assert_eq!(report["php_lines"], json!(0));
        let download = tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": "error", "download": true})).unwrap();
        assert!(download["count"].as_u64().unwrap() <= MAX_SCAN_DOWNLOAD as u64);
        // Helper: newest lines, dropped partial first line, trailing newline, carriage returns.
        assert_eq!(last_lines("a\nb\nc\n", false, 2), (vec!["b", "c"], true));
        assert_eq!(last_lines("x\nb\r\nc", true, 10), (vec!["b", "c"], false));
        assert_eq!(last_lines("", false, 5), (vec![], false));
        assert_eq!(last_lines("\n", false, 5), (vec![""], false));
    }

    #[test]
    fn a_log_older_than_the_account_is_not_served() {
        let f = setup();
        let c = &f.config;
        write(&c.domlogs.join("a.test-ssl_log"), "a.test:443 1.1.1.1 \"GET /old-owner\" 200 5\n");
        write(&c.error_logs.join("a.test-error.log"), "2026-10-28 10:00:00.1 [ERROR] PHP Warning:  old owner in /a.php on line 1\n");
        let ask = |kind: &str| tenant_logs(c, "olscpa", json!({"domain": "a.test", "kind": kind})).unwrap();
        assert_eq!(ask("access")["exists"], json!(true));
        fs::create_dir_all(&c.users_dir).unwrap();
        // The account was created after the log was last written.
        fs::write(c.users_dir.join("olscpa"), format!("STARTDATE={}\n", now() + 3600)).unwrap();
        for kind in ["access", "error"] {
            let view = ask(kind);
            assert_eq!((view["exists"].clone(), view["count"].clone()), (json!(false), json!(0)), "{kind}");
            assert!(!view.to_string().contains("old-owner"));
        }
        assert_eq!(tenant_php_errors(c, "olscpa", json!({"domain": "a.test"})).unwrap()["php_lines"], json!(0));
        // An account created before the log's last write sees it.
        fs::write(c.users_dir.join("olscpa"), "STARTDATE=1000\n").unwrap();
        assert_eq!(ask("access")["exists"], json!(true));
    }
}
