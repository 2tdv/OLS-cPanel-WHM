//! Requests to the administrator (FV-08, docs/product-interfaces.md "Account tools"): a short message from an account
//! with a subject from a fixed list, kept as one root-owned file per request in `/var/lib/ols-cpanel/requests` (0700
//! directory, 0600 files, created without following links) and listed in the WHM view with its status (open or done).
//!
//! Tenant operations (`tenant.request`, `tenant.requests`) take the account from SO_PEERCRED and never a request
//! field: a tenant creates requests as itself and lists only its own. Creation is rate-limited per account and the
//! queue and the number of open requests per account are bounded. The text is stored as given (it is rendered as plain
//! text by the interfaces). Admin operations (`admin.requests`, `admin.request_status`) are on the root-only socket.
//!
//! Account identity. A record carries the identity of the account that wrote it (cPanel's STARTDATE of the account,
//! else the uid and inode of its home) and a tenant sees, counts and is limited by only the records whose identity is
//! its current one, so an account re-created under a removed account's name never reads the old messages. The
//! reconciler moves the requests of removed accounts to an administrator-only archive (src/ObjectCache/AccountRemoval).
//!
//! Retention. Requests marked done are kept for KEEP_DONE (the newest) and DONE_DAYS at most; they are removed before
//! the queue bound is applied, so finished work never fills the queue for good. Admission (check, prune, write) is
//! serialized with a lock file.

use super::{audit, cache, now, random_hex, read_bounded, Config, Reply};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::Duration;

/// The fixed subjects a request can have.
pub const SUBJECTS: [&str; 8] = ["cache", "php", "htaccess", "ssl", "performance", "logs", "domains", "other"];
pub const MAX_TEXT: usize = 1000;
pub const MAX_QUEUE: usize = 2000;
pub const MAX_OPEN_PER_ACCOUNT: usize = 10;
/// Requests marked done that are kept (the newest), and the longest time one is kept.
pub const KEEP_DONE: usize = 500;
pub const DONE_DAYS: u64 = 90;
const MAX_FILE: u64 = 8192;
pub const LIST_LIMIT: usize = 200;
/// One request per account in this time.
pub const INTERVAL: Duration = Duration::from_secs(60);

type Fail = (&'static str, String);

/// `r<unix seconds, 10 digits>-<8 hex>`.
pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 20 && b[0] == b'r' && b[1..11].iter().all(u8::is_ascii_digit) && b[11] == b'-'
        && b[12..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// Every well-formed request, newest first.
fn load(config: &Config) -> Vec<Value> {
    let Ok(dir) = fs::read_dir(&config.requests) else { return vec![] };
    let mut names: Vec<String> = dir.filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").map(str::to_string)).filter(|n| valid_id(n)).collect();
    names.sort();
    names.reverse();
    names.truncate(MAX_QUEUE);
    names.iter().filter_map(|n| read_bounded(&config.requests.join(format!("{n}.json")), MAX_FILE))
        .filter_map(|b| serde_json::from_slice::<Value>(&b).ok())
        .filter(|v| v["id"].is_string() && v["user"].is_string() && SUBJECTS.contains(&v["subject"].as_str().unwrap_or("")))
        .collect()
}

/// cPanel's STARTDATE of the account (when it was created), from `<users_dir>/<user>`.
pub fn start_date(config: &Config, user: &str) -> Option<u64> {
    if !cache::account_ok(user) {
        return None;
    }
    let bytes = read_bounded(&config.users_dir.join(user), 1 << 16)?;
    String::from_utf8_lossy(&bytes).lines().find_map(|l| l.strip_prefix("STARTDATE=")).and_then(|v| v.trim().parse::<u64>().ok())
}

/// What distinguishes this account from an earlier one of the same name: STARTDATE, else the uid and inode of its home
/// (the part of a document root up to the user's own directory). None when neither can be determined.
pub fn account_identity(config: &Config, user: &str) -> Option<String> {
    if let Some(start) = start_date(config, user) {
        return Some(format!("start:{start}"));
    }
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    let docroot = rows.iter().find(|r| r["user"] == json!(user)).and_then(|r| r["docroot"].as_str().map(String::from))?;
    let parts: Vec<&str> = docroot.split('/').collect();
    let at = parts.iter().position(|p| *p == user)?;
    let meta = fs::symlink_metadata(parts[..=at].join("/")).ok().filter(|m| m.is_dir())?;
    Some(format!("home:{}:{}", meta.uid(), meta.ino()))
}

/// Whether a record belongs to the account as it exists now.
fn is_mine(v: &Value, user: &str, identity: &Option<String>) -> bool {
    v["user"] == json!(user) && v["identity"] == json!(identity)
}

/// Serializes admission and status changes; released when the returned file is dropped.
fn lock(config: &Config) -> Result<fs::File, Fail> {
    let dir = &config.requests;
    fs::create_dir_all(dir).map_err(|e| ("INTERNAL", e.to_string()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| ("INTERNAL", e.to_string()))?;
    let file = fs::OpenOptions::new().create(true).read(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(".lock")).map_err(|e| ("INTERNAL", e.to_string()))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(("INTERNAL", "cannot lock the request queue".into()));
    }
    Ok(file)
}

/// Removes the oldest done requests beyond KEEP_DONE and those done more than DONE_DAYS ago; returns the records left.
fn prune_done(config: &Config, mut queue: Vec<Value>) -> Vec<Value> {
    let limit = now().saturating_sub(DONE_DAYS * 86400);
    let mut done = 0;
    queue.retain(|v| {
        // `queue` is newest first, so the first KEEP_DONE done records are the ones kept.
        if v["status"] != json!("done") {
            return true;
        }
        done += 1;
        let old = v["done_at"].as_u64().map_or(false, |t| t < limit);
        let keep = done <= KEEP_DONE && !old;
        if !keep {
            if let Some(id) = v["id"].as_str().filter(|i| valid_id(i)) {
                let _ = fs::remove_file(config.requests.join(format!("{id}.json")));
            }
        }
        keep
    });
    queue
}

fn publish(config: &Config, record: &Value) -> Result<(), Fail> {
    let id = record["id"].as_str().unwrap_or("");
    let dir = &config.requests;
    fs::create_dir_all(dir).map_err(|e| ("INTERNAL", e.to_string()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| ("INTERNAL", e.to_string()))?;
    let temp = dir.join(format!(".tmp-{id}"));
    let _ = fs::remove_file(&temp);
    let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(&temp).map_err(|e| ("INTERNAL", e.to_string()))?;
    file.write_all(record.to_string().as_bytes()).and_then(|_| file.sync_all()).map_err(|e| ("INTERNAL", e.to_string()))?;
    fs::rename(&temp, dir.join(format!("{id}.json"))).map_err(|e| ("INTERNAL", e.to_string()))
}

fn public(v: &Value) -> Value {
    json!({"id": v["id"], "user": v["user"], "subject": v["subject"], "text": v["text"], "created_at": v["created_at"],
           "status": v["status"], "done_at": v["done_at"]})
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CreateArgs {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: String,
}

/// `tenant.request {subject, text}`.
pub fn tenant_create(config: &Config, limiter: &cache::TenantPurges, user: &str, args: Value) -> Reply {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let a: CreateArgs = cache::parse(args)?;
    if !SUBJECTS.contains(&a.subject.as_str()) {
        return Err(("BAD_ARGS", format!("subject must be one of {}", SUBJECTS.join(", "))));
    }
    let length = a.text.chars().count();
    if a.text.trim().is_empty() || length > MAX_TEXT || a.text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(("BAD_ARGS", format!("text must be 1 to {MAX_TEXT} characters of plain text")));
    }
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    if !rows.iter().any(|r| r["user"] == json!(user)) {
        return Err(("NOT_FOUND", "this account has no domains".into()));
    }
    let identity = account_identity(config, user);
    let _guard = lock(config)?;
    let queue = load(config);
    let queue = if queue.len() >= MAX_QUEUE || queue.iter().any(|v| v["status"] == json!("done")) { prune_done(config, queue) } else { queue };
    if queue.len() >= MAX_QUEUE {
        return Err(("BUSY", "the request queue is full; try again later".into()));
    }
    if queue.iter().filter(|v| is_mine(v, user, &identity) && v["status"] == json!("open")).count() >= MAX_OPEN_PER_ACCOUNT {
        return Err(("RATE_LIMITED", format!("at most {MAX_OPEN_PER_ACCOUNT} requests can be open at once")));
    }
    if let Err(wait) = limiter.admit(user) {
        return Err(("RATE_LIMITED", format!("a request can be sent every {} s; try again in {wait} s", limiter.interval_secs())));
    }
    let id = format!("r{:010}-{}", now(), random_hex(4));
    let record = json!({"id": id, "user": user, "identity": identity, "subject": a.subject, "text": a.text, "created_at": now(),
                        "status": "open", "done_at": null});
    publish(config, &record)?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "tenant_request", "user": user, "id": id, "subject": a.subject}));
    Ok(json!({"user": user, "request": public(&record)}))
}

/// `tenant.requests`: the caller's own requests, newest first.
pub fn tenant_list(config: &Config, user: &str) -> Reply {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let identity = account_identity(config, user);
    let mine: Vec<Value> = load(config).iter().filter(|v| is_mine(v, user, &identity)).take(50).map(public).collect();
    Ok(json!({"user": user, "observed_at": now(), "subjects": SUBJECTS, "max_text": MAX_TEXT, "requests": mine}))
}

/// `admin.requests`: every request, newest first (at most LIST_LIMIT), with the number still open.
pub fn admin_list(config: &Config) -> Reply {
    let all = load(config);
    let open = all.iter().filter(|v| v["status"] == json!("open")).count();
    let rows: Vec<Value> = all.iter().take(LIST_LIMIT).map(public).collect();
    Ok(json!({"observed_at": now(), "open": open, "total": all.len(), "requests": rows}))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    #[serde(default)]
    id: String,
    #[serde(default)]
    status: String,
}

/// `admin.request_status {id, status: "open"|"done"}`.
pub fn admin_status(config: &Config, args: Value) -> Reply {
    let a: StatusArgs = cache::parse(args)?;
    if !valid_id(&a.id) || !["open", "done"].contains(&a.status.as_str()) {
        return Err(("BAD_ARGS", "id must be a request id and status open or done".into()));
    }
    let _guard = lock(config)?;
    let bytes = read_bounded(&config.requests.join(format!("{}.json", a.id)), MAX_FILE).ok_or(("NOT_FOUND", "no such request".to_string()))?;
    let mut record: Value = serde_json::from_slice(&bytes).map_err(|_| ("NOT_FOUND", "no such request".to_string()))?;
    record["status"] = json!(a.status);
    record["done_at"] = if a.status == "done" { json!(now()) } else { Value::Null };
    publish(config, &record)?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "request_status", "id": a.id, "status": a.status}));
    Ok(json!({"request": public(&record)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::summary::tests::{fixture, Fixture};

    fn code(r: Reply) -> &'static str {
        r.err().map(|e| e.0).unwrap_or("ok")
    }

    fn setup() -> Fixture {
        let mut f = fixture();
        f.config.requests = f.temp.path().join("requests");
        f
    }

    #[test]
    fn create_list_and_complete() {
        let f = setup();
        let free = cache::TenantPurges::new(Duration::ZERO);
        let made = tenant_create(&f.config, &free, "olscpa", json!({"subject": "php", "text": "Please raise memory_limit\nthanks"})).unwrap();
        let id = made["request"]["id"].as_str().unwrap().to_string();
        assert!(valid_id(&id) && made["request"]["status"] == json!("open"));
        // Private storage.
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&f.config.requests).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(f.config.requests.join(format!("{id}.json"))).unwrap().mode() & 0o777, 0o600);
        tenant_create(&f.config, &free, "olscpb", json!({"subject": "other", "text": "b's request"})).unwrap();
        // A tenant sees only its own.
        let mine = tenant_list(&f.config, "olscpa").unwrap();
        assert_eq!(mine["requests"].as_array().unwrap().len(), 1);
        assert!(!mine.to_string().contains("b's request"));
        let all = admin_list(&f.config).unwrap();
        assert_eq!((all["total"].clone(), all["open"].clone()), (json!(2), json!(2)));
        let done = admin_status(&f.config, json!({"id": id, "status": "done"})).unwrap();
        assert_eq!(done["request"]["status"], json!("done"));
        assert!(done["request"]["done_at"].is_u64());
        assert_eq!(admin_list(&f.config).unwrap()["open"], json!(1));
        assert_eq!(tenant_list(&f.config, "olscpa").unwrap()["requests"][0]["status"], json!("done"));
        let reopened = admin_status(&f.config, json!({"id": id, "status": "open"})).unwrap();
        assert_eq!(reopened["request"]["done_at"], Value::Null);
        let log = fs::read_to_string(&f.config.audit_log).unwrap();
        assert!(log.contains("tenant_request") && log.contains("request_status"));
    }

    #[test]
    fn input_is_bounded_and_identity_is_never_a_field() {
        let f = setup();
        let free = cache::TenantPurges::new(Duration::ZERO);
        for bad in [json!({"subject": "money", "text": "x"}), json!({"subject": "php", "text": ""}), json!({"subject": "php", "text": "  \n "}),
                    json!({"subject": "php", "text": "x".repeat(1001)}), json!({"subject": "php", "text": "a\u{1b}b"}),
                    json!({"subject": "php", "text": "x", "user": "olscpb"}), json!({"text": "x"}), json!("x"), json!([])] {
            assert_eq!(code(tenant_create(&f.config, &free, "olscpa", bad.clone())), "BAD_ARGS", "{bad}");
        }
        assert!(tenant_create(&f.config, &free, "olscpa", json!({"subject": "php", "text": "é".repeat(1000)})).is_ok());
        assert_eq!(code(tenant_create(&f.config, &free, "", json!({"subject": "php", "text": "x"}))), "FORBIDDEN");
        assert_eq!(code(tenant_create(&f.config, &free, "ghost", json!({"subject": "php", "text": "x"}))), "NOT_FOUND");
        assert_eq!(code(tenant_list(&f.config, "")), "FORBIDDEN");
        assert!(tenant_list(&f.config, "ghost").unwrap()["requests"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rate_limit_and_open_cap() {
        let f = setup();
        let limited = cache::TenantPurges::new(Duration::from_secs(60));
        tenant_create(&f.config, &limited, "olscpa", json!({"subject": "php", "text": "one"})).unwrap();
        assert_eq!(code(tenant_create(&f.config, &limited, "olscpa", json!({"subject": "php", "text": "two"}))), "RATE_LIMITED");
        // Another account is not affected by it.
        assert!(tenant_create(&f.config, &limited, "olscpb", json!({"subject": "php", "text": "b"})).is_ok());
        let free = cache::TenantPurges::new(Duration::ZERO);
        for _ in 0..MAX_OPEN_PER_ACCOUNT - 1 {
            tenant_create(&f.config, &free, "olscpa", json!({"subject": "logs", "text": "more"})).unwrap();
        }
        assert_eq!(code(tenant_create(&f.config, &free, "olscpa", json!({"subject": "logs", "text": "too many"}))), "RATE_LIMITED");
    }

    #[test]
    fn admin_status_refuses_forged_ids_and_values() {
        let f = setup();
        let free = cache::TenantPurges::new(Duration::ZERO);
        tenant_create(&f.config, &free, "olscpa", json!({"subject": "php", "text": "x"})).unwrap();
        fs::write(f.temp.path().join("outside.json"), r#"{"id":"x"}"#).unwrap();
        for bad in [json!({"id": "../outside", "status": "done"}), json!({"id": "r0000000001-0000000g", "status": "done"}), json!({"id": "", "status": "done"}),
                    json!({"id": "r0000000001-00000000", "status": "gone"}), json!({"id": "r0000000001-00000000"}), json!({"id": "r0000000001-00000000", "status": "done", "x": 1})] {
            assert_eq!(code(admin_status(&f.config, bad.clone())), "BAD_ARGS", "{bad}");
        }
        assert_eq!(code(admin_status(&f.config, json!({"id": "r0000000001-00000000", "status": "done"}))), "NOT_FOUND");
        // Stray files and malformed records are ignored by the listing.
        fs::write(f.config.requests.join("junk.json"), "{}").unwrap();
        fs::write(f.config.requests.join("r0000000002-00000000.json"), "not json").unwrap();
        fs::write(f.config.requests.join("r0000000003-00000000.json"), r#"{"id":"r0000000003-00000000","user":"u","subject":"hack"}"#).unwrap();
        assert_eq!(admin_list(&f.config).unwrap()["total"], json!(1));
    }

    fn account_file(f: &Fixture, user: &str, start: u64) {
        fs::create_dir_all(&f.config.users_dir).unwrap();
        fs::write(f.config.users_dir.join(user), format!("DNS=a.test\nSTARTDATE={start}\nPLAN=gold\n")).unwrap();
    }

    #[test]
    fn a_recreated_account_does_not_see_the_old_requests() {
        let f = setup();
        let free = cache::TenantPurges::new(Duration::ZERO);
        account_file(&f, "olscpa", 1_700_000_000);
        for _ in 0..MAX_OPEN_PER_ACCOUNT {
            tenant_create(&f.config, &free, "olscpa", json!({"subject": "php", "text": "first owner's secret"})).unwrap();
        }
        assert_eq!(tenant_list(&f.config, "olscpa").unwrap()["requests"].as_array().unwrap().len(), MAX_OPEN_PER_ACCOUNT);
        // The account is removed and created again under the same name: a new STARTDATE.
        account_file(&f, "olscpa", 1_800_000_000);
        let fresh = tenant_list(&f.config, "olscpa").unwrap();
        assert!(fresh["requests"].as_array().unwrap().is_empty() && !fresh.to_string().contains("secret"));
        // The old open requests do not count against the new account, whose own are listed.
        tenant_create(&f.config, &free, "olscpa", json!({"subject": "php", "text": "second owner"})).unwrap();
        let fresh = tenant_list(&f.config, "olscpa").unwrap();
        assert_eq!(fresh["requests"].as_array().unwrap().len(), 1);
        assert!(!fresh.to_string().contains("first owner"));
        // The administrator still sees everything.
        assert_eq!(admin_list(&f.config).unwrap()["total"], json!(MAX_OPEN_PER_ACCOUNT + 1));
        // Another account never matches.
        assert!(tenant_list(&f.config, "olscpb").unwrap()["requests"].as_array().unwrap().is_empty());
    }

    #[test]
    fn done_requests_are_retained_boundedly_and_do_not_fill_the_queue() {
        let f = setup();
        fs::create_dir_all(&f.config.requests).unwrap();
        // A full queue of finished requests, the oldest long ago.
        for i in 0..MAX_QUEUE {
            let id = format!("r{:010}-{:08x}", 1_700_000_000 + i, i);
            let done_at = if i < 10 { 1_000_000_000 } else { now() };
            let record = json!({"id": id, "user": "olscpa", "identity": null, "subject": "php", "text": "x", "created_at": 1, "status": "done", "done_at": done_at});
            fs::write(f.config.requests.join(format!("{id}.json")), record.to_string()).unwrap();
        }
        let free = cache::TenantPurges::new(Duration::ZERO);
        tenant_create(&f.config, &free, "olscpa", json!({"subject": "php", "text": "new"})).unwrap();
        let all = load(&f.config);
        let done = all.iter().filter(|v| v["status"] == json!("done")).count();
        assert_eq!(done, KEEP_DONE);
        assert!(all.iter().any(|v| v["text"] == json!("new")) && all.len() == KEEP_DONE + 1);
        // Open requests are never removed by the retention.
        for _ in 0..3 {
            tenant_create(&f.config, &free, "olscpb", json!({"subject": "php", "text": "open"})).unwrap();
        }
        assert_eq!(load(&f.config).iter().filter(|v| v["status"] == json!("open")).count(), 4);
        assert!(f.config.requests.join(".lock").exists());
    }
}
