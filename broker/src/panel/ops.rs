//! Operations (FV-07, docs/product-interfaces.md "Operations"): the audit log view (`admin.audit`), the notification settings
//! and test (`admin.notify`, `admin.notify_set`, `admin.notify_test`), maintenance windows (`admin.schedule`,
//! `admin.schedule_add`, `admin.schedule_cancel`), the update channel view (`admin.update`) and the list of support bundles
//! (`admin.bundle`; a bundle itself is made by the job `ols.support_bundle`). Admin socket only.
//!
//! Everything that is more than a read of a file runs the product command with a fixed argv. The notification settings are the
//! one exception: they may carry a webhook URL with a secret in it, and an argument would show in the process list, so the broker
//! (root) validates and writes `notify.json` itself (0600, atomic) and only then asks the command for the view. The webhook URL is
//! never returned, never audited and never logged.

use super::{audit, now, product, read_bounded, Config, Page, Reply};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

/// How much of the audit log's end `admin.audit` reads: the newest records, bounded.
pub const AUDIT_TAIL: u64 = 4 << 20;
const DETAIL: usize = 200;
/// Commands that wait for a mail system, a webhook or a package manager.
const SLOW: Duration = Duration::from_secs(38);
/// The notification events (Operations\NotifySettings::EVENTS in the engine, which checks them again).
pub const NOTIFY_EVENTS: [&str; 8] = ["job", "held", "php_env", "upgrade", "cache_emergency", "disk", "objcache", "schedule"];
pub const MAX_EMAILS: usize = 5;
pub const MAX_URL: usize = 512;
const NOTIFY_FILE: &str = "notify.json";
/// A scheduled-job id: `s<UTC yyyymmddhhmmss>-<6 hex>`.
pub fn valid_schedule_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 22 && b[0] == b's' && b[1..15].iter().all(u8::is_ascii_digit) && b[15] == b'-'
        && b[16..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// `bundle-<10 digits>-<8 hex>.tar.gz`.
pub fn valid_bundle_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("bundle-").and_then(|r| r.strip_suffix(".tar.gz")) else { return false };
    let b = rest.as_bytes();
    b.len() == 19 && b[..10].iter().all(u8::is_ascii_digit) && b[10] == b'-' && b[11..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// The command's report (`{observed_at, source, exit_code, output}`) when it succeeded, else a refusal with its reason.
fn cli(config: &Config, args: &[&str], timeout: Duration) -> Reply {
    let reply = product::run_for(&config.cli, args, timeout)?;
    match reply["exit_code"].as_i64() {
        Some(0) => Ok(reply),
        code => {
            let reason: String = reply["output"]["error"].as_str().unwrap_or("the command failed").chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ').take(300).collect();
            Err((if code == Some(1) { "REFUSED" } else { "COMMAND_FAILED" }, reason))
        }
    }
}

fn printable(value: &str, max: usize) -> String {
    value.chars().take(max).map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

// --- Audit view ------------------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AuditArgs {
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    result: Option<String>,
}

/// The last `limit` bytes of a regular file (never through a link), starting at a line.
fn read_tail(path: &Path, limit: u64) -> Option<(String, bool)> {
    let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let cut = meta.len() > limit;
    if cut {
        file.seek(SeekFrom::Start(meta.len() - limit)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Some(if cut { (text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or_default(), true) } else { (text, false) })
}

fn text_of(record: &Value, key: &str, max: usize) -> Option<String> {
    match record.get(key)? {
        Value::String(s) => Some(printable(s, max)),
        Value::Null => None,
        other => Some(printable(&other.to_string(), max)),
    }
}

/// One audit record as the Activity view shows it: when, who, what, result.
fn normalize(record: &Value, principals: &Map<String, Value>) -> Option<Value> {
    let time = record.get("time")?.as_u64()?;
    let event = record.get("event").and_then(Value::as_str).map(|e| printable(e, 40)).unwrap_or_else(|| "capability".to_string());
    let job = text_of(record, "job", 20);
    let actor = text_of(record, "principal", 32).or_else(|| text_of(record, "user", 32))
        .or_else(|| job.as_ref().and_then(|j| principals.get(j)).and_then(|p| p.as_str()).map(str::to_string))
        .unwrap_or_else(|| "system".to_string());
    let failed = record.get("state").and_then(Value::as_str) == Some("failed") || event.ends_with("_error") || record.get("error").map_or(false, |e| !e.is_null());
    let mut detail = Vec::new();
    for key in ["reason", "exit_code", "args", "domain", "found", "restrictions_folded", "enforced", "error", "state"] {
        if let Some(v) = text_of(record, key, 120).filter(|v| v != "null" && !v.is_empty()) {
            detail.push(format!("{key}={v}"));
        }
    }
    Some(json!({"time": time, "event": event, "actor": actor, "action": text_of(record, "action", 40), "scope": text_of(record, "scope", 80), "job": job,
                "result": if failed { "failed" } else { "ok" }, "detail": printable(&detail.join(" "), DETAIL)}))
}

/// `admin.audit {query?, page?, size?, event?, result?}`: the newest audit records first, filtered and paged.
pub fn audit_view(config: &Config, args: Value) -> Reply {
    let a: AuditArgs = if args.is_null() { AuditArgs::default() } else { serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))? };
    if a.event.as_deref().map_or(false, |e| e.is_empty() || e.len() > 40 || !e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')) {
        return Err(("BAD_ARGS", "event must be lower-case letters and underscores".into()));
    }
    if a.result.as_deref().map_or(false, |r| r != "ok" && r != "failed") {
        return Err(("BAD_ARGS", "result must be ok or failed".into()));
    }
    let mut paging = Map::new();
    for (key, value) in [("query", a.query.map(Value::from)), ("page", a.page.map(Value::from)), ("size", a.size.map(Value::from))] {
        if let Some(v) = value {
            paging.insert(key.into(), v);
        }
    }
    let page = Page::parse(Value::Object(paging))?;
    let (text, truncated) = read_tail(&config.audit_log, AUDIT_TAIL).unwrap_or_default();
    let parsed: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(Value::is_object).collect();
    let mut principals = Map::new();
    for r in &parsed {
        if r["event"] == json!("job_start") {
            if let (Some(job), Some(p)) = (r["job"].as_str(), r["principal"].as_str()) {
                principals.insert(job.to_string(), json!(printable(p, 32)));
            }
        }
    }
    let mut events: Vec<String> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    for r in parsed.iter().rev().filter_map(|r| normalize(r, &principals)) {
        let name = r["event"].as_str().unwrap_or("").to_string();
        if !events.contains(&name) {
            events.push(name);
        }
        let hit = a.event.as_deref().map_or(true, |e| r["event"] == json!(e)) && a.result.as_deref().map_or(true, |x| r["result"] == json!(x));
        let fields: Vec<String> = ["event", "actor", "action", "scope", "job", "detail"].iter().map(|k| r[*k].as_str().unwrap_or("").to_ascii_lowercase()).collect();
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        if hit && page.matches(&refs) {
            rows.push(r);
        }
    }
    events.sort();
    let total = rows.len();
    Ok(json!({"observed_at": now(), "source": "broker audit log", "total": total, "page": page.page, "size": page.size,
              "records": page.slice(rows), "events": events, "truncated": truncated, "window_bytes": AUDIT_TAIL}))
}

// --- Notifications ---------------------------------------------------------------------------------------------------------

pub fn valid_email(address: &str) -> bool {
    if address.len() > 254 || address.contains("..") {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else { return false };
    let local_ok = !local.is_empty() && local.len() <= 64 && local.as_bytes()[0].is_ascii_alphanumeric()
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b));
    let labels: Vec<&str> = domain.split('.').collect();
    local_ok && labels.len() >= 2 && labels.iter().all(|l| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// https only, a host name without credentials, no spaces or quotes, bounded.
pub fn valid_webhook(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    if url.len() > MAX_URL || rest.is_empty()
        || !rest.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~:/?#@!$&()*+,;=%-".contains(&b)) {
        return false;
    }
    let authority = rest.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("");
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty() && host.as_bytes()[0].is_ascii_alphanumeric() && host.as_bytes()[host.len() - 1].is_ascii_alphanumeric()
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let port_ok = port.map_or(true, |p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().map_or(false, |n| (1..=65535).contains(&n)));
    host_ok && port_ok
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NotifyArgs {
    #[serde(default)]
    emails: Option<Vec<String>>,
    #[serde(default)]
    webhook: Option<String>,
    #[serde(default)]
    events: Option<Vec<String>>,
}

/// `admin.notify`: the settings (the webhook as its host only) and what was sent.
pub fn notify(config: &Config) -> Reply {
    cli(config, &["notify", "show", "--format=json"], product::TIMEOUT)
}

/// `admin.notify_test`: a test message to every configured channel.
pub fn notify_test(config: &Config) -> Reply {
    let reply = cli(config, &["notify", "test", "--format=json"], SLOW)?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "notify_test", "result": reply["output"]["result"]}));
    Ok(reply)
}

/// Writes a file atomically: a new 0600 file beside it, synced, renamed.
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp-{}", super::random_hex(4)));
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

/// `admin.notify_set {emails?, webhook?, events?}`: a left-out field keeps its stored value; `webhook: ""` removes the URL.
pub fn notify_set(config: &Config, args: Value) -> Reply {
    let a: NotifyArgs = super::cache::parse(args)?;
    if a.emails.is_none() && a.webhook.is_none() && a.events.is_none() {
        return Err(("BAD_ARGS", "give at least one of emails, webhook and events".into()));
    }
    let path = config.state.join(NOTIFY_FILE);
    let old: Value = read_bounded(&path, 64 << 10).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let old_emails: Vec<String> = old["emails"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(str::to_string)).collect();
    let old_events: Vec<String> = match old["events"].as_array() {
        Some(list) => list.iter().filter_map(|e| e.as_str().map(str::to_string)).collect(),
        None => NOTIFY_EVENTS.iter().map(|e| e.to_string()).collect(),
    };
    let old_webhook = old["webhook"].as_str().filter(|w| valid_webhook(w)).map(str::to_string);
    let was_enabled = !old_emails.is_empty() || old_webhook.is_some();
    let mut emails: Vec<String> = Vec::new();
    for e in a.emails.unwrap_or(old_emails) {
        let e = e.to_ascii_lowercase();
        if !valid_email(&e) {
            return Err(("BAD_ARGS", "not a valid e-mail address".into()));
        }
        if !emails.contains(&e) {
            emails.push(e);
        }
    }
    if emails.len() > MAX_EMAILS {
        return Err(("BAD_ARGS", format!("at most {MAX_EMAILS} e-mail addresses")));
    }
    let webhook_change = match a.webhook.as_deref() {
        None => "unchanged",
        Some("") => "removed",
        Some(_) => "set",
    };
    let webhook = match a.webhook.as_deref() {
        None => old_webhook,
        Some("") => None,
        Some(url) if valid_webhook(url) => Some(url.to_string()),
        Some(_) => return Err(("BAD_ARGS", format!("the webhook must be an https URL without credentials (at most {MAX_URL} characters)"))),
    };
    let mut events: Vec<String> = Vec::new();
    for e in a.events.unwrap_or(old_events) {
        if !NOTIFY_EVENTS.contains(&e.as_str()) {
            return Err(("BAD_ARGS", "unknown event".into()));
        }
        if !events.contains(&e) {
            events.push(e);
        }
    }
    let enabled = !emails.is_empty() || webhook.is_some();
    let since = if !enabled { 0 } else if was_enabled { old["enabled_since"].as_u64().unwrap_or_else(now) } else { now() };
    let record = json!({"emails": emails, "webhook": webhook, "events": events, "enabled_since": since, "updated_at": now()});
    write_atomic(&path, &(serde_json::to_string_pretty(&record).unwrap_or_default() + "\n")).map_err(|e| ("INTERNAL", e))?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "notify_settings_set", "emails": emails.len(), "webhook": webhook_change,
                                             "events": events.len()}));
    notify(config)
}

// --- Maintenance windows ---------------------------------------------------------------------------------------------------

/// `admin.schedule`: the scheduled jobs.
pub fn schedule(config: &Config) -> Reply {
    cli(config, &["schedule", "list", "--format=json"], product::TIMEOUT)
}

/// The command that stores an entry (the caller has checked the action, the scope and that the digest is the current one).
pub fn schedule_add(config: &Config, action: &str, scope: &str, digest: &str, at: u64, window: Option<u64>) -> Reply {
    let mut args = vec!["schedule".to_string(), "add".into(), format!("--action={action}"), format!("--scope={scope}"), format!("--digest={digest}"),
                        format!("--at={at}")];
    if let Some(w) = window {
        args.push(format!("--window={w}"));
    }
    args.push("--format=json".into());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let reply = cli(config, &refs, product::TIMEOUT)?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "schedule_add", "action": action, "scope": scope, "at": at, "window": window,
                                             "job": reply["output"]["added"]["id"]}));
    Ok(reply)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelArgs {
    id: String,
}

/// `admin.schedule_cancel {id}`.
pub fn schedule_cancel(config: &Config, args: Value) -> Reply {
    let a: CancelArgs = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    if !valid_schedule_id(&a.id) {
        return Err(("BAD_ARGS", "id must be a scheduled job id".into()));
    }
    let id = format!("--id={}", a.id);
    let reply = cli(config, &["schedule", "cancel", &id, "--format=json"], product::TIMEOUT)?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "schedule_cancel", "scope": a.id}));
    Ok(reply)
}

// --- Update channel and support bundles --------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UpdateArgs {
    #[serde(default)]
    refresh: Option<bool>,
}

/// `admin.update {refresh?}`: the installed version against the latest GitHub release, the package signature and verified-release
/// state (read-only; the update itself is the job `ols.update`).
pub fn update(config: &Config, args: Value) -> Reply {
    let a: UpdateArgs = super::cache::parse(args)?;
    let mut argv = vec!["update", "check", "--format=json"];
    if a.refresh == Some(true) {
        argv.insert(2, "--refresh");
    }
    cli(config, &argv, SLOW)
}

/// `admin.bundle`: the support bundles that exist, newest first.
pub fn bundles(config: &Config) -> Reply {
    let dir = config.state.join("support");
    let mut rows: Vec<(u64, String, u64)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(meta) = fs::symlink_metadata(entry.path()) else { continue };
            if valid_bundle_name(&name) && meta.is_file() {
                rows.push((name[7..17].parse().unwrap_or(0), name, meta.len()));
            }
        }
    }
    rows.sort_by(|a, b| b.cmp(a));
    let list: Vec<Value> = rows.into_iter().take(10).map(|(created, name, size)| json!({"name": name, "size": size, "created": created})).collect();
    Ok(json!({"observed_at": now(), "bundles": list, "limit_bytes": 20 * 1024 * 1024, "keep": 3}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;
    use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::fixture;

    fn lines(config: &Config, items: &[Value]) {
        for item in items {
            audit(&config.audit_log, item).unwrap();
        }
    }

    #[test]
    fn audit_view_is_newest_first_filtered_and_paged() {
        let f = fixture();
        let config = f.config;
        lines(&config, &[
            json!({"time": 100, "event": "job_start", "job": "j1000000100-aaaaaaaa", "action": "ols.cutover", "scope": "p1", "principal": "root", "digest": "x"}),
            json!({"time": 160, "event": "job_finish", "job": "j1000000100-aaaaaaaa", "action": "ols.cutover", "state": "done", "exit_code": 0, "reason": null}),
            json!({"time": 200, "event": "cache_limits_set", "args": ["--per-site-mb=512"]}),
            json!({"time": 300, "event": "job_start", "job": "j1000000300-bbbbbbbb", "action": "ols.apache_return", "scope": "server", "principal": "root"}),
            json!({"time": 330, "event": "job_finish", "job": "j1000000300-bbbbbbbb", "action": "ols.apache_return", "state": "failed", "exit_code": 1, "reason": "refused"}),
            json!({"time": 400, "event": "tenant_cache_purge", "user": "olscpa", "domain": "a.test"}),
            json!({"time": 500, "action": "lab.audit_marker", "principal": "root", "scope": "server", "digest": "d"}),
        ]);
        fs::OpenOptions::new().append(true).open(&config.audit_log).unwrap().write_all(b"not json\n{\"time\": \"x\"}\n").unwrap();
        let all = audit_view(&config, Value::Null).unwrap();
        assert_eq!(all["total"], json!(7));
        let times: Vec<u64> = all["records"].as_array().unwrap().iter().map(|r| r["time"].as_u64().unwrap()).collect();
        assert_eq!(times, [500, 400, 330, 300, 200, 160, 100], "newest first, damaged lines skipped");
        assert_eq!(all["records"][0]["event"], json!("capability"));
        assert_eq!(all["records"][1]["actor"], json!("olscpa"));
        assert_eq!(all["records"][2]["actor"], json!("root"), "a finish takes the actor of its start");
        assert_eq!(all["records"][2]["result"], json!("failed"));
        assert_eq!(all["records"][2]["detail"], json!("reason=refused exit_code=1 state=failed"));
        assert!(all["records"].as_array().unwrap().iter().all(|r| r.get("digest").is_none()), "no digest is shown");
        let failed = audit_view(&config, json!({"result": "failed"})).unwrap();
        assert_eq!(failed["total"], json!(1));
        let jobs = audit_view(&config, json!({"event": "job_finish", "size": 1, "page": 2})).unwrap();
        assert_eq!((jobs["total"].as_u64(), jobs["records"][0]["time"].as_u64()), (Some(2), Some(160)));
        let found = audit_view(&config, json!({"query": "olscpa"})).unwrap();
        assert_eq!(found["total"], json!(1));
        assert!(all["events"].as_array().unwrap().contains(&json!("cache_limits_set")));
        for bad in [json!({"event": "Job-Start"}), json!({"event": ""}), json!({"result": "maybe"}), json!({"size": 0}), json!({"size": 201}), json!({"x": 1}),
                    json!({"query": "a b"}), json!({"page": 0})] {
            assert_eq!(audit_view(&config, bad.clone()).err().map(|e| e.0), Some("BAD_ARGS"), "{bad}");
        }
        // No log yet: an empty view, not an error.
        let e = fixture();
        let mut empty = e.config;
        empty.audit_log = empty.state.join("missing.log");
        assert_eq!(audit_view(&empty, Value::Null).unwrap()["total"], json!(0));
    }

    #[test]
    fn audit_view_reads_a_bounded_tail() {
        let f = fixture();
        let config = f.config;
        let mut text = String::new();
        for i in 0..60_000u64 {
            text.push_str(&format!("{{\"time\": {}, \"event\": \"cache_limits_set\", \"args\": [\"--per-site-mb=512\", \"padding-padding-padding\"]}}\n", 1000 + i));
        }
        assert!(text.len() as u64 > AUDIT_TAIL);
        fs::write(&config.audit_log, text).unwrap();
        let view = audit_view(&config, json!({"size": 200})).unwrap();
        assert_eq!(view["truncated"], json!(true));
        assert_eq!(view["records"][0]["time"], json!(60_999), "the newest record is first");
        assert!(view["total"].as_u64().unwrap() < 60_000, "only the tail is read");
        let link = config.state.join("link.log");
        std::os::unix::fs::symlink(&config.audit_log, &link).unwrap();
        let l = fixture();
        let mut linked = l.config;
        linked.audit_log = link;
        assert_eq!(audit_view(&linked, Value::Null).unwrap()["total"], json!(0), "a link is not followed");
    }

    #[test]
    fn notification_input_grammar() {
        for ok in ["a@b.test", "first.last+tag@mail.example.org", "A_B-c%d@x-y.example.com"] {
            assert!(valid_email(ok), "{ok}");
        }
        for bad in ["", "a", "a@b", "a b@c.test", "a@b.test\nBcc: x@y.test", "a@b..test", "@b.test", "a@-b.test", "a@b.test,c@d.test", ".a@b.test"] {
            assert!(!valid_email(bad), "{bad:?}");
        }
        for ok in ["https://hooks.example.com/services/T1/B2/xyz", "https://example.org:8443/hook?x=1", "https://example.org"] {
            assert!(valid_webhook(ok), "{ok}");
        }
        for bad in ["http://example.com/h", "https://user:pw@example.com/h", "https://", "https://exa mple.com", "https://example.com:99999/h", "https://example.com:/h",
                    "https://@example.com", "https://example.com/'x", "https://example.com/h\r\nX: y", "ftp://example.com", "https://-example.com"] {
            assert!(!valid_webhook(bad), "{bad:?}");
        }
        assert!(!valid_webhook(&format!("https://example.com/{}", "a".repeat(520))));
        assert!(valid_schedule_id("s20261028100000-0a1b2c") && !valid_schedule_id("s20261028100000-0A1B2C") && !valid_schedule_id("../x"));
        assert!(valid_bundle_name("bundle-1800000000-0a1b2c3d.tar.gz") && !valid_bundle_name("bundle-1800000000-0a1b2c3d.tar") && !valid_bundle_name("../bundle-1800000000-0a1b2c3d.tar.gz"));
    }

    #[test]
    fn notification_settings_are_written_by_the_broker_without_the_url_in_any_argument() {
        let temp = TempTree::new();
        let f = fixture();
        let mut config = f.config;
        // The command shows its arguments in a file: the webhook must not be among them.
        let args_log = temp.path().join("args");
        config.cli = fake_cli(temp.path(), &format!("echo \"$*\" >> {}\necho '{{\"settings\": {{\"enabled\": true}}}}'", args_log.display()));
        let url = "https://hooks.example.com/services/SECRETPART";
        let reply = notify_set(&config, json!({"emails": ["Ops@Example.test"], "webhook": url})).unwrap();
        assert_eq!(reply["output"]["settings"]["enabled"], json!(true));
        let stored: Value = serde_json::from_slice(&fs::read(config.state.join("notify.json")).unwrap()).unwrap();
        assert_eq!(stored["emails"], json!(["ops@example.test"]));
        assert_eq!(stored["webhook"], json!(url));
        assert_eq!(stored["events"].as_array().unwrap().len(), NOTIFY_EVENTS.len());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(config.state.join("notify.json")).unwrap().mode() & 0o777, 0o600);
        assert!(!fs::read_to_string(&args_log).unwrap().contains("SECRETPART"));
        assert!(!fs::read_to_string(&config.audit_log).unwrap().contains("SECRETPART"), "the audit log holds no webhook URL");
        assert!(fs::read_to_string(&config.audit_log).unwrap().contains("notify_settings_set"));
        let since = stored["enabled_since"].as_u64().unwrap();
        assert!(since > 0);
        // A left-out webhook is kept; events narrow; enabled_since stays.
        notify_set(&config, json!({"events": ["job", "disk"]})).unwrap();
        let kept: Value = serde_json::from_slice(&fs::read(config.state.join("notify.json")).unwrap()).unwrap();
        assert_eq!((kept["webhook"].clone(), kept["events"].clone(), kept["enabled_since"].as_u64()), (json!(url), json!(["job", "disk"]), Some(since)));
        // Removing every channel switches notifications off.
        notify_set(&config, json!({"emails": [], "webhook": ""})).unwrap();
        let off: Value = serde_json::from_slice(&fs::read(config.state.join("notify.json")).unwrap()).unwrap();
        assert_eq!((off["webhook"].clone(), off["enabled_since"].clone()), (Value::Null, json!(0)));
        for bad in [json!({}), json!({"emails": ["x"]}), json!({"emails": ["a@b.test\nBcc: c@d.test"]}), json!({"webhook": "http://x.test/h"}),
                    json!({"webhook": "https://u:p@x.test/h"}), json!({"events": ["nonsense"]}), json!({"other": 1}), json!({"emails": [1, 2]}),
                    json!({"emails": (1..=6).map(|i| format!("u{i}@b.test")).collect::<Vec<_>>()})] {
            assert_eq!(notify_set(&config, bad.clone()).err().map(|e| e.0), Some("BAD_ARGS"), "{bad}");
        }
    }

    #[test]
    fn schedule_update_and_bundle_commands() {
        let temp = TempTree::new();
        let f = fixture();
        let mut config = f.config;
        let args_log = temp.path().join("args");
        config.cli = fake_cli(temp.path(), &format!("echo \"$*\" >> {}\necho '{{\"added\": {{\"id\": \"s20261028100000-0a1b2c\"}}}}'", args_log.display()));
        schedule(&config).unwrap();
        schedule_add(&config, "ols.cutover", "p1", &"a".repeat(64), 1_900_000_000, Some(30)).unwrap();
        schedule_cancel(&config, json!({"id": "s20261028100000-0a1b2c"})).unwrap();
        assert_eq!(schedule_cancel(&config, json!({"id": "../x"})).err().map(|e| e.0), Some("BAD_ARGS"));
        update(&config, Value::Null).unwrap();
        update(&config, json!({"refresh": true})).unwrap();
        assert_eq!(update(&config, json!({"refresh": "yes"})).err().map(|e| e.0), Some("BAD_ARGS"));
        let log = fs::read_to_string(&args_log).unwrap();
        let digest = "a".repeat(64);
        assert_eq!(log.lines().collect::<Vec<_>>(), [
            "schedule list --format=json".to_string(),
            format!("schedule add --action=ols.cutover --scope=p1 --digest={digest} --at=1900000000 --window=30 --format=json"),
            "schedule cancel --id=s20261028100000-0a1b2c --format=json".to_string(),
            "update check --format=json".to_string(),
            "update check --refresh --format=json".to_string(),
        ]);
        let audit_text = fs::read_to_string(&config.audit_log).unwrap();
        assert!(audit_text.contains("schedule_add") && audit_text.contains("schedule_cancel"));
        // Bundles: only well-named regular files, newest first.
        let dir = config.state.join("support");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bundle-1800000100-0a0a0a0a.tar.gz"), "xx").unwrap();
        fs::write(dir.join("bundle-1800000200-0b0b0b0b.tar.gz"), "yyyy").unwrap();
        fs::write(dir.join("notes.txt"), "no").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("bundle-1800000300-0c0c0c0c.tar.gz")).unwrap();
        let list = bundles(&config).unwrap();
        let names: Vec<&str> = list["bundles"].as_array().unwrap().iter().map(|b| b["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["bundle-1800000200-0b0b0b0b.tar.gz", "bundle-1800000100-0a0a0a0a.tar.gz"]);
        assert_eq!(list["bundles"][0]["size"], json!(4));
    }
}
