//! `server.metrics`: OLS 1.9.3 real-time statistics from the `.rtreport*` files of its status directory.
//!
//! Format (OLS source, `HttpServerImpl::generateRTReport` and the writers it calls), rewritten once per
//! second by every server process (`.rtreport` for the first, `.rtreport.<n>` for process n), each line
//! `NAME: value, NAME: value, ...`:
//!
//! ```text
//! VERSION: LiteSpeed Web Server/Open/1.9.3
//! UPTIME: [N day[s]] HH:MM:SS
//! BPS_IN: <KiB>, BPS_OUT: <KiB>, SSL_BPS_IN: <KiB>, SSL_BPS_OUT: <KiB>
//! MAXCONN: n, MAXSSL_CONN: n, PLAINCONN: n, AVAILCONN: n, IDLECONN: n, SSLCONN: n, AVAILSSL: n
//! REQ_RATE []: REQ_PROCESSING: n, REQ_PER_SEC: n, TOT_REQS: n, PUB_CACHE_HITS_PER_SEC: n, TOTAL_PUB_CACHE_HITS: n,
//!     PRIVATE_CACHE_HITS_PER_SEC: n, TOTAL_PRIVATE_CACHE_HITS: n, STATIC_HITS_PER_SEC: n, TOTAL_STATIC_HITS: n
//! REQ_RATE [<vhost>]: (the same fields, one line per vhost)
//! EXTAPP [<type>] [<vhost or empty>] [<name>]: CMAXCONN: n, EMAXCONN: n, POOL_SIZE: n, INUSE_CONN: n, IDLE_CONN: n,
//!     WAITQUE_DEPTH: n, REQ_PER_SEC: n, TOT_REQS: n
//! BLOCKED_IP: <address>,<address>,...
//! EOF
//! ```
//!
//! Byte counters are KiB per one-second report (plain and TLS counted separately). Processes are
//! aggregated the way OLS's own WebAdmin does (`RealTimeStatsBase::parse_server` and `parse_vhosts`):
//! every numeric field is summed over the process files, the uptime of the last file is kept. A file
//! that is not this format (no VERSION line first, a missing server line, a malformed known line, no
//! EOF) makes the whole report `unavailable`; unknown lines are ignored. Files older than STALE_AFTER
//! give `stale` (the values of the last report are still returned).

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub const DEFAULT_DIR: &str = "/run/ols-cpanel/status";
/// Seconds after which the newest report is stale (OLS rewrites it every second).
pub const STALE_AFTER: u64 = 30;
/// Per file; a report line is at most 1 KiB, so this allows tens of thousands of vhosts.
const MAX_REPORT: u64 = 32 << 20;
const MAX_PROCESSES: usize = 64;
/// Vhosts listed in the reply (the busiest first).
pub const MAX_VHOSTS: usize = 5000;

const REQ_FIELDS: [&str; 9] = ["REQ_PROCESSING", "REQ_PER_SEC", "TOT_REQS", "PUB_CACHE_HITS_PER_SEC", "TOTAL_PUB_CACHE_HITS",
                               "PRIVATE_CACHE_HITS_PER_SEC", "TOTAL_PRIVATE_CACHE_HITS", "STATIC_HITS_PER_SEC", "TOTAL_STATIC_HITS"];
const BPS_FIELDS: [&str; 4] = ["BPS_IN", "BPS_OUT", "SSL_BPS_IN", "SSL_BPS_OUT"];
const CONN_FIELDS: [&str; 7] = ["MAXCONN", "MAXSSL_CONN", "PLAINCONN", "AVAILCONN", "IDLECONN", "SSLCONN", "AVAILSSL"];
const EXTAPP_FIELDS: [&str; 8] = ["CMAXCONN", "EMAXCONN", "POOL_SIZE", "INUSE_CONN", "IDLE_CONN", "WAITQUE_DEPTH", "REQ_PER_SEC", "TOT_REQS"];

type Fields = BTreeMap<String, f64>;

/// One process file or the sum of several.
#[derive(Default, Debug, PartialEq)]
pub struct Report {
    pub version: String,
    pub uptime: String,
    pub server: Fields,
    pub vhosts: BTreeMap<String, Fields>,
    /// Extapps by (vhost, name); the vhost is empty for server-level applications.
    pub extapps: BTreeMap<(String, String), Fields>,
    pub blocked_ips: u64,
}

/// `NAME: value, NAME: value`: every listed field present exactly as a number, nothing else.
fn fields(text: &str, names: &[&str]) -> Option<Fields> {
    let mut out = Fields::new();
    for part in text.split(", ") {
        let (name, value) = part.split_once(':')?;
        let value = value.trim();
        if !names.contains(&name) || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'-') {
            return None;
        }
        out.insert(name.to_string(), value.parse::<f64>().ok().filter(|v| v.is_finite())?);
    }
    (out.len() == names.len()).then_some(out)
}

/// A name OLS printed between brackets, kept only when it is plain printable text.
fn safe_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name.bytes().all(|b| b.is_ascii_graphic() && b != b'[' && b != b']')
}

fn add(into: &mut Fields, from: &Fields) {
    for (k, v) in from {
        *into.entry(k.clone()).or_insert(0.0) += v;
    }
}

/// `[a] [b] [c]: rest` -> (["a", "b", "c"], rest); names may be empty.
fn brackets(mut text: &str, count: usize) -> Option<(Vec<&str>, &str)> {
    let mut names = Vec::new();
    for i in 0..count {
        text = text.strip_prefix('[')?;
        let close = if i + 1 == count { "]: " } else { "] [" };
        let end = text.find(close)?;
        names.push(&text[..end]);
        text = &text[end + if i + 1 == count { 3 } else { 2 }..];
    }
    Some((names, text))
}

/// One process file; None when it is not the OLS 1.9.3 format.
pub fn parse(text: &str) -> Option<Report> {
    let mut lines = text.lines();
    let version = lines.next()?.strip_prefix("VERSION: LiteSpeed Web Server/")?.to_string();
    let mut report = Report { version, ..Report::default() };
    let (mut bps, mut conn, mut req, mut eof) = (false, false, false, false);
    for line in lines {
        if eof {
            return None; // nothing follows EOF in a complete report
        }
        if line == "EOF" {
            eof = true;
        } else if let Some(rest) = line.strip_prefix("UPTIME:") {
            report.uptime = rest.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == ':').collect();
        } else if line.starts_with("BPS_IN:") {
            add(&mut report.server, &fields(line, &BPS_FIELDS)?);
            bps = true;
        } else if line.starts_with("MAXCONN:") {
            add(&mut report.server, &fields(line, &CONN_FIELDS)?);
            conn = true;
        } else if let Some(rest) = line.strip_prefix("REQ_RATE ") {
            let (names, rest) = brackets(rest, 1)?;
            let values = fields(rest, &REQ_FIELDS)?;
            if names[0].is_empty() {
                add(&mut report.server, &values);
                req = true;
            } else if safe_name(names[0]) {
                add(report.vhosts.entry(names[0].to_string()).or_default(), &values);
            }
        } else if let Some(rest) = line.strip_prefix("EXTAPP ") {
            let (names, rest) = brackets(rest, 3)?;
            let values = fields(rest, &EXTAPP_FIELDS)?;
            if safe_name(names[2]) && (names[1].is_empty() || safe_name(names[1])) {
                add(report.extapps.entry((names[1].to_string(), names[2].to_string())).or_default(), &values);
            }
        } else if let Some(rest) = line.strip_prefix("BLOCKED_IP:") {
            report.blocked_ips += rest.split([',', ' ']).filter(|e| !e.trim().is_empty()).count() as u64;
        }
        // Any other line is a field this parser does not know: ignored.
    }
    (bps && conn && req && eof).then_some(report)
}

/// Sum of several process reports (OLS WebAdmin: numbers added, the last uptime kept).
pub fn aggregate(reports: Vec<Report>) -> Report {
    let mut total = Report::default();
    for r in reports {
        if total.version.is_empty() {
            total.version = r.version;
        }
        total.uptime = r.uptime;
        add(&mut total.server, &r.server);
        for (name, f) in &r.vhosts {
            add(total.vhosts.entry(name.clone()).or_default(), f);
        }
        for (key, f) in &r.extapps {
            add(total.extapps.entry(key.clone()).or_default(), f);
        }
        total.blocked_ips += r.blocked_ips;
    }
    total
}

/// `.rtreport` and `.rtreport.<n>` (the text reports; `.json` and `.tmp` files are not read).
fn report_name(name: &str) -> bool {
    match name.strip_prefix(".rtreport") {
        Some("") => true,
        Some(rest) => rest.strip_prefix('.').map_or(false, |n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

/// Regular report files with their modification times, newest first.
fn report_files(dir: &Path) -> Vec<(std::path::PathBuf, u64)> {
    let mut files: Vec<(std::path::PathBuf, u64)> = fs::read_dir(dir)
        .map(|entries| {
            entries.flatten()
                .filter(|e| e.file_name().to_str().map_or(false, report_name))
                .filter_map(|e| {
                    let meta = fs::symlink_metadata(e.path()).ok()?;
                    let mtime = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
                    meta.is_file().then(|| (e.path(), mtime))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    files.truncate(MAX_PROCESSES);
    files
}

fn number(fields: &Fields, name: &str) -> f64 {
    fields.get(name).copied().unwrap_or(0.0)
}

fn json_number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9.0e15 { json!(value as i64) } else { json!(value) }
}

fn extapp_json(apps: &[&Fields]) -> Value {
    let sum = |name: &str| json_number(apps.iter().map(|f| number(f, name)).sum());
    json!({"pools": apps.len(), "in_use": sum("INUSE_CONN"), "idle": sum("IDLE_CONN"), "waiting": sum("WAITQUE_DEPTH"),
           "requests_per_second": sum("REQ_PER_SEC")})
}

fn server_json(r: &Report) -> Value {
    let s = &r.server;
    let n = |name: &str| number(s, name);
    let server_apps: Vec<&Fields> = r.extapps.iter().filter(|((vhost, _), _)| vhost.is_empty()).map(|(_, f)| f).collect();
    json!({
        "version": r.version,
        "uptime": r.uptime,
        "requests_per_second": json_number(n("REQ_PER_SEC")),
        "requests_processing": json_number(n("REQ_PROCESSING")),
        "total_requests": json_number(n("TOT_REQS")),
        "connections": json_number(n("PLAINCONN") + n("SSLCONN")),
        "plain_connections": json_number(n("PLAINCONN")),
        "tls_connections": json_number(n("SSLCONN")),
        "idle_connections": json_number(n("IDLECONN")),
        "max_connections": json_number(n("MAXCONN")),
        "max_tls_connections": json_number(n("MAXSSL_CONN")),
        "available_connections": json_number(n("AVAILCONN")),
        "available_tls_connections": json_number(n("AVAILSSL")),
        "bytes_per_second": json_number((n("BPS_IN") + n("BPS_OUT") + n("SSL_BPS_IN") + n("SSL_BPS_OUT")) * 1024.0),
        "bytes_in_per_second": json_number((n("BPS_IN") + n("SSL_BPS_IN")) * 1024.0),
        "bytes_out_per_second": json_number((n("BPS_OUT") + n("SSL_BPS_OUT")) * 1024.0),
        "tls_bytes_in_per_second": json_number(n("SSL_BPS_IN") * 1024.0),
        "tls_bytes_out_per_second": json_number(n("SSL_BPS_OUT") * 1024.0),
        "cache_hits_per_second": json_number(n("PUB_CACHE_HITS_PER_SEC") + n("PRIVATE_CACHE_HITS_PER_SEC")),
        "static_hits_per_second": json_number(n("STATIC_HITS_PER_SEC")),
        "blocked_ips": r.blocked_ips,
        "extapp": extapp_json(&server_apps),
    })
}

fn vhosts_json(r: &Report) -> Vec<Value> {
    let mut rows: Vec<(f64, &String, &Fields)> = r.vhosts.iter().map(|(name, f)| (number(f, "REQ_PER_SEC"), name, f)).collect();
    // Busiest first, then by name, so a long list keeps the interesting part.
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.1.cmp(b.1)));
    rows.into_iter().take(MAX_VHOSTS).map(|(_, name, f)| {
        let n = |field: &str| number(f, field);
        let apps: Vec<&Fields> = r.extapps.iter().filter(|((vhost, _), _)| vhost == name).map(|(_, f)| f).collect();
        json!({
            "vhost": name,
            "requests_per_second": json_number(n("REQ_PER_SEC")),
            "requests_processing": json_number(n("REQ_PROCESSING")),
            "total_requests": json_number(n("TOT_REQS")),
            "cache_hits_per_second": json_number(n("PUB_CACHE_HITS_PER_SEC") + n("PRIVATE_CACHE_HITS_PER_SEC")),
            "total_cache_hits": json_number(n("TOTAL_PUB_CACHE_HITS") + n("TOTAL_PRIVATE_CACHE_HITS")),
            "static_hits_per_second": json_number(n("STATIC_HITS_PER_SEC")),
            "total_static_hits": json_number(n("TOTAL_STATIC_HITS")),
            "extapp": extapp_json(&apps),
        })
    }).collect()
}

/// The `server.metrics` reply for the report directory `dir` at time `now`.
pub fn metrics(dir: &Path, now: u64) -> Value {
    let source = format!("{}/.rtreport*", dir.display());
    let mut out = Map::new();
    out.insert("observed_at".into(), json!(now));
    out.insert("source".into(), json!(source));
    let unavailable = |mut out: Map<String, Value>, reason: &str| {
        out.insert("status".into(), json!("unavailable"));
        out.insert("reason".into(), json!(reason));
        out.insert("report_age".into(), Value::Null);
        out.insert("processes".into(), json!(0));
        out.insert("server".into(), Value::Null);
        out.insert("vhosts".into(), json!([]));
        Value::Object(out)
    };
    let files = report_files(dir);
    let Some(&(_, newest)) = files.first() else { return unavailable(out, "no real-time report") };
    // A process file far older than the newest one is left over from an earlier process count.
    let current: Vec<_> = files.iter().filter(|(_, mtime)| newest.saturating_sub(*mtime) <= STALE_AFTER).collect();
    let mut reports = Vec::new();
    for (path, _) in &current {
        let Some(bytes) = super::read_bounded(path, MAX_REPORT) else { return unavailable(out, "real-time report unreadable") };
        match std::str::from_utf8(&bytes).ok().and_then(parse) {
            Some(report) => reports.push(report),
            None => return unavailable(out, "unknown real-time report format"),
        }
    }
    let age = now.saturating_sub(newest);
    let total = aggregate(reports);
    out.insert("status".into(), json!(if age > STALE_AFTER { "stale" } else { "ok" }));
    out.insert("reason".into(), if age > STALE_AFTER { json!("the real-time report is not being updated") } else { Value::Null });
    out.insert("report_age".into(), json!(age));
    out.insert("processes".into(), json!(current.len()));
    out.insert("server".into(), server_json(&total));
    out.insert("vhosts".into(), json!(vhosts_json(&total)));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;
    use std::time::{Duration, SystemTime};

    /// Byte for byte what generateRTReport writes for process 1 (format strings of OLS 1.9.3).
    pub const PROCESS_1: &str = "VERSION: LiteSpeed Web Server/Open/1.9.3\n\
UPTIME: 2 days 01:02:03\n\
BPS_IN: 10, BPS_OUT: 200, SSL_BPS_IN: 3, SSL_BPS_OUT: 40\n\
MAXCONN: 10000, MAXSSL_CONN: 10000, PLAINCONN: 5, AVAILCONN: 9990, IDLECONN: 2, SSLCONN: 5, AVAILSSL: 9995\n\
REQ_RATE []: REQ_PROCESSING: 3, REQ_PER_SEC: 12, TOT_REQS: 3456, PUB_CACHE_HITS_PER_SEC: 0, TOTAL_PUB_CACHE_HITS: 0, \
PRIVATE_CACHE_HITS_PER_SEC: 0, TOTAL_PRIVATE_CACHE_HITS: 0, STATIC_HITS_PER_SEC: 4, TOTAL_STATIC_HITS: 900\n\
REQ_RATE [a.test]: REQ_PROCESSING: 1, REQ_PER_SEC: 7, TOT_REQS: 2000, PUB_CACHE_HITS_PER_SEC: 1, TOTAL_PUB_CACHE_HITS: 10, \
PRIVATE_CACHE_HITS_PER_SEC: 2, TOTAL_PRIVATE_CACHE_HITS: 20, STATIC_HITS_PER_SEC: 3, TOTAL_STATIC_HITS: 500\n\
REQ_RATE [b.test]: REQ_PROCESSING: 0, REQ_PER_SEC: 5, TOT_REQS: 1000, PUB_CACHE_HITS_PER_SEC: 0, TOTAL_PUB_CACHE_HITS: 0, \
PRIVATE_CACHE_HITS_PER_SEC: 0, TOTAL_PRIVATE_CACHE_HITS: 0, STATIC_HITS_PER_SEC: 1, TOTAL_STATIC_HITS: 400\n\
EXTAPP [LSAPI] [a.test] [lsphp-olscpa]: CMAXCONN: 10, EMAXCONN: 10, POOL_SIZE: 2, INUSE_CONN: 1, IDLE_CONN: 1, WAITQUE_DEPTH: 0, \
REQ_PER_SEC: 6, TOT_REQS: 1500\n\
EXTAPP [CGI] [] [lscgid]: CMAXCONN: 20, EMAXCONN: 20, POOL_SIZE: 1, INUSE_CONN: 0, IDLE_CONN: 1, WAITQUE_DEPTH: 0, \
REQ_PER_SEC: 0, TOT_REQS: 3\n\
BLOCKED_IP: \n\
EOF\n";

    /// Process 2 of the same server: a newer uptime, one vhost only, two blocked addresses.
    pub const PROCESS_2: &str = "VERSION: LiteSpeed Web Server/Open/1.9.3\n\
UPTIME: 2 days 01:02:04\n\
BPS_IN: 1, BPS_OUT: 2, SSL_BPS_IN: 0, SSL_BPS_OUT: 0\n\
MAXCONN: 10000, MAXSSL_CONN: 10000, PLAINCONN: 1, AVAILCONN: 9999, IDLECONN: 0, SSLCONN: 0, AVAILSSL: 10000\n\
REQ_RATE []: REQ_PROCESSING: 1, REQ_PER_SEC: 3, TOT_REQS: 44, PUB_CACHE_HITS_PER_SEC: 0, TOTAL_PUB_CACHE_HITS: 0, \
PRIVATE_CACHE_HITS_PER_SEC: 0, TOTAL_PRIVATE_CACHE_HITS: 0, STATIC_HITS_PER_SEC: 0, TOTAL_STATIC_HITS: 0\n\
REQ_RATE [a.test]: REQ_PROCESSING: 1, REQ_PER_SEC: 3, TOT_REQS: 44, PUB_CACHE_HITS_PER_SEC: 0, TOTAL_PUB_CACHE_HITS: 0, \
PRIVATE_CACHE_HITS_PER_SEC: 0, TOTAL_PRIVATE_CACHE_HITS: 0, STATIC_HITS_PER_SEC: 0, TOTAL_STATIC_HITS: 0\n\
EXTAPP [LSAPI] [a.test] [lsphp-olscpa]: CMAXCONN: 10, EMAXCONN: 10, POOL_SIZE: 1, INUSE_CONN: 1, IDLE_CONN: 0, WAITQUE_DEPTH: 2, \
REQ_PER_SEC: 3, TOT_REQS: 44\n\
BLOCKED_IP: 192.0.2.1,2001:db8::1,\n\
EOF\n";

    #[test]
    fn one_process_file() {
        let r = parse(PROCESS_1).unwrap();
        assert_eq!(r.version, "Open/1.9.3");
        assert_eq!(r.uptime, "2 days 01:02:03");
        assert_eq!(r.server["REQ_PER_SEC"], 12.0);
        assert_eq!(r.server["BPS_OUT"], 200.0);
        assert_eq!(r.server["MAXCONN"], 10000.0);
        assert_eq!(r.vhosts.len(), 2);
        assert_eq!(r.vhosts["a.test"]["TOT_REQS"], 2000.0);
        assert_eq!(r.extapps[&("a.test".to_string(), "lsphp-olscpa".to_string())]["INUSE_CONN"], 1.0);
        assert_eq!(r.extapps[&(String::new(), "lscgid".to_string())]["POOL_SIZE"], 1.0);
        assert_eq!(r.blocked_ips, 0);
        assert_eq!(parse(PROCESS_2).unwrap().blocked_ips, 2);
    }

    #[test]
    fn processes_are_summed_like_webadmin() {
        let total = aggregate(vec![parse(PROCESS_1).unwrap(), parse(PROCESS_2).unwrap()]);
        assert_eq!(total.uptime, "2 days 01:02:04");
        assert_eq!(total.server["REQ_PER_SEC"], 15.0);
        assert_eq!(total.server["MAXCONN"], 20000.0);
        assert_eq!(total.vhosts["a.test"]["REQ_PER_SEC"], 10.0);
        assert_eq!(total.vhosts["b.test"]["REQ_PER_SEC"], 5.0);
        let server = server_json(&total);
        assert_eq!(server["requests_per_second"], json!(15));
        assert_eq!(server["connections"], json!(11));
        assert_eq!(server["bytes_in_per_second"], json!((10 + 3 + 1) * 1024));
        assert_eq!(server["bytes_out_per_second"], json!((200 + 40 + 2) * 1024));
        assert_eq!(server["bytes_per_second"], json!((14 + 242) * 1024));
        assert_eq!(server["blocked_ips"], json!(2));
        assert_eq!(server["extapp"], json!({"pools": 1, "in_use": 0, "idle": 1, "waiting": 0, "requests_per_second": 0}));
        let vhosts = vhosts_json(&total);
        assert_eq!(vhosts[0]["vhost"], json!("a.test"));
        assert_eq!(vhosts[0]["cache_hits_per_second"], json!(3));
        assert_eq!(vhosts[0]["extapp"], json!({"pools": 1, "in_use": 2, "idle": 1, "waiting": 2, "requests_per_second": 9}));
        assert_eq!(vhosts[1]["vhost"], json!("b.test"));
        assert_eq!(vhosts[1]["extapp"]["pools"], json!(0));
    }

    #[test]
    fn unknown_format_and_unknown_lines() {
        // Unknown lines are ignored.
        let extra = PROCESS_1.replace("BLOCKED_IP: \n", "BLOCKED_IP: \nNEW_COUNTER: 5\n");
        assert!(parse(&extra).is_some());
        // Anything else that is not the format is refused.
        for bad in [
            String::new(),
            PROCESS_1.replace("VERSION: LiteSpeed Web Server/", "VERSION: Other/"),
            PROCESS_1.replace("EOF\n", ""),
            PROCESS_1.replace("BPS_IN: 10,", "BPS_IN: ten,"),
            PROCESS_1.replace("MAXCONN: 10000, ", ""),
            PROCESS_1.replace("REQ_RATE []", "REQ_RATE [x.test]"),
            PROCESS_1.replace(", TOTAL_STATIC_HITS: 900", ", TOTAL_STATIC_HITS: 900, EXTRA: 1"),
            PROCESS_1.replace("EXTAPP [CGI] [] [lscgid]", "EXTAPP [CGI] [lscgid]"),
            PROCESS_1.replace("EOF\n", "EOF\nBPS_IN: 1\n"),
            "{\"version\": \"1.9.3\"}".to_string(),
        ] {
            assert!(parse(&bad).is_none(), "{bad}");
        }
        // A vhost name with characters that are not plain text is dropped, not passed on.
        let odd = PROCESS_1.replace("REQ_RATE [b.test]", "REQ_RATE [b test]");
        assert_eq!(parse(&odd).unwrap().vhosts.len(), 1);
    }

    fn touch(path: &Path, age: u64) {
        let file = fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(age)).unwrap();
    }

    #[test]
    fn directory_states() {
        let temp = TempTree::new();
        let dir = temp.path();
        let now = super::super::now();
        let empty = metrics(dir, now);
        assert_eq!(empty["status"], json!("unavailable"));
        assert_eq!(empty["server"], Value::Null);
        assert_eq!(metrics(&dir.join("missing"), now)["status"], json!("unavailable"));
        fs::write(dir.join(".rtreport"), PROCESS_1).unwrap();
        fs::write(dir.join(".rtreport.2"), PROCESS_2).unwrap();
        // Ignored names: JSON reports, temporary files, other files.
        fs::write(dir.join(".rtreport.json"), "{}").unwrap();
        fs::write(dir.join(".rtreport.tmp"), "garbage").unwrap();
        fs::write(dir.join(".status"), "garbage").unwrap();
        let ok = metrics(dir, now);
        assert_eq!(ok["status"], json!("ok"), "{ok}");
        assert_eq!(ok["processes"], json!(2));
        assert_eq!(ok["server"]["requests_per_second"], json!(15));
        assert_eq!(ok["vhosts"].as_array().unwrap().len(), 2);
        assert!(ok["observed_at"].is_u64() && ok["source"].as_str().unwrap().ends_with("/.rtreport*"));
        // A process file left over from an earlier process count is not added.
        fs::write(dir.join(".rtreport.3"), PROCESS_2).unwrap();
        touch(&dir.join(".rtreport.3"), 600);
        assert_eq!(metrics(dir, now)["processes"], json!(2));
        // Stale: the newest report is older than 30 s; the last values are still shown.
        for name in [".rtreport", ".rtreport.2"] {
            touch(&dir.join(name), 45);
        }
        let stale = metrics(dir, now);
        assert_eq!(stale["status"], json!("stale"));
        assert!(stale["report_age"].as_u64().unwrap() >= 45);
        assert_eq!(stale["server"]["requests_per_second"], json!(15));
        // One unknown process file makes the whole report unavailable.
        fs::write(dir.join(".rtreport.2"), "VERSION: something else\n").unwrap();
        let unknown = metrics(dir, now);
        assert_eq!(unknown["status"], json!("unavailable"));
        assert_eq!(unknown["reason"], json!("unknown real-time report format"));
        // A planted link is never followed.
        fs::remove_file(dir.join(".rtreport.2")).unwrap();
        fs::remove_file(dir.join(".rtreport.3")).unwrap();
        fs::remove_file(dir.join(".rtreport")).unwrap();
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, PROCESS_1).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join(".rtreport")).unwrap();
        assert_eq!(metrics(dir, now)["status"], json!("unavailable"));
    }

    #[test]
    fn report_names() {
        for good in [".rtreport", ".rtreport.2", ".rtreport.16"] {
            assert!(report_name(good), "{good}");
        }
        for bad in [".rtreport.json", ".rtreport.2.json", ".rtreport.tmp", ".rtreport.", ".rtreport.1234", "rtreport", ".status"] {
            assert!(!report_name(bad), "{bad}");
        }
    }
}
