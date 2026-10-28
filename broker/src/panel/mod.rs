//! Data and jobs for the WHM and cPanel plugins (docs/product-interfaces.md, "Plugin data and actions
//! (release 1)"): the admin socket's read views (status, metrics, inventory, compatibility findings, plans,
//! generations, doctor, jobs), the job runner behind `cap.execute`, and the tenant socket's `tenant.sites`.
//! Everything here is read by root from root-owned product and cPanel state; nothing takes a path, a
//! command or an account from the request (accounts come from SO_PEERCRED in the broker).

pub mod cache;
pub mod history;
pub mod certificate;
pub mod jobs;
pub mod objcache;
pub mod ops;
pub mod php;
pub mod metrics;
pub mod product;
pub mod redact;
pub mod requests;
pub mod summary;
pub mod tools;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Reply = Result<Value, (&'static str, String)>;

/// Default page size and the largest one a caller may ask for (inventory.accounts, compat.findings).
pub const PAGE_SIZE: u64 = 50;
pub const MAX_PAGE_SIZE: u64 = 200;
const MAX_PAGE: u64 = 1_000_000;
/// Search text: what a domain, account or vhost name can contain.
const MAX_QUERY: usize = 253;

/// Every location the plugin operations read or write, injectable for tests.
pub struct Config {
    /// /var/lib/ols-cpanel: active, generations/, plans/, profile.json, jobs/.
    pub state: PathBuf,
    /// The product command line (`ols-cpanel`), run with fixed argv only.
    pub cli: PathBuf,
    /// OLS real-time report directory (statDir of the product's OLS).
    pub rtreport_dir: PathBuf,
    /// cPanel's installed certificate per vhost: `<dir>/<vhost>/combined`.
    pub tls_dir: PathBuf,
    /// cPanel's suspension markers: `<dir>/<user>`.
    pub suspended_dir: PathBuf,
    pub userdatadomains: PathBuf,
    /// The broker's audit log (capability executions, job start and finish).
    pub audit_log: PathBuf,
    /// cPanel's domain access logs: `<dir>/<domain>` and `<dir>/<domain>-ssl_log` (tools::tenant_logs).
    pub domlogs: PathBuf,
    /// OLS's per-vhost error logs: `<dir>/<vhost>-error.log`.
    pub error_logs: PathBuf,
    /// The requests to the administrator, one file each (requests.rs).
    pub requests: PathBuf,
    /// cPanel's account files `<dir>/<user>` (STARTDATE identifies an account's creation; requests.rs, tools.rs).
    pub users_dir: PathBuf,
    /// Programs the account tools run with fixed argv: curl (performance checks), runuser and tail (an account's own file),
    /// find (WordPress folders under a document root, as the account).
    pub curl: PathBuf,
    pub runuser: PathBuf,
    pub tail: PathBuf,
    pub find: PathBuf,
}

impl Config {
    pub fn production() -> Config {
        Config {
            state: PathBuf::from(crate::activator::generation::STATE),
            cli: PathBuf::from("/usr/local/ols-cpanel/bin/ols-cpanel"),
            rtreport_dir: PathBuf::from(metrics::DEFAULT_DIR),
            tls_dir: PathBuf::from("/var/cpanel/ssl/apache_tls"),
            suspended_dir: PathBuf::from("/var/cpanel/suspended"),
            userdatadomains: PathBuf::from("/etc/userdatadomains"),
            audit_log: PathBuf::from("/var/lib/ols-cpanel/broker-audit.log"),
            domlogs: PathBuf::from("/etc/apache2/logs/domlogs"),
            error_logs: PathBuf::from("/usr/local/lsws/logs/vhosts"),
            requests: PathBuf::from("/var/lib/ols-cpanel/requests"),
            users_dir: PathBuf::from("/var/cpanel/users"),
            curl: PathBuf::from("/usr/bin/curl"),
            runuser: PathBuf::from("/usr/sbin/runuser"),
            tail: PathBuf::from("/usr/bin/tail"),
            find: PathBuf::from("/usr/bin/find"),
        }
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    if fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).is_err() {
        panic!("no randomness source");
    }
    hex(&bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

/// A cPanel account name as the inventory accepts it.
pub fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A domain as the inventory accepts it (looser than the builder's grammar; never "/" and never "..").
pub fn valid_domain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.contains('.') && !value.starts_with('.')
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

pub fn valid_path(value: &str) -> bool {
    value.starts_with('/') && !value.contains("/../") && !value.ends_with("/..")
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-@+".contains(&b))
}

/// Sanitized rows of /etc/userdatadomains, sorted by domain; malformed rows are counted, never passed through.
pub fn domain_rows(path: &Path) -> (Vec<Value>, usize) {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut rows = Vec::new();
    let mut rejected = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some((domain, rest)) = line.split_once(": ") else { rejected += 1; continue };
        let fields: Vec<&str> = rest.split("==").collect();
        if fields.len() < 10 {
            rejected += 1;
            continue;
        }
        let (user, kind, parent, docroot, php) = (fields[0], fields[2], fields[3], fields[4], fields[9]);
        let kind_ok = ["main", "sub", "addon", "parked"].contains(&kind);
        let php_ok = php.is_empty() || (php.len() <= 32 && php.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !(valid_domain(domain) && valid_name(user) && kind_ok && valid_domain(parent) && valid_path(docroot) && php_ok) {
            rejected += 1;
            continue;
        }
        rows.push(json!({"domain": domain, "user": user, "type": kind, "parent": parent,
                         "docroot": docroot, "php": if php.is_empty() { Value::Null } else { json!(php) }}));
    }
    rows.sort_by(|a, b| a["domain"].as_str().cmp(&b["domain"].as_str()));
    (rows, rejected)
}

/// Appends one JSON line to the audit log (0600, never through a link) and syncs it.
pub fn audit(path: &Path, record: &Value) -> Result<(), String> {
    let line = record.to_string() + "\n";
    let mut file = fs::OpenOptions::new().create(true).append(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

/// Reads a regular file of at most `limit` bytes without following a link at the last component.
pub fn read_bounded(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > limit {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

/// The plugin operations' state: paths, the summary cache, the cached product commands and the job runner.
pub struct Panel {
    pub config: Config,
    pub summaries: summary::Summaries,
    pub cli_status: product::Cached,
    pub doctor: product::Cached,
    pub jobs: jobs::Jobs,
    pub purges: cache::TenantPurges,
    pub php_restarts: cache::TenantPurges,
    pub perf_checks: cache::TenantPurges,
    pub requests: cache::TenantPurges,
}

impl Panel {
    pub fn new(config: Config, limits: jobs::Limits) -> Panel {
        let jobs = jobs::Jobs::with_launcher(config.state.join("jobs"), config.cli.clone(), config.audit_log.clone(), limits,
            Some(jobs::Launcher::system()));
        Panel {
            summaries: summary::Summaries::default(),
            cli_status: product::Cached::new(product::STATUS, product::STATUS_CACHE),
            doctor: product::Cached::new(product::DOCTOR, product::DOCTOR_CACHE),
            jobs,
            purges: cache::TenantPurges::new(cache::TENANT_PURGE_INTERVAL),
            php_restarts: cache::TenantPurges::new(php::TENANT_RESTART_INTERVAL),
            perf_checks: cache::TenantPurges::new(tools::PERF_INTERVAL),
            requests: cache::TenantPurges::new(requests::INTERVAL),
            config,
        }
    }

    pub fn metrics(&self) -> Reply {
        Ok(metrics::metrics(&self.config.rtreport_dir, now()))
    }

    pub fn metrics_history(&self, args: Value) -> Reply {
        history::admin_history(&self.config, args)
    }

    pub fn tenant_metrics(&self, user: &str, args: Value) -> Reply {
        history::tenant_history(&self.config, user, args)
    }

    pub fn inventory(&self, args: Value) -> Reply {
        summary::inventory(&self.config, &self.summaries, args)
    }

    pub fn compat(&self, args: Value) -> Reply {
        summary::compat(&self.config, &self.summaries, args)
    }

    pub fn plan_latest(&self) -> Reply {
        summary::latest_plan(&self.config)
    }

    pub fn generations(&self) -> Reply {
        product::run(&self.config.cli, product::GENERATIONS)
    }

    pub fn doctor(&self) -> Reply {
        self.doctor.get(&self.config.cli)
    }

    pub fn cache_stats(&self, args: Value) -> Reply {
        cache::stats(&self.config.cli, args)
    }

    pub fn cache_limits(&self, args: Value) -> Reply {
        cache::limits(&self.config, args)
    }

    pub fn tenant_cache_stats(&self, user: &str) -> Reply {
        cache::tenant_stats(&self.config, user)
    }

    pub fn tenant_cache_purge(&self, user: &str, args: Value) -> Reply {
        cache::tenant_purge(&self.config, &self.purges, user, args)
    }

    pub fn audit(&self, args: Value) -> Reply {
        ops::audit_view(&self.config, args)
    }

    pub fn notify(&self) -> Reply {
        ops::notify(&self.config)
    }

    pub fn notify_set(&self, args: Value) -> Reply {
        ops::notify_set(&self.config, args)
    }

    pub fn notify_test(&self) -> Reply {
        ops::notify_test(&self.config)
    }

    pub fn schedule(&self) -> Reply {
        ops::schedule(&self.config)
    }

    pub fn schedule_add(&self, action: &str, scope: &str, digest: &str, at: u64, window: Option<u64>) -> Reply {
        ops::schedule_add(&self.config, action, scope, digest, at, window)
    }

    pub fn schedule_cancel(&self, args: Value) -> Reply {
        ops::schedule_cancel(&self.config, args)
    }

    pub fn update(&self, args: Value) -> Reply {
        ops::update(&self.config, args)
    }

    pub fn bundles(&self) -> Reply {
        ops::bundles(&self.config)
    }

    pub fn php_status(&self) -> Reply {
        php::status(&self.config.cli)
    }

    pub fn tenant_objcache(&self, user: &str) -> Reply {
        objcache::tenant_objcache(&self.config, user)
    }

    pub fn tenant_php(&self, user: &str) -> Reply {
        php::tenant_php(&self.config, &self.summaries, user)
    }

    pub fn tenant_php_restart(&self, user: &str, args: Value) -> Reply {
        php::tenant_restart(&self.config, &self.php_restarts, user, args)
    }

    pub fn tenant_logs(&self, user: &str, args: Value) -> Reply {
        tools::tenant_logs(&self.config, user, args)
    }

    pub fn tenant_php_errors(&self, user: &str, args: Value) -> Reply {
        tools::tenant_php_errors(&self.config, user, args)
    }

    pub fn tenant_perf(&self, user: &str, args: Value) -> Reply {
        tools::tenant_perf(&self.config, &self.perf_checks, user, args)
    }

    pub fn tenant_request(&self, user: &str, args: Value) -> Reply {
        requests::tenant_create(&self.config, &self.requests, user, args)
    }

    pub fn tenant_requests(&self, user: &str) -> Reply {
        requests::tenant_list(&self.config, user)
    }

    pub fn admin_requests(&self) -> Reply {
        requests::admin_list(&self.config)
    }

    pub fn admin_request_status(&self, args: Value) -> Reply {
        requests::admin_status(&self.config, args)
    }

    pub fn tenant_sites(&self, user: &str) -> Reply {
        summary::tenant_sites(&self.config, &self.summaries, user)
    }

    /// `server.status` additions from `ols-cpanel status`: copied when the command answered, null otherwise,
    /// with `cli` saying which.
    pub fn status_extension(&self) -> Map<String, Value> {
        let mut out = Map::new();
        let reply = self.cli_status.get(&self.config.cli);
        let output = reply.as_ref().ok().map(|r| r["output"].clone()).unwrap_or(Value::Null);
        for key in STATUS_FIELDS {
            out.insert(key.to_string(), output.get(key).cloned().unwrap_or(Value::Null));
        }
        out.insert("cli".into(), match &reply {
            Ok(r) => json!({"status": "ok", "exit_code": r["exit_code"], "error": null}),
            Err((code, _)) => json!({"status": "unavailable", "exit_code": null, "error": code}),
        });
        out
    }
}

/// What `server.status` takes from `ols-cpanel status --format=json`.
pub const STATUS_FIELDS: [&str; 6] = ["cut_over", "profile", "ports", "epoch", "pending_events", "hybrid_vhosts"];
/// The fields the status digest covers: what a server-scoped action depends on. Not the time, the
/// ports' process details or the pending event count, which change without the operator's view being wrong.
pub const DIGEST_FIELDS: [&str; 7] = ["ols_active", "apache_active", "active_generation", "cut_over", "profile", "epoch", "hybrid_vhosts"];

/// SHA-256 of the canonical JSON (keys sorted) of the status digest fields.
pub fn status_digest(status: &Value) -> String {
    let mut fields = Map::new();
    for key in DIGEST_FIELDS {
        fields.insert(key.to_string(), status.get(key).cloned().unwrap_or(Value::Null));
    }
    sha256_hex(Value::Object(fields).to_string().as_bytes())
}

/// Search and paging arguments (`{"query", "page", "size"}`, all optional).
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PageArgs {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub page: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
}

pub struct Page {
    /// Lowercase search text; empty matches everything.
    pub query: String,
    pub page: u64,
    pub size: u64,
}

impl Page {
    pub fn parse(args: Value) -> Result<Page, (&'static str, String)> {
        let a: PageArgs = if args.is_null() { PageArgs::default() } else {
            serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?
        };
        let query = a.query.unwrap_or_default();
        if query.len() > MAX_QUERY || !query.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            return Err(("BAD_ARGS", format!("query must be at most {MAX_QUERY} letters, digits, '.', '_' or '-'")));
        }
        let page = a.page.unwrap_or(1);
        let size = a.size.unwrap_or(PAGE_SIZE);
        if !(1..=MAX_PAGE).contains(&page) {
            return Err(("BAD_ARGS", format!("page must be 1..{MAX_PAGE}")));
        }
        if !(1..=MAX_PAGE_SIZE).contains(&size) {
            return Err(("BAD_ARGS", format!("size must be 1..{MAX_PAGE_SIZE}")));
        }
        Ok(Page { query: query.to_ascii_lowercase(), page, size })
    }

    pub fn matches(&self, fields: &[&str]) -> bool {
        self.query.is_empty() || fields.iter().any(|f| f.contains(self.query.as_str()))
    }

    /// The items of this page (1-based; past the end is empty).
    pub fn slice<T>(&self, items: Vec<T>) -> Vec<T> {
        let start = (self.page - 1).saturating_mul(self.size) as usize;
        items.into_iter().skip(start).take(self.size as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;

    #[test]
    fn paging_arguments() {
        let p = Page::parse(Value::Null).unwrap();
        assert_eq!((p.query.as_str(), p.page, p.size), ("", 1, PAGE_SIZE));
        let p = Page::parse(json!({"query": "Shop.A-Test_1", "page": 3, "size": 200})).unwrap();
        assert_eq!((p.query.as_str(), p.page, p.size), ("shop.a-test_1", 3, 200));
        assert_eq!(Page::parse(json!({})).unwrap().size, PAGE_SIZE);
        for bad in [json!({"size": 0}), json!({"size": 201}), json!({"page": 0}), json!({"page": -1}), json!({"page": 1.5}),
                    json!({"page": "2"}), json!({"query": "a b"}), json!({"query": "a/b"}), json!({"query": "<x>"}),
                    json!({"query": "x".repeat(254)}), json!({"query": 5}), json!({"other": 1}), json!([1])] {
            assert_eq!(Page::parse(bad.clone()).err().map(|e| e.0), Some("BAD_ARGS"), "{bad}");
        }
        let p = Page::parse(json!({"page": 2, "size": 3})).unwrap();
        assert_eq!(p.slice((1..=8).collect()), vec![4, 5, 6]);
        let p = Page::parse(json!({"page": 3, "size": 3})).unwrap();
        assert_eq!(p.slice((1..=8).collect()), vec![7, 8]);
        let p = Page::parse(json!({"page": 9, "size": 3})).unwrap();
        assert!(p.slice((1..=8).collect::<Vec<i32>>()).is_empty());
        let p = Page::parse(json!({"query": "shop"})).unwrap();
        assert!(p.matches(&["a.test", "shop1"]) && !p.matches(&["a.test", "olscpa"]));
    }

    #[test]
    fn status_digest_covers_the_state_not_the_time() {
        let base = json!({"ols_active": true, "apache_active": false, "active_generation": "r1", "cut_over": true,
                          "profile": {"production": true, "hybrid_ports": null}, "epoch": 3, "hybrid_vhosts": [],
                          "observed_at": 1, "pending_events": 0});
        let digest = status_digest(&base);
        assert_eq!(digest.len(), 64);
        let mut later = base.clone();
        later["observed_at"] = json!(99);
        later["pending_events"] = json!(5);
        assert_eq!(status_digest(&later), digest);
        for (key, value) in [("active_generation", json!("r2")), ("epoch", json!(4)), ("ols_active", json!(false)),
                             ("hybrid_vhosts", json!(["a.test"])), ("cut_over", json!(false))] {
            let mut changed = base.clone();
            changed[key] = value;
            assert_ne!(status_digest(&changed), digest, "{key}");
        }
    }

    #[test]
    fn status_extension_from_the_cli() {
        let temp = TempTree::new();
        let mut config = summary::tests::fixture().config;
        config.cli = product::tests::fake_cli(temp.path(), r#"echo '{"cut_over": false, "profile": null, "epoch": 2, "pending_events": 1, "hybrid_vhosts": [], "role": "root", "ports": {"80": "httpd"}}'"#);
        let panel = Panel::new(config, jobs::Limits::default());
        let ext = panel.status_extension();
        assert_eq!(Value::Object(ext), json!({"cut_over": false, "profile": null, "ports": {"80": "httpd"}, "epoch": 2, "pending_events": 1,
                                             "hybrid_vhosts": [], "cli": {"status": "ok", "exit_code": 0, "error": null}}));
        let mut missing = summary::tests::fixture().config;
        missing.cli = temp.path().join("missing");
        let ext = Panel::new(missing, jobs::Limits::default()).status_extension();
        assert_eq!(ext["epoch"], Value::Null);
        assert_eq!(ext["cli"], json!({"status": "unavailable", "exit_code": null, "error": "SPAWN_FAILED"}));
    }

    #[test]
    fn userdatadomains_rows_are_sanitized() {
        let temp = TempTree::new();
        let path = temp.path().join("userdatadomains");
        fs::write(&path, "b.test: olscpb==root==main==b.test==/home/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
                          a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==\n\
                          evil.test: ../x==root==main==evil.test==/home/x==1:80==1:443====0==\n\
                          short.test: olscpa==root==main\n").unwrap();
        let (rows, rejected) = domain_rows(&path);
        assert_eq!(rejected, 2);
        assert_eq!(rows.iter().map(|r| r["domain"].as_str().unwrap()).collect::<Vec<_>>(), ["a.test", "b.test"]);
        assert_eq!(rows[0]["php"], Value::Null);
        assert_eq!(rows[1]["php"], json!("ea-php83"));
    }

    #[test]
    fn bounded_reads_and_audit() {
        let temp = TempTree::new();
        let file = temp.path().join("f");
        fs::write(&file, "12345").unwrap();
        assert_eq!(read_bounded(&file, 5).unwrap(), b"12345");
        assert!(read_bounded(&file, 4).is_none());
        let link = temp.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_bounded(&link, 100).is_none());
        assert!(read_bounded(temp.path(), 100).is_none());
        let log = temp.path().join("audit.log");
        audit(&log, &json!({"a": 1})).unwrap();
        audit(&log, &json!({"b": 2})).unwrap();
        assert_eq!(fs::read_to_string(&log).unwrap(), "{\"a\":1}\n{\"b\":2}\n");
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
        assert!(audit(&link, &json!({})).is_err());
    }
}
