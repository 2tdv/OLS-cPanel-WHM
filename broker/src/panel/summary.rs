//! The compile summary the engine publishes (docs/product-interfaces.md, "Data the engine publishes"):
//! `summary.json` of the active generation, or the `summary` of the latest plan when no generation is
//! active. The views built on it: `inventory.accounts` (domains with engine, PHP handler, TLS and
//! suspension), `compat.findings`, `plan.latest` and the tenant's `tenant.sites`.
//!
//! Engine of a domain: its vhost (main and sub domains are vhosts; addon and parked domains are served by
//! their parent's vhost) in `hybrid_vhosts` is "hybrid", any other vhost of the summary is "ols"; a
//! domain the summary does not contain, or no summary at all, is "unknown". The top-level
//! `engine_source` says whether that came from the active generation or from a plan (not yet active).

use super::{certificate, domain_rows, now, read_bounded, sha256_hex, Config, Page, Reply};
use serde_json::{json, Map, Value};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// summary.json and plan files are read whole; a summary of tens of thousands of vhosts stays below this.
pub const MAX_SUMMARY: u64 = 64 << 20;

/// A plan id (`plans/<id>.json`, the scope of `ols.cutover`): `^[0-9A-Za-z_-]{1,64}$`.
pub fn valid_plan_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub struct Summary {
    /// "generation" or "plan".
    pub source: &'static str,
    /// The generation or plan id.
    pub id: String,
    pub path: PathBuf,
    pub value: Value,
}

impl Summary {
    pub fn vhost(&self, name: &str) -> Option<&Value> {
        self.value.get("vhosts").and_then(|v| v.get(name)).filter(|v| v.is_object())
    }

    pub fn hybrid(&self, name: &str) -> bool {
        self.value.get("hybrid_vhosts").and_then(Value::as_array).map_or(false, |l| l.iter().any(|v| v == name))
    }

    pub fn engine(&self, vhost: &str) -> &'static str {
        match self.vhost(vhost) {
            Some(_) if self.hybrid(vhost) => "hybrid",
            Some(_) => "ols",
            None => "unknown",
        }
    }

    pub fn php_handler(&self, vhost: &str) -> Value {
        self.vhost(vhost).and_then(|v| v.get("php_handler")).filter(|v| v.is_string()).cloned().unwrap_or(Value::Null)
    }

    pub fn describe(&self) -> Value {
        json!({"source": self.source, "id": self.id, "compiled_at": self.value.get("compiled_at").cloned().unwrap_or(Value::Null)})
    }
}

/// The file identity a cached summary was read from.
type Key = (PathBuf, u64, u64, i64, i64);

fn key(path: &Path) -> Option<Key> {
    let meta = fs::metadata(path).ok()?;
    Some((path.to_path_buf(), meta.ino(), meta.len(), meta.mtime(), meta.mtime_nsec()))
}

/// Plan files `plans/<id>.json`, newest first (modification time, then id).
pub fn plans(state: &Path) -> Vec<(String, PathBuf, i64)> {
    let mut found: Vec<(String, PathBuf, i64)> = fs::read_dir(state.join("plans"))
        .map(|entries| {
            entries.flatten().filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json").filter(|id| valid_plan_id(id))?.to_string();
                let meta = fs::symlink_metadata(e.path()).ok()?;
                meta.is_file().then(|| (id, e.path(), meta.mtime()))
            }).collect()
        })
        .unwrap_or_default();
    found.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.0.cmp(&a.0)));
    found
}

/// The summary a plan carries: its embedded `summary` object when present (the contract's form), else the
/// summary-shaped view of what `install --prepare` writes today (`vhosts`: names, `hybrid_vhosts`:
/// `[{"vhost", "reasons"}]`, `created`). A plan with neither is no summary.
fn plan_summary(plan: &Value) -> Option<Value> {
    if let Some(summary) = plan.get("summary").filter(|s| s.is_object()) {
        return Some(summary.clone());
    }
    let names = plan.get("vhosts")?.as_array()?;
    let mut vhosts = Map::new();
    for name in names.iter().filter_map(Value::as_str) {
        vhosts.insert(name.to_string(), json!({}));
    }
    let (mut hybrid, mut blockers) = (Vec::new(), Map::new());
    for entry in plan.get("hybrid_vhosts").and_then(Value::as_array).into_iter().flatten() {
        let (name, reasons) = match entry {
            Value::String(name) => (name.as_str(), json!([])),
            Value::Object(o) => (o.get("vhost").and_then(Value::as_str).unwrap_or(""), o.get("reasons").cloned().unwrap_or(json!([]))),
            _ => continue,
        };
        if !name.is_empty() {
            hybrid.push(json!(name));
            blockers.insert(name.to_string(), if reasons.is_array() { reasons } else { json!([]) });
        }
    }
    Some(json!({"vhosts": vhosts, "hybrid_vhosts": hybrid, "htaccess_blockers": blockers,
                "compiled_at": plan.get("created").cloned().unwrap_or(Value::Null)}))
}

fn json_object(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(bytes).ok().filter(Value::is_object)
}

/// Loads summaries and keeps the last one while its file is unchanged (tenant requests read it often).
pub struct Summaries {
    cache: Mutex<Option<(Key, Arc<Summary>)>>,
}

impl Default for Summaries {
    fn default() -> Self {
        Summaries { cache: Mutex::new(None) }
    }
}

impl Summaries {
    /// The active generation's summary.json, else the latest plan's `summary`, else None.
    pub fn current(&self, state: &Path) -> Option<Arc<Summary>> {
        let active = state.join("active");
        let generation = fs::read_link(&active).ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
        let candidate = match generation {
            Some(id) if key(&active.join("summary.json")).is_some() => Some(("generation", id, active.join("summary.json"))),
            _ => plans(state).into_iter().next().map(|(id, path, _)| ("plan", id, path)),
        }?;
        let (source, id, path) = candidate;
        let k = key(&path)?;
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((cached, summary)) = cache.as_ref() {
            if *cached == k && summary.id == id {
                return Some(Arc::clone(summary));
            }
        }
        let document = json_object(&read_bounded(&path, MAX_SUMMARY)?)?;
        let value = if source == "plan" { plan_summary(&document)? } else { document };
        let summary = Arc::new(Summary { source, id, path, value });
        *cache = Some((k, Arc::clone(&summary)));
        Some(summary)
    }
}

/// The vhost that serves a userdatadomains row: main and sub domains are vhosts, addon and parked
/// domains are served by their parent's.
pub fn vhost_of(row: &Value) -> &str {
    match row["type"].as_str() {
        Some("addon" | "parked") => row["parent"].as_str().unwrap_or(""),
        _ => row["domain"].as_str().unwrap_or(""),
    }
}

fn combined(config: &Config, vhost: &str) -> PathBuf {
    config.tls_dir.join(vhost).join("combined")
}

fn tls_present(config: &Config, vhost: &str) -> bool {
    fs::symlink_metadata(combined(config, vhost)).map_or(false, |m| m.is_file())
}

fn suspended(config: &Config, user: &str) -> bool {
    fs::symlink_metadata(config.suspended_dir.join(user)).is_ok()
}

fn engine_source(summary: &Option<Arc<Summary>>) -> Value {
    summary.as_ref().map_or(Value::Null, |s| s.describe())
}

/// One inventory row (shared by inventory.accounts and tenant.sites).
fn site(config: &Config, summary: &Option<Arc<Summary>>, row: &Value) -> Map<String, Value> {
    let vhost = vhost_of(row);
    let user = row["user"].as_str().unwrap_or("");
    let mut out = Map::new();
    for field in ["user", "domain", "type", "parent", "docroot"] {
        out.insert(field.into(), row[field].clone());
    }
    out.insert("vhost".into(), json!(vhost));
    out.insert("engine".into(), json!(summary.as_ref().map_or("unknown", |s| s.engine(vhost))));
    out.insert("php_version".into(), row["php"].clone());
    out.insert("php_handler".into(), summary.as_ref().map_or(Value::Null, |s| s.php_handler(vhost)));
    out.insert("suspended".into(), json!(suspended(config, user)));
    out
}

/// `inventory.accounts`: server-side search (domain, account, vhost) and paging over every domain.
pub fn inventory(config: &Config, summaries: &Summaries, args: Value) -> Reply {
    let page = Page::parse(args)?;
    let (rows, rejected) = domain_rows(&config.userdatadomains);
    let summary = summaries.current(&config.state);
    let matching: Vec<Value> = rows.into_iter()
        .filter(|r| page.matches(&[r["domain"].as_str().unwrap_or(""), r["user"].as_str().unwrap_or(""), vhost_of(r)]))
        .collect();
    let total = matching.len();
    let domains: Vec<Value> = page.slice(matching).iter().map(|row| {
        let mut out = site(config, &summary, row);
        out.insert("php".into(), row["php"].clone());
        out.insert("tls".into(), json!(tls_present(config, vhost_of(row))));
        Value::Object(out)
    }).collect();
    Ok(json!({"observed_at": now(), "source": config.userdatadomains.display().to_string(), "engine_source": engine_source(&summary),
              "total": total, "page": page.page, "size": page.size, "rejected_rows": rejected, "domains": domains}))
}

/// Ordered (text, explanation key) pairs for the blocker texts of HtaccessTranslator and the builder.
const BLOCKER_KEYS: &[(&str, &str)] = &[
    ("unsupported PHP handler", "php.handler"),
    (".htaccess scan incomplete", "htaccess.scan_incomplete"),
    (".htaccess is a symlink", "htaccess.symlink"),
    (".htaccess unreadable", "htaccess.unreadable"),
    ("unsafe path", "htaccess.unsafe_path"),
    ("unsupported Directory Privacy section", "htaccess.directory_privacy"),
    ("with unsupported body", "htaccess.section_body"),
    ("unsupported <", "htaccess.section_pattern"),
    ("unsupported access rule combination", "htaccess.access_rules"),
    ("unsupported Options", "htaccess.options"),
    ("unsupported conditional Header", "htaccess.conditional_header"),
    ("rewrite", "htaccess.rewrite"),
    ("Rewrite", "htaccess.rewrite"),
    ("unsupported directive", "htaccess.directive"),
];

/// One blocker text (`<directory uri>: <message>`) as a finding of the vhost with document root `docroot`.
pub fn finding(docroot: &str, text: &str) -> Value {
    let (uri, message) = match text.find("/: ") {
        Some(i) if text.starts_with('/') => (&text[..i + 1], &text[i + 3..]),
        _ => ("", text),
    };
    let key = BLOCKER_KEYS.iter().find(|(needle, _)| message.contains(needle)).map_or("htaccess.other", |(_, k)| k);
    // `directory` is relative to the document root; `file` only when the document root is known.
    let file = if uri.is_empty() || docroot.is_empty() { Value::Null } else {
        json!(format!("{}{uri}.htaccess", docroot.trim_end_matches('/')))
    };
    let directory = if uri.is_empty() { Value::Null } else { json!(uri) };
    let kind = if key.starts_with("php.") { "php" } else { "htaccess" };
    json!({"kind": kind, "severity": "blocker", "directory": directory, "file": file, "line": null, "key": key, "message": text})
}

/// `compat.findings`: per vhost of the summary, the .htaccess blockers (why it cannot be served natively)
/// and whether it is a hybrid vhost; vhosts without either are not listed.
pub fn compat(config: &Config, summaries: &Summaries, args: Value) -> Reply {
    let page = Page::parse(args)?;
    let summary = summaries.current(&config.state);
    let mut rows = Vec::new();
    if let Some(s) = &summary {
        let empty = Map::new();
        let vhosts = s.value.get("vhosts").and_then(Value::as_object).unwrap_or(&empty);
        for (name, v) in vhosts {
            let user = v.get("user").and_then(Value::as_str).unwrap_or("");
            let docroot = v.get("docroot").and_then(Value::as_str).unwrap_or("");
            let blockers: Vec<Value> = s.value.get("htaccess_blockers").and_then(|b| b.get(name)).and_then(Value::as_array)
                .map(|list| list.iter().filter_map(Value::as_str).map(|t| finding(docroot, t)).collect())
                .unwrap_or_default();
            let hybrid = s.hybrid(name);
            if (blockers.is_empty() && !hybrid) || !page.matches(&[name.as_str(), user]) {
                continue;
            }
            rows.push(json!({"vhost": name, "user": user, "docroot": docroot, "engine": s.engine(name), "hybrid": hybrid,
                             "findings": blockers}));
        }
    }
    let total = rows.len();
    Ok(json!({"observed_at": now(), "source": summary.as_ref().map(|s| s.path.display().to_string()),
              "engine_source": engine_source(&summary), "total": total, "page": page.page, "size": page.size,
              "vhosts": page.slice(rows)}))
}

/// The SHA-256 of a plan file (what `ols.cutover` binds to), or None when it is missing or unreadable.
pub fn plan_digest(state: &Path, id: &str) -> Option<String> {
    if !valid_plan_id(id) {
        return None;
    }
    read_bounded(&state.join("plans").join(format!("{id}.json")), MAX_SUMMARY).map(|bytes| sha256_hex(&bytes))
}

/// `plan.latest`: the newest plan with its digest, or `plan: null`.
pub fn latest_plan(config: &Config) -> Reply {
    let plan = plans(&config.state).into_iter().next().and_then(|(id, path, mtime)| {
        let bytes = read_bounded(&path, MAX_SUMMARY)?;
        let content = json_object(&bytes);
        Some(json!({"id": id, "digest": sha256_hex(&bytes), "modified_at": mtime, "valid": content.is_some(),
                    "content": content.unwrap_or(Value::Null)}))
    });
    Ok(json!({"observed_at": now(), "source": config.state.join("plans").display().to_string(), "plan": plan}))
}

/// `tenant.sites`: the caller's own domains only (`user` comes from SO_PEERCRED).
pub fn tenant_sites(config: &Config, summaries: &Summaries, user: &str) -> Reply {
    let (rows, _) = domain_rows(&config.userdatadomains);
    let summary = summaries.current(&config.state);
    let sites: Vec<Value> = rows.iter().filter(|r| r["user"] == json!(user)).map(|row| {
        let vhost = vhost_of(row);
        let mut out = site(config, &summary, row);
        out.remove("user");
        let present = tls_present(config, vhost);
        let not_after = if present {
            read_bounded(&combined(config, vhost), certificate::MAX_PEM)
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|text| certificate::not_after_pem(&text))
        } else {
            None
        };
        out.insert("tls".into(), json!({"present": present, "not_after": not_after}));
        Value::Object(out)
    }).collect();
    Ok(json!({"user": user, "observed_at": now(), "source": config.userdatadomains.display().to_string(),
              "engine_source": engine_source(&summary), "sites": sites}))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;

    pub const USERDATADOMAINS: &str = "\
a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83
shop.a.test: olscpa==root==sub==a.test==/home/olscpa/shop==1.2.3.4:80==1.2.3.4:443====0==ea-php82
addon.test: olscpa==root==addon==addon.a.test==/home/olscpa/addon==1.2.3.4:80==1.2.3.4:443====0==ea-php83
addon.a.test: olscpa==root==sub==a.test==/home/olscpa/addon==1.2.3.4:80==1.2.3.4:443====0==ea-php83
parked.test: olscpa==root==parked==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83
b.test: olscpb==root==main==b.test==/home/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83
new.b.test: olscpb==root==sub==b.test==/home/olscpb/new==1.2.3.4:80==1.2.3.4:443====0==ea-php83
";

    /// The shape ServerConfigurationBuilder::compile() gives `summary` (plus compiled_at).
    pub fn summary_json() -> Value {
        let vhost = |user: &str, kind: &str, docroot: &str, handler: &str| json!({"user": user, "type": kind, "docroot": docroot,
            "aliases": [], "php": "ea-php83", "php_handler": handler, "pool": "x", "service_domains": []});
        json!({
            "vhosts": {
                "a.test": vhost("olscpa", "main", "/home/olscpa/public_html", "fpm"),
                "shop.a.test": vhost("olscpa", "sub", "/home/olscpa/shop", "cgi"),
                "addon.a.test": vhost("olscpa", "sub", "/home/olscpa/addon", "fpm"),
                "b.test": vhost("olscpb", "main", "/home/olscpb/public_html", "fpm"),
            },
            "hybrid_vhosts": ["shop.a.test"],
            "htaccess_blockers": {
                "a.test": [],
                "shop.a.test": ["/: unsupported directive 'SetHandler x'", "/sub/: unsupported RewriteRule '^(.*)$ [P]'",
                                "/old/: .htaccess is a symlink"],
                "addon.a.test": [],
                "b.test": [],
            },
            "tls_sources": {"a.test": "/var/cpanel/ssl/apache_tls/a.test/combined"},
            "suspended_accounts": ["olscpb"],
            "missing_alias_dirs": {},
            "compiled_at": "2026-10-22T12:00:00Z",
        })
    }

    pub struct Fixture {
        pub temp: TempTree,
        pub config: Config,
    }

    pub fn fixture() -> Fixture {
        let temp = TempTree::new();
        let root = temp.path();
        let config = Config {
            state: root.join("state"),
            cli: root.join("ols-cpanel"),
            rtreport_dir: root.join("lshttpd"),
            tls_dir: root.join("apache_tls"),
            suspended_dir: root.join("suspended"),
            userdatadomains: root.join("userdatadomains"),
            audit_log: root.join("state/broker-audit.log"),
            domlogs: root.join("domlogs"),
            error_logs: root.join("vhostlogs"),
            requests: root.join("requests"),
            users_dir: root.join("cpusers"),
            curl: root.join("curl"),
            runuser: root.join("runuser"),
            tail: PathBuf::from("/usr/bin/tail"),
            find: PathBuf::from("/usr/bin/find"),
        };
        for dir in [&config.state, &config.tls_dir, &config.suspended_dir] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(&config.userdatadomains, USERDATADOMAINS).unwrap();
        Fixture { temp, config }
    }

    /// The active generation `gen` with this summary.
    pub fn activate(config: &Config, gen: &str, summary: &Value) {
        let dir = config.state.join("generations").join(gen);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("summary.json"), summary.to_string()).unwrap();
        let _ = fs::remove_file(config.state.join("active"));
        std::os::unix::fs::symlink(&dir, config.state.join("active")).unwrap();
    }

    pub fn write_plan(config: &Config, id: &str, summary: &Value, age: u64) -> String {
        let dir = config.state.join("plans");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{id}.json"));
        let text = json!({"id": id, "hybrid": true, "summary": summary}).to_string();
        fs::write(&path, &text).unwrap();
        let file = fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age)).unwrap();
        sha256_hex(text.as_bytes())
    }

    fn domains(reply: &Value) -> Vec<&str> {
        reply["domains"].as_array().unwrap().iter().map(|d| d["domain"].as_str().unwrap()).collect()
    }

    #[test]
    fn inventory_paging_search_and_engines() {
        let f = fixture();
        let summaries = Summaries::default();
        // No summary: every engine is unknown.
        let all = inventory(&f.config, &summaries, Value::Null).unwrap();
        assert_eq!(all["total"], json!(7));
        assert_eq!(all["engine_source"], Value::Null);
        assert!(all["domains"].as_array().unwrap().iter().all(|d| d["engine"] == json!("unknown") && d["php_handler"].is_null()));
        // The latest plan when no generation is active.
        write_plan(&f.config, "p-old", &json!({"vhosts": {}}), 100);
        write_plan(&f.config, "p-new", &summary_json(), 10);
        let planned = inventory(&f.config, &summaries, json!({"query": "a.test"})).unwrap();
        assert_eq!(planned["engine_source"]["source"], json!("plan"));
        assert_eq!(planned["engine_source"]["id"], json!("p-new"));
        // The active generation wins over plans.
        let mut active = summary_json();
        active["hybrid_vhosts"] = json!([]);
        activate(&f.config, "r20261022120000-a1b2c3", &active);
        fs::create_dir_all(f.config.tls_dir.join("a.test")).unwrap();
        fs::write(f.config.tls_dir.join("a.test/combined"), "x").unwrap();
        fs::write(f.config.suspended_dir.join("olscpb"), "").unwrap();
        let all = inventory(&f.config, &summaries, json!({})).unwrap();
        assert_eq!(all["engine_source"], json!({"source": "generation", "id": "r20261022120000-a1b2c3", "compiled_at": "2026-10-22T12:00:00Z"}));
        assert_eq!(domains(&all), ["a.test", "addon.a.test", "addon.test", "b.test", "new.b.test", "parked.test", "shop.a.test"]);
        let by_name = |name: &str| all["domains"].as_array().unwrap().iter().find(|d| d["domain"] == json!(name)).unwrap().clone();
        let a = by_name("a.test");
        assert_eq!((a["engine"].as_str(), a["php_handler"].as_str(), a["tls"].as_bool(), a["suspended"].as_bool()),
                   (Some("ols"), Some("fpm"), Some(true), Some(false)));
        // Parked and addon domains take their parent vhost's engine, handler and certificate.
        assert_eq!(by_name("parked.test")["vhost"], json!("a.test"));
        assert_eq!(by_name("parked.test")["tls"], json!(true));
        assert_eq!(by_name("addon.test")["vhost"], json!("addon.a.test"));
        assert_eq!(by_name("addon.test")["engine"], json!("ols"));
        assert_eq!(by_name("b.test")["suspended"], json!(true));
        // A domain the summary does not know (added after the last compile).
        assert_eq!(by_name("new.b.test")["engine"], json!("unknown"));
        // Search over domain, account and vhost; paging.
        assert_eq!(domains(&inventory(&f.config, &summaries, json!({"query": "OLSCPB"})).unwrap()), ["b.test", "new.b.test"]);
        assert_eq!(domains(&inventory(&f.config, &summaries, json!({"query": "addon.a"})).unwrap()), ["addon.a.test", "addon.test"]);
        let page = inventory(&f.config, &summaries, json!({"page": 2, "size": 3})).unwrap();
        assert_eq!((page["total"].as_u64(), page["page"].as_u64(), page["size"].as_u64()), (Some(7), Some(2), Some(3)));
        assert_eq!(domains(&page), ["b.test", "new.b.test", "parked.test"]);
        assert!(domains(&inventory(&f.config, &summaries, json!({"page": 4, "size": 3})).unwrap()).is_empty());
        assert_eq!(inventory(&f.config, &summaries, json!({"size": 500})).unwrap_err().0, "BAD_ARGS");
        assert_eq!(inventory(&f.config, &summaries, json!({"user": "olscpb"})).unwrap_err().0, "BAD_ARGS");
        // The hybrid list of the active summary decides.
        activate(&f.config, "r20261022130000-a1b2c3", &summary_json());
        let hybrid = inventory(&f.config, &summaries, json!({"query": "shop"})).unwrap();
        assert_eq!(hybrid["domains"][0]["engine"], json!("hybrid"));
        assert_eq!(hybrid["domains"][0]["php_handler"], json!("cgi"));
    }

    #[test]
    fn summaries_are_cached_until_the_file_changes() {
        let f = fixture();
        let summaries = Summaries::default();
        assert!(summaries.current(&f.config.state).is_none());
        activate(&f.config, "r20261022120000-a1b2c3", &summary_json());
        let first = summaries.current(&f.config.state).unwrap();
        assert!(Arc::ptr_eq(&first, &summaries.current(&f.config.state).unwrap()));
        activate(&f.config, "r20261022130000-a1b2c3", &json!({"vhosts": {}}));
        let second = summaries.current(&f.config.state).unwrap();
        assert_eq!(second.id, "r20261022130000-a1b2c3");
        assert!(second.vhost("a.test").is_none());
        // A malformed summary is no summary (engine unknown), never a partial one.
        fs::write(f.config.state.join("active/summary.json"), "{not json").unwrap();
        assert!(summaries.current(&f.config.state).is_none());
        // A plan without an embedded summary is not used.
        fs::remove_file(f.config.state.join("active")).unwrap();
        fs::create_dir_all(f.config.state.join("plans")).unwrap();
        fs::write(f.config.state.join("plans/p1.json"), "{\"id\": \"p1\"}").unwrap();
        assert!(summaries.current(&f.config.state).is_none());
    }

    #[test]
    fn compat_findings() {
        let f = fixture();
        let summaries = Summaries::default();
        let none = compat(&f.config, &summaries, Value::Null).unwrap();
        assert_eq!((none["total"].as_u64(), none["source"].is_null()), (Some(0), true));
        activate(&f.config, "r20261022120000-a1b2c3", &summary_json());
        let out = compat(&f.config, &summaries, json!({})).unwrap();
        assert_eq!(out["total"], json!(1));
        let vhost = &out["vhosts"][0];
        assert_eq!((vhost["vhost"].as_str(), vhost["engine"].as_str(), vhost["hybrid"].as_bool()), (Some("shop.a.test"), Some("hybrid"), Some(true)));
        let findings = vhost["findings"].as_array().unwrap();
        assert_eq!(findings[0], json!({"kind": "htaccess", "severity": "blocker", "directory": "/", "file": "/home/olscpa/shop/.htaccess", "line": null,
                                       "key": "htaccess.directive", "message": "/: unsupported directive 'SetHandler x'"}));
        assert_eq!(findings[1]["file"], json!("/home/olscpa/shop/sub/.htaccess"));
        assert_eq!(findings[1]["key"], json!("htaccess.rewrite"));
        assert_eq!(findings[2]["key"], json!("htaccess.symlink"));
        assert_eq!(compat(&f.config, &summaries, json!({"query": "olscpb"})).unwrap()["total"], json!(0));
        assert_eq!(compat(&f.config, &summaries, json!({"query": "olscpa", "page": 2, "size": 1})).unwrap()["vhosts"], json!([]));
        assert_eq!(compat(&f.config, &summaries, json!({"query": "a b"})).unwrap_err().0, "BAD_ARGS");
        // Every blocker text the translator and the builder produce has its own key.
        for (text, key) in [("/: unsafe path", "htaccess.unsafe_path"), ("/x/: unsupported Directory Privacy section", "htaccess.directory_privacy"),
                            ("/: <Files x> with unsupported body", "htaccess.section_body"), ("/: unsupported <Files> pattern 'x'", "htaccess.section_pattern"),
                            ("/: unsupported access rule combination ['deny']", "htaccess.access_rules"), ("/: unsupported Options '+x'", "htaccess.options"),
                            ("/: unsupported conditional Header 'x'", "htaccess.conditional_header"), ("/: rewrite line with control characters", "htaccess.rewrite"),
                            ("/: rewrite directives without RewriteEngine", "htaccess.rewrite"), ("/: unsupported RewriteBase 'x'", "htaccess.rewrite"),
                            ("/: .htaccess scan incomplete (find: x)", "htaccess.scan_incomplete"), ("/a/: .htaccess unreadable", "htaccess.unreadable"),
                            ("something new", "htaccess.other")] {
            assert_eq!(finding("/home/u/public_html/", text)["key"], json!(key), "{text}");
        }
        assert_eq!(finding("/d", "something new")["file"], Value::Null);
    }

    #[test]
    fn plans_as_install_prepare_writes_them() {
        // CutoverPlan::prepare: vhost names and hybrid vhosts with their reasons, no embedded summary.
        let f = fixture();
        let summaries = Summaries::default();
        fs::create_dir_all(f.config.state.join("plans")).unwrap();
        fs::write(f.config.state.join("plans/p20261022120000-a1b2c3.json"), json!({
            "schema_version": 1, "id": "p20261022120000-a1b2c3", "created": "2026-10-22T12:00:00+00:00",
            "profile": {"production": true, "hybrid_ports": [81, 444]},
            "hybrid_vhosts": [{"vhost": "shop.a.test", "reasons": ["/: unsupported directive 'SetHandler x'", "unsupported PHP handler 'dso'"]}],
            "vhost_count": 4, "vhosts": ["a.test", "addon.a.test", "b.test", "shop.a.test"]}).to_string()).unwrap();
        let inv = inventory(&f.config, &summaries, json!({"size": 200})).unwrap();
        assert_eq!(inv["engine_source"], json!({"source": "plan", "id": "p20261022120000-a1b2c3", "compiled_at": "2026-10-22T12:00:00+00:00"}));
        let engines: Vec<(&str, &str)> = inv["domains"].as_array().unwrap().iter()
            .map(|d| (d["domain"].as_str().unwrap(), d["engine"].as_str().unwrap())).collect();
        assert_eq!(engines, [("a.test", "ols"), ("addon.a.test", "ols"), ("addon.test", "ols"), ("b.test", "ols"),
                             ("new.b.test", "unknown"), ("parked.test", "ols"), ("shop.a.test", "hybrid")]);
        let out = compat(&f.config, &summaries, Value::Null).unwrap();
        assert_eq!(out["total"], json!(1));
        let findings = &out["vhosts"][0]["findings"];
        assert_eq!((findings[0]["kind"].as_str(), findings[0]["key"].as_str(), findings[0]["directory"].as_str(), findings[0]["file"].clone()),
                   (Some("htaccess"), Some("htaccess.directive"), Some("/"), Value::Null));
        assert_eq!((findings[1]["kind"].as_str(), findings[1]["key"].as_str(), findings[1]["file"].clone()),
                   (Some("php"), Some("php.handler"), Value::Null));
    }

    #[test]
    fn plans_and_digests() {
        let f = fixture();
        assert_eq!(latest_plan(&f.config).unwrap()["plan"], Value::Null);
        write_plan(&f.config, "p1", &summary_json(), 50);
        let digest = write_plan(&f.config, "p2", &summary_json(), 5);
        // Names that are not plan ids are never listed or read.
        fs::write(f.config.state.join("plans/bad name.json"), "{}").unwrap();
        fs::write(f.config.state.join("plans/notes.txt"), "{}").unwrap();
        std::os::unix::fs::symlink(f.config.state.join("plans/p1.json"), f.config.state.join("plans/p9.json")).unwrap();
        let latest = latest_plan(&f.config).unwrap();
        assert_eq!(latest["plan"]["id"], json!("p2"));
        assert_eq!(latest["plan"]["digest"], json!(digest));
        assert_eq!(latest["plan"]["valid"], json!(true));
        assert_eq!(latest["plan"]["content"]["summary"]["hybrid_vhosts"], json!(["shop.a.test"]));
        assert_eq!(plan_digest(&f.config.state, "p2"), Some(digest));
        assert_eq!(plan_digest(&f.config.state, "missing"), None);
        assert_eq!(plan_digest(&f.config.state, "../p2"), None);
        for good in ["p1", "PLAN_2026-10-22", &"a".repeat(64)] {
            assert!(valid_plan_id(good), "{good}");
        }
        for bad in ["", "a b", "a/b", "..", "a.json", &"a".repeat(65), "p\n"] {
            assert!(!valid_plan_id(bad), "{bad}");
        }
    }

    #[test]
    fn tenant_sites_are_the_callers_only() {
        let f = fixture();
        let summaries = Summaries::default();
        activate(&f.config, "r20261022120000-a1b2c3", &summary_json());
        fs::create_dir_all(f.config.tls_dir.join("a.test")).unwrap();
        let key = format!("-----BEGIN {0} KEY-----\nAAAA\n-----END {0} KEY-----\n", "PRIVATE");
        fs::write(f.config.tls_dir.join("a.test/combined"), format!("{key}{}", certificate::tests::UTC_TIME)).unwrap();
        fs::create_dir_all(f.config.tls_dir.join("b.test")).unwrap();
        fs::write(f.config.tls_dir.join("b.test/combined"), "not a certificate").unwrap();
        let a = tenant_sites(&f.config, &summaries, "olscpa").unwrap();
        assert_eq!(a["user"], json!("olscpa"));
        let sites = a["sites"].as_array().unwrap();
        assert_eq!(sites.iter().map(|s| s["domain"].as_str().unwrap()).collect::<Vec<_>>(),
                   ["a.test", "addon.a.test", "addon.test", "parked.test", "shop.a.test"]);
        assert_eq!(sites[0]["tls"], json!({"present": true, "not_after": certificate::tests::UTC_TIME_NOT_AFTER}));
        assert_eq!(sites[0]["php_version"], json!("ea-php83"));
        assert_eq!(sites[3]["tls"]["present"], json!(true)); // parked on a.test
        assert_eq!(sites[1]["tls"], json!({"present": false, "not_after": null}));
        assert_eq!(sites[4]["engine"], json!("hybrid"));
        assert!(sites.iter().all(|s| s.get("user").is_none()));
        // Nothing of the key reaches the reply.
        assert!(!a.to_string().contains("AAAA"));
        let b = tenant_sites(&f.config, &summaries, "olscpb").unwrap();
        assert_eq!(b["sites"][0]["tls"], json!({"present": true, "not_after": null}));
        assert_eq!(b["sites"].as_array().unwrap().len(), 2);
        assert_eq!(tenant_sites(&f.config, &summaries, "nobody").unwrap()["sites"], json!([]));
    }
}
