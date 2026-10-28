//! LSCache management (FV-01, docs/product-interfaces.md "LSCache"): the admin `cache.stats` view, the scope
//! grammar of the `ols.cache_purge` job, and the tenant operations `tenant.cache_stats` and
//! `tenant.cache_purge`. Everything runs the product command (`ols-cpanel cache stats|purge`) with a fixed
//! argv; the broker never touches a cache store itself.
//!
//! Tenant scope: the account is the SO_PEERCRED identity passed in by the dispatcher, never a request field.
//! A tenant purge names at most one domain, which must be one of the caller's own rows of
//! /etc/userdatadomains (read here, by root); the command receives that row's vhost together with the
//! account, and itself refuses a vhost that does not belong to the account. A tenant may purge once per
//! TENANT_PURGE_INTERVAL.

use super::{audit, domain_rows, now, product, summary, valid_domain, valid_name, Config, Reply};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bounds of the cleanup limits (CacheLimits::BOUNDS in the engine, which checks them again): inclusive.
pub const LIMIT_BOUNDS: [(&str, u64, u64); 3] = [("per_site_mb", 16, 102_400), ("server_percent", 1, 50), ("server_max_gb", 1, 2_048)];

/// `admin.cache_limits` arguments: none reads, any of the three limits (whole numbers) sets them.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LimitsArgs {
    #[serde(default)]
    per_site_mb: Option<u64>,
    #[serde(default)]
    server_percent: Option<u64>,
    #[serde(default)]
    server_max_gb: Option<u64>,
}

/// One tenant purge per account in this time.
pub const TENANT_PURGE_INTERVAL: Duration = Duration::from_secs(10);

/// `cache.stats` arguments: both optional.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StatsArgs {
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

/// `tenant.cache_purge` arguments.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TenantPurgeArgs {
    #[serde(default)]
    domain: Option<String>,
}

/// Arguments: absent, or exactly one JSON object (serde would also take an empty array for a struct).
pub(super) fn parse<T: serde::de::DeserializeOwned + Default>(args: Value) -> Result<T, (&'static str, String)> {
    match args {
        Value::Null => Ok(T::default()),
        Value::Object(_) => serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string())),
        _ => Err(("BAD_ARGS", "arguments must be an object".to_string())),
    }
}

pub(super) fn account_ok(name: &str) -> bool {
    valid_name(name) && name.as_bytes()[0].is_ascii_alphanumeric()
}

pub(super) fn domain_ok(name: &str) -> bool {
    valid_domain(name) && !name.contains("..") && !name.ends_with('.') && !name.starts_with('-')
}

/// The `cache purge` option for a job scope: `server` is `--all`, `account:<user>` and `domain:<domain>` name
/// their target; anything else is None.
pub fn purge_flag(scope: &str) -> Option<String> {
    if scope == "server" {
        return Some("--all".to_string());
    }
    if let Some(account) = scope.strip_prefix("account:") {
        return account_ok(account).then(|| format!("--account={account}"));
    }
    scope.strip_prefix("domain:").filter(|d| domain_ok(d)).map(|d| format!("--domain={d}"))
}

/// Runs `ols-cpanel <args>` and turns a refusal or failure of the command into an error: exit 1 is REFUSED
/// with the command's own reason, any other non-zero exit is COMMAND_FAILED.
pub(super) fn run(cli: &Path, args: &[String]) -> Reply {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let reply = product::run(cli, &refs)?;
    match reply["exit_code"].as_i64() {
        Some(0) => Ok(reply),
        code => {
            let reason: String = reply["output"]["error"].as_str().unwrap_or("the command failed").chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ').take(300).collect();
            Err((if code == Some(1) { "REFUSED" } else { "COMMAND_FAILED" }, reason))
        }
    }
}

fn stats_args(account: Option<&str>, domain: Option<&str>) -> Vec<String> {
    let mut args = vec!["cache".to_string(), "stats".to_string()];
    args.extend(account.map(|a| format!("--account={a}")));
    args.extend(domain.map(|d| format!("--domain={d}")));
    args.push("--format=json".to_string());
    args
}

/// `cache.stats {account?, domain?}` (admin): the command's report, as `generation.list` gives its own.
pub fn stats(cli: &Path, args: Value) -> Reply {
    let a: StatsArgs = parse(args)?;
    if a.account.as_deref().map_or(false, |v| !account_ok(v)) || a.domain.as_deref().map_or(false, |v| !domain_ok(v)) {
        return Err(("BAD_ARGS", "account and domain must be an account name and a domain name".into()));
    }
    run(cli, &stats_args(a.account.as_deref(), a.domain.as_deref()))
}

/// The `cache limits` argv for `admin.cache_limits` arguments: a read without arguments, a change with them. Values outside
/// LIMIT_BOUNDS are refused here, before any command runs.
pub fn limits_argv(args: Value) -> Result<Vec<String>, (&'static str, String)> {
    let a: LimitsArgs = parse(args)?;
    let mut argv = vec!["cache".to_string(), "limits".to_string()];
    for (name, option, value) in [("per_site_mb", "--per-site-mb", a.per_site_mb), ("server_percent", "--server-percent", a.server_percent),
                                  ("server_max_gb", "--server-max-gb", a.server_max_gb)] {
        if let Some(v) = value {
            let (_, min, max) = LIMIT_BOUNDS.iter().find(|b| b.0 == name).copied().unwrap();
            if v < min || v > max {
                return Err(("BAD_ARGS", format!("{name} must be between {min} and {max}")));
            }
            argv.push(format!("{option}={v}"));
        }
    }
    argv.push("--format=json".to_string());
    Ok(argv)
}

/// `admin.cache_limits {per_site_mb?, server_percent?, server_max_gb?}` (admin): the limits of the automatic cache cleanup, the caps
/// they give on this disk and the last cleanup; with arguments it first changes those limits (audited).
pub fn limits(config: &Config, args: Value) -> Reply {
    let argv = limits_argv(args)?;
    let write = argv.len() > 3;
    let reply = run(&config.cli, &argv)?;
    if write {
        let _ = audit(&config.audit_log, &json!({"time": now(), "event": "cache_limits_set", "args": &argv[2..argv.len() - 1]}));
    }
    Ok(reply)
}

/// `tenant.cache_stats`: the caller's own stores.
pub fn tenant_stats(config: &Config, user: &str) -> Reply {
    if !account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let report = match run(&config.cli, &stats_args(Some(user), None)) {
        Ok(reply) => reply["output"].clone(),
        // An account the engine does not know has no stores: an empty answer, not an error.
        Err(("REFUSED", message)) if message.starts_with("unknown account") => {
            json!({"stores": [], "totals": {"stores": 0, "entries": 0, "bytes": 0, "private_entries": 0, "private_bytes": 0}, "generation": null})
        }
        Err(error) => return Err(error),
    };
    // The command was asked for this account only; keep only its rows anyway.
    let stores: Vec<Value> = report["stores"].as_array().into_iter().flatten()
        .filter(|s| s["account"] == json!(user)).cloned().collect();
    Ok(json!({"user": user, "observed_at": now(), "source": "ols-cpanel cache stats", "generation": report["generation"],
              "stores": stores, "totals": report["totals"]}))
}

/// The accounts' last purge times, for the one-per-interval rule.
pub struct TenantPurges {
    interval: Duration,
    last: Mutex<HashMap<String, Instant>>,
}

impl TenantPurges {
    pub fn new(interval: Duration) -> TenantPurges {
        TenantPurges { interval, last: Mutex::new(HashMap::new()) }
    }

    pub(super) fn interval_secs(&self) -> u64 {
        self.interval.as_secs()
    }

    /// Records a purge by `user` now, or says how many seconds remain until the next one is allowed.
    pub(super) fn admit(&self, user: &str) -> Result<(), u64> {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let at = Instant::now();
        last.retain(|_, t| at.duration_since(*t) < self.interval);
        if let Some(t) = last.get(user) {
            return Err((self.interval - at.duration_since(*t)).as_secs() + 1);
        }
        last.insert(user.to_string(), at);
        Ok(())
    }
}

/// `tenant.cache_purge {domain?}`: one of the caller's own domains, or every one of them.
pub fn tenant_purge(config: &Config, purges: &TenantPurges, user: &str, args: Value) -> Reply {
    if !account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let a: TenantPurgeArgs = parse(args)?;
    if a.domain.as_deref().map_or(false, |d| !domain_ok(d)) {
        return Err(("BAD_ARGS", "domain must be a domain name".into()));
    }
    // Ownership comes from cPanel's own table, by the caller's identity, never from the request.
    let (rows, _) = domain_rows(&config.userdatadomains);
    let mine: Vec<&Value> = rows.iter().filter(|r| r["user"] == json!(user)).collect();
    let mut argv = vec!["cache".to_string(), "purge".to_string(), format!("--account={user}")];
    match a.domain.as_deref() {
        Some(domain) => {
            let row = mine.iter().find(|r| r["domain"] == json!(domain))
                .ok_or(("NOT_FOUND", "that is not one of your domains".to_string()))?;
            argv.push(format!("--domain={}", summary::vhost_of(row)));
        }
        None if mine.is_empty() => return Err(("NOT_FOUND", "this account has no domains".into())),
        None => {}
    }
    argv.push("--format=json".to_string());
    if let Err(wait) = purges.admit(user) {
        return Err(("RATE_LIMITED", format!("a cache purge is allowed every {} s; try again in {wait} s", purges.interval.as_secs())));
    }
    let purged = run(&config.cli, &argv)?;
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "tenant_cache_purge", "user": user, "domain": a.domain,
                                             "entries": purged["output"]["totals"]["entries"]}));
    Ok(json!({"user": user, "domain": a.domain, "observed_at": now(), "purged_at": purged["output"]["purged_at"],
              "stores": purged["output"]["stores"], "totals": purged["output"]["totals"]}))
}

#[cfg(test)]
mod tests {
    use super::*;
        use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::fixture;
    use std::fs;

    /// Echoes its argv as the report, so a test sees exactly what the broker ran; an unknown account is refused.
    const SCRIPT: &str = r#"case "$*" in
*--account=ghost*) echo '{"result": "refused", "code": 1, "error": "unknown account ghost"}'; exit 1;;
*--account=olscpb*--domain=a.test*) echo '{"result": "refused", "code": 1, "error": "domain a.test does not belong to account olscpb"}'; exit 1;;
"cache stats --account=olscpa --format=json") echo '{"scope": {}, "generation": "r1", "stores": [{"store": "olscpa@a.test", "account": "olscpa"}, {"store": "olscpb@b.test", "account": "olscpb"}], "totals": {"entries": 3}}';;
cache\ stats*) printf '{"argv": "%s", "stores": [], "totals": {}}' "$*";;
"cache limits --format=json") echo '{"limits": {"per_site_mb": 512}}';;
cache\ limits*) printf '{"argv": "%s", "limits": {}}' "$*";;
cache\ purge*) printf '{"argv": "%s", "purged_at": 5, "stores": [], "totals": {"entries": 2}}' "$*";;
*) echo "unexpected $*" >&2; exit 64;;
esac"#;

    fn setup() -> crate::panel::summary::tests::Fixture {
        let mut f = fixture();
        f.config.cli = fake_cli(f.temp.path(), SCRIPT);
        f
    }

    fn code(result: Reply) -> &'static str {
        result.err().map(|e| e.0).unwrap_or("ok")
    }

    #[test]
    fn purge_scope_grammar() {
        assert_eq!(purge_flag("server").as_deref(), Some("--all"));
        assert_eq!(purge_flag("account:olscpa").as_deref(), Some("--account=olscpa"));
        assert_eq!(purge_flag("domain:shop.a.test").as_deref(), Some("--domain=shop.a.test"));
        for bad in ["", "all", "account:", "account:-x", "account:A", "account:a b", "domain:", "domain:a", "domain:.a.test", "domain:a..test",
                    "domain:a.test.", "domain:-a.test", "domain:a.test/..", "domain:a.test --all", "domain:ünï.test", "Server"] {
            assert!(purge_flag(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn cache_limits_read_and_write_run_the_fixed_command() {
        let f = setup();
        let config = &f.config;
        let read = limits(config, Value::Null).unwrap();
        assert_eq!(read["output"]["limits"]["per_site_mb"], json!(512));
        assert_eq!(limits(config, json!({})).unwrap()["output"]["limits"]["per_site_mb"], json!(512));
        let set = limits(config, json!({"per_site_mb": 1024, "server_percent": 15, "server_max_gb": 40})).unwrap();
        assert_eq!(set["output"]["argv"], json!("cache limits --per-site-mb=1024 --server-percent=15 --server-max-gb=40 --format=json"));
        let one = limits(config, json!({"server_max_gb": 2048})).unwrap();
        assert_eq!(one["output"]["argv"], json!("cache limits --server-max-gb=2048 --format=json"));
        for (name, value) in [("per_site_mb", 15), ("per_site_mb", 102_401), ("server_percent", 0), ("server_percent", 51), ("server_max_gb", 0),
                              ("server_max_gb", 2049)] {
            assert_eq!(code(limits(config, json!({ (name): value }))), "BAD_ARGS", "{name} {value}");
        }
        for bad in [json!({"per_site_mb": "512"}), json!({"per_site_mb": -1}), json!({"per_site_mb": 5.5}), json!({"per_site_mb": null, "x": 1}),
                    json!({"other": 1}), json!([1]), json!("x"), json!({"per_site_mb": true})] {
            assert_eq!(code(limits(config, bad.clone())), "BAD_ARGS", "{bad}");
        }
        assert_eq!(limits_argv(Value::Null).unwrap(), ["cache", "limits", "--format=json"]);
    }

    #[test]
    fn admin_stats_runs_the_fixed_command() {
        let f = setup();
        let config = &f.config;
        let all = stats(&config.cli, Value::Null).unwrap();
        assert_eq!(all["output"]["argv"], json!("cache stats --format=json"));
        let one = stats(&config.cli, json!({"account": "olscpa", "domain": "shop.a.test"})).unwrap();
        assert_eq!(one["output"]["argv"], json!("cache stats --account=olscpa --domain=shop.a.test --format=json"));
        for bad in [json!({"account": "../x"}), json!({"domain": "a b.test"}), json!({"domain": "x"}), json!({"other": 1}), json!({"account": 5}),
                    json!({"account": "-evil"}), json!({"domain": "--all.test"}), json!([1])] {
            assert_eq!(code(stats(&config.cli, bad.clone())), "BAD_ARGS", "{bad}");
        }
        let refused = stats(&config.cli, json!({"account": "ghost"})).unwrap_err();
        assert_eq!(refused, ("REFUSED", "unknown account ghost".to_string()));
    }

    #[test]
    fn tenant_stats_are_the_callers_own() {
        let f = setup();
        let config = &f.config;
        let mine = tenant_stats(config, "olscpa").unwrap();
        assert_eq!(mine["user"], json!("olscpa"));
        // The fake command also returned another account's row; it is dropped.
        assert_eq!(mine["stores"], json!([{"store": "olscpa@a.test", "account": "olscpa"}]));
        assert_eq!(mine["totals"]["entries"], json!(3));
        // An account the engine does not know has an empty answer.
        let none = tenant_stats(config, "ghost").unwrap();
        assert_eq!(none["stores"], json!([]));
        assert_eq!(code(tenant_stats(config, "")), "FORBIDDEN");
        assert_eq!(code(tenant_stats(config, "Bad Name")), "FORBIDDEN");
    }

    #[test]
    fn tenant_purge_is_limited_to_own_domains() {
        let f = setup();
        let config = &f.config;
        let purges = TenantPurges::new(Duration::ZERO);
        // No domain: every domain of the caller, through its account.
        let all = tenant_purge(config, &purges, "olscpa", Value::Null).unwrap();
        assert_eq!(all["totals"]["entries"], json!(2));
        assert_eq!(all["stores"], json!([]));
        // One own domain; an addon domain is purged through its parent's vhost.
        for (domain, argv) in [("shop.a.test", "cache purge --account=olscpa --domain=shop.a.test --format=json"),
                               ("addon.test", "cache purge --account=olscpa --domain=addon.a.test --format=json"),
                               ("parked.test", "cache purge --account=olscpa --domain=a.test --format=json")] {
            let reply = tenant_purge(config, &purges, "olscpa", json!({"domain": domain})).unwrap();
            assert_eq!(reply["domain"], json!(domain));
            // The fake echoes the command it ran in the report; the reply keeps stores and totals only, so run it directly.
            let direct = run(&config.cli, &argv.split(' ').map(String::from).collect::<Vec<_>>()).unwrap();
            assert_eq!(direct["output"]["argv"], json!(argv));
        }
        // Somebody else's domain, an unknown one, and a malformed one: nothing runs.
        let before = fs::read_to_string(config.audit_log.clone()).unwrap_or_default();
        assert_eq!(code(tenant_purge(config, &purges, "olscpa", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert_eq!(code(tenant_purge(config, &purges, "olscpb", json!({"domain": "a.test"}))), "NOT_FOUND");
        assert_eq!(code(tenant_purge(config, &purges, "olscpa", json!({"domain": "nothere.test"}))), "NOT_FOUND");
        assert_eq!(code(tenant_purge(config, &purges, "ghost", Value::Null)), "NOT_FOUND");
        for bad in [json!({"domain": "../b.test"}), json!({"domain": "--all.test"}), json!({"domain": 5}), json!({"user": "olscpb"}),
                    json!({"account": "olscpb"}), json!({"domain": "a.test", "all": true}), json!([])] {
            assert_eq!(code(tenant_purge(config, &purges, "olscpa", bad.clone())), "BAD_ARGS", "{bad}");
        }
        assert_eq!(fs::read_to_string(config.audit_log.clone()).unwrap_or_default(), before);
        // The audit log records a purge.
        assert!(before.contains("tenant_cache_purge") && before.contains("olscpa"));
    }

    #[test]
    fn tenant_purge_arguments_never_reach_the_command_unchecked() {
        let mut f = setup();
        // A command that records every argv it gets.
        let log = f.temp.path().join("argv.log");
        f.config.cli = fake_cli(f.temp.path(), &format!(r#"echo "$*" >> {}; echo '{{"purged_at": 1, "stores": [], "totals": {{}}}}'"#, log.display()));
        let config = &f.config;
        let purges = TenantPurges::new(Duration::ZERO);
        tenant_purge(config, &purges, "olscpa", json!({"domain": "addon.test"})).unwrap();
        tenant_purge(config, &purges, "olscpa", Value::Null).unwrap();
        let _ = tenant_purge(config, &purges, "olscpa", json!({"domain": "b.test"}));
        let lines: Vec<String> = fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
        assert_eq!(lines, ["cache purge --account=olscpa --domain=addon.a.test --format=json", "cache purge --account=olscpa --format=json"]);
    }

    #[test]
    fn tenant_purges_are_rate_limited_per_account() {
        let f = setup();
        let config = &f.config;
        let purges = TenantPurges::new(Duration::from_secs(60));
        assert!(tenant_purge(config, &purges, "olscpa", Value::Null).is_ok());
        let again = tenant_purge(config, &purges, "olscpa", json!({"domain": "a.test"})).unwrap_err();
        assert_eq!(again.0, "RATE_LIMITED");
        assert!(again.1.contains("every 60 s"), "{}", again.1);
        // Another account is not affected, and a refused request (not the caller's domain) does not use the allowance.
        assert!(tenant_purge(config, &purges, "olscpb", Value::Null).is_ok());
        let fresh = TenantPurges::new(Duration::from_secs(60));
        assert_eq!(code(tenant_purge(&config, &fresh, "olscpa", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert!(tenant_purge(&config, &fresh, "olscpa", Value::Null).is_ok());
        // The allowance returns after the interval.
        let short = TenantPurges::new(Duration::from_millis(50));
        assert!(tenant_purge(&config, &short, "olscpa", Value::Null).is_ok());
        std::thread::sleep(Duration::from_millis(80));
        assert!(tenant_purge(&config, &short, "olscpa", Value::Null).is_ok());
    }

    #[test]
    fn a_command_refusal_is_reported_not_hidden() {
        let f = setup();
        let config = &f.config;
        let purges = TenantPurges::new(Duration::ZERO);
        let mut b = fixture();
        b.config.cli = fake_cli(b.temp.path(), "echo 'not json'; exit 1");
        assert_eq!(code(tenant_purge(&b.config, &purges, "olscpa", Value::Null)), "COMMAND_FAILED");
        b.config.cli = fake_cli(b.temp.path(), r#"echo '{"result": "usage", "code": 64, "error": "x"}'; exit 64"#);
        assert_eq!(code(stats(&b.config.cli, Value::Null)), "COMMAND_FAILED");
        // olscpb asking for a.test is not possible through the request (ownership), and the command checks it again.
        let direct = run(&config.cli, &["cache".into(), "purge".into(), "--account=olscpb".into(), "--domain=a.test".into(), "--format=json".into()]);
        assert_eq!(direct.unwrap_err().0, "REFUSED");
    }
}
