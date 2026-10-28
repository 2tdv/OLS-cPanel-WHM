//! PHP manager (FV-03, docs/product-interfaces.md "PHP manager"): the admin `php.status` view, the scope grammars of
//! the `ols.php_restart` and `ols.opcache_install` jobs, and the tenant operations `tenant.php` and
//! `tenant.php_restart`. Everything runs the product command (`ols-cpanel php status|restart|opcache install`)
//! with a fixed argv; the broker never signals a process or installs a package itself.
//!
//! Tenant scope: the account is the SO_PEERCRED identity passed in by the dispatcher, never a request field. A
//! tenant sees its own sites' PHP version and handler, its own lsphp processes, its effective limits and whether
//! OPcache is loaded for the versions it uses; it can restart its own lsphp processes once per
//! TENANT_RESTART_INTERVAL, and every restart is audited.

use super::{audit, cache, now, summary, valid_name, Config, Reply};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

/// One tenant restart per account in this time.
pub const TENANT_RESTART_INTERVAL: Duration = Duration::from_secs(30);

/// An EA4 PHP version as the product names it: `ea-php` and two or three digits.
pub fn version_ok(version: &str) -> bool {
    version.strip_prefix("ea-php").map_or(false, |d| (2..=3).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()))
}

/// The `php restart` option for a job scope: `server` is `--all`, `account:<user>` names the account.
pub fn restart_flag(scope: &str) -> Option<String> {
    if scope == "server" {
        return Some("--all".to_string());
    }
    scope.strip_prefix("account:").filter(|a| cache::account_ok(a)).map(|a| format!("--account={a}"))
}

/// The `php opcache install` option for a job scope: `server` is `--all`, `version:ea-phpNN` names the version.
pub fn opcache_flag(scope: &str) -> Option<String> {
    if scope == "server" {
        return Some("--all".to_string());
    }
    scope.strip_prefix("version:").filter(|v| version_ok(v)).map(|v| format!("--version={v}"))
}

fn cli_args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// `php.status` (admin): OPcache per version, the lsphp process summary per account and the limits in force.
pub fn status(cli: &Path) -> Reply {
    cache::run(cli, &cli_args(&["php", "status", "--format=json"]))
}

/// `tenant.php`: the caller's own PHP view.
pub fn tenant_php(config: &Config, summaries: &summary::Summaries, user: &str) -> Reply {
    if !cache::account_ok(user) || !valid_name(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let sites = summary::tenant_sites(config, summaries, user)?;
    let sites: Vec<Value> = sites["sites"].as_array().into_iter().flatten().map(|s| {
        json!({"domain": s["domain"], "type": s["type"], "vhost": s["vhost"], "engine": s["engine"],
               "php_version": s["php_version"], "php_handler": s["php_handler"]})
    }).collect();
    let used: BTreeSet<&str> = sites.iter().filter_map(|s| s["php_version"].as_str()).collect();
    let report = cache::run(&config.cli, &["php".to_string(), "status".to_string(), format!("--account={user}"), "--format=json".to_string()])?;
    let output = &report["output"];
    // Only the versions the account's own sites use, and only what a tenant needs to know about them.
    let opcache: Vec<Value> = output["opcache"]["versions"].as_array().into_iter().flatten()
        .filter(|v| v["version"].as_str().map_or(false, |n| used.contains(n)))
        .map(|v| json!({"version": v["version"], "php": v["php"], "loaded": v["loaded"], "tuned": v["tuned"]})).collect();
    let family = output["processes"]["accounts"].as_array().into_iter().flatten().find(|a| a["account"] == json!(user)).cloned();
    Ok(json!({"user": user, "observed_at": now(), "source": "ols-cpanel php status", "sites": sites, "opcache": opcache,
              "processes": family.unwrap_or(Value::Null), "thresholds": output["processes"]["thresholds"],
              "limits": output["limits"]["account"]}))
}

/// `tenant.php_restart`: ends the caller's own lsphp processes (the next request starts new ones).
pub fn tenant_restart(config: &Config, restarts: &cache::TenantPurges, user: &str, args: Value) -> Reply {
    if !cache::account_ok(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    if !(args.is_null() || args == json!({})) {
        return Err(("BAD_ARGS", "this operation takes no arguments".into()));
    }
    // Ownership comes from cPanel's own table, by the caller's identity.
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    if !rows.iter().any(|r| r["user"] == json!(user)) {
        return Err(("NOT_FOUND", "this account has no domains".into()));
    }
    if let Err(wait) = restarts.admit(user) {
        return Err(("RATE_LIMITED", format!("a PHP restart is allowed every {} s; try again in {wait} s", restarts.interval_secs())));
    }
    let done = cache::run(&config.cli, &["php".to_string(), "restart".into(), format!("--account={user}"), "--format=json".into()])?;
    let out = &done["output"];
    let _ = audit(&config.audit_log, &json!({"time": now(), "event": "tenant_php_restart", "user": user, "found": out["found"],
                                             "killed": out["killed"], "result": out["result"]}));
    Ok(json!({"user": user, "observed_at": now(), "result": out["result"], "found": out["found"], "killed": out["killed"],
              "remaining": out["remaining"]}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::{fixture, Fixture};
    use std::fs;

    /// Echoes what it was asked and answers the way the product command does.
    const SCRIPT: &str = r#"case "$*" in
"php status --format=json") echo '{"result": "status", "opcache": {"versions": [{"version": "ea-php83", "loaded": true}]}, "processes": {"totals": {}, "accounts": []}, "limits": {}}';;
"php status --account=olscpa --format=json") echo '{"result": "status", "opcache": {"versions": [{"version": "ea-php82", "php": "8.2", "loaded": false, "tuned": false, "settings": {"x": 1}}, {"version": "ea-php83", "php": "8.3", "loaded": true, "tuned": true, "settings": {"validate_root": "On"}}, {"version": "ea-php74", "php": "7.4", "loaded": true, "tuned": true}]}, "processes": {"thresholds": {"cpu_seconds": 900}, "accounts": [{"account": "olscpb", "children": 9}, {"account": "olscpa", "children": 2, "processes": [{"pid": 1}]}]}, "limits": {"account": {"children": 5}}, "other": 1}';;
"php status --account=olscpb --format=json") echo '{"result": "status", "opcache": {"versions": []}, "processes": {"thresholds": {}, "accounts": []}, "limits": {"account": {"children": 5}}}';;
"php restart --account=olscpa --format=json") echo '{"result": "restarted", "found": 3, "killed": 3, "remaining": 0, "killed_with_sigkill": 0}';;
"php restart --account=olscpb --format=json") echo '{"result": "refused", "code": 1, "error": "unknown account olscpb"}'; exit 1;;
*) echo "unexpected $*" >&2; exit 64;;
esac"#;

    fn setup() -> Fixture {
        let mut f = fixture();
        f.config.cli = fake_cli(f.temp.path(), SCRIPT);
        f
    }

    fn code(result: Reply) -> &'static str {
        result.err().map(|e| e.0).unwrap_or("ok")
    }

    #[test]
    fn scope_grammars() {
        assert_eq!(restart_flag("server").as_deref(), Some("--all"));
        assert_eq!(restart_flag("account:olscpa").as_deref(), Some("--account=olscpa"));
        assert_eq!(opcache_flag("server").as_deref(), Some("--all"));
        assert_eq!(opcache_flag("version:ea-php83").as_deref(), Some("--version=ea-php83"));
        assert_eq!(opcache_flag("version:ea-php100").as_deref(), Some("--version=ea-php100"));
        for bad in ["", "all", "--all", "account:", "account:-x", "account:A", "account:a b", "account:a/b", "version:ea-php83", "server ", "plan:p1"] {
            assert!(restart_flag(bad).is_none(), "{bad}");
        }
        for bad in ["", "all", "version:", "version:ea-php8", "version:ea-php1000", "version:ea-phpx3", "version:alt-php81", "version:ea-php83 --all",
                    "version:../ea-php83", "version:EA-PHP83", "account:olscpa", "version:ea-php83;id"] {
            assert!(opcache_flag(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn admin_status_runs_the_fixed_command() {
        let f = setup();
        assert_eq!(status(&f.config.cli).unwrap()["output"]["opcache"]["versions"][0]["version"], json!("ea-php83"));
        let mut b = fixture();
        b.config.cli = fake_cli(b.temp.path(), "echo 'not json'; exit 1");
        assert_eq!(code(status(&b.config.cli)), "COMMAND_FAILED");
    }

    #[test]
    fn tenant_view_is_the_callers_own() {
        let f = setup();
        let summaries = summary::Summaries::default();
        let mine = tenant_php(&f.config, &summaries, "olscpa").unwrap();
        assert_eq!(mine["user"], json!("olscpa"));
        // Sites: only the caller's own, with version and handler.
        let domains: Vec<&str> = mine["sites"].as_array().unwrap().iter().map(|s| s["domain"].as_str().unwrap()).collect();
        assert!(domains.contains(&"a.test") && domains.contains(&"shop.a.test") && !domains.contains(&"b.test"), "{domains:?}");
        assert_eq!(mine["sites"][0]["php_version"], json!("ea-php83"));
        // OPcache: only the versions the account's sites use (ea-php74 is installed but unused), without raw settings.
        let versions: Vec<&str> = mine["opcache"].as_array().unwrap().iter().map(|v| v["version"].as_str().unwrap()).collect();
        assert_eq!(versions, ["ea-php82", "ea-php83"]);
        assert_eq!(mine["opcache"][1], json!({"version": "ea-php83", "php": "8.3", "loaded": true, "tuned": true}));
        // Processes: only the caller's family, never another account's.
        assert_eq!(mine["processes"]["account"], json!("olscpa"));
        assert_eq!(mine["limits"], json!({"children": 5}));
        assert!(mine.get("other").is_none());
        // An account with no processes has null, and no cached view of another account leaks.
        let other = tenant_php(&f.config, &summaries, "olscpb").unwrap();
        assert_eq!(other["processes"], Value::Null);
        assert!(other["sites"].as_array().unwrap().iter().all(|s| s["domain"] != json!("a.test")));
        assert_eq!(code(tenant_php(&f.config, &summaries, "")), "FORBIDDEN");
        assert_eq!(code(tenant_php(&f.config, &summaries, "Bad Name")), "FORBIDDEN");
    }

    #[test]
    fn tenant_restart_is_scoped_limited_and_audited() {
        let f = setup();
        let restarts = cache::TenantPurges::new(Duration::from_secs(60));
        let done = tenant_restart(&f.config, &restarts, "olscpa", Value::Null).unwrap();
        assert_eq!((done["result"].clone(), done["found"].clone(), done["killed"].clone()), (json!("restarted"), json!(3), json!(3)));
        let again = tenant_restart(&f.config, &restarts, "olscpa", json!({})).unwrap_err();
        assert_eq!(again.0, "RATE_LIMITED");
        assert!(again.1.contains("every 60 s"), "{}", again.1);
        let log = fs::read_to_string(&f.config.audit_log).unwrap();
        assert!(log.contains("tenant_php_restart") && log.contains("olscpa") && !log.contains("olscpb"));
        // Arguments never reach the command: an account, a scope or anything else is refused.
        let free = cache::TenantPurges::new(Duration::ZERO);
        for bad in [json!({"account": "olscpb"}), json!({"user": "olscpb"}), json!({"all": true}), json!([]), json!("x")] {
            assert_eq!(code(tenant_restart(&f.config, &free, "olscpa", bad.clone())), "BAD_ARGS", "{bad}");
        }
        // No domains: nothing runs, and the allowance is not used. The command's own refusal is reported.
        assert_eq!(code(tenant_restart(&f.config, &free, "ghost", Value::Null)), "NOT_FOUND");
        assert_eq!(code(tenant_restart(&f.config, &free, "", Value::Null)), "FORBIDDEN");
        assert_eq!(code(tenant_restart(&f.config, &free, "olscpb", Value::Null)), "REFUSED");
    }
}
