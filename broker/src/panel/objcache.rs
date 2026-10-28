//! Object cache (FV-09, docs/product-interfaces.md "Object cache"): the admin operation `admin.objcache` (every
//! account's object cache and the automatic mode, which it can switch) and the tenant operation `tenant.objcache`, the
//! caller's own object cache view for the cPanel plugin. It runs the product command
//! (`ols-cpanel objcache status --account=<caller> --format=json`) with a fixed argv; the account is the
//! SO_PEERCRED identity passed in by the dispatcher, never a request field, and only the fields a customer needs are
//! passed on: whether the cache runs, the connection values (the socket path as host, port 0, no password), the
//! usage numbers and the WordPress sites with the state of their LiteSpeed Cache object cache.

use super::{audit, cache, now, valid_name, Config, Reply};
use serde::Deserialize;
use serde_json::{json, Value};

/// `admin.objcache` arguments: none reads, `automatic` switches the automatic mode first.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AdminArgs {
    #[serde(default)]
    automatic: Option<bool>,
}

/// `admin.objcache {automatic?}` (admin): `ols-cpanel objcache status --format=json` (every account with its origin, the
/// automatic mode); with `automatic` it first runs `ols-cpanel objcache auto --on|--off` (audited) and then reads, so the
/// reply is the state after the change. Turning the mode off removes only automatic accounts, by the pass the command starts.
pub fn admin_objcache(config: &Config, args: Value) -> Reply {
    let a: AdminArgs = cache::parse(args)?;
    if let Some(on) = a.automatic {
        let flag = if on { "--on" } else { "--off" };
        cache::run(&config.cli, &["objcache".to_string(), "auto".to_string(), flag.to_string(), "--format=json".to_string()])?;
        let _ = audit(&config.audit_log, &json!({"time": now(), "event": "objcache_automatic_set", "args": [flag]}));
    }
    cache::run(&config.cli, &["objcache".to_string(), "status".to_string(), "--format=json".to_string()])
}

/// `tenant.objcache`: the caller's own object cache.
pub fn tenant_objcache(config: &Config, user: &str) -> Reply {
    if !cache::account_ok(user) || !valid_name(user) {
        return Err(("FORBIDDEN", "not a cPanel account".into()));
    }
    let report = cache::run(&config.cli, &["objcache".to_string(), "status".to_string(), format!("--account={user}"), "--format=json".to_string()])?;
    let out = &report["output"];
    let sites: Vec<Value> = out["wordpress"].as_array().into_iter().flatten().map(|s| {
        json!({"path": s["path"], "state": s["state"], "configured_by_product": s["configured_by_product"],
               "checked_at": s["checked_at"], "error": s["error"]})
    }).collect();
    let usage = if out["usage"].is_object() {
        let u = &out["usage"];
        json!({"used_memory": u["used_memory"], "maxmemory": u["maxmemory"], "keys": u["keys"], "evicted_keys": u["evicted_keys"],
               "hit_rate": u["hit_rate"], "connected_clients": u["connected_clients"]})
    } else {
        Value::Null
    };
    // "origin" and "automatic" let the view tell "ready for your WordPress", "starts with WordPress" and "turned off by
    // your hosting provider" apart; the package name stays behind.
    Ok(json!({"user": user, "observed_at": now(), "source": "ols-cpanel objcache status", "enabled": out["enabled"],
              "origin": out["origin"], "automatic": out["automatic"],
              "suspended": out["suspended"], "state": out["state"], "memory_mb": out["memory_mb"],
              "connection": out["connection"], "wordpress": sites, "usage": usage}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::fixture;

    const SCRIPT: &str = r#"case "$*" in
"objcache status --account=olscpa --format=json") echo '{"result": "status", "engine": {"present": true}, "account": "olscpa", "package": "gold", "origin": "automatic", "automatic": true, "enabled": true, "memory_mb": 64, "suspended": false, "state": "active", "socket": "/home/olscpa/.ols-objcache/valkey.sock", "connection": {"host": "/home/olscpa/.ols-objcache/valkey.sock", "port": 0, "password": null}, "wordpress": [{"path": "/home/olscpa/public_html", "state": "automatic", "configured_by_product": true, "checked_at": 5, "php": "ea-php83", "error": null}, {"path": "/home/olscpa/blog", "state": "owner", "configured_by_product": false, "checked_at": 6, "php": "ea-php82", "error": null}], "usage": {"used_memory": 10, "maxmemory": 20, "keys": 3, "evicted_keys": 0, "hit_rate": 0.5, "connected_clients": 1, "uptime_seconds": 9}}';;
"objcache status --account=olscpb --format=json") echo '{"result": "refused", "code": 1, "error": "olscpb is not a cPanel account"}'; exit 1;;
"objcache status --format=json") echo "{\"result\": \"status\", \"automatic\": $(cat "$0.auto" 2>/dev/null || echo true), \"accounts\": [{\"account\": \"olscpa\", \"origin\": \"automatic\"}]}";;
"objcache auto --off --format=json") echo false > "$0.auto"; echo '{"result": "automatic_off", "automatic": false}';;
"objcache auto --on --format=json") echo true > "$0.auto"; echo '{"result": "automatic_on", "automatic": true}';;
*) echo "unexpected $*" >&2; exit 64;;
esac"#;

    fn code(result: Reply) -> &'static str {
        result.err().map(|e| e.0).unwrap_or("ok")
    }

    #[test]
    fn tenant_view_is_the_callers_own_and_minimal() {
        let mut f = fixture();
        f.config.cli = fake_cli(f.temp.path(), SCRIPT);
        let view = tenant_objcache(&f.config, "olscpa").unwrap();
        assert_eq!(view["user"], json!("olscpa"));
        assert_eq!(view["connection"], json!({"host": "/home/olscpa/.ols-objcache/valkey.sock", "port": 0, "password": null}));
        assert_eq!(view["wordpress"][0], json!({"path": "/home/olscpa/public_html", "state": "automatic", "configured_by_product": true,
                                                  "checked_at": 5, "error": null}));
        assert_eq!(view["wordpress"][1]["state"], json!("owner"));
        assert_eq!(view["usage"]["hit_rate"], json!(0.5));
        assert_eq!((view["origin"].clone(), view["automatic"].clone()), (json!("automatic"), json!(true)));
        // Operator-only facts stay behind.
        assert!(view.get("package").is_none() && view.get("engine").is_none() && view["usage"].get("uptime_seconds").is_none());
        assert_eq!(code(tenant_objcache(&f.config, "olscpb")), "REFUSED");
        assert_eq!(code(tenant_objcache(&f.config, "")), "FORBIDDEN");
        assert_eq!(code(tenant_objcache(&f.config, "Bad Name")), "FORBIDDEN");
    }

    #[test]
    fn admin_view_reads_and_switches_the_automatic_mode() {
        let mut f = fixture();
        f.config.cli = fake_cli(f.temp.path(), SCRIPT);
        let read = admin_objcache(&f.config, Value::Null).unwrap();
        assert_eq!(read["output"]["automatic"], json!(true));
        assert_eq!(read["output"]["accounts"][0]["origin"], json!("automatic"));
        // A switch runs the command, is audited, and the reply is the state after it.
        let off = admin_objcache(&f.config, json!({"automatic": false})).unwrap();
        assert_eq!(off["output"]["automatic"], json!(false));
        let log = std::fs::read_to_string(&f.config.audit_log).unwrap();
        assert!(log.contains("\"event\":\"objcache_automatic_set\"") && log.contains("--off"), "{log}");
        assert_eq!(admin_objcache(&f.config, json!({"automatic": true})).unwrap()["output"]["automatic"], json!(true));
        assert_eq!(admin_objcache(&f.config, json!({})).unwrap()["output"]["automatic"], json!(true));
        for bad in [json!({"automatic": "off"}), json!({"automatic": 1}), json!({"x": true}), json!([true])] {
            assert_eq!(code(admin_objcache(&f.config, bad.clone())), "BAD_ARGS", "{bad}");
        }
    }
}
