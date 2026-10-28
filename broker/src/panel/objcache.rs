//! Object cache (FV-09, docs/product-interfaces.md "Object cache"): the tenant operation `tenant.objcache`, the
//! caller's own object cache view for the cPanel plugin. It runs the product command
//! (`ols-cpanel objcache status --account=<caller> --format=json`) with a fixed argv; the account is the
//! SO_PEERCRED identity passed in by the dispatcher, never a request field, and only the fields a customer needs are
//! passed on: whether the cache runs, the connection values (the socket path as host, port 0, no password), the
//! usage numbers and the WordPress sites with the state of their LiteSpeed Cache object cache.

use super::{cache, now, valid_name, Config, Reply};
use serde_json::{json, Value};

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
    Ok(json!({"user": user, "observed_at": now(), "source": "ols-cpanel objcache status", "enabled": out["enabled"],
              "suspended": out["suspended"], "state": out["state"], "memory_mb": out["memory_mb"],
              "connection": out["connection"], "wordpress": sites, "usage": usage}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::fixture;

    const SCRIPT: &str = r#"case "$*" in
"objcache status --account=olscpa --format=json") echo '{"result": "status", "engine": {"present": true}, "account": "olscpa", "package": "gold", "enabled": true, "memory_mb": 64, "suspended": false, "state": "active", "socket": "/home/olscpa/.ols-objcache/valkey.sock", "connection": {"host": "/home/olscpa/.ols-objcache/valkey.sock", "port": 0, "password": null}, "wordpress": [{"path": "/home/olscpa/public_html", "state": "automatic", "configured_by_product": true, "checked_at": 5, "php": "ea-php83", "error": null}, {"path": "/home/olscpa/blog", "state": "owner", "configured_by_product": false, "checked_at": 6, "php": "ea-php82", "error": null}], "usage": {"used_memory": 10, "maxmemory": 20, "keys": 3, "evicted_keys": 0, "hit_rate": 0.5, "connected_clients": 1, "uptime_seconds": 9}}';;
"objcache status --account=olscpb --format=json") echo '{"result": "refused", "code": 1, "error": "olscpb is not a cPanel account"}'; exit 1;;
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
        // Operator-only facts stay behind.
        assert!(view.get("package").is_none() && view.get("engine").is_none() && view["usage"].get("uptime_seconds").is_none());
        assert_eq!(code(tenant_objcache(&f.config, "olscpb")), "REFUSED");
        assert_eq!(code(tenant_objcache(&f.config, "")), "FORBIDDEN");
        assert_eq!(code(tenant_objcache(&f.config, "Bad Name")), "FORBIDDEN");
    }
}
