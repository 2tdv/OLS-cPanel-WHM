//! WordPress login guard (RV-64, CMP-04; docs/product-interfaces.md "Login guard"): the admin operation `admin.login_guard`
//! reads the guard (`ols-cpanel login-guard status --format=json`: the switch, the limits, the blocked addresses with their
//! counts, the recent blocks) and, with `enabled`, switches it first (`ols-cpanel login-guard set --enabled=yes|no`, audited).
//! The argv is fixed; the only request value that reaches it is the boolean. Admin socket only.

use super::{audit, cache, now, Config, Reply};
use serde::Deserialize;
use serde_json::{json, Value};

/// `admin.login_guard` arguments: none reads, `enabled` switches the guard first.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AdminArgs {
    #[serde(default)]
    enabled: Option<bool>,
}

/// `admin.login_guard {enabled?}` (admin): the guard's status; with `enabled` the switch runs first and the reply is the state
/// after it (off empties the block list at once).
pub fn admin_login_guard(config: &Config, args: Value) -> Reply {
    let a: AdminArgs = cache::parse(args)?;
    if let Some(on) = a.enabled {
        let flag = if on { "--enabled=yes" } else { "--enabled=no" };
        cache::run(&config.cli, &["login-guard".to_string(), "set".to_string(), flag.to_string(), "--format=json".to_string()])?;
        let _ = audit(&config.audit_log, &json!({"time": now(), "event": "login_guard_set", "args": [flag]}));
    }
    cache::run(&config.cli, &["login-guard".to_string(), "status".to_string(), "--format=json".to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::fixture;

    const SCRIPT: &str = r#"case "$*" in
"login-guard status --format=json") echo "{\"command\": \"login-guard status\", \"enabled\": $(cat "$0.on" 2>/dev/null || echo true), \"limits\": {\"xmlrpc\": 30, \"wp-login\": 20}, \"blocked\": [{\"domain\": \"ltwp05.example.test\", \"address\": \"34.30.196.241\", \"endpoint\": \"xmlrpc.php\", \"requests\": 31, \"refused\": 900}]}";;
"login-guard set --enabled=no --format=json") echo false > "$0.on"; echo '{"changed": true, "enabled": false}';;
"login-guard set --enabled=yes --format=json") echo true > "$0.on"; echo '{"changed": true, "enabled": true}';;
*) echo "unexpected $*" >&2; exit 64;;
esac"#;

    fn code(result: Reply) -> &'static str {
        result.err().map(|e| e.0).unwrap_or("ok")
    }

    #[test]
    fn reads_and_switches_the_guard() {
        let mut f = fixture();
        f.config.cli = fake_cli(f.temp.path(), SCRIPT);
        let read = admin_login_guard(&f.config, Value::Null).unwrap();
        assert_eq!(read["output"]["enabled"], json!(true));
        assert_eq!(read["output"]["blocked"][0]["address"], json!("34.30.196.241"));
        assert_eq!(read["output"]["blocked"][0]["refused"], json!(900));
        // A switch runs the command, is audited, and the reply is the state after it.
        let off = admin_login_guard(&f.config, json!({"enabled": false})).unwrap();
        assert_eq!(off["output"]["enabled"], json!(false));
        let log = std::fs::read_to_string(&f.config.audit_log).unwrap();
        assert!(log.contains("\"event\":\"login_guard_set\"") && log.contains("--enabled=no"), "{log}");
        assert_eq!(admin_login_guard(&f.config, json!({"enabled": true})).unwrap()["output"]["enabled"], json!(true));
        assert_eq!(admin_login_guard(&f.config, json!({})).unwrap()["output"]["enabled"], json!(true));
        for bad in [json!({"enabled": "no"}), json!({"enabled": 0}), json!({"unblock": "1.2.3.4"}), json!([true]), json!("x")] {
            assert_eq!(code(admin_login_guard(&f.config, bad.clone())), "BAD_ARGS", "{bad}");
        }
    }
}
