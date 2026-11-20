//! HTTP/3 per domain (FV-04, CMP-07, docs/product-interfaces.md "HTTP/3"): the admin operation `admin.http3`. A read runs
//! `ols-cpanel http3 status --format=json` (the operator input with its per-domain off list, the UDP 443 firewall state
//! and the protocol share of each vhost); a write `{domain, enabled}` first runs `ols-cpanel http3 on|off --domain=<domain>
//! --format=json` (audited as `http3_domain_set`) and then reads, so the reply is the state after the change. The
//! reconciler compiles the change within its next pass. The argv is fixed; the domain is validated here and again by the
//! command, which also refuses a domain that is not a vhost of the active generation.

use super::{audit, cache, now, Config, Reply};
use serde::Deserialize;
use serde_json::{json, Value};

/// `admin.http3` arguments: none reads; `domain` and `enabled` together switch one domain.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AdminArgs {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// `admin.http3 {domain?, enabled?}` (admin).
pub fn admin_http3(config: &Config, args: Value) -> Reply {
    let a: AdminArgs = cache::parse(args)?;
    match (a.domain.as_deref(), a.enabled) {
        (None, None) => {}
        (Some(domain), Some(enabled)) => {
            if !cache::domain_ok(domain) {
                return Err(("BAD_ARGS", "domain must be a domain name".into()));
            }
            let verb = if enabled { "on" } else { "off" };
            cache::run(&config.cli, &["http3".to_string(), verb.to_string(), format!("--domain={domain}"), "--format=json".to_string()])?;
            let _ = audit(&config.audit_log, &json!({"time": now(), "event": "http3_domain_set", "args": [verb, domain]}));
        }
        _ => return Err(("BAD_ARGS", "domain and enabled are given together".into())),
    }
    cache::run(&config.cli, &["http3".to_string(), "status".to_string(), "--format=json".to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::product::tests::fake_cli;
    use crate::panel::summary::tests::fixture;

    const SCRIPT: &str = r#"case "$*" in
"http3 status --format=json") echo "{\"result\": \"status\", \"enabled\": true, \"input\": {\"off\": [$(cat "$0.off" 2>/dev/null)], \"off_unknown\": []}, \"protocol_share\": []}";;
"http3 off --domain=a.example --format=json") echo '"a.example"' > "$0.off"; echo '{"result": "ok", "changed": true}';;
"http3 on --domain=a.example --format=json") : > "$0.off"; echo '{"result": "ok", "changed": true}';;
"http3 off --domain=missing.example --format=json") echo '{"result": "refused", "code": 1, "error": "missing.example is not a vhost of the active generation"}'; exit 1;;
*) echo "unexpected $*" >&2; exit 64;;
esac"#;

    fn code(result: Reply) -> &'static str {
        result.err().map(|e| e.0).unwrap_or("ok")
    }

    #[test]
    fn admin_view_reads_and_switches_one_domain() {
        let mut f = fixture();
        f.config.cli = fake_cli(f.temp.path(), SCRIPT);
        let read = admin_http3(&f.config, Value::Null).unwrap();
        assert_eq!(read["output"]["input"]["off"], json!([]));
        // A switch runs the command, is audited, and the reply is the state after it.
        let off = admin_http3(&f.config, json!({"domain": "a.example", "enabled": false})).unwrap();
        assert_eq!(off["output"]["input"]["off"], json!(["a.example"]));
        let log = std::fs::read_to_string(&f.config.audit_log).unwrap();
        assert!(log.contains("\"event\":\"http3_domain_set\"") && log.contains("a.example") && log.contains("off"), "{log}");
        let on = admin_http3(&f.config, json!({"domain": "a.example", "enabled": true})).unwrap();
        assert_eq!(on["output"]["input"]["off"], json!([]));
        assert_eq!(code(admin_http3(&f.config, json!({"domain": "missing.example", "enabled": false}))), "REFUSED");
        for bad in [json!({"domain": "a.example"}), json!({"enabled": false}), json!({"domain": "A.example", "enabled": false}),
                    json!({"domain": "a.example;x", "enabled": false}), json!({"domain": "localhost", "enabled": false}),
                    json!({"domain": "a.example", "enabled": "off"}), json!({"domain": 1, "enabled": true}), json!({"x": 1}), json!([true])] {
            assert_eq!(code(admin_http3(&f.config, bad.clone())), "BAD_ARGS", "{bad}");
        }
    }
}
