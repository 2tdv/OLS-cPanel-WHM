//! `engine.apply`: the generation tree the reconciler compiled, checked and written under staging/
//! (fresh 0700 directory, files created exclusively without following links), then staged, validated
//! and activated by the activator in-process, exactly like `ols-cpanel-activator stage/validate/activate`.

use super::valid_domain;
use crate::activator::generation::{Activator, Error};
use crate::activator::pyjson::{self, Ordered};
use crate::activator::runtime::Runtime;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Total size of the files of one generation.
pub const MAX_FILES: usize = 64 << 20;
pub const HEALTH_PREFIX: &str = "/.ols-cpanel-generation/";
/// Vhosts that are not cPanel domains (CpanelSurface::PROXY_VHOST, DEFAULT_VHOST, the generation marker).
pub const FIXED_VHOSTS: [&str; 3] = ["cpanel-proxy", "server-default", "olscp-gen"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apply {
    pub generation: String,
    pub files: BTreeMap<String, String>,
    pub health: Vec<Target>,
    pub epoch: i64,
    pub source_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub vhost: String,
    pub host: String,
    pub url: String,
}

pub fn valid_generation(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 22
        && b[0] == b'r'
        && b[1..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'-'
        && b[16..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A cPanel domain, a fixed product vhost or the service vhost `svc.<domain>`.
pub fn valid_vhost(name: &str) -> bool {
    valid_domain(name) || FIXED_VHOSTS.contains(&name) || name.strip_prefix("svc.").map_or(false, valid_domain)
}

/// The only relative paths a generation tree may contain besides the files the broker adds.
pub fn valid_tree_path(path: &str) -> bool {
    // summary.json: the compile summary the plugins read (docs/product-interfaces.md, plugin data).
    if path == "httpd_config.conf" || path == "marker/generation" || path == "summary.json" {
        return true;
    }
    let parts: Vec<&str> = path.split('/').collect();
    matches!(parts.as_slice(), ["vhosts", vhost, "vhconf.conf"] | ["health", vhost, "id"] if valid_vhost(vhost))
}

fn decimal(text: &str, max: u32) -> bool {
    !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|b| b.is_ascii_digit())
        && !(text.len() > 1 && text.starts_with('0'))
        && text.parse::<u32>().map_or(false, |n| n <= max)
}

fn ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| decimal(p, 255))
}

/// `http://127.0.0.1:<port>/.ols-cpanel-generation/<file>`, `http://<IPv4>:80/.ols-cpanel-generation/<file>` or
/// `https://<IPv4>:443/.ols-cpanel-generation/<file>` (review RV-29, finding 12; GenerationTree::validHealthUrl).
pub fn valid_health_url(url: &str) -> bool {
    let (https, rest) = match (url.strip_prefix("http://"), url.strip_prefix("https://")) {
        (Some(rest), _) => (false, rest),
        (_, Some(rest)) => (true, rest),
        _ => return false,
    };
    let Some(slash) = rest.find('/') else { return false };
    let (authority, path) = rest.split_at(slash);
    let Some((address, port)) = authority.split_once(':') else { return false };
    let Some(file) = path.strip_prefix(HEALTH_PREFIX) else { return false };
    let file_ok = !file.is_empty()
        && !file.starts_with('.')
        && file.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    let port_ok = decimal(port, 65535) && port != "0";
    let scheme_ok = if https { port == "443" } else { address == "127.0.0.1" || port == "80" };
    file_ok && port_ok && ipv4(address) && scheme_ok
}

pub fn check(a: &Apply) -> Result<(), String> {
    if !valid_generation(&a.generation) {
        return Err("generation must match r<YYYYmmddHHMMSS>-<6 hex>".into());
    }
    if !lower_hex(&a.source_sha256, 64) {
        return Err("source_sha256 must be 64 lowercase hex digits".into());
    }
    if a.epoch < 0 {
        return Err("epoch must not be negative".into());
    }
    let mut total = 0usize;
    for (path, text) in &a.files {
        if !valid_tree_path(path) {
            return Err(format!("file path not allowed: {}", super::printable(path)));
        }
        total += text.len();
    }
    if total > MAX_FILES {
        return Err("files exceed 64 MiB in total".into());
    }
    for target in &a.health {
        if !valid_vhost(&target.vhost) || !valid_domain(&target.host) || !valid_health_url(&target.url) {
            return Err(format!("invalid health target for {}", super::printable(&target.vhost)));
        }
    }
    Ok(())
}

/// health.json byte for byte as ols_generation_probe.generation_tree writes it: json.dumps(targets, indent=1).
pub fn health_json(targets: &[Target]) -> String {
    let items: Vec<Ordered<'_>> = targets
        .iter()
        .map(|t| Ordered(vec![("vhost", json!(t.vhost)), ("host", json!(t.host)), ("url", json!(t.url))]))
        .collect();
    pyjson::dumps_ordered_list(&items, Some(1))
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> String + '_ {
    move |e| format!("{}: {e}", path.display())
}

/// A new directory with exactly `mode` (whatever the umask); an existing one is an error.
fn create_dir(path: &Path, mode: u32) -> Result<(), String> {
    fs::DirBuilder::new().mode(mode).create(path).map_err(io(path))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io(path))
}

/// `root/rel` created exclusively (O_CREAT|O_EXCL|O_NOFOLLOW), 0644, below directories this call creates.
fn write_new(root: &Path, rel: &str, bytes: &[u8]) -> Result<(), String> {
    let mut dir = root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    let (name, parents) = parts.split_last().ok_or("empty path")?;
    for part in parents {
        dir.push(part);
        match create_dir(&dir, 0o755) {
            Ok(()) => {}
            // Created earlier in this tree (several files per directory); never a link.
            Err(_) if fs::symlink_metadata(&dir).map_or(false, |m| m.is_dir()) => {}
            Err(e) => return Err(e),
        }
    }
    let path = dir.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(io(&path))?;
    file.set_permissions(fs::Permissions::from_mode(0o644)).map_err(io(&path))?;
    file.write_all(bytes).map_err(io(&path))
}

/// The tree under `dir` (created here, 0700): the request's files plus health.json, EPOCH and SOURCE_SHA256.
pub fn write_tree(dir: &Path, a: &Apply) -> Result<(), String> {
    create_dir(dir, 0o700)?;
    for (rel, text) in &a.files {
        write_new(dir, rel, text.as_bytes())?;
    }
    write_new(dir, "health.json", health_json(&a.health).as_bytes())?;
    write_new(dir, "EPOCH", format!("{}\n", a.epoch).as_bytes())?;
    write_new(dir, "SOURCE_SHA256", format!("{}\n", a.source_sha256).as_bytes())
}

pub fn activator_error(e: Error) -> (&'static str, String) {
    match e {
        Error::Exit(m) | Error::Fatal(m) => ("ACTIVATOR", m),
        Error::Epoch(m) => ("ACTIVATOR", format!("EpochError: {m}")),
        Error::Crash => ("ACTIVATOR", "activator stopped".into()),
    }
}

/// Write, stage, validate, activate. The caller serializes applies; `activate` itself takes the
/// activation lock (the broker never holds it around these calls, so enforce cannot deadlock with it).
pub fn apply<R: Runtime>(activator: &Activator<R>, staging: &Path, a: Apply) -> Result<Value, (&'static str, String)> {
    check(&a).map_err(|m| ("BAD_ARGS", m))?;
    let gen = a.generation.as_str();
    activator.ensure_dirs().map_err(activator_error)?;
    if fs::symlink_metadata(activator.paths.gen_root.join(gen)).is_ok() {
        return Err(("EXISTS", format!("generation {gen} exists (generations are immutable)")));
    }
    match fs::symlink_metadata(staging) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(("INTERNAL", format!("{} is not a directory", staging.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => create_dir(staging, 0o700).map_err(|m| ("INTERNAL", m))?,
        Err(e) => return Err(("INTERNAL", format!("{}: {e}", staging.display()))),
    }
    let tree = staging.join(gen);
    if fs::symlink_metadata(&tree).is_ok() {
        return Err(("EXISTS", format!("staging tree {gen} exists")));
    }
    let staged = write_tree(&tree, &a).map_err(|m| ("INTERNAL", m)).and_then(|()| activator.stage(gen, &tree).map_err(activator_error));
    // stage copied the tree into generations/; the staging copy is never needed again.
    let _ = fs::remove_dir_all(&tree);
    staged?;
    let validation = activator.validate(gen).map_err(activator_error)?;
    let valid = validation.get("valid") == Some(&json!(true));
    let outcome = if valid {
        activator.activate(gen, None).map_err(activator_error)?
    } else {
        json!({"result": "invalid", "reason": validation.get("report")})
    };
    // Python reconcile: outcome.get("reason") or outcome.get("failing").
    let reason = match outcome.get("reason") {
        Some(r) if crate::activator::generation::truthy(Some(r)) => r.clone(),
        _ => outcome.get("failing").cloned().unwrap_or(Value::Null),
    };
    Ok(json!({"generation": gen, "valid": valid, "result": outcome.get("result").cloned().unwrap_or(Value::Null), "reason": reason}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::generation::Paths;
    use crate::activator::testutil::{Mock, TempTree};
    use std::os::unix::fs::MetadataExt;

    const GEN: &str = "r20261022120000-a1b2c3";
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn target(vhost: &str, host: &str, url: &str) -> Target {
        Target { vhost: vhost.into(), host: host.into(), url: url.into() }
    }

    fn request() -> Apply {
        let mut files = BTreeMap::new();
        files.insert("httpd_config.conf".to_string(), "# server\n".to_string());
        files.insert("vhosts/a.test/vhconf.conf".to_string(), "docRoot /home/a/public_html/\n".to_string());
        files.insert("vhosts/svc.a.test/vhconf.conf".to_string(), "# service\n".to_string());
        files.insert("vhosts/olscp-gen/vhconf.conf".to_string(), "docRoot x\n".to_string());
        files.insert("health/a.test/id".to_string(), format!("{GEN} a.test\n"));
        files.insert("marker/generation".to_string(), format!("{GEN}\n"));
        files.insert("summary.json".to_string(), "{\"compiled_at\": \"2026-10-22T12:00:00Z\", \"vhosts\": {}}\n".to_string());
        Apply {
            generation: GEN.into(),
            files,
            health: vec![target("a.test", "a.test", "http://10.0.0.5:80/.ols-cpanel-generation/id")],
            epoch: 3,
            source_sha256: SHA.into(),
        }
    }

    #[test]
    fn grammars() {
        assert!(valid_generation(GEN));
        for bad in ["r2026102212000-a1b2c3", "r20261022120000-a1b2c", "r20261022120000-A1B2C3", "x20261022120000-a1b2c3",
                    "r20261022120000_a1b2c3", "r20261022120000-a1b2c3/", "../r20261022120000-a1b2c", ""] {
            assert!(!valid_generation(bad), "{bad}");
        }
        for good in ["httpd_config.conf", "marker/generation", "vhosts/a.test/vhconf.conf", "vhosts/svc.a.test/vhconf.conf",
                     "vhosts/cpanel-proxy/vhconf.conf", "vhosts/server-default/vhconf.conf", "vhosts/olscp-gen/vhconf.conf",
                     "health/olscp-c.test/id", "health/svc.b.example.com/id", "summary.json"] {
            assert!(valid_tree_path(good), "{good}");
        }
        for bad in ["", "/httpd_config.conf", "./httpd_config.conf", "health.json", "EPOCH", "SOURCE_SHA256", "MANIFEST.json",
                    "summary.json/x", "vhosts/a.test/summary.json", "./summary.json", "Summary.json",
                    "vhosts/a.test/vhconf.conf/x", "vhosts/../vhconf.conf", "vhosts/a.test/../../x/vhconf.conf",
                    "vhosts/A.test/vhconf.conf", "vhosts/localhost/vhconf.conf", "vhosts/svc./vhconf.conf",
                    "vhosts/a.test/other.conf", "health/a.test/id/", "health//id", "marker/other", "vhosts/a..test/vhconf.conf",
                    "vhosts/-a.test/vhconf.conf", "vhosts/a-.test/vhconf.conf"] {
            assert!(!valid_tree_path(bad), "{bad}");
        }
        for good in ["http://127.0.0.1:8088/.ols-cpanel-generation/id", "http://10.0.0.5:80/.ols-cpanel-generation/id",
                     "http://127.0.0.1:80/.ols-cpanel-generation/id", "http://127.0.0.1:65535/.ols-cpanel-generation/a_b-1.txt",
                     "https://10.0.0.5:443/.ols-cpanel-generation/id", "https://127.0.0.1:443/.ols-cpanel-generation/id"] {
            assert!(valid_health_url(good), "{good}");
        }
        for bad in ["https://127.0.0.1:8088/.ols-cpanel-generation/id", "http://10.0.0.5:8080/.ols-cpanel-generation/id",
                    "https://10.0.0.5:80/.ols-cpanel-generation/id", "https://10.0.0.5/.ols-cpanel-generation/id",
                    "https://10.0.0.5:0443/.ols-cpanel-generation/id", "https://a.test:443/.ols-cpanel-generation/id",
                    "https://10.0.0.5:443/.ols-cpanel-generation/.id", "https://10.0.0.5:443/other", "httpss://10.0.0.5:443/.ols-cpanel-generation/id",
                    "HTTPS://10.0.0.5:443/.ols-cpanel-generation/id", "https://[::1]:443/.ols-cpanel-generation/id",
                    "http://10.0.0.5/.ols-cpanel-generation/id", "http://a.test:80/.ols-cpanel-generation/id",
                    "http://127.0.0.1:8088/id", "http://127.0.0.1:8088/.ols-cpanel-generation/", "http://127.0.0.1:8088/.ols-cpanel-generation/../x",
                    "http://127.0.0.1:8088/.ols-cpanel-generation/a/b", "http://127.0.0.1:0/.ols-cpanel-generation/id",
                    "http://127.0.0.1:65536/.ols-cpanel-generation/id", "http://127.0.0.1:080/.ols-cpanel-generation/id",
                    "http://10.0.0.05:80/.ols-cpanel-generation/id", "http://10.0.0.256:80/.ols-cpanel-generation/id",
                    "http://user@127.0.0.1:8088/.ols-cpanel-generation/id", "http://[::1]:8088/.ols-cpanel-generation/id",
                    "http://127.0.0.1:8088/.ols-cpanel-generation/id?x", "http://127.0.0.1:8088/.ols-cpanel-generation/.id"] {
            assert!(!valid_health_url(bad), "{bad}");
        }
    }

    #[test]
    fn requests_are_checked() {
        assert!(check(&request()).is_ok());
        let cases: Vec<Box<dyn Fn(&mut Apply)>> = vec![
            Box::new(|a| a.generation = "r1-abc".into()),
            Box::new(|a| a.source_sha256 = SHA.to_uppercase()),
            Box::new(|a| a.source_sha256 = SHA[1..].into()),
            Box::new(|a| a.epoch = -1),
            Box::new(|a| {
                a.files.insert("../etc/passwd".into(), String::new());
            }),
            Box::new(|a| {
                a.files.insert("health.json".into(), "[]".into());
            }),
            Box::new(|a| a.health.push(target("bad_name", "a.test", "http://127.0.0.1:8088/.ols-cpanel-generation/id"))),
            Box::new(|a| a.health.push(target("a.test", "a.test\r\nX: y", "http://127.0.0.1:8088/.ols-cpanel-generation/id"))),
            Box::new(|a| a.health.push(target("a.test", "a.test", "http://192.0.2.1:80/other"))),
            Box::new(|a| {
                a.files.insert("httpd_config.conf".into(), "x".repeat(MAX_FILES + 1));
            }),
        ];
        for change in cases {
            let mut a = request();
            change(&mut a);
            assert!(check(&a).is_err());
        }
        // Unknown and missing fields, wrong types.
        let base = json!({"generation": GEN, "files": {}, "health": [], "epoch": 0, "source_sha256": SHA});
        assert!(serde_json::from_value::<Apply>(base.clone()).is_ok());
        for (key, value) in [("extra", json!(1)), ("epoch", json!(1.5)), ("epoch", json!("1")), ("files", json!({"a": 1})),
                             ("health", json!([{"vhost": "a.test", "host": "a.test", "url": "u", "x": 1}]))] {
            let mut bad = base.clone();
            bad[key] = value;
            assert!(serde_json::from_value::<Apply>(bad).is_err(), "{key}");
        }
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("source_sha256");
        assert!(serde_json::from_value::<Apply>(missing).is_err());
    }

    #[test]
    fn health_json_matches_python() {
        // json.dumps(targets, indent=1) in ols_generation_probe.generation_tree
        let targets = [
            target("a.test", "a.test", "http://127.0.0.1:8088/.ols-cpanel-generation/id"),
            target("cpanel-proxy", "cpanel.ols-health.invalid", "http://10.0.0.5:80/.ols-cpanel-generation/id"),
        ];
        assert_eq!(
            health_json(&targets),
            "[\n {\n  \"vhost\": \"a.test\",\n  \"host\": \"a.test\",\n  \"url\": \"http://127.0.0.1:8088/.ols-cpanel-generation/id\"\n },\n \
             {\n  \"vhost\": \"cpanel-proxy\",\n  \"host\": \"cpanel.ols-health.invalid\",\n  \"url\": \"http://10.0.0.5:80/.ols-cpanel-generation/id\"\n }\n]"
        );
        assert_eq!(health_json(&[]), "[]");
    }

    #[test]
    fn tree_is_written_exclusively() {
        let temp = TempTree::new();
        let dir = temp.path().join(GEN);
        write_tree(&dir, &request()).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(fs::metadata(dir.join("vhosts/a.test")).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(fs::metadata(dir.join("vhosts/a.test/vhconf.conf")).unwrap().mode() & 0o7777, 0o644);
        assert_eq!(fs::read_to_string(dir.join("EPOCH")).unwrap(), "3\n");
        assert_eq!(fs::read_to_string(dir.join("SOURCE_SHA256")).unwrap(), format!("{SHA}\n"));
        assert_eq!(fs::read_to_string(dir.join("marker/generation")).unwrap(), format!("{GEN}\n"));
        assert!(fs::read_to_string(dir.join("summary.json")).unwrap().starts_with("{\"compiled_at\""));
        assert_eq!(fs::metadata(dir.join("summary.json")).unwrap().mode() & 0o7777, 0o644);
        assert!(fs::read_to_string(dir.join("health.json")).unwrap().starts_with("[\n {\n  \"vhost\": \"a.test\""));
        // An existing tree is never reused or written through.
        assert!(write_tree(&dir, &request()).is_err());
        // A planted link is never followed (the file is created exclusively).
        let other = temp.path().join("other");
        create_dir(&other, 0o700).unwrap();
        fs::create_dir(other.join("marker")).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, other.join("marker/generation")).unwrap();
        assert!(write_new(&other, "marker/generation", b"x").is_err());
        std::os::unix::fs::symlink(temp.path(), other.join("vhosts")).unwrap();
        assert!(write_new(&other, "vhosts/victim", b"x").is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    }

    fn activator(temp: &TempTree, validator: &str, mock: Mock) -> Activator<Mock> {
        let state = temp.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let binary = state.join("openlitespeed");
        fs::write(&binary, b"binary").unwrap();
        // The restriction epoch the generations of these tests were compiled against.
        fs::write(state.join("epoch.json"), r#"{"epoch": 3, "history": []}"#).unwrap();
        let mut a = Activator::new(Paths::under(&state, &binary), mock);
        a.validator = vec![validator.into()];
        a.validator_file = binary;
        a
    }

    #[test]
    fn apply_stages_validates_and_activates() {
        let temp = TempTree::new();
        let mock = Mock::new();
        *mock.after_reload.borrow_mut() = Some(GEN.to_string());
        let a = activator(&temp, "/usr/bin/true", mock);
        let staging = temp.path().join("state/staging");
        let out = apply(&a, &staging, request()).unwrap();
        assert_eq!(out, json!({"generation": GEN, "valid": true, "result": "committed", "reason": null}));
        let gen = a.paths.gen_root.join(GEN);
        assert_eq!(fs::read_to_string(gen.join("SOURCE_SHA256")).unwrap(), format!("{SHA}\n"));
        assert_eq!(a.generation_epoch(GEN), 3);
        assert_eq!(a.health_targets(GEN).unwrap().len(), 1);
        assert!(gen.join("MANIFEST.json").is_file());
        // The staging copy is gone; the staging directory itself is root-only.
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        assert_eq!(fs::metadata(&staging).unwrap().mode() & 0o7777, 0o700);
        // Generations are immutable.
        assert_eq!(apply(&a, &staging, request()).unwrap_err().0, "EXISTS");
    }

    #[test]
    fn invalid_and_refused_generations() {
        let temp = TempTree::new();
        let a = activator(&temp, "/usr/bin/false", Mock::new());
        let staging = temp.path().join("state/staging");
        let out = apply(&a, &staging, request()).unwrap();
        assert_eq!(out["valid"], json!(false));
        assert_eq!(out["result"], json!("invalid"));
        // A generation without health targets validates but the activator refuses it.
        let temp = TempTree::new();
        let a = activator(&temp, "/usr/bin/true", Mock::new());
        let mut req = request();
        req.health.clear();
        let out = apply(&a, &temp.path().join("state/staging"), req).unwrap();
        assert_eq!(out, json!({"generation": GEN, "valid": true, "result": "refused", "reason": "no vhost health targets"}));
        // Bad arguments never touch the disk.
        let mut req = request();
        req.epoch = -5;
        assert_eq!(apply(&a, &temp.path().join("state/staging2"), req).unwrap_err().0, "BAD_ARGS");
        assert!(!temp.path().join("state/staging2").exists());
    }
}
