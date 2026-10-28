//! `engine.events`, `engine.events_done` and `engine.events_quarantine`: the hook spool (events/*.json, one
//! event per file, names `<time_ns>-<uuid hex>.json` as ols_events.hook writes them) read and consumed through
//! the broker; malformed entries are moved to events/quarantine/ (review RV-29, finding 16).

use crate::activator::generation::{intent_name, oldest_first, uuid_hex};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const MAX_PENDING: usize = 1000;
/// A hook event is a few hundred bytes; anything far larger is not one.
const MAX_EVENT: u64 = 1 << 20;

type Reply = Result<Value, (&'static str, String)>;

/// `^[0-9]{1,24}-[0-9a-f]{32}\.json$` (LocalEngine::EVENT_NAME; also the restriction intents' names).
pub fn valid_name(name: &str) -> bool {
    intent_name(name)
}

fn read_event(path: &Path) -> Result<Value, String> {
    // Never follow a link out of the spool; O_NONBLOCK keeps a planted FIFO from blocking the read.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_EVENT + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_EVENT {
        return Err("event file too large".into());
    }
    match serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())? {
        event @ Value::Object(_) => Ok(event),
        _ => Err("event is not a JSON object".into()),
    }
}

/// Spool entries oldest first (names start with the time in nanoseconds: shorter names first, then byte order,
/// like LocalEngine), at most MAX_PENDING; unreadable or malformed ones are listed with an error instead of the
/// event.
pub fn pending(spool: &Path) -> Reply {
    let entries = match fs::read_dir(spool) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(json!({"pending": []})),
        Err(e) => return Err(("INTERNAL", format!("{}: {e}", spool.display()))),
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    oldest_first(&mut names);
    names.truncate(MAX_PENDING);
    let pending: Vec<Value> = names
        .into_iter()
        .map(|name| {
            let result = if valid_name(&name) { read_event(&spool.join(&name)) } else { Err("not a spool file name".into()) };
            match result {
                Ok(event) => json!({"name": name, "event": event}),
                Err(error) => json!({"name": name, "error": error}),
            }
        })
        .collect();
    Ok(json!({"pending": pending}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    names: Vec<String>,
}

/// Moves the named spool entries to done/; all names are checked before anything moves.
pub fn done(spool: &Path, args: Value) -> Reply {
    let a: Done = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    if a.names.len() > MAX_PENDING {
        return Err(("BAD_ARGS", format!("at most {MAX_PENDING} names")));
    }
    let mut seen = HashSet::new();
    for name in &a.names {
        if !valid_name(name) || !seen.insert(name.as_str()) {
            return Err(("BAD_ARGS", format!("not a spool file name (or repeated): {}", super::printable(name))));
        }
        if !fs::symlink_metadata(spool.join(name)).map_or(false, |m| m.is_file()) {
            return Err(("NOT_FOUND", format!("no spool entry {name}")));
        }
    }
    let target = subdirectory(spool, "done")?;
    for name in &a.names {
        fs::rename(spool.join(name), target.join(name)).map_err(|e| ("INTERNAL", format!("{name}: {e}")))?;
    }
    Ok(json!({"done": a.names}))
}

/// `spool/<name>`, a root 0700 directory, created when absent (never through a link).
fn subdirectory(spool: &Path, name: &str) -> Result<std::path::PathBuf, (&'static str, String)> {
    let target = spool.join(name);
    match fs::symlink_metadata(&target) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(("INTERNAL", format!("{} is not a directory", target.display()))),
        Err(_) => {
            fs::DirBuilder::new().mode(0o700).create(&target).map_err(|e| ("INTERNAL", format!("{}: {e}", target.display())))?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).map_err(|e| ("INTERNAL", e.to_string()))?;
        }
    }
    Ok(target)
}

/// One directory entry of the spool as `pending` lists it: a `*.json` name, never a path, "." or "..".
fn entry_name(name: &str) -> bool {
    name.ends_with(".json") && name.len() <= 255 && !name.contains('/') && !name.contains('\0')
}

/// The spool entry `pending` listed as `name`: that name, or (for a name that is not UTF-8, which `pending` lists
/// with U+FFFD) the one entry listed that way.
fn locate(spool: &Path, name: &str) -> Option<OsString> {
    if fs::symlink_metadata(spool.join(name)).is_ok() {
        return Some(OsString::from(name));
    }
    if !name.contains('\u{fffd}') {
        return None;
    }
    fs::read_dir(spool).ok()?.filter_map(Result::ok).map(|e| e.file_name()).find(|n| n.to_string_lossy() == name)
}

/// rename(2) that never replaces an existing target (RENAME_NOREPLACE; plain rename after a check where the file
/// system lacks it: the directory is root's alone).
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    let c = |p: &Path| CString::new(p.as_os_str().as_bytes()).map_err(|_| std::io::Error::from(ErrorKind::InvalidInput));
    let (old, new) = (c(from)?, c(to)?);
    // SAFETY: two valid NUL-terminated paths; renameat2 has no other preconditions.
    let rc = unsafe {
        libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, old.as_ptr(), libc::AT_FDCWD, new.as_ptr(), libc::RENAME_NOREPLACE)
    };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EINVAL) => {
            if fs::symlink_metadata(to).is_ok() {
                return Err(ErrorKind::AlreadyExists.into());
            }
            fs::rename(from, to)
        }
        _ => Err(error),
    }
}

/// Moves the named spool entries (names as `pending` lists them, malformed ones included; a link is moved as the
/// link) to quarantine/; all names are checked before anything moves, and an entry already quarantined under the
/// same name is never replaced (the newcomer gets a `.<16 hex>` suffix).
pub fn quarantine(spool: &Path, args: Value) -> Reply {
    let a: Done = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    if a.names.len() > MAX_PENDING {
        return Err(("BAD_ARGS", format!("at most {MAX_PENDING} names")));
    }
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(a.names.len());
    for name in &a.names {
        if !entry_name(name) || !seen.insert(name.as_str()) {
            return Err(("BAD_ARGS", format!("not a spool entry name (or repeated): {}", super::printable(name))));
        }
        let entry = locate(spool, name).ok_or_else(|| ("NOT_FOUND", format!("no spool entry {}", super::printable(name))))?;
        entries.push(entry);
    }
    let target = subdirectory(spool, "quarantine")?;
    for entry in entries {
        let from = spool.join(&entry);
        let mut to = target.join(&entry);
        let mut attempts = 0;
        loop {
            match rename_noreplace(&from, &to) {
                Ok(()) => break,
                Err(e) if e.kind() == ErrorKind::AlreadyExists && attempts < 8 => {
                    attempts += 1;
                    let mut renamed = entry.clone();
                    renamed.push(format!(".{}", &uuid_hex()[..16]));
                    to = target.join(renamed);
                }
                Err(e) => return Err(("INTERNAL", format!("{}: {e}", super::printable(&entry.to_string_lossy())))),
            }
        }
    }
    let _ = crate::activator::generation::fsync_dir(spool);
    let _ = crate::activator::generation::fsync_dir(&target);
    Ok(json!({"quarantined": a.names}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::testutil::TempTree;

    const A: &str = "1729600000000000001-0123456789abcdef0123456789abcdef.json";
    const B: &str = "1729600000000000002-fedcba9876543210fedcba9876543210.json";

    #[test]
    fn names() {
        assert!(valid_name(A) && valid_name(B));
        for bad in ["", ".json", "1-0123456789abcdef0123456789abcde.json", "1-0123456789ABCDEF0123456789abcdef.json",
                    "x-0123456789abcdef0123456789abcdef.json", "1-0123456789abcdef0123456789abcdef.json.tmp",
                    "../1-0123456789abcdef0123456789abcdef.json", "1-0123456789abcdef0123456789abcdef", "done"] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn spool_is_listed_oldest_first_and_consumed() {
        let temp = TempTree::new();
        let spool = temp.path().join("events");
        assert_eq!(pending(&spool).unwrap(), json!({"pending": []}));
        fs::create_dir(&spool).unwrap();
        fs::write(spool.join(B), r#"{"event": "Accounts::Remove", "user": "b"}"#).unwrap();
        fs::write(spool.join(A), r#"{"event": "Accounts::suspendacct", "user": "a"}"#).unwrap();
        let broken = "1729600000000000003-00000000000000000000000000000000.json";
        fs::write(spool.join(broken), "{not json").unwrap();
        let link = "1729600000000000004-11111111111111111111111111111111.json";
        std::os::unix::fs::symlink("/etc/passwd", spool.join(link)).unwrap();
        fs::write(spool.join("stray.json"), "{}").unwrap();
        fs::write(spool.join("x.tmp-1"), "{}").unwrap();
        let list = pending(&spool).unwrap()["pending"].as_array().unwrap().clone();
        let names: Vec<&str> = list.iter().map(|e| e["name"].as_str().unwrap()).collect();
        // Shorter names first, then byte order (LocalEngine's order).
        assert_eq!(names, ["stray.json", A, B, broken, link]);
        assert_eq!(list[1]["event"]["user"], json!("a"));
        assert!(list[3]["error"].is_string() && list[3].get("event").is_none());
        assert!(list[4]["error"].is_string() && list[0]["error"].is_string());

        assert_eq!(done(&spool, json!({"names": [A]})).unwrap(), json!({"done": [A]}));
        assert!(spool.join("done").join(A).is_file() && !spool.join(A).exists());
        assert_eq!(fs::metadata(spool.join("done")).unwrap().permissions().mode() & 0o7777, 0o700);
        // Already moved, never existed, not a spool name, a link, repeated, unknown fields: nothing moves.
        for (args, code) in [
            (json!({"names": [B, A]}), "NOT_FOUND"),
            (json!({"names": [B, "../../etc/passwd"]}), "BAD_ARGS"),
            (json!({"names": [B, "stray.json"]}), "BAD_ARGS"),
            (json!({"names": [B, link]}), "NOT_FOUND"),
            (json!({"names": [B, B]}), "BAD_ARGS"),
            (json!({"names": [B], "all": true}), "BAD_ARGS"),
            (json!({}), "BAD_ARGS"),
        ] {
            assert_eq!(done(&spool, args).unwrap_err().0, code);
            assert!(spool.join(B).is_file());
        }
    }

    #[test]
    fn oldest_first_by_length_then_bytes() {
        let temp = TempTree::new();
        let late = "1000000000000000000-0123456789abcdef0123456789abcdef.json";
        let early = "999999999999999999-0123456789abcdef0123456789abcdef.json";
        for name in [late, early] {
            fs::write(temp.path().join(name), "{}").unwrap();
        }
        let list = pending(temp.path()).unwrap()["pending"].as_array().unwrap().clone();
        assert_eq!(list.iter().map(|e| e["name"].as_str().unwrap()).collect::<Vec<_>>(), [early, late]);
        assert!(valid_name(&format!("{}-0123456789abcdef0123456789abcdef.json", "9".repeat(24))));
        assert!(!valid_name(&format!("{}-0123456789abcdef0123456789abcdef.json", "9".repeat(25))));
    }

    #[test]
    fn malformed_entries_are_quarantined() {
        let temp = TempTree::new();
        let spool = temp.path().join("events");
        fs::create_dir(&spool).unwrap();
        let broken = "1729600000000000003-00000000000000000000000000000000.json";
        let link = "1729600000000000004-11111111111111111111111111111111.json";
        let victim = temp.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        fs::write(spool.join(broken), "{not json").unwrap();
        fs::write(spool.join(A), "{}").unwrap();
        std::os::unix::fs::symlink(&victim, spool.join(link)).unwrap();
        fs::write(spool.join("stray.json"), "{}").unwrap();
        // A name that is not UTF-8 is listed lossily and still addressable by that listing.
        let raw = std::ffi::OsStr::from_bytes(b"x\xff.json");
        fs::write(spool.join(raw), "{}").unwrap();
        let listed: Vec<String> = pending(&spool).unwrap()["pending"].as_array().unwrap().iter()
            .filter(|e| e.get("error").is_some()).map(|e| e["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(listed.len(), 4);
        // Nothing moves when any name is invalid, repeated or absent.
        for (args, code) in [
            (json!({"names": [broken, "../x.json"]}), "BAD_ARGS"),
            (json!({"names": [broken, "done"]}), "BAD_ARGS"),
            (json!({"names": [broken, "a/b.json"]}), "BAD_ARGS"),
            (json!({"names": [broken, broken]}), "BAD_ARGS"),
            (json!({"names": [broken, B]}), "NOT_FOUND"),
            (json!({"names": [broken], "x": 1}), "BAD_ARGS"),
            (json!({"names": vec![broken; 1001]}), "BAD_ARGS"),
        ] {
            assert_eq!(quarantine(&spool, args).unwrap_err().0, code);
            assert!(spool.join(broken).is_file());
        }
        assert_eq!(quarantine(&spool, json!({"names": listed})).unwrap(), json!({"quarantined": listed}));
        let q = spool.join("quarantine");
        assert_eq!(fs::metadata(&q).unwrap().permissions().mode() & 0o7777, 0o700);
        assert!(q.join(broken).is_file() && q.join("stray.json").is_file() && q.join(raw).is_file());
        // The link moved as the link; its target is untouched.
        assert_eq!(fs::read_link(q.join(link)).unwrap(), victim);
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        // Valid entries stay; what remains lists only them.
        let rest = pending(&spool).unwrap()["pending"].as_array().unwrap().clone();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0]["name"], json!(A));
        // The same name again never replaces the earlier quarantined entry.
        fs::write(spool.join(broken), "second").unwrap();
        quarantine(&spool, json!({"names": [broken]})).unwrap();
        assert_eq!(fs::read_to_string(q.join(broken)).unwrap(), "{not json");
        let suffixed: Vec<String> = fs::read_dir(&q).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(broken) && n.len() == broken.len() + 17).collect();
        assert_eq!(suffixed.len(), 1);
        assert_eq!(fs::read_to_string(q.join(&suffixed[0])).unwrap(), "second");
        assert!(rename_noreplace(&q.join(broken), &q.join("stray.json")).is_err());
    }

    #[test]
    fn at_most_a_thousand_entries() {
        let temp = TempTree::new();
        for i in 0..1005 {
            fs::write(temp.path().join(format!("{:019}-0123456789abcdef0123456789abcdef.json", 1_000_000 + i)), "{}").unwrap();
        }
        let list = pending(temp.path()).unwrap()["pending"].as_array().unwrap().clone();
        assert_eq!(list.len(), MAX_PENDING);
        assert_eq!(list[0]["name"], json!("0000000000001000000-0123456789abcdef0123456789abcdef.json"));
    }
}
