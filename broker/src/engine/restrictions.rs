//! `engine.restrictions_fold` and the first step of every round of the broker's enforcement thread: the hook's
//! durable restriction intents (restrictions/, docs/product-interfaces.md "Restriction intents") folded into
//! the restriction epoch, oldest first, each removed only once the raised epoch is durable. Byte for byte the
//! reasons of `LocalEngine::intentReason` and `ols_events.intent_reason`.

use crate::activator::generation::{cat, fsync_dir, read_intent, Activator};
use crate::activator::runtime::Runtime;
use serde_json::{json, Value};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

type Reply = Result<Value, (&'static str, String)>;

/// The `restrict` reason of an intent: its "reason" (each byte outside printable ASCII becomes "?", at most 200
/// bytes) when it is a JSON object with a non-empty text reason; otherwise, unreadable, a link, larger than
/// 64 KiB or malformed, it is still a restriction (fail closed) with a reason naming the file.
pub fn intent_reason(path: &Path, name: &str) -> String {
    let reason = read_intent(path)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|intent| match intent {
            Value::Object(map) => map.get("reason").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .unwrap_or_default();
    let printable: String = reason.bytes().take(200).map(|b| if (0x20..=0x7e).contains(&b) { b as char } else { '?' }).collect();
    if printable.is_empty() {
        format!("restriction intent {name} (malformed)")
    } else {
        printable
    }
}

/// Folds every intent, oldest first: `restrict` with the intent's reason and its time (the epoch history keeps the
/// time the restriction was requested, so folding never moves the enforcement deadline), then the intent removed
/// and the directory synced. The activation lock is awaited at most `wait` seconds per intent; a busy lock or a
/// failed `restrict` stops the fold (`ACTIVATOR`) with that intent and the later ones kept.
/// Returns `{"folded": [names], "epoch": <epoch after the last fold, or null>}`.
pub fn fold<R: Runtime>(activator: &Activator<R>, wait: f64) -> Reply {
    let dir = &activator.paths.restrictions;
    let intents = activator.pending_intents().map_err(|e| ("INTERNAL", e))?;
    let mut folded = Vec::new();
    let mut epoch = Value::Null;
    for (name, since) in intents {
        let path = cat(dir, &name);
        let reason = intent_reason(&path, &name);
        let raised = activator
            .restrict_since(&reason, since, wait)
            .map_err(super::apply::activator_error)?
            .ok_or(("ACTIVATOR", format!("activation lock busy: restriction intent {name} kept")))?;
        match raised.get("epoch") {
            Some(Value::Number(n)) if n.is_i64() => epoch = raised["epoch"].clone(),
            _ => return Err(("ACTIVATOR", "activator restrict returned no epoch".into())),
        }
        // Only now that the raised epoch is durable may the intent go. Gone already: another folder raised it too.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(("INTERNAL", format!("cannot remove the folded restriction intent {name}: {e}"))),
        }
        fsync_dir(dir).map_err(super::apply::activator_error)?;
        folded.push(name);
    }
    Ok(json!({"folded": folded, "epoch": epoch}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activator::generation::Paths;
    use crate::activator::testutil::{Mock, TempTree};

    const OLD: &str = "1729600000000000001-0123456789abcdef0123456789abcdef.json";
    const MID: &str = "1729600000000000002-fedcba9876543210fedcba9876543210.json";
    const NEW: &str = "17296000000000000030-00000000000000000000000000000000.json";

    fn activator(temp: &TempTree) -> Activator<Mock> {
        let state = temp.path().join("state");
        fs::create_dir_all(state.join("restrictions")).unwrap();
        let a = Activator::new(Paths::under(&state, &state.join("openlitespeed")), Mock::new());
        a.ensure_dirs().unwrap();
        a
    }

    fn history(a: &Activator<Mock>) -> Vec<Value> {
        let record: Value = serde_json::from_slice(&fs::read(&a.paths.epoch).unwrap()).unwrap();
        record["history"].as_array().unwrap().clone()
    }

    #[test]
    fn reasons_like_the_php_engine() {
        let temp = TempTree::new();
        let dir = temp.path();
        let write = |name: &str, text: &[u8]| {
            fs::write(dir.join(name), text).unwrap();
            dir.join(name)
        };
        let reason = |path: &Path| intent_reason(path, "n.json");
        assert_eq!(reason(&write("a", br#"{"event": "Accounts::suspendacct", "reason": "Accounts::suspendacct bob", "time": 1, "user": "bob"}"#)),
                   "Accounts::suspendacct bob");
        // One "?" per byte outside printable ASCII (UTF-8 bytes, tabs, newlines), at most 200 bytes.
        assert_eq!(reason(&write("b", "{\"reason\": \"caf\u{e9}\\tx\\n\"}".as_bytes())), "caf???x?");
        assert_eq!(reason(&write("c", format!("{{\"reason\": \"{}\"}}", "r".repeat(300)).as_bytes())).len(), 200);
        let malformed = "restriction intent n.json (malformed)";
        for text in [&b"{broken"[..], b"[\"reason\"]", b"{\"reason\": 5}", b"{\"reason\": \"\"}", b"{}", b"", b"\"x\"",
                     b"{\"reason\": \"\\ud800\"}", b"{\"reason\": \"a\xff\"}"] {
            assert_eq!(reason(&write("d", text)), malformed, "{text:?}");
        }
        let big = format!("{{\"reason\": \"x\", \"pad\": \"{}\"}}", "p".repeat(70000));
        assert_eq!(reason(&write("e", big.as_bytes())), malformed);
        let target = write("f", br#"{"reason": "via link"}"#);
        std::os::unix::fs::symlink(&target, dir.join("g")).unwrap();
        assert_eq!(reason(&dir.join("g")), malformed);
        assert_eq!(reason(&dir.join("missing")), malformed);
    }

    #[test]
    fn folds_oldest_first_and_keeps_the_intent_time() {
        let temp = TempTree::new();
        let a = activator(&temp);
        assert_eq!(fold(&a, 1.0).unwrap(), json!({"folded": [], "epoch": null}));
        let dir = &a.paths.restrictions;
        fs::write(cat(dir, NEW), r#"{"event": null, "reason": "third", "time": 990.5, "user": null}"#).unwrap();
        fs::write(cat(dir, MID), "{not json").unwrap();
        fs::write(cat(dir, OLD), r#"{"event": "Accounts::Remove", "reason": "Accounts::Remove bob", "time": 900, "user": "bob"}"#).unwrap();
        fs::write(cat(dir, "x.json.tmp-0123"), "{}").unwrap(); // ignored: not an intent name
        // Every unfolded intent makes every generation stale.
        assert!(a.stale(Some("any")));
        let out = fold(&a, 1.0).unwrap();
        assert_eq!(out, json!({"folded": [OLD, MID, NEW], "epoch": 3}));
        let h = history(&a);
        assert_eq!(h.iter().map(|e| e["reason"].as_str().unwrap()).collect::<Vec<_>>(),
                   ["Accounts::Remove bob", &format!("restriction intent {MID} (malformed)"), "third"]);
        // History times are the intents' (never later than now: the mock clock is 1000; the malformed intent counts
        // from its modification time, which is later, so from now).
        assert_eq!(h[0]["time"], json!(900.0));
        assert_eq!(h[1]["time"], json!(1000.0));
        assert_eq!(h[2]["time"], json!(990.5));
        let left: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left, ["x.json.tmp-0123"]);
        assert_eq!(a.pending_intents().unwrap(), []);
    }

    #[test]
    fn a_failed_restrict_keeps_that_intent_and_the_later_ones() {
        let temp = TempTree::new();
        let a = activator(&temp);
        let dir = &a.paths.restrictions;
        fs::write(cat(dir, OLD), r#"{"reason": "first", "time": 1}"#).unwrap();
        fs::write(cat(dir, MID), r#"{"reason": "second", "time": 2}"#).unwrap();
        // The activation lock held elsewhere (a transaction): the bounded wait gives up, nothing is removed.
        let holder = fs::OpenOptions::new().append(true).create(true).open(&a.paths.lock).unwrap();
        assert_eq!(unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&holder), libc::LOCK_EX) }, 0);
        let (code, _) = fold(&a, 2.0).unwrap_err();
        assert_eq!(code, "ACTIVATOR");
        assert!(cat(dir, OLD).exists() && cat(dir, MID).exists());
        drop(holder);
        // A damaged epoch record: restrict refuses, both intents stay.
        fs::write(&a.paths.epoch, "{broken").unwrap();
        assert_eq!(fold(&a, 1.0).unwrap_err().0, "ACTIVATOR");
        assert!(cat(dir, OLD).exists() && cat(dir, MID).exists());
        fs::remove_file(&a.paths.epoch).unwrap();
        assert_eq!(fold(&a, 1.0).unwrap()["folded"], json!([OLD, MID]));
    }
}
