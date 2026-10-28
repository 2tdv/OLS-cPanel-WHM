//! Decision logic of the activator against a scripted runtime: no root, no services, no network.

use super::*;
use crate::activator::testutil::{Mock, TempTree};

fn fixture(mock: Mock) -> (TempTree, Activator<Mock>) {
    let temp = TempTree::new();
    let state = temp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    let binary = state.join("openlitespeed");
    fs::write(&binary, b"binary-1").unwrap();
    let activator = Activator::new(Paths::under(&state, &binary), mock);
    activator.ensure_dirs().unwrap();
    (temp, activator)
}

/// A generation like ols_generation_probe.generation_tree: EPOCH, health.json and per-vhost IDs.
fn generation(a: &Activator<Mock>, gen: &str, epoch: Option<i64>, vhosts: &[&str]) {
    let dir = a.gen_dir(gen);
    fs::create_dir_all(dir.join("marker")).unwrap();
    fs::write(dir.join("marker/generation"), format!("{gen}\n")).unwrap();
    fs::write(dir.join("httpd_config.conf"), format!("# {gen}\n")).unwrap();
    if let Some(epoch) = epoch {
        fs::write(dir.join("EPOCH"), format!("{epoch}\n")).unwrap();
    }
    let targets: Vec<Value> = vhosts
        .iter()
        .map(|v| json!({"vhost": v, "host": v, "url": format!("http://127.0.0.1:80/.well-known/ols-cpanel-health/{v}")}))
        .collect();
    if !targets.is_empty() {
        fs::write(dir.join("health.json"), serde_json::to_string(&targets).unwrap()).unwrap();
    }
}

/// A passing validation record bound to the current tree and binary.
fn bind(a: &Activator<Mock>, gen: &str) {
    let record = json!({"generation": gen, "valid": true, "tree_sha256": a.tree_sha256(gen).unwrap(),
                        "binary_sha256": file_sha256(&a.paths.binary).unwrap()});
    fs::write(cat(&a.paths.validations, &format!("{gen}.json")), record.to_string()).unwrap();
}

fn tx(a: &Activator<Mock>, file: &str, record: Value) {
    fs::write(cat(&a.paths.journal, &format!("{file}.json")), record.to_string()).unwrap();
}

fn point(a: &Activator<Mock>, gen: &str) {
    a.switch(gen).unwrap();
}

fn epoch_record(a: &Activator<Mock>, text: &str) {
    fs::write(&a.paths.epoch, text).unwrap();
}

fn journal_record(a: &Activator<Mock>, id: &str) -> Value {
    serde_json::from_slice(&fs::read(cat(&a.paths.journal, &format!("{id}.json"))).unwrap()).unwrap()
}

#[test]
fn epoch_fresh_installation_and_restrict() {
    let (_t, a) = fixture(Mock::new());
    generation(&a, "old", Some(0), &[]);
    assert_eq!(a.current_epoch(), Ok(0));
    assert!(!a.stale(Some("old")) && !a.stale(None));
    let out = a.restrict("suspend x").unwrap();
    assert_eq!(out, json!({"epoch": 1, "reason": "suspend x"}));
    assert_eq!(a.current_epoch(), Ok(1));
    assert_eq!(fs::read_to_string(&a.paths.epoch_high).unwrap(), "1\n");
    let record: Value = serde_json::from_slice(&fs::read(&a.paths.epoch).unwrap()).unwrap();
    assert_eq!(record["history"], json!([{"epoch": 1, "reason": "suspend x", "time": 1000.0}]));
    generation(&a, "new", Some(1), &[]);
    assert!(a.stale(Some("old")) && !a.stale(Some("new")));
    generation(&a, "broken", None, &[]);
    assert!(a.stale(Some("broken"))); // unknown epoch is never treated as current
    assert_eq!(a.restrict(&"r".repeat(300)).unwrap()["reason"].as_str().unwrap().len(), 200);
}

#[test]
fn epoch_missing_record_fails_closed() {
    let (_t, a) = fixture(Mock::new());
    // Missing record while a generation of a later epoch exists.
    generation(&a, "g1", Some(1), &[]);
    assert!(a.current_epoch().is_err());
    assert!(a.stale(Some("g1")));
    fs::remove_dir_all(a.gen_dir("g1")).unwrap();
    // Missing record while a generation of unknown epoch exists (e.g. a staging leftover).
    generation(&a, ".staging-x", None, &[]);
    assert!(a.current_epoch().is_err());
    fs::remove_dir_all(a.gen_dir(".staging-x")).unwrap();
    assert_eq!(a.current_epoch(), Ok(0));
    // Missing record with a high-water mark.
    fs::write(&a.paths.epoch_high, "1\n").unwrap();
    assert!(a.current_epoch().is_err());
    assert!(matches!(a.restrict("x"), Err(Error::Epoch(_))));
}

#[test]
fn epoch_damaged_records_fail_closed() {
    let (_t, a) = fixture(Mock::new());
    generation(&a, "g1", Some(1), &[]);
    for text in ["{broken", "{\"epoch\": true}", "{\"epoch\": -1}", "{\"epoch\": 1.0}", "{\"epoch\": \"1\"}", "[1]", "{}", "null", ""] {
        epoch_record(&a, text);
        assert!(a.current_epoch().is_err(), "{text}");
        assert!(a.stale(Some("g1")), "{text}");
        assert!(matches!(a.restrict("x"), Err(Error::Epoch(_))), "{text}");
        assert_eq!(fs::read_to_string(&a.paths.epoch).unwrap(), text, "a damaged record is never reset");
    }
    epoch_record(&a, "{\"epoch\": 1, \"history\": []}");
    assert_eq!(a.current_epoch(), Ok(1));
    // Below its high-water mark, or an unreadable mark.
    fs::write(&a.paths.epoch_high, "2\n").unwrap();
    assert!(a.current_epoch().is_err());
    fs::write(&a.paths.epoch_high, "two\n").unwrap();
    assert!(a.current_epoch().is_err());
    fs::write(&a.paths.epoch_high, " 1 \n").unwrap();
    assert_eq!(a.current_epoch(), Ok(1));
    assert!(!a.stale(Some("g1")));
}

#[test]
fn first_unapplied_restriction_counts_from_the_earliest_missing() {
    let (_t, a) = fixture(Mock::new());
    assert_eq!(a.first_unapplied_restriction(0), None);
    epoch_record(&a, r#"{"epoch": 2, "history": [{"epoch": 1, "time": 100.0}, {"epoch": 2, "time": 900.0}]}"#);
    assert_eq!(a.first_unapplied_restriction(0), Some(100.0));
    assert_eq!(a.first_unapplied_restriction(1), Some(900.0));
    assert_eq!(a.first_unapplied_restriction(2), None);
    assert_eq!(a.first_unapplied_restriction(-1), Some(100.0));
    epoch_record(&a, r#"{"epoch": 2, "history": [{"epoch": true, "time": 5}, {"epoch": 1.0, "time": 6}, {"epoch": 2, "time": "300"}]}"#);
    assert_eq!(a.first_unapplied_restriction(0), Some(300.0));
    epoch_record(&a, r#"{"epoch": 2, "history": [{"epoch": 1, "time": 100}, {"epoch": 2}]}"#);
    assert_eq!(a.first_unapplied_restriction(0), None, "one unreadable entry makes the deadline unknown");
    assert_eq!(a.first_unapplied_restriction(1), None);
    epoch_record(&a, r#"{"epoch": 2, "history": null}"#);
    assert_eq!(a.first_unapplied_restriction(0), None);
    epoch_record(&a, "{broken");
    assert_eq!(a.first_unapplied_restriction(0), None);
}

#[test]
fn journal_orders_by_seq_never_by_name_or_time() {
    let (_t, a) = fixture(Mock::new());
    tx(&a, "a", json!({"id": "a", "seq": 3, "new": "g3", "state": "committed", "started": 1.0}));
    tx(&a, "b", json!({"id": "b", "seq": 1, "new": "g1", "state": "committed", "started": 9.0}));
    tx(&a, "c", json!({"id": "c", "seq": 2, "new": "g2", "state": "committed", "started": 5.0}));
    tx(&a, "d", json!({"id": "d", "seq": 2, "new": "g2b", "state": "aborted", "started": 4.0}));
    tx(&a, "e", json!({"id": "e", "new": "g0", "state": "aborted"}));
    let order: Vec<Value> = a.transactions().unwrap().iter().map(|t| t["id"].clone()).collect();
    assert_eq!(order, vec![json!("e"), json!("b"), json!("d"), json!("c"), json!("a")]);
    assert_eq!(a.committed().unwrap().as_deref(), Some("g3"));
    assert_eq!(a.next_seq().unwrap(), json!(4));
    // Leftover temporary files of write_durable are not records.
    fs::write(cat(&a.paths.journal, "x.json.tmp-0"), "{broken").unwrap();
    assert_eq!(a.transactions().unwrap().len(), 5);
    tx(&a, "f", json!({"id": "f", "seq": "7", "new": "g", "state": "aborted"}));
    assert!(a.transactions().is_err(), "a non-numeric seq is a crash in Python too");
}

#[test]
fn journal_writes_history_and_sorted_json() {
    let (_t, a) = fixture(Mock::new());
    let mut record = Map::new();
    record.insert("id".into(), json!("t1"));
    record.insert("seq".into(), json!(1));
    a.journal(&mut record, vec![("state", json!("intent"))]).unwrap();
    a.journal(&mut record, vec![("state", json!("reloaded")), ("reload_exit", json!(0))]).unwrap();
    let text = fs::read_to_string(cat(&a.paths.journal, "t1.json")).unwrap();
    assert_eq!(text, r#"{"history": ["intent", "reloaded"], "id": "t1", "reload_exit": 0, "seq": 1, "state": "reloaded", "updated": 1000.0}"#);
}

#[test]
fn superseded_transactions_are_not_rolled_back() {
    let mock = Mock::running(Some("g2"));
    let (_t, a) = fixture(mock);
    for gen in ["g0", "g1", "g2"] {
        generation(&a, gen, Some(0), &["site"]);
        bind(&a, gen);
    }
    point(&a, "g2");
    for (seq, (gen, state)) in [("g0", "committed"), ("g1", "switched"), ("g2", "committed")].iter().enumerate() {
        tx(&a, &format!("t{}", seq + 1), json!({"id": format!("t{}", seq + 1), "seq": seq + 1, "new": gen, "previous": null, "state": state}));
    }
    let actions = a.recover_locked().unwrap();
    assert_eq!(actions, vec![json!({"tx": "t2", "action": "superseded"})]);
    assert!(a.rt.calls().is_empty(), "no reload, no stop: {:?}", a.rt.calls());
    assert_eq!(a.pointer().as_deref(), Some("g2"));
    assert_eq!(journal_record(&a, "t2")["history"], json!(["superseded"]));
    assert_eq!(a.status().unwrap()["coherent"], json!(true));
}

#[test]
fn interrupted_intent_is_aborted() {
    let (_t, a) = fixture(Mock::new());
    tx(&a, "t1", json!({"id": "t1", "seq": 1, "new": "g1", "previous": null, "state": "intent"}));
    assert_eq!(a.recover_locked().unwrap(), vec![json!({"tx": "t1", "action": "aborted"})]);
    assert_eq!(journal_record(&a, "t1")["state"], json!("aborted"));
}

#[test]
fn rollback_target_requires_a_binding_validation_and_the_current_epoch() {
    let (_t, a) = fixture(Mock::new());
    for gen in ["g0", "g1", "g2"] {
        generation(&a, gen, Some(0), &["site"]);
        bind(&a, gen);
    }
    tx(&a, "t0", json!({"id": "t0", "seq": 1, "new": "g0", "previous": null, "state": "committed"}));
    tx(&a, "t1", json!({"id": "t1", "seq": 2, "new": "g1", "previous": "g0", "state": "committed"}));
    let failing = json!({"id": "t2", "seq": 3, "new": "g2", "previous": "g1", "state": "unhealthy"});
    let failing = failing.as_object().unwrap().clone();
    assert_eq!(a.fresh_target(&failing).unwrap().as_deref(), Some("g1"));
    // The previous generation changed after validation: its validation no longer binds.
    fs::write(a.gen_dir("g1").join("marker/generation"), "changed\n").unwrap();
    assert_eq!(a.validation_problem("g1").unwrap().as_deref(), Some("generation changed after validation"));
    assert_eq!(a.fresh_target(&failing).unwrap().as_deref(), Some("g0"));
    // A failed validation, a missing one, or an OLS binary change never qualify either.
    fs::write(cat(&a.paths.validations, "g0.json"), json!({"valid": false}).to_string()).unwrap();
    assert_eq!(a.fresh_target(&failing).unwrap(), None);
    bind(&a, "g0");
    fs::write(&a.paths.binary, b"binary-2").unwrap();
    assert_eq!(a.fresh_target(&failing).unwrap(), None);
    fs::write(&a.paths.binary, b"binary-1").unwrap();
    assert_eq!(a.fresh_target(&failing).unwrap().as_deref(), Some("g0"));
    // Never the failing generation itself.
    let own = json!({"id": "t3", "seq": 4, "new": "g0", "previous": "g0"}).as_object().unwrap().clone();
    assert_eq!(a.fresh_target(&own).unwrap(), None);
    // Never one from an older restriction epoch.
    a.restrict("suspend").unwrap();
    assert_eq!(a.fresh_target(&failing).unwrap(), None);
    generation(&a, "g4", Some(1), &["site"]);
    bind(&a, "g4");
    tx(&a, "t4", json!({"id": "t4", "seq": 5, "new": "g4", "previous": "g0", "state": "committed"}));
    assert_eq!(a.fresh_target(&failing).unwrap().as_deref(), Some("g4"));
}

#[test]
fn rollback_outcomes() {
    // Nothing to roll back to.
    let (_t, a) = fixture(Mock::running(None));
    generation(&a, "g1", Some(0), &["site"]);
    let mut first = json!({"id": "t1", "seq": 1, "new": "g1", "previous": null}).as_object().unwrap().clone();
    assert_eq!(a.rollback(&mut first).unwrap()["result"], json!("failed_no_previous"));

    // A stale previous generation while the new, current one serves: keep it (never revive privileges).
    let (_t, a) = fixture(Mock::running(Some("g1")));
    generation(&a, "g0", Some(0), &["site"]);
    bind(&a, "g0");
    a.restrict("suspend").unwrap();
    generation(&a, "g1", Some(1), &["site"]);
    bind(&a, "g1");
    let mut record = json!({"id": "t1", "seq": 1, "new": "g1", "previous": "g0"}).as_object().unwrap().clone();
    let out = a.rollback(&mut record).unwrap();
    assert_eq!(Value::Object(out), json!({"result": "rollback_refused_stale", "generation": "g1"}));
    assert_eq!(record["epoch"], json!(1));

    // The same, but the new generation does not serve: stop and verify the stop.
    *a.rt.serving.borrow_mut() = Some("g0".into());
    let out = a.rollback(&mut record).unwrap();
    assert_eq!(Value::Object(out), json!({"result": "stopped_no_fresh_generation", "stopped": true}));
    assert_eq!(a.rt.calls(), vec!["stop"]);

    // A fresh previous generation that serves after the reload: rolled back.
    let (_t, a) = fixture(Mock::running(Some("g2")));
    for gen in ["g1", "g2"] {
        generation(&a, gen, Some(0), &["site"]);
        bind(&a, gen);
    }
    *a.rt.after_reload.borrow_mut() = Some("g1".into());
    let mut record = json!({"id": "t2", "seq": 2, "new": "g2", "previous": "g1"}).as_object().unwrap().clone();
    let out = a.rollback(&mut record).unwrap();
    assert_eq!(Value::Object(out), json!({"result": "rolled_back", "generation": "g1"}));
    assert_eq!(a.pointer().as_deref(), Some("g1"));
    // ... and one that does not answer: rollback_failed and stopped.
    a.rt.healthy.set(false);
    let out = a.rollback(&mut record).unwrap();
    assert_eq!(Value::Object(out), json!({"result": "rollback_failed", "generation": "g1", "stopped": true}));
}

#[test]
fn activation_commits_or_rolls_back_and_recovers_after_a_crash() {
    let (_t, a) = fixture(Mock::new());
    generation(&a, "g1", Some(0), &["a", "b"]);
    assert_eq!(a.activate("g1", None).unwrap(), json!({"result": "refused", "generation": "g1", "reason": "not validated"}));
    fs::remove_file(a.gen_dir("g1").join("health.json")).unwrap();
    bind(&a, "g1");
    assert_eq!(a.activate("g1", None).unwrap()["reason"], json!("no vhost health targets"));
    generation(&a, "g1", Some(0), &["a", "b"]);
    bind(&a, "g1");
    *a.rt.after_reload.borrow_mut() = Some("g1".into());
    let out = a.activate("g1", None).unwrap();
    assert_eq!((out["result"].clone(), out["generation"].clone()), (json!("committed"), json!("g1")));
    let id = out["tx"].as_str().unwrap().to_string();
    let record = journal_record(&a, &id);
    assert_eq!(record["history"], json!(["intent", "switched", "reloaded", "committed"]));
    assert_eq!((record["seq"].clone(), record["previous"].clone(), record["reload_exit"].clone()), (json!(1), Value::Null, json!(0)));
    assert_eq!(a.rt.calls(), vec!["start"]);
    assert_eq!(a.status().unwrap(), json!({"pointer": "g1", "served": "g1", "committed": "g1", "epoch": 0,
                                           "active_epoch": 0, "coherent": true}));

    // An unhealthy vhost: rolled back to the previous generation.
    generation(&a, "g2", Some(0), &["a", "b"]);
    bind(&a, "g2");
    *a.rt.after_reload.borrow_mut() = Some("g2".into());
    a.rt.healthy.set(false);
    let out = a.activate("g2", None).unwrap();
    assert_eq!(out["result"], json!("rollback_failed"), "g1 does not answer health either: {out}");
    a.rt.healthy.set(true);

    // A crash after the switch: recovery completes the transaction once it serves and is healthy.
    let (_t, a) = fixture(Mock::new());
    generation(&a, "g1", Some(0), &["a"]);
    bind(&a, "g1");
    assert!(matches!(a.activate("g1", Some("switched")), Err(Error::Crash)));
    assert_eq!(a.pointer().as_deref(), Some("g1"));
    *a.rt.after_reload.borrow_mut() = Some("g1".into());
    let out = a.recover(0.0).unwrap();
    assert_eq!(out["actions"].as_array().unwrap().len(), 1);
    assert_eq!(out["actions"][0]["action"], json!("completed"));
    assert_eq!(out["coherent"], json!(true));
    let id = out["actions"][0]["tx"].as_str().unwrap().to_string();
    assert_eq!(journal_record(&a, &id)["history"], json!(["intent", "switched", "committed"]));
    assert_eq!(journal_record(&a, &id)["recovered"], json!(true));
}

/// Review RV-29, finding 4: 200 targets that never answer (2 s each) cannot hold a transaction past its deadline.
#[test]
fn transactions_have_a_total_deadline() {
    let many: Vec<String> = (0..200).map(|i| format!("v{i}.test")).collect();
    let names: Vec<&str> = many.iter().map(String::as_str).collect();
    // health: the active generation's targets share the deadline; the rest are not asked and count as failing.
    let (_t, a) = fixture(Mock::running(Some("g1")));
    generation(&a, "g1", Some(0), &names);
    point(&a, "g1");
    a.rt.slow_health.set(true);
    let failing = a.health(60.0).unwrap()["failing"].as_array().unwrap().clone();
    assert_eq!(failing.len(), 200);
    assert!(a.rt.clock.get() <= TRANSACTION_SECONDS + 1.0, "{}", a.rt.clock.get());
    assert!(a.rt.health_timeouts.borrow().iter().all(|t| *t > 0.0 && *t <= 2.0));
    assert_eq!(failing.last().unwrap()["got"], json!(DEADLINE_EXCEEDED));

    // activate: the forward checks stop ROLLBACK_RESERVE before the deadline, the rollback gets the rest, and the
    // whole transaction (stop included) ends within the deadline plus the bounded stop.
    let (_t, a) = fixture(Mock::running(Some("g1")));
    for gen in ["g1", "g2"] {
        generation(&a, gen, Some(0), &names);
        bind(&a, gen);
    }
    point(&a, "g1");
    *a.rt.after_reload.borrow_mut() = Some("g2".into());
    a.rt.slow_health.set(true);
    let out = a.activate("g2", None).unwrap();
    assert_eq!(out["result"], json!("rollback_failed"), "{out}");
    assert_eq!(out["failing"].as_array().unwrap().len(), 200);
    let elapsed = a.rt.clock.get();
    assert!(elapsed <= TRANSACTION_SECONDS + 1.0, "{elapsed}");
    // The forward phase asked targets for at most TRANSACTION_SECONDS - ROLLBACK_RESERVE, leaving the reserve to
    // the rollback (whose previous generation never came up here: 20 s of waiting, then the stop).
    let asked: f64 = a.rt.health_timeouts.borrow().iter().sum();
    assert!(asked > 60.0 && asked <= TRANSACTION_SECONDS - ROLLBACK_RESERVE + 1e-6, "{asked}");
    assert!(elapsed >= asked + 20.0 - 1e-6, "{elapsed}");
    assert_eq!(a.rt.calls(), ["reload", "reload", "stop"]);
    // Outside a transaction nothing is left over.
    assert_eq!(a.budget(7.0), 7.0);
}

#[test]
fn a_stopped_server_is_never_restarted_with_a_stale_generation() {
    // Enforcement stopped OLS (an intent unfolded): neither the activation's reload nor recovery starts anything.
    let (_t, a) = fixture(Mock::new());
    generation(&a, "g1", Some(0), &["site"]);
    bind(&a, "g1");
    point(&a, "g1");
    fs::create_dir_all(&a.paths.restrictions).unwrap();
    let intent = "1729600000000000001-0123456789abcdef0123456789abcdef.json";
    fs::write(a.paths.restrictions.join(intent), r#"{"reason": "x", "time": 990}"#).unwrap();
    assert_eq!(a.pending_intents().unwrap(), vec![(intent.to_string(), 990.0)]);
    assert_eq!(a.first_unapplied_restriction(0), Some(990.0));
    assert_eq!(a.reload(), 1);
    assert_eq!(a.recover(0.0).unwrap()["actions"], json!([]));
    assert!(a.rt.calls().is_empty());
    // Names other than intents are ignored; a time later than the file's modification time is not trusted.
    fs::write(a.paths.restrictions.join("x.json.tmp-1"), "{}").unwrap();
    fs::write(a.paths.restrictions.join(intent), r#"{"reason": "x", "time": 1e300}"#).unwrap();
    let intents = a.pending_intents().unwrap();
    assert_eq!(intents.len(), 1);
    assert!(intents[0].1 < 1e12);
    fs::remove_file(a.paths.restrictions.join(intent)).unwrap();
    assert!(!a.stale(Some("g1")));
    *a.rt.after_reload.borrow_mut() = Some("g1".into());
    assert_eq!(a.reload(), 0);
    assert_eq!(a.rt.calls(), ["start"]);
}

/// The enforcement decision table (hook-independent; runs from recovery and the reconciler).
#[test]
fn enforce_decision_table() {
    struct Row {
        name: &'static str,
        mock: fn() -> Mock,
        pointer: Option<&'static str>,
        damaged_epoch: bool,
        grace: f64,
        expect: Option<&'static str>,
    }
    let rows = [
        Row { name: "OLS not running", mock: || Mock::new(), pointer: Some("old"), damaged_epoch: false, grace: 0.0, expect: None },
        Row { name: "serving a current generation", mock: || Mock::running(Some("new")), pointer: Some("new"), damaged_epoch: false, grace: 0.0, expect: None },
        Row { name: "marker silent, current pointer trusted", mock: || Mock::running(None), pointer: Some("new"), damaged_epoch: false, grace: 0.0, expect: None },
        Row { name: "marker silent, stale pointer", mock: || Mock::running(None), pointer: Some("old"), damaged_epoch: false, grace: 0.0, expect: Some("stopped") },
        Row { name: "marker silent, no pointer", mock: || Mock::running(None), pointer: None, damaged_epoch: false, grace: 300.0, expect: Some("within-grace") },
        Row { name: "stale, within grace", mock: || Mock::running(Some("old")), pointer: Some("old"), damaged_epoch: false, grace: 300.0, expect: Some("within-grace") },
        Row { name: "stale, grace expired", mock: || Mock::running(Some("old")), pointer: Some("old"), damaged_epoch: false, grace: 50.0, expect: Some("stopped") },
        Row { name: "stale, no grace", mock: || Mock::running(Some("old")), pointer: Some("old"), damaged_epoch: false, grace: 0.0, expect: Some("stopped") },
        Row { name: "stale served, current pointer reloads", mock: || { let m = Mock::running(Some("old")); *m.after_reload.borrow_mut() = Some("new".into()); m }, pointer: Some("new"), damaged_epoch: false, grace: 0.0, expect: Some("reloaded-current") },
        Row { name: "current pointer does not come up", mock: || Mock::running(Some("old")), pointer: Some("new"), damaged_epoch: false, grace: 0.0, expect: Some("stopped") },
        Row { name: "unknown epoch gets no grace", mock: || Mock::running(Some("new")), pointer: Some("new"), damaged_epoch: true, grace: 300.0, expect: Some("stopped") },
        Row { name: "stop fails", mock: || { let m = Mock::running(Some("old")); m.stop_works.set(false); m.kill_works.set(false); m }, pointer: Some("old"), damaged_epoch: false, grace: 0.0, expect: Some("stop-failed") },
        Row { name: "stop needs the kill", mock: || { let m = Mock::running(Some("old")); m.stop_works.set(false); m }, pointer: Some("old"), damaged_epoch: false, grace: 0.0, expect: Some("stopped") },
    ];
    for row in rows {
        let (_t, a) = fixture((row.mock)());
        generation(&a, "old", Some(0), &["site"]);
        bind(&a, "old");
        // Restriction 1 at wall time 900 (mock now is 1000): 100 s ago.
        a.rt.wall.set(900.0);
        a.restrict("suspend").unwrap();
        a.rt.wall.set(1000.0);
        generation(&a, "new", Some(1), &["site"]);
        bind(&a, "new");
        if let Some(gen) = row.pointer {
            point(&a, gen);
        }
        if row.damaged_epoch {
            epoch_record(&a, "{broken");
        }
        assert_eq!(a.enforce(row.grace).unwrap(), row.expect, "{}", row.name);
    }
}

#[test]
fn recovery_enforces_with_its_grace() {
    let (_t, a) = fixture(Mock::running(Some("old")));
    generation(&a, "old", Some(0), &["site"]);
    bind(&a, "old");
    point(&a, "old");
    a.rt.wall.set(990.0);
    a.restrict("suspend").unwrap();
    a.rt.wall.set(1000.0);
    let out = a.recover(300.0).unwrap();
    assert_eq!(out["actions"], json!([{"action": "enforce", "result": "within-grace"}]));
    let out = a.recover(0.0).unwrap();
    assert_eq!(out["actions"], json!([{"action": "enforce", "result": "stopped"}]));
    assert_eq!(out["coherent"], json!(false));
}

#[test]
fn staging_is_immutable_and_digested() {
    let (temp, a) = fixture(Mock::new());
    let src = temp.path().join("src");
    fs::create_dir_all(src.join("vhosts/a")).unwrap();
    fs::write(src.join("httpd_config.conf"), "x\n").unwrap();
    fs::write(src.join("vhosts/a/vhconf.conf"), "y\n").unwrap();
    fs::write(src.join("EPOCH"), "0\n").unwrap();
    let out = a.stage("g1", &src).unwrap();
    assert_eq!(out, json!({"generation": "g1", "files": 3}));
    let dir = a.gen_dir("g1");
    assert_eq!(fs::metadata(dir.join("httpd_config.conf")).unwrap().permissions().mode() & 0o777, 0o444);
    assert_eq!(fs::metadata(dir.join("vhosts")).unwrap().permissions().mode() & 0o777, 0o755);
    assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
    let manifest: Value = serde_json::from_slice(&fs::read(dir.join("MANIFEST.json")).unwrap()).unwrap();
    assert_eq!(manifest["generation"], json!("g1"));
    assert_eq!(manifest["files"]["vhosts/a/vhconf.conf"], json!(hex(&Sha256::digest(b"y\n"))));
    assert_eq!(fs::read_to_string(src.join("httpd_config.conf")).unwrap(), "x\n", "the source is untouched");
    assert!(matches!(a.stage("g1", &src), Err(Error::Exit(m)) if m == "generation g1 exists (generations are immutable)"));
    let digest = a.tree_sha256("g1").unwrap();
    assert_eq!(digest, a.tree_sha256("g1").unwrap());
    fs::set_permissions(dir.join("EPOCH"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(dir.join("EPOCH"), "1\n").unwrap();
    assert_ne!(a.tree_sha256("g1").unwrap(), digest);
}

#[test]
fn tree_digest_matches_the_python_definition() {
    let (_t, a) = fixture(Mock::new());
    let dir = a.gen_dir("g");
    fs::create_dir_all(dir.join("a")).unwrap();
    fs::create_dir_all(dir.join("a-b")).unwrap();
    fs::write(dir.join("a/x"), "1").unwrap();
    fs::write(dir.join("a-b/y"), "2").unwrap();
    fs::write(dir.join("z"), "3").unwrap();
    std::os::unix::fs::symlink("z", dir.join("link")).unwrap();
    std::os::unix::fs::symlink("a", dir.join("dirlink")).unwrap(); // listed as a directory: not digested
    // sorted(os.walk(base)) sorts roots as strings: ".../g" < ".../g/a" < ".../g/a-b".
    let mut expected = Sha256::new();
    for (rel, value) in [("link", "link:z".to_string()), ("z", hex(&Sha256::digest(b"3"))),
                         ("a/x", hex(&Sha256::digest(b"1"))), ("a-b/y", hex(&Sha256::digest(b"2")))] {
        expected.update(format!("{rel}\0{value}\n").as_bytes());
    }
    assert_eq!(a.tree_sha256("g").unwrap(), hex(&expected.finalize()));
}

#[test]
fn status_reports_damage_without_failing() {
    let (_t, a) = fixture(Mock::new());
    assert_eq!(a.status().unwrap(), json!({"pointer": null, "served": null, "committed": null, "epoch": 0,
                                           "active_epoch": null, "coherent": false}));
    epoch_record(&a, "{broken");
    assert_eq!(a.status().unwrap()["epoch"], Value::Null);
}

#[test]
fn health_of_the_active_generation() {
    // No active pointer: nothing to check.
    let (_t, a) = fixture(Mock::running(Some("g1")));
    assert_eq!(a.health(5.0).unwrap(), json!({"generation": null, "failing": []}));
    // Serving the active generation: every target answers with its ID.
    generation(&a, "g1", Some(0), &["a.test", "b.test"]);
    point(&a, "g1");
    assert_eq!(a.health(5.0).unwrap(), json!({"generation": "g1", "failing": []}));
    assert_eq!(a.rt.clock.get(), 0.0, "a healthy generation is answered at once");
    // Failing vhosts are retried until the deadline, then listed with what they answered.
    a.rt.healthy.set(false);
    let out = a.health(2.0).unwrap();
    assert_eq!(out, json!({"generation": "g1", "failing": [{"vhost": "a.test", "got": "error: HTTP 404"},
                                                           {"vhost": "b.test", "got": "error: HTTP 404"}]}));
    assert!(a.rt.clock.get() > 2.0);
    // Zero seconds: one retry at most (the Python loop's deadline check).
    a.rt.clock.set(0.0);
    assert_eq!(a.health(0.0).unwrap()["failing"].as_array().unwrap().len(), 2);
    assert_eq!(a.rt.clock.get(), 0.5);
    // Without health.json there are no targets (Python: `health_targets(current) or []`).
    generation(&a, "g2", Some(0), &[]);
    point(&a, "g2");
    assert_eq!(a.health(5.0).unwrap(), json!({"generation": "g2", "failing": []}));
}

#[test]
fn health_seconds_argument() {
    use crate::activator::cli::seconds;
    let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    assert_eq!(seconds(&args(&["health"])).unwrap(), 5.0);
    assert_eq!(seconds(&args(&["health", "--seconds", "0"])).unwrap(), 0.0);
    assert_eq!(seconds(&args(&["health", "--seconds", "60"])).unwrap(), 60.0);
    for bad in [&["health", "--seconds"][..], &["health", "--seconds", "61"], &["health", "--seconds", "-1"],
                &["health", "--seconds", "1.5"], &["health", "--seconds", "x"]] {
        assert!(matches!(seconds(&args(bad)), Err(Error::Exit(_))), "{bad:?}");
    }
}

#[test]
fn generations_directory_is_traversable_whatever_the_umask() {
    // Created by a process with UMask=0077 (the broker unit): repaired so OLS's workers can read the marker and configuration.
    let (_temp, a) = fixture(Mock::new());
    fs::set_permissions(&a.paths.gen_root, fs::Permissions::from_mode(0o700)).unwrap();
    a.ensure_dirs().unwrap();
    assert_eq!(fs::metadata(&a.paths.gen_root).unwrap().permissions().mode() & 0o777, 0o755);
    assert_eq!(fs::metadata(&a.paths.journal).unwrap().permissions().mode() & 0o777, 0o700);
}
