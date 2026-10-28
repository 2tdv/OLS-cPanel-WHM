//! Minimal privileged broker for OLS-cPanel (G0-H prototype, plan sections 5.1-5.5).
//!
//! Three Unix sockets with different callers:
//! - admin: root only (peer credentials). Used by the WHM gateway after it verified the cPanel
//!   principal. Read views (status, metrics, inventory, compatibility findings, plans, generations,
//!   doctor, jobs) plus short-lived, single-use capabilities for mutations, which start product jobs
//!   (the `panel` module of the library; docs/product-interfaces.md, "Plugin data and actions").
//! - tenant: any local user. The account is the peer's UID as reported by the kernel
//!   (SO_PEERCRED); nothing in the request can name another account.
//! - engine: root and the `olscpanel` reconciler (docs/product-interfaces.md, engine socket). cPanel
//!   input reads from one fixed allowlist, generation apply through the activator, status,
//!   enforcement, recovery and the event spool (the `engine` module of the library).
//! Plus HR-D11 enforcement in its own thread (rounds at most 5 s apart, independent of the reconciler):
//! restriction intents folded, then a stale generation stopped no later than its deadline, with or without the
//! activation lock; every action is recorded in the audit log (review RV-29, finding 3).
//! One request per connection: a single JSON object (newline-terminated), at most MAX_REQUEST
//! bytes received within REQUEST_DEADLINE, a fixed protocol version, unknown fields rejected,
//! operations from a fixed list. There is no shell and no general file or exec operation; the
//! engine's argv and paths are checked against fixed patterns. Connection slots are separate per
//! socket and capped per tenant UID, so local users cannot starve the admin or engine socket
//! (human review 2026-10-22, concern 1).

use hmac::{Hmac, Mac};
use ols_cpanel_broker::engine::{self, Config, Engine};
use ols_cpanel_broker::panel::{self, hex, jobs, now, random_hex, summary, valid_name, Panel};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL: u32 = 1;
const MAX_REQUEST: usize = 64 * 1024;
const MAX_ADMIN_CONNECTIONS: usize = 16;
const MAX_TENANT_CONNECTIONS: usize = 64;
const MAX_ENGINE_CONNECTIONS: usize = 8;
const MAX_CONNECTIONS_PER_UID: u32 = 4;
/// Whole-request budget: a slow sender cannot hold a slot by trickling bytes.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
/// engine.apply carries a whole compiled configuration; every other request keeps MAX_REQUEST.
const MAX_APPLY_REQUEST: usize = 64 << 20;
/// Budget for receiving (and sending) up to 64 MiB on the engine socket; its callers are trusted.
const ENGINE_DEADLINE: Duration = Duration::from_secs(30);
/// Replies carry compiler inputs (engine.run output of up to 16 MiB, escaped).
const MAX_REPLY: usize = 32 << 20;
/// The reconciler's account (build/product/ols-cpanel.sysusers); also the engine socket's group.
const ENGINE_USER: &str = "olscpanel";
const STATUS_CACHE: Duration = Duration::from_secs(2);
const CAPABILITY_TTL: u64 = 60;
const RATE_PER_SECOND: u32 = 50;
const OLS_BINARY: &str = "/usr/local/lsws/bin/openlitespeed";
/// The lab probes' capability action: an audit record only (build/vm-qualification/broker_probe.py).
/// Every other action is a product job of `jobs::ACTIONS`.
const LAB_ACTION: &str = "lab.audit_marker";

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u32,
    id: String,
    op: String,
    #[serde(default)]
    args: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapIssue {
    principal: String,
    action: String,
    scope: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapExecute {
    token: String,
    action: String,
    scope: String,
    digest: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Socket {
    Admin,
    Tenant,
    Engine,
}

impl Socket {
    fn name(self) -> &'static str {
        match self {
            Socket::Admin => "admin",
            Socket::Tenant => "tenant",
            Socket::Engine => "engine",
        }
    }
}

struct State {
    secret: [u8; 32],
    /// Nonce -> expiry; entries are dropped once the capability could no longer be valid.
    used_nonces: Mutex<HashMap<String, u64>>,
    rate: Mutex<HashMap<u32, (u64, u32)>>,
    admin_connections: AtomicUsize,
    tenant_connections: AtomicUsize,
    engine_connections: AtomicUsize,
    tenant_per_uid: Mutex<HashMap<u32, u32>>,
    status: Mutex<Option<(Instant, Value)>>,
    engine: Engine,
    panel: Panel,
}

/// A poisoned lock (a panicking request thread) must not take the broker down with it.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A held connection slot; released on drop, including when the request thread panics.
struct Slot {
    state: Arc<State>,
    socket: Socket,
    uid: u32,
}

impl Slot {
    fn acquire(state: &Arc<State>, socket: Socket, uid: u32) -> Option<Slot> {
        let (counter, limit) = match socket {
            Socket::Admin => (&state.admin_connections, MAX_ADMIN_CONNECTIONS),
            Socket::Tenant => (&state.tenant_connections, MAX_TENANT_CONNECTIONS),
            Socket::Engine => (&state.engine_connections, MAX_ENGINE_CONNECTIONS),
        };
        if socket == Socket::Tenant {
            let mut per_uid = lock(&state.tenant_per_uid);
            let held = per_uid.entry(uid).or_insert(0);
            if *held >= MAX_CONNECTIONS_PER_UID {
                return None;
            }
            *held += 1;
        }
        let slot = Slot { state: Arc::clone(state), socket, uid };
        if counter.fetch_add(1, Ordering::SeqCst) >= limit {
            return None; // drop(slot) gives back both the socket and the per-UID count
        }
        Some(slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let counter = match self.socket {
            Socket::Admin => &self.state.admin_connections,
            Socket::Tenant => &self.state.tenant_connections,
            Socket::Engine => &self.state.engine_connections,
        };
        counter.fetch_sub(1, Ordering::SeqCst);
        if self.socket == Socket::Tenant {
            let mut per_uid = lock(&self.state.tenant_per_uid);
            if let Some(held) = per_uid.get_mut(&self.uid) {
                *held -= 1;
                if *held == 0 {
                    per_uid.remove(&self.uid);
                }
            }
        }
    }
}

struct Peer {
    uid: u32,
    pid: i32,
}

fn error(id: &str, code: &str, message: &str) -> Value {
    json!({"v": PROTOCOL, "id": id, "ok": false, "error": {"code": code, "message": message}})
}

fn peer_credentials(stream: &UnixStream) -> Option<Peer> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`, a properly sized ucred.
    let rc = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
                         &mut cred as *mut libc::ucred as *mut libc::c_void, &mut len)
    };
    if rc == 0 && len as usize == std::mem::size_of::<libc::ucred>() {
        Some(Peer { uid: cred.uid, pid: cred.pid })
    } else {
        None
    }
}

/// The account name of a UID from the system user database (never from the request).
fn user_name(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r fills `pwd` using `buf`; we only read pw_name when result is non-null.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    name.to_str().ok().map(str::to_owned)
}

/// The UID of an account from the system user database.
fn user_id(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r fills `pwd` using `buf`; we only read pw_uid when result is non-null.
    let rc = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    (rc == 0 && !result.is_null()).then_some(pwd.pw_uid)
}

/// The GID of a group from the system group database.
fn group_id(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: getgrnam_r fills `grp` using `buf`; we only read gr_gid when result is non-null.
    let rc = unsafe { libc::getgrnam_r(name.as_ptr(), &mut grp, buf.as_mut_ptr(), buf.len(), &mut result) };
    (rc == 0 && !result.is_null()).then_some(grp.gr_gid)
}

fn unit_active(unit: &str) -> bool {
    // Fixed executable and arguments; no shell.
    std::process::Command::new("/usr/bin/systemctl").args(["is-active", "--quiet", unit])
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Cached for STATUS_CACHE so tenants cannot turn status requests into a process storm (concern 2).
fn base_status(state: &State) -> Value {
    let mut cached = lock(&state.status);
    if let Some((at, value)) = cached.as_ref() {
        if at.elapsed() < STATUS_CACHE {
            return value.clone();
        }
    }
    let value = read_server_status(&state.panel.config.state.join("active"));
    *cached = Some((Instant::now(), value.clone()));
    value
}

fn read_server_status(active: &Path) -> Value {
    let generation = fs::read_link(active).ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
    json!({
        "ols_installed": Path::new(OLS_BINARY).exists(),
        "ols_active": unit_active("ols-cpanel.service"),
        "apache_active": unit_active("httpd.service"),
        "active_generation": generation,
        "observed_at": now(),
    })
}

/// `server.status` (admin): the broker's own view plus `ols-cpanel status` (cached 2 s, 30 s limit) and the
/// status digest a server-scoped action must present.
fn server_status(state: &State) -> Value {
    let mut status = base_status(state);
    if let Value::Object(map) = &mut status {
        map.extend(state.panel.status_extension());
        map.insert("source".into(), json!("systemctl, the active generation pointer, ols-cpanel status --format=json"));
    }
    status["digest"] = json!(panel::status_digest(&status));
    status
}

fn capability_mac(state: &State, fields: &[&str]) -> String {
    let mut mac = HmacSha256::new_from_slice(&state.secret).expect("HMAC accepts any key length");
    for field in fields {
        mac.update(field.as_bytes());
        mac.update(&[0]);
    }
    hex(&mac.finalize().into_bytes())
}

/// The scope an action may carry: lab marker "server" or an account; a job its action's scope.
fn valid_capability(action: &str, scope: &str) -> bool {
    if action == LAB_ACTION {
        return scope == "server" || valid_name(scope);
    }
    jobs::action(action).map_or(false, |a| jobs::valid_scope(a, scope))
}

fn issue(state: &State, args: Value) -> Result<Value, (&'static str, String)> {
    let a: CapIssue = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    if !valid_name(&a.principal) || !valid_capability(&a.action, &a.scope) || a.digest.len() != 64
        || !a.digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(("BAD_ARGS", "invalid principal, action, scope or digest".into()));
    }
    let nonce = random_hex(16);
    let expires = (now() + CAPABILITY_TTL).to_string();
    let mac = capability_mac(state, &[&a.principal, &a.action, &a.scope, &a.digest, &nonce, &expires]);
    Ok(json!({"token": format!("{}.{}.{}.{}", a.principal, nonce, expires, mac), "expires": expires}))
}

/// The digest of what a job's scope stands for right now: the plan file, or the server status.
fn current_digest(state: &State, action: &jobs::Action, scope: &str) -> Result<String, (&'static str, String)> {
    match action.scope {
        jobs::Scope::Plan => summary::plan_digest(&state.panel.config.state, scope)
            .ok_or(("NOT_FOUND", "no such plan".to_string())),
        // A cache purge is bound to the same status digest as the other server-scoped actions.
        jobs::Scope::Server | jobs::Scope::Cache | jobs::Scope::PhpRestart | jobs::Scope::Opcache => Ok(server_status(state)["digest"].as_str().unwrap_or("").to_string()),
    }
}

fn execute(state: &State, args: Value) -> Result<Value, (&'static str, String)> {
    let a: CapExecute = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    let parts: Vec<&str> = a.token.split('.').collect();
    if parts.len() != 4 {
        return Err(("CAPABILITY_INVALID", "malformed token".into()));
    }
    let (principal, nonce, expires, mac) = (parts[0], parts[1], parts[2], parts[3]);
    let expected = capability_mac(state, &[principal, &a.action, &a.scope, &a.digest, nonce, expires]);
    // Constant-time comparison of the MACs.
    let same = expected.len() == mac.len()
        && expected.bytes().zip(mac.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0;
    if !same {
        return Err(("CAPABILITY_INVALID", "capability does not match action, scope or request".into()));
    }
    if expires.parse::<u64>().map(|e| e < now()).unwrap_or(true) {
        return Err(("CAPABILITY_EXPIRED", "capability expired".into()));
    }
    {
        let mut used = lock(&state.used_nonces);
        let current = now();
        used.retain(|_, expiry| *expiry >= current);
        if used.contains_key(nonce) {
            return Err(("CAPABILITY_REPLAYED", "capability already used".into()));
        }
        used.insert(nonce.to_string(), expires.parse().unwrap_or(current));
    }
    if a.action == LAB_ACTION {
        // Append an audit record (no caller-controlled path or content).
        let record = json!({"time": now(), "principal": principal, "action": a.action, "scope": a.scope, "digest": a.digest});
        panel::audit(&state.panel.config.audit_log, &record).map_err(|e| ("INTERNAL", e))?;
        return Ok(json!({"executed": a.action, "principal": principal}));
    }
    let action = jobs::action(&a.action).ok_or(("BAD_ARGS", "unknown action".to_string()))?;
    // The operator approved what they saw: the plan file or the server status must still be that.
    if current_digest(state, action, &a.scope)? != a.digest {
        return Err(("STALE", "the plan or server state changed since it was shown; reload and confirm again".into()));
    }
    let job = state.panel.jobs.start(action, &a.scope, principal, &a.digest)?;
    Ok(json!({"job": job}))
}

/// `admin.schedule_add {action, scope, digest, at, window?}`: a switch or a return for a maintenance window. The digest must be the
/// plan's (switch) or the server status' (return) right now, exactly as for the capability flow: what the operator approved. The
/// stored job is started later by the root timer through `cap.issue` and `cap.execute`, which check it again.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleAdd {
    action: String,
    scope: String,
    digest: String,
    at: u64,
    #[serde(default)]
    window: Option<u64>,
}

fn schedule_add(state: &State, args: Value) -> Result<Value, (&'static str, String)> {
    let a: ScheduleAdd = serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))?;
    if !["ols.cutover", "ols.apache_return"].contains(&a.action.as_str()) {
        return Err(("BAD_ARGS", "only ols.cutover and ols.apache_return can be scheduled".into()));
    }
    let action = jobs::action(&a.action).ok_or(("BAD_ARGS", "unknown action".to_string()))?;
    if !jobs::valid_scope(action, &a.scope) || a.digest.len() != 64 || !a.digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(("BAD_ARGS", "invalid scope or digest".into()));
    }
    if current_digest(state, action, &a.scope)? != a.digest {
        return Err(("STALE", "the plan or server state changed since it was shown; reload and confirm again".into()));
    }
    state.panel.schedule_add(&a.action, &a.scope, &a.digest, a.at, a.window)
}

fn rate_ok(state: &State, uid: u32) -> bool {
    let second = now();
    let mut rate = lock(&state.rate);
    let entry = rate.entry(uid).or_insert((second, 0));
    if entry.0 != second {
        *entry = (second, 0);
    }
    entry.1 += 1;
    entry.1 <= RATE_PER_SECOND
}

/// The tenant's account: the peer UID's name, never root.
fn tenant(peer: &Peer) -> Option<String> {
    user_name(peer.uid).filter(|_| peer.uid != 0)
}

fn dispatch(state: &State, socket: Socket, peer: &Peer, req: Request) -> Value {
    let id = req.id.clone();
    if req.v != PROTOCOL {
        return error(&id, "PROTOCOL", "unsupported protocol version");
    }
    let empty_args = req.args.is_null() || req.args == json!({});
    let result: Result<Value, (&str, String)> = match (socket, req.op.as_str()) {
        (Socket::Admin, "server.status") if empty_args => Ok(server_status(state)),
        (Socket::Admin, "server.metrics") if empty_args => state.panel.metrics(),
        (Socket::Admin, "admin.metrics") => state.panel.metrics_history(req.args),
        (Socket::Admin, "inventory.accounts") => state.panel.inventory(req.args),
        (Socket::Admin, "compat.findings") => state.panel.compat(req.args),
        (Socket::Admin, "plan.latest") if empty_args => state.panel.plan_latest(),
        (Socket::Admin, "generation.list") if empty_args => state.panel.generations(),
        (Socket::Admin, "doctor.report") if empty_args => state.panel.doctor(),
        (Socket::Admin, "cache.stats") => state.panel.cache_stats(req.args),
        (Socket::Admin, "admin.cache_limits") => state.panel.cache_limits(req.args),
        (Socket::Admin, "php.status") if empty_args => state.panel.php_status(),
        (Socket::Admin, "admin.objcache") => state.panel.objcache(req.args),
        (Socket::Admin, "admin.audit") => state.panel.audit(req.args),
        (Socket::Admin, "admin.notify") if empty_args => state.panel.notify(),
        (Socket::Admin, "admin.notify_set") => state.panel.notify_set(req.args),
        (Socket::Admin, "admin.notify_test") if empty_args => state.panel.notify_test(),
        (Socket::Admin, "admin.schedule") if empty_args => state.panel.schedule(),
        (Socket::Admin, "admin.schedule_add") => schedule_add(state, req.args),
        (Socket::Admin, "admin.schedule_cancel") => state.panel.schedule_cancel(req.args),
        (Socket::Admin, "admin.update") => state.panel.update(req.args),
        (Socket::Admin, "admin.bundle") if empty_args => state.panel.bundles(),
        (Socket::Admin, "job.list") if empty_args => state.panel.jobs.list(),
        (Socket::Admin, "job.status") => state.panel.jobs.status(req.args),
        (Socket::Admin, "cap.issue") => issue(state, req.args),
        (Socket::Admin, "cap.execute") => execute(state, req.args),
        (Socket::Tenant, "tenant.status") if empty_args => {
            let s = base_status(state);
            Ok(json!({"ols_active": s["ols_active"], "apache_active": s["apache_active"], "observed_at": s["observed_at"]}))
        }
        (Socket::Tenant, "tenant.domains") if empty_args => match tenant(peer) {
            Some(user) => {
                let (rows, _) = panel::domain_rows(&state.panel.config.userdatadomains);
                let mine: Vec<Value> = rows.into_iter().filter(|r| r["user"] == json!(user)).collect();
                Ok(json!({"user": user, "domains": mine}))
            }
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.sites") if empty_args => match tenant(peer) {
            Some(user) => state.panel.tenant_sites(&user),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.cache_stats") if empty_args => match tenant(peer) {
            Some(user) => state.panel.tenant_cache_stats(&user),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.php") if empty_args => match tenant(peer) {
            Some(user) => state.panel.tenant_php(&user),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.objcache") if empty_args => match tenant(peer) {
            Some(user) => state.panel.tenant_objcache(&user),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.metrics") => match tenant(peer) {
            Some(user) => state.panel.tenant_metrics(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.logs") => match tenant(peer) {
            Some(user) => state.panel.tenant_logs(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.php_errors") => match tenant(peer) {
            Some(user) => state.panel.tenant_php_errors(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.perf") => match tenant(peer) {
            Some(user) => state.panel.tenant_perf(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.request") => match tenant(peer) {
            Some(user) => state.panel.tenant_request(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.requests") if empty_args => match tenant(peer) {
            Some(user) => state.panel.tenant_requests(&user),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Admin, "admin.requests") if empty_args => state.panel.admin_requests(),
        (Socket::Admin, "admin.request_status") => state.panel.admin_request_status(req.args),
        (Socket::Tenant, "tenant.php_restart") => match tenant(peer) {
            Some(user) => state.panel.tenant_php_restart(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        (Socket::Tenant, "tenant.cache_purge") => match tenant(peer) {
            Some(user) => state.panel.tenant_cache_purge(&user, req.args),
            None => Err(("FORBIDDEN", "tenant operations require a non-root account".into())),
        },
        // Only operations offered on this socket may say "takes no arguments"; others stay unknown,
        // so a tenant cannot even learn which admin operations exist.
        (Socket::Engine, "engine.run") => state.engine.run(req.args),
        (Socket::Engine, "engine.apply") => state.engine.apply(req.args),
        (Socket::Engine, "engine.status") if empty_args => state.engine.status(),
        (Socket::Engine, "engine.enforce") => state.engine.enforce(req.args),
        (Socket::Engine, "engine.health") => state.engine.health(req.args),
        (Socket::Engine, "engine.recover") => state.engine.recover(req.args),
        (Socket::Engine, "engine.events") if empty_args => state.engine.events(),
        (Socket::Engine, "engine.events_done") => state.engine.events_done(req.args),
        (Socket::Engine, "engine.events_quarantine") => state.engine.events_quarantine(req.args),
        (Socket::Engine, "engine.restrictions_fold") if empty_args => state.engine.restrictions_fold(),
        (Socket::Admin, "server.status" | "server.metrics" | "plan.latest" | "generation.list" | "doctor.report" | "job.list" | "php.status"
                        | "admin.requests" | "admin.notify" | "admin.notify_test" | "admin.schedule" | "admin.bundle")
        | (Socket::Tenant, "tenant.status" | "tenant.domains" | "tenant.sites" | "tenant.cache_stats" | "tenant.php" | "tenant.objcache" | "tenant.requests")
        | (Socket::Engine, "engine.status" | "engine.events" | "engine.restrictions_fold") => {
            Err(("BAD_ARGS", "this operation takes no arguments".into()))
        }
        _ => Err(("UNKNOWN_OPERATION", "operation not available on this socket".into())),
    };
    match result {
        Ok(value) => json!({"v": PROTOCOL, "id": id, "ok": true, "result": value}),
        Err((code, message)) => error(&id, code, &message),
    }
}

/// Printable ASCII only, so log lines cannot be forged with control characters (concern 5).
fn log_safe(value: &str) -> String {
    value.chars().take(64).map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect()
}

fn handle(state: &State, socket: Socket, peer: &Peer, stream: &mut UnixStream) -> Value {
    if socket == Socket::Admin && peer.uid != 0 {
        return error("", "FORBIDDEN", "the admin socket is root-only");
    }
    // Looked up per connection: the account may be created (systemd-sysusers) after the broker started.
    if socket == Socket::Engine && peer.uid != 0 && user_id(ENGINE_USER) != Some(peer.uid) {
        return error("", "FORBIDDEN", "the engine socket is for root and olscpanel");
    }
    // A compilation issues over a hundred engine.run calls in quick succession; engine callers are
    // trusted and bounded by their connection slots instead.
    if socket != Socket::Engine && !rate_ok(state, peer.uid) {
        return error("", "RATE_LIMITED", "too many requests");
    }
    let (limit, budget) = if socket == Socket::Engine { (MAX_APPLY_REQUEST, ENGINE_DEADLINE) } else { (MAX_REQUEST, REQUEST_DEADLINE) };
    let deadline = Instant::now() + budget;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = vec![0u8; 65536];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return error("", "TIMEOUT", "request not received in time");
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > limit {
                    return error("", "TOO_LARGE", "request exceeds the size limit");
                }
                // Only the new bytes: rescanning the buffer would be quadratic for 64 MiB requests.
                if chunk[..n].contains(&b'\n') {
                    break;
                }
            }
            Err(_) => return error("", "TIMEOUT", "request not received in time"),
        }
    }
    let line = buf.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let request: Request = match serde_json::from_slice(line) {
        Ok(r) => r,
        Err(e) => return error("", "BAD_REQUEST", &e.to_string()),
    };
    if request.id.is_empty() || request.id.len() > 64 || !request.id.bytes().all(|b| b.is_ascii_graphic()) {
        return error("", "BAD_REQUEST", "id must be 1-64 printable ASCII characters");
    }
    if line.len() > MAX_REQUEST && request.op != "engine.apply" {
        return error(&request.id, "TOO_LARGE", "request exceeds the size limit");
    }
    let id = request.id.clone();
    let op = log_safe(&request.op);
    let reply = dispatch(state, socket, peer, request);
    eprintln!("{} socket={} uid={} pid={} id={} op={} ok={}", now(), socket.name(), peer.uid, peer.pid,
              log_safe(&id), op, reply["ok"]);
    reply
}

fn reply(stream: &mut UnixStream, socket: Socket, value: &Value) {
    let mut text = value.to_string();
    if text.len() > MAX_REPLY {
        // Refused, never truncated: a cut reply would be read as different cPanel input.
        let id = value["id"].as_str().unwrap_or("");
        text = error(id, "OUTPUT_TOO_LARGE", "reply exceeds 32 MiB").to_string();
    }
    let _ = stream.set_write_timeout(Some(if socket == Socket::Engine { ENGINE_DEADLINE } else { REQUEST_DEADLINE }));
    let _ = stream.write_all((text + "\n").as_bytes());
}

/// Group first, then mode: the socket is never reachable by a group it was not meant for.
fn listen(path: &str, mode: u32, group: Option<u32>) -> UnixListener {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap_or_else(|e| panic!("bind {path}: {e}"));
    if let Some(gid) = group {
        std::os::unix::fs::chown(path, None, Some(gid)).expect("socket group");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("socket permissions");
    listener
}

fn serve(state: Arc<State>, socket: Socket, listener: UnixListener) {
    for mut stream in listener.incoming().flatten() {
        let Some(peer) = peer_credentials(&stream) else {
            reply(&mut stream, socket, &error("", "PEER", "no peer credentials"));
            continue;
        };
        let Some(slot) = Slot::acquire(&state, socket, peer.uid) else {
            reply(&mut stream, socket, &error("", "BUSY", "too many connections"));
            continue;
        };
        thread::spawn(move || {
            let value = handle(&slot.state, socket, &peer, &mut stream);
            reply(&mut stream, socket, &value);
            drop(slot);
        });
    }
}

/// The audit records of one enforcement round: folded intents, every enforcement action (a stop, a reload of the
/// current generation, a failed stop), and errors when they change (a persistent error is not repeated every 5 s).
fn enforcement_records(round: &engine::Round, last_error: &mut Option<String>) -> Vec<Value> {
    let mut records = Vec::new();
    if let Ok(fold) = &round.fold {
        if fold["folded"].as_array().map_or(false, |names| !names.is_empty()) {
            records.push(json!({"time": now(), "event": "enforcement", "restrictions_folded": fold["folded"], "epoch": fold["epoch"]}));
        }
    }
    if let Ok(Some(result)) = round.enforced {
        if result != "within-grace" {
            records.push(json!({"time": now(), "event": "enforcement", "enforced": result}));
        }
    }
    let error = [round.fold.as_ref().err(), round.enforced.as_ref().err()].into_iter().flatten().cloned().collect::<Vec<_>>().join("; ");
    let error = (!error.is_empty()).then_some(error);
    if error.is_some() && error != *last_error {
        records.push(json!({"time": now(), "event": "enforcement_error", "error": error}));
    }
    *last_error = error;
    records
}

/// HR-D11 enforcement in the broker, independent of the reconciler (docs/product-interfaces.md, "Locks,
/// deadlines and recovery"; review RV-29, finding 3): rounds at most 5 s apart, earlier before a deadline.
fn enforcement(state: Arc<State>) {
    let mut last_error = None;
    loop {
        let round = state.engine.enforcement_round();
        for record in enforcement_records(&round, &mut last_error) {
            eprintln!("{} enforcement {}", now(), record);
            if let Err(e) = panel::audit(&state.panel.config.audit_log, &record) {
                eprintln!("{} enforcement audit: {}", now(), log_safe(&e));
            }
        }
        thread::sleep(Duration::from_secs_f64(round.wake));
    }
}

/// FV-05: the metrics history sampler (panel::history), one round per SAMPLE_INTERVAL on the interval's boundary,
/// pruning once an hour. A persistent error is logged when it changes, not every round.
fn sampler(state: Arc<State>) {
    let mut last_error: Option<String> = None;
    let mut rounds = 0u64;
    loop {
        let at = now();
        match panel::history::sample(&state.panel.config, at) {
            Ok(_) => last_error = None,
            Err(e) if last_error.as_deref() != Some(e.as_str()) => {
                eprintln!("{} metrics history: {}", at, log_safe(&e));
                last_error = Some(e);
            }
            Err(_) => {}
        }
        rounds += 1;
        if rounds % panel::history::PRUNE_EVERY == 0 {
            panel::history::prune(&state.panel.config, at);
        }
        let interval = panel::history::SAMPLE_INTERVAL;
        thread::sleep(Duration::from_secs(interval - now() % interval));
    }
}

/// Command line: `ols-cpanel-broker [SOCKET_DIR] [--rtreport-dir=DIR]` (OLS's real-time report directory,
/// default /run/ols-cpanel/status, the server statDir).
fn arguments(args: &[String]) -> Result<(String, Option<PathBuf>), String> {
    let mut dir = None;
    let mut rtreport = None;
    for arg in args {
        if let Some(path) = arg.strip_prefix("--rtreport-dir=") {
            if !path.starts_with('/') || path.split('/').any(|c| c == "..") {
                return Err("--rtreport-dir needs an absolute path".into());
            }
            rtreport = Some(PathBuf::from(path));
        } else if arg.starts_with('-') || dir.is_some() {
            return Err(format!("usage: ols-cpanel-broker [SOCKET_DIR] [--rtreport-dir=DIR] (unexpected {})", log_safe(arg)));
        } else {
            dir = Some(arg.clone());
        }
    }
    Ok((dir.unwrap_or_else(|| "/run/ols-cpanel-broker".into()), rtreport))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (dir, rtreport) = arguments(&args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(64);
    });
    let mut panel_config = panel::Config::production();
    if let Some(path) = rtreport {
        panel_config.rtreport_dir = path;
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("ols-cpanel-broker must run as root");
        std::process::exit(2);
    }
    let mut secret = [0u8; 32];
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut secret)).expect("randomness");
    let state = Arc::new(State {
        secret,
        used_nonces: Mutex::new(HashMap::new()),
        rate: Mutex::new(HashMap::new()),
        admin_connections: AtomicUsize::new(0),
        tenant_connections: AtomicUsize::new(0),
        engine_connections: AtomicUsize::new(0),
        tenant_per_uid: Mutex::new(HashMap::new()),
        status: Mutex::new(None),
        engine: Engine::new(Config::production()),
        panel: Panel::new(panel_config, jobs::Limits::default()),
    });
    // Jobs an earlier broker process left running (docs/product-interfaces.md, admin socket jobs).
    state.panel.jobs.recover();
    let enforcement_state = Arc::clone(&state);
    thread::spawn(move || enforcement(enforcement_state));
    let sampler_state = Arc::clone(&state);
    thread::spawn(move || sampler(sampler_state));
    let admin = listen(&format!("{dir}/admin.sock"), 0o600, None);
    let tenant = listen(&format!("{dir}/tenant.sock"), 0o666, None);
    // Without the olscpanel group (before systemd-sysusers ran) the engine socket is root-only.
    let engine_group = group_id(ENGINE_USER);
    let engine = listen(&format!("{dir}/engine.sock"), if engine_group.is_some() { 0o660 } else { 0o600 }, engine_group);
    let admin_state = Arc::clone(&state);
    let admin_thread = thread::spawn(move || serve(admin_state, Socket::Admin, admin));
    let engine_state = Arc::clone(&state);
    let engine_thread = thread::spawn(move || serve(engine_state, Socket::Engine, engine));
    serve(state, Socket::Tenant, tenant);
    let _ = admin_thread.join();
    let _ = engine_thread.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;

    static TREES: AtomicU32 = AtomicU32::new(0);

    /// A temporary directory removed on drop (the library's test helpers are not visible to the binary).
    struct Tree(PathBuf);

    impl Tree {
        fn new() -> Tree {
            let n = TREES.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("ols-broker-main-test-{}-{n}", std::process::id()));
            fs::create_dir_all(path.join("state")).unwrap();
            Tree(path)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn state_with(panel: Panel) -> State {
        let none = PathBuf::from("/nonexistent-broker-test");
        State {
            secret: [7; 32],
            used_nonces: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            admin_connections: AtomicUsize::new(0),
            tenant_connections: AtomicUsize::new(0),
            engine_connections: AtomicUsize::new(0),
            tenant_per_uid: Mutex::new(HashMap::new()),
            status: Mutex::new(None),
            engine: Engine::new(Config {
                state: none.clone(),
                ols_binary: none.clone(),
                activator: none.clone(),
                userdatadomains: none,
            }),
            panel,
        }
    }

    fn panel_config(root: &Path) -> panel::Config {
        panel::Config {
            state: root.join("state"),
            cli: root.join("ols-cpanel"),
            rtreport_dir: root.join("lshttpd"),
            tls_dir: root.join("apache_tls"),
            suspended_dir: root.join("suspended"),
            userdatadomains: root.join("userdatadomains"),
            audit_log: root.join("state/broker-audit.log"),
            domlogs: root.join("domlogs"),
            error_logs: root.join("vhostlogs"),
            requests: root.join("requests"),
            users_dir: root.join("cpusers"),
            curl: root.join("curl"),
            runuser: root.join("runuser"),
            tail: PathBuf::from("/usr/bin/tail"),
            find: PathBuf::from("/usr/bin/find"),
        }
    }

    fn state() -> State {
        state_with(Panel::new(panel_config(Path::new("/nonexistent-broker-test")), jobs::Limits::default()))
    }

    /// A broker over `tree` with a stand-in product command.
    fn state_in(tree: &Tree, cli: &str) -> State {
        let config = panel_config(&tree.0);
        fs::write(&config.cli, format!("#!/bin/sh\n{cli}\n")).unwrap();
        fs::set_permissions(&config.cli, fs::Permissions::from_mode(0o755)).unwrap();
        let limits = jobs::Limits { timeout: Duration::from_secs(20), max_output: 1 << 20, poll: Duration::from_millis(10) };
        state_with(Panel::new(config, limits))
    }

    fn call_as(state: &State, socket: Socket, uid: u32, op: &str, args: Value) -> Value {
        let req = Request { v: PROTOCOL, id: "t".into(), op: op.into(), args };
        dispatch(state, socket, &Peer { uid, pid: 1 }, req)
    }

    fn call(state: &State, socket: Socket, op: &str, args: Value) -> Value {
        call_as(state, socket, 0, op, args)
    }

    fn code(reply: &Value) -> &str {
        reply["error"]["code"].as_str().unwrap_or("")
    }

    const ADMIN_OPS: [&str; 27] = ["server.status", "server.metrics", "admin.metrics", "inventory.accounts", "compat.findings", "plan.latest",
                                   "generation.list", "doctor.report", "job.list", "job.status", "cap.issue", "cap.execute", "cache.stats",
                                   "admin.cache_limits", "admin.objcache", "php.status", "admin.requests", "admin.request_status", "admin.audit", "admin.notify", "admin.notify_set", "admin.notify_test",
                                   "admin.schedule", "admin.schedule_add", "admin.schedule_cancel", "admin.update", "admin.bundle"];

    #[test]
    fn operations_stay_on_their_socket() {
        let s = state();
        for op in ["engine.run", "engine.apply", "engine.status", "engine.enforce", "engine.health", "engine.recover", "engine.events",
                   "engine.events_done", "engine.events_quarantine", "engine.restrictions_fold"] {
            for socket in [Socket::Admin, Socket::Tenant] {
                assert_eq!(code(&call(&s, socket, op, json!({}))), "UNKNOWN_OPERATION", "{op}");
            }
        }
        for op in ADMIN_OPS.iter().chain(&["tenant.status", "tenant.domains", "tenant.sites", "tenant.cache_stats", "tenant.cache_purge", "tenant.php", "tenant.php_restart", "tenant.objcache", "tenant.logs", "tenant.php_errors", "tenant.perf", "tenant.request", "tenant.requests", "tenant.metrics"]) {
            assert_eq!(code(&call(&s, Socket::Engine, op, json!({}))), "UNKNOWN_OPERATION", "{op}");
        }
        // A tenant cannot reach any admin operation, nor learn which take arguments.
        for op in ADMIN_OPS {
            assert_eq!(code(&call_as(&s, Socket::Tenant, 1, op, json!({"x": 1}))), "UNKNOWN_OPERATION", "{op}");
        }
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.sites", json!({}))), "UNKNOWN_OPERATION");
        for op in ["server.status", "server.metrics", "plan.latest", "generation.list", "doctor.report", "job.list", "admin.notify", "admin.notify_test",
                   "admin.schedule", "admin.bundle"] {
            assert_eq!(code(&call(&s, Socket::Admin, op, json!({"x": 1}))), "BAD_ARGS", "{op}");
        }
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.sites", json!({"user": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.cache_stats", json!({"user": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.cache_purge", json!({}))), "UNKNOWN_OPERATION");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.php", json!({"user": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.php_restart", json!({"user": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.objcache", json!({"user": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.objcache", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.objcache", json!({}))), "UNKNOWN_OPERATION");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.metrics", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.metrics", json!({"user": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.metrics", json!({}))), "UNKNOWN_OPERATION");
        assert_eq!(code(&call(&s, Socket::Admin, "admin.metrics", json!({"resolution": "year"}))), "BAD_ARGS");
        assert_eq!(call(&s, Socket::Admin, "admin.metrics", json!({"resolution": "week"}))["result"]["samples"], json!(0));
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.php", json!({}))), "UNKNOWN_OPERATION");
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.php_restart", json!({}))), "UNKNOWN_OPERATION");
        assert_eq!(code(&call(&s, Socket::Admin, "tenant.cache_stats", json!({}))), "UNKNOWN_OPERATION");
        for op in ["tenant.logs", "tenant.php_errors", "tenant.perf", "tenant.request", "tenant.requests"] {
            assert_eq!(code(&call(&s, Socket::Admin, op, json!({}))), "UNKNOWN_OPERATION", "{op}");
            assert_eq!(code(&call_as(&s, Socket::Tenant, 0, op, json!({}))), "FORBIDDEN", "{op}");
            assert_eq!(code(&call_as(&s, Socket::Tenant, 4_000_000_000, op, json!({}))), "FORBIDDEN", "{op}");
        }
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.requests", json!({"user": "x"}))), "BAD_ARGS");
        for op in ["admin.requests", "admin.request_status"] {
            assert_eq!(code(&call_as(&s, Socket::Tenant, 1, op, json!({}))), "UNKNOWN_OPERATION", "{op}");
        }
        assert_eq!(code(&call(&s, Socket::Admin, "admin.requests", json!({"x": 1}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.status", json!({"x": 1}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.events", json!({"x": 1}))), "BAD_ARGS");
        assert_eq!(call(&s, Socket::Engine, "engine.events", json!({}))["result"], json!({"pending": []}));
        let run = call(&s, Socket::Engine, "engine.run", json!({"name": "id", "argv": ["/usr/bin/id"]}));
        assert_eq!(code(&run), "FORBIDDEN");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.enforce", json!({"grace": -1}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.health", json!({"seconds": 61}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.apply", json!({"generation": "x"}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.restrictions_fold", json!({"x": 1}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.events_quarantine", json!({"names": ["../x.json"]}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Engine, "engine.events_quarantine", json!({"names": ["x.json"]}))), "NOT_FOUND");
    }

    #[test]
    fn operations_views_and_maintenance_windows() {
        let tree = Tree::new();
        let calls_file = tree.0.join("calls");
        let s = state_in(&tree, &format!("echo \"$*\" >> {}; echo '{{\"result\": \"ok\", \"added\": {{\"id\": \"s20261028100000-0a1b2c\"}}}}'", calls_file.display()));
        // The audit view reads the broker's own log: a capability's records appear, newest first.
        let digest = call(&s, Socket::Admin, "server.status", Value::Null)["result"]["digest"].as_str().unwrap().to_string();
        capability(&s, "lab.audit_marker", "server", &digest);
        let view = call(&s, Socket::Admin, "admin.audit", json!({"size": 5}))["result"].clone();
        assert_eq!((view["total"].clone(), view["records"][0]["action"].clone(), view["records"][0]["actor"].clone()), (json!(1), json!("lab.audit_marker"), json!("root")));
        assert_eq!(code(&call(&s, Socket::Admin, "admin.audit", json!({"event": "Bad"}))), "BAD_ARGS");
        // A switch can only be scheduled for the plan the operator saw; the plan must exist.
        let plan = "p20261022120000-a1b2c3";
        let args = |digest: &str| json!({"action": "ols.cutover", "scope": plan, "digest": digest, "at": 1_900_000_000u64, "window": 60});
        assert_eq!(code(&call(&s, Socket::Admin, "admin.schedule_add", args(&"0".repeat(64)))), "NOT_FOUND");
        fs::create_dir_all(tree.0.join("state/plans")).unwrap();
        fs::write(tree.0.join(format!("state/plans/{plan}.json")), "{\"id\": \"x\"}").unwrap();
        assert_eq!(code(&call(&s, Socket::Admin, "admin.schedule_add", args(&"0".repeat(64)))), "STALE");
        let shown = call(&s, Socket::Admin, "plan.latest", json!({}))["result"]["plan"]["digest"].as_str().unwrap().to_string();
        assert!(call(&s, Socket::Admin, "admin.schedule_add", args(&shown))["ok"].as_bool().unwrap());
        // A return is bound to the status digest; nothing else can be scheduled.
        let ret = json!({"action": "ols.apache_return", "scope": "server", "digest": digest, "at": 1_900_000_000u64});
        assert!(call(&s, Socket::Admin, "admin.schedule_add", ret)["ok"].as_bool().unwrap());
        for bad in [json!({"action": "ols.sync", "scope": "server", "digest": digest, "at": 1}), json!({"action": "ols.cutover", "scope": "server", "digest": digest, "at": 1}),
                    json!({"action": "ols.cutover", "scope": plan, "digest": "zz", "at": 1}), json!({"action": "ols.cutover", "scope": plan, "digest": shown}),
                    json!({"action": "ols.cutover", "scope": plan, "digest": shown, "at": "soon"}), json!({"action": "ols.cutover", "scope": plan, "digest": shown, "at": 1, "x": 1})] {
            assert_eq!(code(&call(&s, Socket::Admin, "admin.schedule_add", bad.clone())), "BAD_ARGS", "{bad}");
        }
        let calls = fs::read_to_string(&calls_file).unwrap();
        assert!(calls.contains(&format!("schedule add --action=ols.cutover --scope={plan} --digest={shown} --at=1900000000 --window=60 --format=json")), "{calls}");
        assert!(call(&s, Socket::Admin, "admin.schedule", json!({}))["ok"].as_bool().unwrap());
        assert!(call(&s, Socket::Admin, "admin.update", json!({"refresh": true}))["ok"].as_bool().unwrap());
        assert_eq!(call(&s, Socket::Admin, "admin.bundle", json!({}))["result"]["bundles"], json!([]));
        // The support bundle is a job of the capability flow, with and without anonymization.
        let job = capability(&s, "ols.support_bundle", "server", &digest)["result"]["job"].as_str().unwrap().to_string();
        assert_eq!(finished(&s, &job)["output"]["added"]["id"], json!("s20261028100000-0a1b2c"));
        assert!(fs::read_to_string(&calls_file).unwrap().contains("support bundle --format=json"));
    }

    #[test]
    fn enforcement_rounds_are_audited() {
        let round = |fold: Result<Value, String>, enforced: Result<Option<&'static str>, String>| engine::Round { fold, enforced, wake: 5.0 };
        let none = || Ok(json!({"folded": [], "epoch": null}));
        let mut last = None;
        assert!(enforcement_records(&round(none(), Ok(None)), &mut last).is_empty());
        assert!(enforcement_records(&round(none(), Ok(Some("within-grace"))), &mut last).is_empty());
        let records = enforcement_records(&round(Ok(json!({"folded": ["a.json"], "epoch": 4})), Ok(Some("stopped-without-lock"))), &mut last);
        assert_eq!(records.len(), 2);
        assert_eq!((records[0]["restrictions_folded"].clone(), records[0]["epoch"].clone()), (json!(["a.json"]), json!(4)));
        assert_eq!(records[1]["enforced"], json!("stopped-without-lock"));
        // An error is recorded when it appears or changes, not every round.
        let failing = || round(Err("ACTIVATOR: activation lock busy".into()), Ok(None));
        assert_eq!(enforcement_records(&failing(), &mut last).len(), 1);
        assert!(enforcement_records(&failing(), &mut last).is_empty());
        assert!(enforcement_records(&round(none(), Ok(None)), &mut last).is_empty());
        assert_eq!(enforcement_records(&failing(), &mut last)[0]["event"], json!("enforcement_error"));
    }

    #[test]
    fn read_views_without_product_state() {
        let s = state();
        let status = call(&s, Socket::Admin, "server.status", Value::Null)["result"].clone();
        assert_eq!(status["cli"]["status"], json!("unavailable"));
        assert_eq!(status["digest"].as_str().map(str::len), Some(64));
        assert_eq!(call(&s, Socket::Admin, "server.metrics", json!({}))["result"]["status"], json!("unavailable"));
        let inventory = call(&s, Socket::Admin, "inventory.accounts", json!({"page": 1, "size": 10}))["result"].clone();
        assert_eq!((inventory["total"].as_u64(), inventory["size"].as_u64()), (Some(0), Some(10)));
        assert_eq!(code(&call(&s, Socket::Admin, "inventory.accounts", json!({"size": 0}))), "BAD_ARGS");
        assert_eq!(call(&s, Socket::Admin, "plan.latest", json!({}))["result"]["plan"], Value::Null);
        assert_eq!(call(&s, Socket::Admin, "compat.findings", json!({}))["result"]["total"], json!(0));
        assert_eq!(code(&call(&s, Socket::Admin, "doctor.report", json!({}))), "SPAWN_FAILED");
        assert_eq!(call(&s, Socket::Admin, "job.list", json!({}))["result"]["jobs"], json!([]));
        assert_eq!(code(&call(&s, Socket::Admin, "job.status", json!({"job": "j1761134400-0a1b2c3d"}))), "NOT_FOUND");
        // The tenant's status is the broker's own view only (no product command for tenants).
        let tenant = call_as(&s, Socket::Tenant, 1, "tenant.status", json!({}))["result"].clone();
        assert_eq!(tenant.as_object().unwrap().keys().collect::<Vec<_>>(), ["apache_active", "observed_at", "ols_active"]);
    }

    #[test]
    fn tenant_sites_come_from_the_peer_uid() {
        let tree = Tree::new();
        let s = state_in(&tree, "exit 1");
        // uid 1 is "daemon" in the build container's and the server's user database.
        let me = user_name(1).unwrap();
        fs::write(&s.panel.config.userdatadomains, format!(
            "a.test: {me}==root==main==a.test==/home/{me}/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
             b.test: other==root==main==b.test==/home/other/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n")).unwrap();
        let reply = call_as(&s, Socket::Tenant, 1, "tenant.sites", json!({}));
        assert_eq!(reply["result"]["user"], json!(me));
        let sites = reply["result"]["sites"].as_array().unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!((sites[0]["domain"].as_str(), sites[0]["engine"].as_str()), (Some("a.test"), Some("unknown")));
        assert_eq!(sites[0]["tls"], json!({"present": false, "not_after": null}));
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.sites", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 4_000_000_000, "tenant.sites", json!({}))), "FORBIDDEN");
    }

    const CLI: &str = r#"case "$1" in
status) echo '{"cut_over": true, "profile": {"production": true, "hybrid_ports": null}, "epoch": 3, "pending_events": 0, "hybrid_vhosts": []}';;
sync) sleep 1; echo '{"result": "committed"}';;
install) printf '{"argv": "%s"}' "$*";;
*) echo '{"result": "ok"}';;
esac"#;

    fn capability(s: &State, action: &str, scope: &str, digest: &str) -> Value {
        let token = call(s, Socket::Admin, "cap.issue", json!({"principal": "root", "action": action, "scope": scope, "digest": digest}));
        let Some(token) = token["result"]["token"].as_str() else { return token };
        call(s, Socket::Admin, "cap.execute", json!({"token": token, "action": action, "scope": scope, "digest": digest}))
    }

    fn finished(s: &State, job: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = call(s, Socket::Admin, "job.status", json!({"job": job}))["result"].clone();
            if status["state"] != json!("running") {
                return status;
            }
            assert!(Instant::now() < deadline, "job did not finish");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn capabilities_start_jobs() {
        let tree = Tree::new();
        let s = state_in(&tree, CLI);
        let status = call(&s, Socket::Admin, "server.status", json!({}))["result"].clone();
        assert_eq!((status["epoch"].as_i64(), status["cut_over"].as_bool()), (Some(3), Some(true)));
        assert_eq!(status["cli"]["status"], json!("ok"));
        let digest = status["digest"].as_str().unwrap().to_string();
        // A job per action, with the status the operator saw.
        let job = capability(&s, "ols.sync", "server", &digest)["result"]["job"].as_str().unwrap().to_string();
        assert_eq!(call(&s, Socket::Admin, "job.list", json!({}))["result"]["running"], json!(job));
        // One at a time.
        assert_eq!(code(&capability(&s, "ols.rollback", "server", &digest)), "BUSY");
        let done = finished(&s, &job);
        assert_eq!((done["state"].as_str(), done["output"].clone()), (Some("done"), json!({"result": "committed"})));
        assert_eq!(done["principal"], json!("root"));
        // A different view of the server is refused.
        assert_eq!(code(&capability(&s, "ols.rollback", "server", &"0".repeat(64))), "STALE");
        // Cutover binds to the plan file's digest.
        let plan = "p20261022120000-a1b2c3";
        assert_eq!(code(&capability(&s, "ols.cutover", plan, &"0".repeat(64))), "NOT_FOUND");
        fs::create_dir_all(tree.0.join("state/plans")).unwrap();
        fs::write(tree.0.join(format!("state/plans/{plan}.json")), "{\"id\": \"p20261022120000-a1b2c3\"}").unwrap();
        let shown = call(&s, Socket::Admin, "plan.latest", json!({}))["result"]["plan"]["digest"].as_str().unwrap().to_string();
        assert_eq!(code(&capability(&s, "ols.cutover", plan, &"0".repeat(64))), "STALE");
        let job = capability(&s, "ols.cutover", plan, &shown)["result"]["job"].as_str().unwrap().to_string();
        assert_eq!(finished(&s, &job)["output"]["argv"], json!(format!("install --cutover --plan={plan} --yes --format=json")));
        // Scopes and actions outside the table never get a capability.
        for (action, scope) in [("ols.sync", plan), ("ols.cutover", "server"), ("ols.cutover", "../x"), ("ols.restart", "server"),
                                ("server.status", "server"), ("ols.plan", "root")] {
            let reply = call(&s, Socket::Admin, "cap.issue", json!({"principal": "root", "action": action, "scope": scope, "digest": digest}));
            assert_eq!(code(&reply), "BAD_ARGS", "{action} {scope}");
        }
        // The lab marker keeps working: one audit record, no job.
        assert_eq!(capability(&s, "lab.audit_marker", "server", &digest)["result"]["executed"], json!("lab.audit_marker"));
        let audit: Vec<Value> = fs::read_to_string(tree.0.join("state/broker-audit.log")).unwrap().lines()
            .map(|l| serde_json::from_str(l).unwrap()).collect();
        let events: Vec<&str> = audit.iter().map(|r| r["event"].as_str().unwrap_or("marker")).collect();
        assert_eq!(events, ["job_start", "job_finish", "job_start", "job_finish", "marker"]);
        assert_eq!(audit[4]["action"], json!("lab.audit_marker"));
        assert_eq!(call(&s, Socket::Admin, "job.list", json!({}))["result"]["jobs"].as_array().unwrap().len(), 2);
    }

    const CACHE_CLI: &str = r#"case "$1 $2" in
"status --format=json") echo '{"cut_over": true, "epoch": 3}';;
"cache stats") printf '{"argv": "%s", "stores": [{"store": "%s@a.test", "account": "%s"}], "totals": {}}' "$*" "$USER_NAME" "$USER_NAME";;
"cache purge") printf '{"argv": "%s", "purged_at": 7, "stores": [], "totals": {"entries": 1}}' "$*";;
"cache limits") printf '{"argv": "%s", "limits": {"per_site_mb": 512}}' "$*";;
*) echo '{"result": "ok"}';;
esac"#;

    #[test]
    fn cache_operations() {
        let tree = Tree::new();
        // uid 1 is "daemon" in the build container's and the server's user database.
        let me = user_name(1).unwrap();
        let s = state_in(&tree, &CACHE_CLI.replace("$USER_NAME", &me));
        fs::write(&s.panel.config.userdatadomains, format!(
            "a.test: {me}==root==main==a.test==/home/{me}/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
             b.test: other==root==main==b.test==/home/other/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n")).unwrap();
        // Admin statistics: the command's report, arguments validated.
        let all = call(&s, Socket::Admin, "cache.stats", json!({}))["result"].clone();
        assert_eq!(all["output"]["argv"], json!("cache stats --format=json"));
        assert_eq!(call(&s, Socket::Admin, "cache.stats", json!({"domain": "a.test"}))["result"]["output"]["argv"],
                   json!("cache stats --domain=a.test --format=json"));
        assert_eq!(code(&call(&s, Socket::Admin, "cache.stats", json!({"account": "x y"}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Admin, "cache.stats", json!({"scope": "x"}))), "BAD_ARGS");
        // The cleanup limits: a read, a validated write, and never on the tenant or engine socket.
        assert_eq!(call(&s, Socket::Admin, "admin.cache_limits", json!({}))["result"]["output"]["argv"], json!("cache limits --format=json"));
        assert_eq!(call(&s, Socket::Admin, "admin.cache_limits", json!({"per_site_mb": 1024}))["result"]["output"]["argv"],
                   json!("cache limits --per-site-mb=1024 --format=json"));
        assert_eq!(code(&call(&s, Socket::Admin, "admin.cache_limits", json!({"per_site_mb": 1}))), "BAD_ARGS");
        assert_eq!(code(&call(&s, Socket::Admin, "admin.cache_limits", json!({"x": 1}))), "BAD_ARGS");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "admin.cache_limits", json!({"per_site_mb": 1024}))), "UNKNOWN_OPERATION");
        // Tenant statistics and purge use the peer's account, never a request field.
        let stats = call_as(&s, Socket::Tenant, 1, "tenant.cache_stats", json!({}));
        assert_eq!(stats["result"]["user"], json!(me));
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.cache_stats", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.cache_purge", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 4_000_000_000, "tenant.cache_purge", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.cache_purge", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.cache_purge", json!({"account": "other"}))), "BAD_ARGS");
        let purged = call_as(&s, Socket::Tenant, 1, "tenant.cache_purge", json!({"domain": "a.test"}));
        assert_eq!((purged["result"]["user"].clone(), purged["result"]["domain"].clone()), (json!(me), json!("a.test")));
        // The second purge within the interval is limited.
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.cache_purge", json!({}))), "RATE_LIMITED");
        // The purge job: a capability bound to the status digest, scope grammar enforced.
        let digest = call(&s, Socket::Admin, "server.status", json!({}))["result"]["digest"].as_str().unwrap().to_string();
        for (scope, argv) in [("server", "cache purge --all --format=json"), ("account:olscpa", "cache purge --account=olscpa --format=json"),
                              ("domain:a.test", "cache purge --domain=a.test --format=json")] {
            let job = capability(&s, "ols.cache_purge", scope, &digest)["result"]["job"].as_str().unwrap().to_string();
            assert_eq!(finished(&s, &job)["output"]["argv"], json!(argv));
        }
        assert_eq!(code(&capability(&s, "ols.cache_purge", "server", &"0".repeat(64))), "STALE");
        for scope in ["", "all", "account:", "domain:a", "account:a b", "domain:a.test --all", "plan:p1"] {
            let reply = call(&s, Socket::Admin, "cap.issue", json!({"principal": "root", "action": "ols.cache_purge", "scope": scope, "digest": digest}));
            assert_eq!(code(&reply), "BAD_ARGS", "{scope}");
        }
    }

    const PHP_CLI: &str = r#"case "$1 $2" in
"status --format=json") echo '{"cut_over": true, "epoch": 3}';;
"php status") case "$*" in
  *--account=*) printf '{"result": "status", "opcache": {"versions": [{"version": "ea-php83", "php": "8.3", "loaded": true, "tuned": true}]}, "processes": {"thresholds": {}, "accounts": [{"account": "%s", "children": 2}]}, "limits": {"account": {"children": 5}}}' "$USER_NAME";;
  *) printf '{"result": "status", "argv": "%s"}' "$*";;
esac;;
"php restart") printf '{"result": "restarted", "found": 2, "killed": 2, "remaining": 0, "argv": "%s"}' "$*";;
"php opcache") printf '{"result": "installed", "argv": "%s"}' "$*";;
"php env") printf '{"result": "repaired", "argv": "%s"}' "$*";;
*) echo '{"result": "ok"}';;
esac"#;

    #[test]
    fn php_operations() {
        let tree = Tree::new();
        let me = user_name(1).unwrap();
        let s = state_in(&tree, &PHP_CLI.replace("$USER_NAME", &me));
        fs::write(&s.panel.config.userdatadomains, format!(
            "a.test: {me}==root==main==a.test==/home/{me}/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
             b.test: other==root==main==b.test==/home/other/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n")).unwrap();
        // Admin view: the fixed command, no arguments.
        assert_eq!(call(&s, Socket::Admin, "php.status", json!({}))["result"]["output"]["argv"], json!("php status --format=json"));
        assert_eq!(code(&call(&s, Socket::Admin, "php.status", json!({"account": "x"}))), "BAD_ARGS");
        // Tenant view and restart use the peer's account, never a request field.
        let view = call_as(&s, Socket::Tenant, 1, "tenant.php", json!({}));
        assert_eq!(view["result"]["user"], json!(me));
        assert_eq!(view["result"]["processes"]["account"], json!(me));
        assert_eq!(view["result"]["sites"][0]["php_version"], json!("ea-php83"));
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.php", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 0, "tenant.php_restart", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 4_000_000_000, "tenant.php_restart", json!({}))), "FORBIDDEN");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.php_restart", json!({"account": "other"}))), "BAD_ARGS");
        let restarted = call_as(&s, Socket::Tenant, 1, "tenant.php_restart", json!({}));
        assert_eq!((restarted["result"]["user"].clone(), restarted["result"]["killed"].clone()), (json!(me), json!(2)));
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.php_restart", json!({}))), "RATE_LIMITED");
        assert!(fs::read_to_string(&s.panel.config.audit_log).unwrap().contains("tenant_php_restart"));
        // The jobs: capabilities bound to the status digest, scope grammars enforced.
        let digest = call(&s, Socket::Admin, "server.status", json!({}))["result"]["digest"].as_str().unwrap().to_string();
        for (action, scope, argv) in [("ols.php_restart", "server", "php restart --all --format=json"),
                                      ("ols.php_restart", "account:olscpa", "php restart --account=olscpa --format=json"),
                                      ("ols.opcache_install", "server", "php opcache install --all --format=json"),
                                      ("ols.opcache_install", "version:ea-php83", "php opcache install --version=ea-php83 --format=json"),
                                      ("ols.php_env_repair", "server", "php env repair --format=json")] {
            let job = capability(&s, action, scope, &digest)["result"]["job"].as_str().unwrap().to_string();
            assert_eq!(finished(&s, &job)["output"]["argv"], json!(argv));
        }
        assert_eq!(code(&capability(&s, "ols.php_restart", "server", &"0".repeat(64))), "STALE");
        for (action, scope) in [("ols.php_restart", "version:ea-php83"), ("ols.php_restart", "domain:a.test"), ("ols.opcache_install", "account:olscpa"),
                                ("ols.opcache_install", "version:ea-php8"), ("ols.opcache_install", "version:ea-php83 --all"), ("ols.php_restart", ""),
                                ("ols.php_env_repair", "all"), ("ols.php_env_repair", "version:ea-php83"), ("ols.php_env_repair", "account:olscpa"),
                                ("ols.update", "all"), ("ols.update", "version:0.2.3"), ("ols.update", "")] {
            let reply = call(&s, Socket::Admin, "cap.issue", json!({"principal": "root", "action": action, "scope": scope, "digest": digest}));
            assert_eq!(code(&reply), "BAD_ARGS", "{action} {scope}");
        }
    }

    #[test]
    fn account_tools_use_the_peer_identity() {
        let tree = Tree::new();
        let s = state_in(&tree, "exit 1");
        let me = user_name(1).unwrap();
        let c = &s.panel.config;
        fs::write(&c.userdatadomains, format!(
            "a.test: {me}==root==main==a.test==/home/{me}/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n\
             b.test: other==root==main==b.test==/home/other/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n")).unwrap();
        fs::create_dir_all(&c.state).unwrap();
        fs::write(c.state.join("domain-owners.json"), json!({"a.test": {"owner": me, "since": 0}, "b.test": {"owner": "other", "since": 0}}).to_string()).unwrap();
        fs::create_dir_all(&c.domlogs).unwrap();
        fs::write(c.domlogs.join("a.test-ssl_log"), "GET /?token=abc 200\n").unwrap();
        fs::write(c.domlogs.join("b.test-ssl_log"), "GET /other-account 200\n").unwrap();
        let mine = call_as(&s, Socket::Tenant, 1, "tenant.logs", json!({"domain": "a.test", "kind": "access"}));
        assert_eq!(mine["result"]["user"], json!(me));
        assert_eq!(mine["result"]["lines"], json!(["GET /?token=[redacted] 200"]));
        // Another account's domain, and a forged account, are refused; the peer is never a request field.
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.logs", json!({"domain": "b.test", "kind": "access"}))), "NOT_FOUND");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.logs", json!({"domain": "a.test", "kind": "access", "user": "other"}))), "BAD_ARGS");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.php_errors", json!({"domain": "b.test"}))), "NOT_FOUND");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.perf", json!({"domain": "b.test"}))), "NOT_FOUND");
        // Requests: created as the peer, listed for the peer only, administered on the admin socket.
        let made = call_as(&s, Socket::Tenant, 1, "tenant.request", json!({"subject": "php", "text": "hello"}));
        assert_eq!(made["result"]["request"]["user"], json!(me));
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.request", json!({"subject": "php", "text": "again"}))), "RATE_LIMITED");
        assert_eq!(code(&call_as(&s, Socket::Tenant, 1, "tenant.request", json!({"subject": "php", "text": "x", "user": "other"}))), "BAD_ARGS");
        assert_eq!(call_as(&s, Socket::Tenant, 1, "tenant.requests", json!({}))["result"]["requests"].as_array().unwrap().len(), 1);
        let id = made["result"]["request"]["id"].as_str().unwrap();
        assert_eq!(call(&s, Socket::Admin, "admin.requests", json!({}))["result"]["open"], json!(1));
        let done = call(&s, Socket::Admin, "admin.request_status", json!({"id": id, "status": "done"}));
        assert_eq!(done["result"]["request"]["status"], json!("done"));
    }

    #[test]
    fn command_line() {
        let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        assert_eq!(arguments(&args(&[])).unwrap(), ("/run/ols-cpanel-broker".to_string(), None));
        assert_eq!(arguments(&args(&["/run/x", "--rtreport-dir=/run/ols/st"])).unwrap(),
                   ("/run/x".to_string(), Some(PathBuf::from("/run/ols/st"))));
        for bad in [&["--rtreport-dir=relative"][..], &["--rtreport-dir=/a/../b"], &["/a", "/b"], &["--other"]] {
            assert!(arguments(&args(bad)).is_err(), "{bad:?}");
        }
    }

    /// Sends `line` on one end of a socket pair and runs `handle` on the other.
    fn exchange(socket: Socket, uid: u32, line: Vec<u8>) -> Value {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            let _ = client.write_all(&line);
            client
        });
        let reply = handle(&state(), socket, &Peer { uid, pid: 1 }, &mut server);
        drop(writer.join());
        reply
    }

    fn padded(op: &str, size: usize) -> Vec<u8> {
        let mut line = json!({"v": 1, "id": "t", "op": op, "args": {"name": "x".repeat(size), "argv": []}}).to_string();
        line.push('\n');
        line.into_bytes()
    }

    #[test]
    fn request_limits_per_socket_and_operation() {
        // 64 KiB everywhere except engine.apply on the engine socket.
        assert_eq!(code(&exchange(Socket::Admin, 0, padded("server.status", 100_000))), "TOO_LARGE");
        assert_eq!(code(&exchange(Socket::Engine, 0, padded("engine.run", 100_000))), "TOO_LARGE");
        assert_eq!(code(&exchange(Socket::Engine, 0, padded("engine.run", 1000))), "BAD_ARGS");
        // A large apply is read and parsed (then refused for its arguments, not its size).
        assert_eq!(code(&exchange(Socket::Engine, 0, padded("engine.apply", 1_000_000))), "BAD_ARGS");
        // Only root and olscpanel reach the engine socket.
        assert_eq!(code(&exchange(Socket::Engine, 4_000_000_000, padded("engine.events", 0))), "FORBIDDEN");
    }
}
