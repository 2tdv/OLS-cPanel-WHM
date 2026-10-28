//! Metrics history (FV-05): a sampler of OLS's real-time reports into bounded ring files, and the read views
//! `admin.metrics` (the server or any vhost) and `tenant.metrics` (only the caller's own vhosts).
//!
//! The sampler is a thread of the broker (`ols-cpanel-broker` main): the broker already runs as root all
//! the time with the report directory, the account list and the state directory at hand, so history needs
//! no extra unit, timer or installation step and starts with the broker after every install and upgrade.
//! Every SAMPLE_INTERVAL seconds it takes the live view `metrics::metrics` (the same aggregation of the
//! `.rtreport*` files that `server.metrics` returns, so a history point is exactly a value OLS reported)
//! and folds it into the rings. Reports that are not `ok` (missing, stale, unknown format) leave a gap.
//!
//! One ring file per series, `<state>/metrics/server.ring` and `<state>/metrics/vhosts/<vhost>.ring` (root,
//! 0600, directories 0700). A file has a fixed size and three levels, RRD style:
//!
//! ```text
//! header   48 bytes: "OLSM", version u16, channels u16, 8 reserved, owner (cPanel user, NUL padded, 32 bytes)
//! hour     360 slots of 10 s   (one hour)
//! day     1440 slots of 1 min  (one day)
//! week    1008 slots of 10 min (one week)
//! slot     ts u32 (bucket start, unix seconds), count u32, then `channels` f32 sums
//! ```
//!
//! A sample goes to the slot `(ts / step) % slots` of each level; a slot whose bucket differs is reset, so
//! a ring never grows and old data is overwritten, never deleted. A reader returns sum / count per bucket
//! (the mean of the samples that fell in it) and `null` for buckets without samples. Values are f32:
//! exact for counts up to 16.7 million and within 1e-7 relative above that.
//!
//! Ownership: a vhost ring records the cPanel user that owned the vhost when the ring was started (the server ring
//! has no owner). The sampler and every reader compare it with the vhost's current owner in /etc/userdatadomains;
//! when they differ (the domain moved to another account or was re-created) the ring is started again, so a new
//! owner never sees a previous owner's history, and a tenant read only returns data recorded under the caller.
//!
//! Bounded disk use: a server ring is `HEADER + 2808 * (8 + 4 * SERVER_CHANNELS)` = 112,368 bytes, a vhost
//! ring `HEADER + 2808 * (8 + 4 * VHOST_CHANNELS)` = 67,440 bytes. At most MAX_VHOST_RINGS vhost rings are
//! kept (the busiest vhosts get theirs first because an idle vhost has no ring until its first non-zero
//! sample), so the directory never exceeds about 67.5 MB. Rings of vhosts that have not been in a report
//! for PRUNE_AFTER (longer than the week they cover) are removed, as is anything else in the directory.

use super::{now, summary, valid_domain, Config, Reply};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Seconds between samples (the finest resolution).
pub const SAMPLE_INTERVAL: u64 = 10;
/// Resolutions: name, bucket seconds, slots.
pub const LEVELS: [(&str, u64, usize); 3] = [("hour", 10, 360), ("day", 60, 1440), ("week", 600, 1008)];
/// Per series, in the order they are stored.
pub const SERVER_CHANNELS: [&str; 8] = ["requests_per_second", "requests_processing", "connections", "tls_connections",
    "bytes_in_per_second", "bytes_out_per_second", "cache_hits_per_second", "php_in_use"];
pub const VHOST_CHANNELS: [&str; 4] = ["requests_per_second", "cache_hits_per_second", "static_hits_per_second", "php_in_use"];
pub const MAX_VHOST_RINGS: usize = 1000;
/// A vhost ring not written for this long (8 days, more than the week it holds) is pruned.
pub const PRUNE_AFTER: u64 = 8 * 86400;
/// Pruning runs every this many sampler rounds (once an hour).
pub const PRUNE_EVERY: u64 = 360;
const HEADER: usize = 48;
const OWNER_AT: usize = 16;
const OWNER_LEN: usize = 32;
const MAGIC: &[u8; 4] = b"OLSM";
const VERSION: u16 = 2;

fn slot_size(channels: usize) -> usize {
    8 + 4 * channels
}

/// Byte size of a whole ring file.
pub fn ring_size(channels: usize) -> usize {
    HEADER + LEVELS.iter().map(|l| l.2).sum::<usize>() * slot_size(channels)
}

/// Upper bound of the whole metrics directory.
pub fn disk_bound() -> usize {
    ring_size(SERVER_CHANNELS.len()) + MAX_VHOST_RINGS * ring_size(VHOST_CHANNELS.len())
}

fn level_offset(level: usize, channels: usize) -> usize {
    HEADER + LEVELS[..level].iter().map(|l| l.2).sum::<usize>() * slot_size(channels)
}

pub fn dir(config: &Config) -> PathBuf {
    config.state.join("metrics")
}

fn server_path(config: &Config) -> PathBuf {
    dir(config).join("server.ring")
}

fn vhost_path(config: &Config, vhost: &str) -> PathBuf {
    dir(config).join("vhosts").join(format!("{vhost}.ring"))
}

fn header(channels: usize, owner: &str) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    let name = owner.as_bytes();
    h[OWNER_AT..OWNER_AT + name.len().min(OWNER_LEN)].copy_from_slice(&name[..name.len().min(OWNER_LEN)]);
    h[..4].copy_from_slice(MAGIC);
    h[4..6].copy_from_slice(&VERSION.to_le_bytes());
    h[6..8].copy_from_slice(&(channels as u16).to_le_bytes());
    h
}

fn open(path: &Path, channels: usize, owner: &str, create: bool) -> std::io::Result<Option<fs::File>> {
    let existing = fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(path);
    match existing {
        Ok(file) => {
            let meta = file.metadata()?;
            let mut head = [0u8; HEADER];
            if meta.is_file() && meta.len() == ring_size(channels) as u64 && file.read_at(&mut head, 0)? == HEADER && head == header(channels, owner) {
                return Ok(Some(file));
            }
            // Another layout, another owner or a damaged file: start it again.
            drop(file);
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if !create {
        return Ok(None);
    }
    let file = fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
    file.set_len(ring_size(channels) as u64)?;
    file.write_all_at(&header(channels, owner), 0)?;
    Ok(Some(file))
}

fn read_slot(file: &fs::File, offset: usize, channels: usize) -> std::io::Result<(u32, u32, Vec<f32>)> {
    let mut raw = vec![0u8; slot_size(channels)];
    file.read_exact_at(&mut raw, offset as u64)?;
    let ts = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let count = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    let sums = raw[8..].chunks_exact(4).map(|c| f32::from_le_bytes(c.try_into().unwrap())).collect();
    Ok((ts, count, sums))
}

/// Folds one sample taken at `at` into every level of the ring.
fn record(file: &fs::File, values: &[f32], at: u64) -> std::io::Result<()> {
    let channels = values.len();
    for (level, &(_, step, slots)) in LEVELS.iter().enumerate() {
        let bucket = at / step * step;
        let offset = level_offset(level, channels) + (bucket / step) as usize % slots * slot_size(channels);
        let (ts, count, mut sums) = read_slot(file, offset, channels)?;
        let count = if u64::from(ts) == bucket && count > 0 {
            for (sum, value) in sums.iter_mut().zip(values) {
                *sum += value;
            }
            count + 1
        } else {
            sums = values.to_vec();
            1
        };
        let mut raw = Vec::with_capacity(slot_size(channels));
        raw.extend_from_slice(&(bucket as u32).to_le_bytes());
        raw.extend_from_slice(&count.to_le_bytes());
        for sum in sums {
            raw.extend_from_slice(&sum.to_le_bytes());
        }
        file.write_all_at(&raw, offset as u64)?;
    }
    Ok(())
}

/// The `slots` buckets ending with the one that contains `at`, oldest first: the mean of each channel, or None.
fn read_level(file: &fs::File, level: usize, channels: usize, at: u64) -> std::io::Result<(u64, Vec<Option<Vec<f32>>>)> {
    let (_, step, slots) = LEVELS[level];
    let size = slot_size(channels);
    let mut raw = vec![0u8; slots * size];
    file.read_exact_at(&mut raw, level_offset(level, channels) as u64)?;
    let end = at / step * step;
    let start = end.saturating_sub((slots as u64 - 1) * step);
    let mut out = Vec::with_capacity(slots);
    for i in 0..slots as u64 {
        let bucket = start + i * step;
        let at_slot = (bucket / step) as usize % slots * size;
        let slot = &raw[at_slot..at_slot + size];
        let ts = u32::from_le_bytes(slot[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(slot[4..8].try_into().unwrap());
        out.push((u64::from(ts) == bucket && count > 0).then(|| {
            slot[8..].chunks_exact(4).map(|c| f32::from_le_bytes(c.try_into().unwrap()) / count as f32).collect()
        }));
    }
    Ok((start, out))
}

fn number(v: &Value) -> f32 {
    v.as_f64().filter(|x| x.is_finite() && *x >= 0.0).unwrap_or(0.0) as f32
}

fn server_values(server: &Value) -> Vec<f32> {
    let mut values: Vec<f32> = SERVER_CHANNELS[..SERVER_CHANNELS.len() - 1].iter().map(|c| number(&server[*c])).collect();
    values.push(number(&server["extapp"]["in_use"]));
    values
}

fn vhost_values(vhost: &Value) -> Vec<f32> {
    let mut values: Vec<f32> = VHOST_CHANNELS[..VHOST_CHANNELS.len() - 1].iter().map(|c| number(&vhost[*c])).collect();
    values.push(number(&vhost["extapp"]["in_use"]));
    values
}

/// What one sampler round did.
#[derive(Debug, Default, PartialEq)]
pub struct Round {
    /// Whether the report was usable (`ok`); false leaves a gap.
    pub sampled: bool,
    pub vhosts: usize,
    /// Vhosts that could not get a ring because MAX_VHOST_RINGS is reached.
    pub skipped: usize,
}

/// The current owner of every vhost, from /etc/userdatadomains.
fn owners(config: &Config) -> std::collections::HashMap<String, String> {
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    rows.iter().filter_map(|r| Some((summary::vhost_of(r).to_string(), r["user"].as_str()?.to_string()))).collect()
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn ring_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir).map(|e| e.flatten().map(|e| e.path()).filter(|p| p.extension().map_or(false, |x| x == "ring")).collect()).unwrap_or_default()
}

/// One sampler round at time `at`: the live report folded into the server ring and every vhost's ring.
pub fn sample(config: &Config, at: u64) -> Result<Round, String> {
    let live = super::metrics::metrics(&config.rtreport_dir, at);
    let mut round = Round::default();
    if live["status"] != json!("ok") {
        return Ok(round);
    }
    let vhosts_dir = dir(config).join("vhosts");
    private_dir(&dir(config)).and_then(|_| private_dir(&vhosts_dir)).map_err(|e| format!("metrics directory: {e}"))?;
    let write = |path: &Path, values: Vec<f32>, owner: &str, create: bool| -> Result<bool, String> {
        match open(path, values.len(), owner, create).map_err(|e| format!("{}: {e}", path.display()))? {
            Some(file) => record(&file, &values, at).map(|_| true).map_err(|e| format!("{}: {e}", path.display())),
            None => Ok(false),
        }
    };
    let mut error = None;
    if let Err(e) = write(&server_path(config), server_values(&live["server"]), "", true) {
        error = Some(e);
    }
    let mut count = None;
    let owners = owners(config);
    for vhost in live["vhosts"].as_array().into_iter().flatten() {
        let Some(name) = vhost["vhost"].as_str().filter(|n| valid_domain(n)) else { continue };
        let values = vhost_values(vhost);
        let path = vhost_path(config, name);
        let exists = fs::symlink_metadata(&path).is_ok();
        // An idle vhost without a ring stays without one; a ring is created by the first traffic.
        let busy = values.iter().any(|v| *v != 0.0);
        let create = if exists {
            true // an existing ring is rewritten as it is, or started again when damaged
        } else if busy {
            *count.get_or_insert_with(|| ring_files(&vhosts_dir).len()) < MAX_VHOST_RINGS
        } else {
            continue;
        };
        if !create {
            round.skipped += 1;
            continue;
        }
        match write(&path, values, owners.get(name).map_or("", String::as_str), true) {
            Ok(true) => {
                round.vhosts += 1;
                if !exists {
                    count = count.map(|c| c + 1);
                }
            }
            Ok(false) => {}
            Err(e) => error = Some(e),
        }
    }
    round.sampled = true;
    error.map_or(Ok(round), Err)
}

/// Removes vhost rings not written for PRUNE_AFTER and anything in the directory that is not a ring.
pub fn prune(config: &Config, at: u64) -> usize {
    let mut removed = 0;
    let vhosts_dir = dir(config).join("vhosts");
    for entry in fs::read_dir(&vhosts_dir).into_iter().flatten().flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        let is_ring = meta.is_file() && path.extension().map_or(false, |x| x == "ring");
        let old = at.saturating_sub(meta.mtime().max(0) as u64) > PRUNE_AFTER;
        if (!is_ring || old) && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    resolution: Option<String>,
    #[serde(default)]
    vhost: Option<String>,
}

fn parse(args: Value) -> Result<(usize, Option<String>), (&'static str, String)> {
    let a: Args = if args.is_null() { Args::default() } else { serde_json::from_value(args).map_err(|e| ("BAD_ARGS", e.to_string()))? };
    let name = a.resolution.unwrap_or_else(|| "hour".into());
    let level = LEVELS.iter().position(|l| l.0 == name)
        .ok_or(("BAD_ARGS", "resolution must be hour, day or week".to_string()))?;
    if let Some(vhost) = &a.vhost {
        if !valid_domain(vhost) {
            return Err(("BAD_ARGS", "vhost must be a domain name".into()));
        }
    }
    Ok((level, a.vhost))
}

fn round3(v: f32) -> Value {
    let x = (f64::from(v) * 1000.0).round() / 1000.0;
    if x.fract() == 0.0 { json!(x as i64) } else { json!(x) }
}

/// The reply for one series at `level`; `path` None or an unreadable ring gives all gaps.
fn series(path: Option<&Path>, names: &[&str], owner: &str, level: usize, at: u64) -> Map<String, Value> {
    let (_, step, slots) = LEVELS[level];
    let data = path.and_then(|p| open(p, names.len(), owner, false).ok().flatten()).and_then(|f| read_level(&f, level, names.len(), at).ok());
    let start = data.as_ref().map(|d| d.0).unwrap_or_else(|| (at / step * step).saturating_sub((slots as u64 - 1) * step));
    let mut channels = Map::new();
    let mut samples = 0;
    for (c, name) in names.iter().enumerate() {
        let column: Vec<Value> = (0..slots).map(|i| match data.as_ref().and_then(|d| d.1[i].as_ref()) {
            Some(values) => round3(values[c]),
            None => Value::Null,
        }).collect();
        if c == 0 {
            samples = column.iter().filter(|v| !v.is_null()).count();
        }
        channels.insert(name.to_string(), Value::Array(column));
    }
    let mut out = Map::new();
    out.insert("resolution".into(), json!(LEVELS[level].0));
    out.insert("start".into(), json!(start));
    out.insert("step".into(), json!(step));
    out.insert("count".into(), json!(slots));
    out.insert("samples".into(), json!(samples));
    out.insert("channels".into(), Value::Object(channels));
    out
}

/// `admin.metrics`: the server history, or one vhost's.
pub fn admin_history(config: &Config, args: Value) -> Reply {
    let (level, vhost) = parse(args)?;
    let at = now();
    let mut out = match &vhost {
        None => series(Some(&server_path(config)), &SERVER_CHANNELS, "", level, at),
        Some(v) => series(Some(&vhost_path(config, v)), &VHOST_CHANNELS, owners(config).get(v).map_or("", String::as_str), level, at),
    };
    let mut known: Vec<String> = ring_files(&dir(config).join("vhosts")).iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(String::from)).filter(|n| valid_domain(n)).collect();
    known.sort();
    out.insert("observed_at".into(), json!(at));
    out.insert("source".into(), json!(dir(config).display().to_string()));
    out.insert("scope".into(), json!(if vhost.is_some() { "vhost" } else { "server" }));
    out.insert("vhost".into(), json!(vhost));
    out.insert("interval".into(), json!(SAMPLE_INTERVAL));
    out.insert("vhosts".into(), json!(known));
    Ok(Value::Object(out))
}

/// The vhosts an account owns: the vhosts serving its domains, from /etc/userdatadomains.
pub fn own_vhosts(config: &Config, user: &str) -> Vec<String> {
    let (rows, _) = super::domain_rows(&config.userdatadomains);
    let mut names: Vec<String> = rows.iter().filter(|r| r["user"] == json!(user)).map(|r| summary::vhost_of(r).to_string()).collect();
    names.sort();
    names.dedup();
    names
}

/// `tenant.metrics`: the history of one of the caller's own vhosts (default the first by name).
pub fn tenant_history(config: &Config, user: &str, args: Value) -> Reply {
    let (level, vhost) = parse(args)?;
    let mine = own_vhosts(config, user);
    let chosen = match vhost {
        // A vhost of another account answers like one that does not exist.
        Some(v) if !mine.contains(&v) => return Err(("NOT_FOUND", "no such site".into())),
        Some(v) => Some(v),
        None => mine.first().cloned(),
    };
    let at = now();
    let mut out = match &chosen {
        Some(v) => series(Some(&vhost_path(config, v)), &VHOST_CHANNELS, user, level, at),
        None => series(None, &VHOST_CHANNELS, user, level, at),
    };
    out.insert("user".into(), json!(user));
    out.insert("observed_at".into(), json!(at));
    out.insert("source".into(), json!("OpenLiteSpeed real-time reports"));
    out.insert("vhost".into(), json!(chosen));
    out.insert("interval".into(), json!(SAMPLE_INTERVAL));
    out.insert("vhosts".into(), json!(mine));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::summary::tests::fixture;

    fn report(a_rps: u32, b_rps: u32, kib_out: u32) -> String {
        let req = |name: &str, rps: u32, hits: u32| format!(
            "REQ_RATE [{name}]: REQ_PROCESSING: 1, REQ_PER_SEC: {rps}, TOT_REQS: 50, PUB_CACHE_HITS_PER_SEC: {hits}, TOTAL_PUB_CACHE_HITS: 0, \
PRIVATE_CACHE_HITS_PER_SEC: 0, TOTAL_PRIVATE_CACHE_HITS: 0, STATIC_HITS_PER_SEC: {}, TOTAL_STATIC_HITS: 9\n", if rps + hits > 0 { 2 } else { 0 });
        format!("VERSION: LiteSpeed Web Server/Open/1.9.3\nUPTIME: 00:10:00\n\
BPS_IN: 10, BPS_OUT: {kib_out}, SSL_BPS_IN: 1, SSL_BPS_OUT: 0\n\
MAXCONN: 10000, MAXSSL_CONN: 10000, PLAINCONN: 4, AVAILCONN: 9996, IDLECONN: 1, SSLCONN: 6, AVAILSSL: 9994\n{}{}{}{}\
EXTAPP [LSAPI] [a.test] [lsphp]: CMAXCONN: 10, EMAXCONN: 10, POOL_SIZE: 2, INUSE_CONN: 3, IDLE_CONN: 0, WAITQUE_DEPTH: 0, REQ_PER_SEC: 1, TOT_REQS: 4\n\
BLOCKED_IP: \nEOF\n", req("", a_rps + b_rps, 1), req("a.test", a_rps, 1), req("b.test", b_rps, 0), req("idle.test", 0, 0))
    }

    /// The report file as OLS writes it, last modified at `at` (the time the sampler is told).
    fn put_report(config: &Config, text: &str, at: u64) {
        fs::create_dir_all(&config.rtreport_dir).unwrap();
        let path = config.rtreport_dir.join(".rtreport");
        fs::write(&path, text).unwrap();
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at)).unwrap();
    }

    fn column<'a>(reply: &'a Value, channel: &str) -> &'a Vec<Value> {
        reply["channels"][channel].as_array().unwrap()
    }

    #[test]
    fn sizes_are_fixed_and_stated() {
        assert_eq!(ring_size(SERVER_CHANNELS.len()), HEADER + 2808 * 40);
        assert_eq!(ring_size(VHOST_CHANNELS.len()), HEADER + 2808 * 24);
        assert_eq!(ring_size(SERVER_CHANNELS.len()), 112_368);
        assert_eq!(ring_size(VHOST_CHANNELS.len()), 67_440);
        assert!(disk_bound() < 68 * 1_000_000);
    }

    #[test]
    fn samples_match_the_live_report_and_rings_stay_bounded() {
        let f = fixture();
        let at = 1_800_000_000 / 600 * 600; // a bucket boundary of every level
        put_report(&f.config, &report(7, 5, 200), at);
        let live = crate::panel::metrics::metrics(&f.config.rtreport_dir, at);
        let round = sample(&f.config, at).unwrap();
        // The idle vhost has no ring; the two busy ones do.
        assert_eq!(round, Round { sampled: true, vhosts: 2, skipped: 0 });
        assert_eq!(ring_files(&dir(&f.config).join("vhosts")).len(), 2);
        let sz = |p: PathBuf| fs::metadata(p).unwrap().len() as usize;
        assert_eq!(sz(server_path(&f.config)), ring_size(8));
        assert_eq!(sz(vhost_path(&f.config, "a.test")), ring_size(4));
        assert_eq!(fs::metadata(server_path(&f.config)).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(dir(&f.config)).unwrap().mode() & 0o777, 0o700);

        let (level, _) = parse(json!({"resolution": "hour"})).unwrap();
        let data = series(Some(&server_path(&f.config)), &SERVER_CHANNELS, "", level, at);
        let last = |c: &str| data["channels"][c][359].clone();
        for channel in &SERVER_CHANNELS[..7] {
            assert_eq!(last(channel), live["server"][channel], "{channel}");
        }
        assert_eq!(last("php_in_use"), live["server"]["extapp"]["in_use"]);
        assert_eq!(last("requests_per_second"), json!(12));
        assert_eq!(last("bytes_out_per_second"), json!(200 * 1024));
        let a = series(Some(&vhost_path(&f.config, "a.test")), &VHOST_CHANNELS, "olscpa", level, at);
        assert_eq!(a["channels"]["requests_per_second"][359], json!(7));
        assert_eq!(a["channels"]["php_in_use"][359], json!(3));
        assert_eq!(a["channels"]["requests_per_second"][358], Value::Null);
        assert_eq!(a["samples"], json!(1));

        // Many rounds over more than a week: the size never changes, the coarser levels average.
        // The first rounds go through the whole sampler, the rest straight into the rings (the same `record`).
        let server = open(&server_path(&f.config), 8, "", false).unwrap().unwrap();
        let ring = open(&vhost_path(&f.config, "a.test"), 4, "olscpa", false).unwrap().unwrap();
        for i in 1..=(8 * 86400 / 10u64) {
            let t = at + i * 10;
            if i <= 30 {
                put_report(&f.config, &report((i % 20) as u32, 1, 100), t);
                sample(&f.config, t).unwrap();
            } else {
                record(&server, &[1.0; 8], t).unwrap();
                record(&ring, &[(i % 20) as f32, 1.0, 2.0, 3.0], t).unwrap();
            }
            if i % 20_000 == 0 {
                assert_eq!(sz(server_path(&f.config)), ring_size(8));
            }
        }
        assert_eq!(sz(server_path(&f.config)), ring_size(8));
        assert_eq!(sz(vhost_path(&f.config, "a.test")), ring_size(4));
        let end = at + 8 * 86400;
        let week = series(Some(&vhost_path(&f.config, "a.test")), &VHOST_CHANNELS, "olscpa", 2, end);
        assert_eq!(week["samples"], json!(1008));
        // Every 10-minute bucket holds 60 samples of i % 20 (i = 1..): mean 9.5.
        assert_eq!(week["channels"]["requests_per_second"][500], json!(9.5));
        let day = series(Some(&vhost_path(&f.config, "a.test")), &VHOST_CHANNELS, "olscpa", 1, end);
        assert_eq!(day["samples"], json!(1440));
        // Unreadable data (a stale report leaves a gap).
        put_report(&f.config, "garbage", end + 10);
        assert_eq!(sample(&f.config, end + 10).unwrap(), Round::default());
    }

    #[test]
    fn gaps_and_unusable_reports() {
        let f = fixture();
        assert_eq!(sample(&f.config, 1_800_000_000).unwrap(), Round::default());
        assert!(!dir(&f.config).exists());
        let reply = admin_history(&f.config, json!({"resolution": "day"})).unwrap();
        assert_eq!(reply["samples"], json!(0));
        assert_eq!(reply["count"], json!(1440));
        assert!(column(&reply, "requests_per_second").iter().all(|v| v.is_null()));
        assert_eq!(reply["scope"], json!("server"));
    }

    #[test]
    fn ring_cap_and_pruning() {
        let f = fixture();
        let at = 1_800_000_000;
        put_report(&f.config, &report(3, 4, 1), at);
        sample(&f.config, at).unwrap();
        let vhosts = dir(&f.config).join("vhosts");
        // Fill up to the cap with other names: the busy vhost b.test (new) is refused, a.test keeps writing.
        fs::remove_file(vhost_path(&f.config, "b.test")).unwrap();
        for i in 0..MAX_VHOST_RINGS - 1 {
            fs::write(vhosts.join(format!("x{i}.test.ring")), "").unwrap();
        }
        put_report(&f.config, &report(3, 4, 1), at + 10);
        let round = sample(&f.config, at + 10).unwrap();
        assert_eq!(round, Round { sampled: true, vhosts: 1, skipped: 1 });
        assert!(!vhost_path(&f.config, "b.test").exists());
        // Old rings and foreign files are pruned; a recent ring stays.
        fs::write(vhosts.join("note.txt"), "x").unwrap();
        let removed = prune(&f.config, now() + PRUNE_AFTER + 10);
        assert!(removed >= MAX_VHOST_RINGS && !vhost_path(&f.config, "a.test").exists());
        let removed_recent = prune(&f.config, now());
        assert_eq!(removed_recent, 0);
    }

    #[test]
    fn a_damaged_ring_starts_again_and_links_are_not_followed() {
        let f = fixture();
        let at = 1_800_000_000;
        put_report(&f.config, &report(3, 4, 1), at);
        sample(&f.config, at).unwrap();
        let path = vhost_path(&f.config, "a.test");
        fs::write(&path, "short").unwrap();
        put_report(&f.config, &report(3, 4, 1), at + 10);
        sample(&f.config, at + 10).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len() as usize, ring_size(4));
        let target = f.temp.path().join("elsewhere");
        fs::write(&target, "keep").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        put_report(&f.config, &report(3, 4, 1), at + 20);
        assert!(sample(&f.config, at + 20).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn a_ring_is_restarted_when_the_vhost_changes_owner() {
        let f = fixture();
        let at = now() / 600 * 600;
        put_report(&f.config, &report(7, 5, 200), at);
        sample(&f.config, at).unwrap();
        assert!(tenant_history(&f.config, "olscpa", json!({"vhost": "a.test"})).unwrap()["samples"].as_u64().unwrap() >= 1);
        // a.test moves to olscpb: the new owner starts with nothing, the old one no longer sees it.
        let moved: String = fs::read_to_string(&f.config.userdatadomains).unwrap().lines()
            .map(|l| if l.starts_with("a.test: ") || l.starts_with("parked.test: ") { l.replace("olscpa==", "olscpb==") } else { l.to_string() } + "\n").collect();
        assert_ne!(moved, fs::read_to_string(&f.config.userdatadomains).unwrap());
        fs::write(&f.config.userdatadomains, moved).unwrap();
        let b = tenant_history(&f.config, "olscpb", json!({"vhost": "a.test"})).unwrap();
        assert_eq!(b["samples"], json!(0));
        assert!(tenant_history(&f.config, "olscpa", json!({"vhost": "a.test"})).is_err());
        // The sampler starts the ring under the new owner and the old history is gone.
        put_report(&f.config, &report(1, 5, 200), at + 10);
        sample(&f.config, at + 10).unwrap();
        let b = tenant_history(&f.config, "olscpb", json!({"vhost": "a.test"})).unwrap();
        assert_eq!(b["samples"], json!(1));
        let head = fs::read(vhost_path(&f.config, "a.test")).unwrap();
        assert_eq!(&head[..HEADER], &header(4, "olscpb"));
        // A version 1 file (16 byte header layout) is not accepted.
        fs::write(vhost_path(&f.config, "a.test"), vec![0u8; ring_size(4)]).unwrap();
        assert_eq!(tenant_history(&f.config, "olscpb", json!({"vhost": "a.test"})).unwrap()["samples"], json!(0));
    }

    #[test]
    fn arguments_are_validated() {
        for bad in [json!({"resolution": "year"}), json!({"resolution": 5}), json!({"vhost": "../x"}), json!({"vhost": "a/b.test"}),
                    json!({"vhost": "A.test"}), json!({"x": 1}), json!([1])] {
            assert_eq!(parse(bad.clone()).err().map(|e| e.0), Some("BAD_ARGS"), "{bad}");
        }
        assert_eq!(parse(json!({})).unwrap(), (0, None));
        assert_eq!(parse(json!({"resolution": "week", "vhost": "a.test"})).unwrap(), (2, Some("a.test".into())));
    }

    #[test]
    fn a_tenant_sees_only_its_own_vhosts() {
        let f = fixture();
        let at = now() / 600 * 600;
        put_report(&f.config, &report(7, 5, 200), at);
        sample(&f.config, at).unwrap();
        // Server data and another account's vhost are not reachable through the tenant view.
        let a = tenant_history(&f.config, "olscpa", json!({"resolution": "hour", "vhost": "a.test"})).unwrap();
        assert_eq!(a["user"], json!("olscpa"));
        assert_eq!(a["vhost"], json!("a.test"));
        assert_eq!(a["vhosts"], json!(["a.test", "addon.a.test", "shop.a.test"]));
        assert!(a["channels"].get("bytes_out_per_second").is_none() && a["channels"].get("connections").is_none());
        assert!(a["samples"].as_u64().unwrap() >= 1);
        for other in ["b.test", "new.b.test", "idle.test", "nope.test"] {
            assert_eq!(tenant_history(&f.config, "olscpa", json!({"vhost": other})).err().map(|e| e.0), Some("NOT_FOUND"), "{other}");
        }
        let b = tenant_history(&f.config, "olscpb", json!({})).unwrap();
        assert_eq!(b["vhost"], json!("b.test"));
        assert_eq!(b["vhosts"], json!(["b.test", "new.b.test"]));
        assert!(!b.to_string().contains("a.test"));
        let none = tenant_history(&f.config, "nobody", json!({})).unwrap();
        assert_eq!((none["vhost"].clone(), none["samples"].clone()), (Value::Null, json!(0)));
        assert_eq!(tenant_history(&f.config, "olscpa", json!({"resolution": "bad"})).err().map(|e| e.0), Some("BAD_ARGS"));
        // The admin view reads the server and any vhost.
        let server = admin_history(&f.config, json!({})).unwrap();
        assert_eq!(server["vhosts"], json!(["a.test", "b.test"]));
        assert!(server["channels"].get("bytes_out_per_second").is_some());
        let b = admin_history(&f.config, json!({"vhost": "b.test", "resolution": "week"})).unwrap();
        assert_eq!((b["scope"].clone(), b["step"].clone(), b["count"].clone()), (json!("vhost"), json!(600), json!(1008)));
    }
}
