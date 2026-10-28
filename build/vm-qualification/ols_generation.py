#!/usr/bin/python3 -I
"""Generation activation prototype for G0-G (plan section 17), run as root by ols_generation_probe.py.
Immutable generations live in GEN_ROOT/<id>/ and reference only their own absolute paths; one
pointer (ACTIVE, a symlink replaced by rename) selects the live one, and OLS's fixed main config is
a stable symlink to ACTIVE/httpd_config.conf. Every activation writes a durable journal:
intent -> switched -> reloaded -> committed | rolled_back | aborted. Each generation contains a
loopback-only marker vhost serving its own ID, so verification checks what OLS actually serves.
`recover` brings any interrupted transaction to a coherent state: pointer == served generation ==
the last committed (or newly verified) generation.
Activation requires a passing validation record of exactly this generation (tree digest) and this OLS
binary, and a generation commits only when the marker AND every vhost listed in its health.json
answer from this generation (review RV-02: OLS skips a failing vhost and keeps serving the others).
Restriction epoch (plan 14.4, review RV-05): every security-sensitive cPanel change (suspension,
removal, revoked privilege) raises a durable epoch; each generation records the epoch it was compiled
against (file EPOCH). No activation, rollback or recovery ever selects a generation from an older
epoch, so a rollback cannot revive a suspended or removed account.
Lab prototype, not the product broker.

Commands: stage <id> <src-dir> | validate <id> | activate <id> [--crash-after STEP] | recover | status
          | restrict <reason> | health [--seconds N]"""
import fcntl
import hashlib
import http.client
import json
import math
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

STATE = "/var/lib/ols-cpanel"
GEN_ROOT = STATE + "/generations"
JOURNAL = STATE + "/journal"
VALIDATIONS = STATE + "/validations"
EPOCH = STATE + "/epoch.json"
# Independent high-water mark of the restriction epoch: losing epoch.json must not lose a restriction.
EPOCH_HIGH = STATE + "/epoch.high"
BINARY = "/usr/local/lsws/bin/openlitespeed"
ACTIVE = STATE + "/active"
LOCK = STATE + "/activation.lock"
MAIN_CONFIG = "/usr/local/lsws/conf/httpd_config.conf"
MARKER_URL = "http://127.0.0.1:8097/generation"
VALIDATOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ols_stage_validate.py")
CRASH_POINTS = ("intent", "switched", "reloaded")
# The hook's durable restriction intents (ols_events.record_intent): each is a restriction no generation has
# applied until it is folded into the epoch (docs/product-interfaces.md, "Restriction intents").
RESTRICTIONS = STATE + "/restrictions"
INTENT_NAME = re.compile(r"[0-9]{1,24}-[0-9a-f]{32}\.json")

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_durable(path, text):
    tmp = f"{path}.tmp-{uuid.uuid4().hex}"
    with open(tmp, "w") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.rename(tmp, path)
    fsync_dir(os.path.dirname(path))

def next_seq():
    """Monotonic transaction order (never wall-clock time: review F-17..F-20); called under LOCK."""
    seqs = [0]
    for name in os.listdir(JOURNAL):
        if name.endswith(".json"):
            with open(f"{JOURNAL}/{name}") as handle:
                seqs.append(json.load(handle).get("seq", 0))
    return max(seqs) + 1

def journal(tx, **fields):
    path = f"{JOURNAL}/{tx['id']}.json"
    tx.update(fields, updated=time.time())
    tx.setdefault("history", []).append(fields.get("state"))
    write_durable(path, json.dumps(tx, sort_keys=True))

def pointer():
    try:
        return os.path.basename(os.readlink(ACTIVE))
    except OSError:
        return None

def served(timeout=1.0):
    try:
        with urllib.request.urlopen(MARKER_URL, timeout=timeout) as response:
            return response.read().decode().strip()
    except OSError:
        return None

def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

def tree_sha256(gen):
    """Digest of every file and symlink in the generation, by relative path."""
    base = f"{GEN_ROOT}/{gen}"
    digest = hashlib.sha256()
    for root, dirs, files in sorted(os.walk(base)):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, base)
            value = "link:" + os.readlink(path) if os.path.islink(path) else file_sha256(path)
            digest.update(f"{rel}\0{value}\n".encode())
    return digest.hexdigest()

class EpochError(Exception):
    """The restriction epoch record is damaged; nothing may be treated as current (fail closed)."""

def _generations_with_epoch():
    try:
        names = os.listdir(GEN_ROOT)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise EpochError(f"generations unreadable: {exc}")
    return [g for g in names if generation_epoch(g) != 0]  # unknown (-1) counts: fail closed

def current_epoch():
    """The restriction epoch. A missing record means epoch 0 only on a fresh installation; a damaged
    record, or a missing one while generations of a later epoch exist, raises EpochError (never reset)."""
    try:
        with open(EPOCH) as handle:
            value = json.load(handle)["epoch"]
    except FileNotFoundError:
        if os.path.exists(EPOCH_HIGH) or _generations_with_epoch():
            raise EpochError("epoch record missing although a restriction was recorded")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise EpochError(f"epoch record unreadable: {exc}")
    if type(value) is not int or value < 0:
        raise EpochError("epoch record malformed")
    try:
        with open(EPOCH_HIGH) as handle:
            high = int(handle.read().strip())
    except FileNotFoundError:
        high = 0
    except (OSError, ValueError) as exc:
        raise EpochError(f"epoch high-water mark unreadable: {exc}")
    if high > value:
        raise EpochError("epoch record older than its high-water mark")
    return value

def generation_epoch(gen):
    try:
        with open(f"{GEN_ROOT}/{gen}/EPOCH") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return -1  # unknown: never newer than any recorded epoch

def pending_intents():
    """The restriction intents not yet folded into the epoch, oldest first: [(name, time)], `time` the intent's own
    unless unusable or later than the file's modification time (then that time). Raises EpochError when the
    directory cannot be read (fail closed)."""
    try:
        names = sorted((n for n in os.listdir(RESTRICTIONS) if INTENT_NAME.fullmatch(n)), key=lambda n: (len(n), n))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise EpochError(f"restriction intents unreadable: {exc}")
    out = []
    for name in names:
        path = f"{RESTRICTIONS}/{name}"
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue  # folded meanwhile
        when = None
        try:
            if not os.path.islink(path) and os.path.isfile(path) and info.st_size <= 65536:
                with open(path, "rb") as handle:
                    intent = json.loads(handle.read(65537))
                value = intent.get("time") if isinstance(intent, dict) else None
                when = float(value) if type(value) in (int, float) and math.isfinite(value) else None
        except (OSError, ValueError):
            when = None
        out.append((name, when if when is not None and when <= info.st_mtime else info.st_mtime))
    return out

def stale(gen):
    if gen is None:
        return False
    try:
        if pending_intents():
            return True  # an unfolded intent is a restriction no generation has applied
    except EpochError:
        return True
    try:
        return generation_epoch(gen) < current_epoch()
    except EpochError:
        return True  # unknown restrictions: nothing is current

def restrict(reason):
    """Raise the restriction epoch durably before a security-sensitive change is acknowledged."""
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        epoch = current_epoch()  # raises on a damaged record: never restart the counter
        try:
            with open(EPOCH) as handle:
                record = json.load(handle)
        except FileNotFoundError:
            record = {"epoch": 0, "history": []}
        record["epoch"] = epoch + 1
        record["history"].append({"epoch": record["epoch"], "reason": reason[:200], "time": time.time()})
        write_durable(EPOCH_HIGH, f"{record['epoch']}\n")  # first: a lost epoch.json can never read as older
        write_durable(EPOCH, json.dumps(record, sort_keys=True))
        return {"epoch": record["epoch"], "reason": reason[:200]}

def health_targets(gen):
    """Vhosts the generation must serve: [{"vhost", "host", "url"}]; the body must be "<gen> <vhost>"."""
    try:
        with open(f"{GEN_ROOT}/{gen}/health.json") as handle:
            targets = json.load(handle)
    except (OSError, ValueError):
        return None
    return targets if isinstance(targets, list) and targets else None

class _SniConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed address with a chosen SNI name; the certificate is not verified (a health check proves
    which generation answers, not who the server is: it connects to the local server's own address)."""

    def __init__(self, address, port, sni, timeout):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(address, port, timeout=timeout, context=context)
        self._sni = sni

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._sni)

def health_body(target, timeout=2):
    """The body a health target answers, or "error: ..." (review RV-29, finding 12: `url` is
    http://<IPv4>:<port>/... or https://<IPv4>:443/..., where `host` is the Host header and, over TLS, the SNI)."""
    url = target["url"]
    try:
        if url.startswith("https://"):
            authority, _, path = url[len("https://"):].partition("/")
            address, _, port = authority.rpartition(":")
            connection = _SniConnection(address, int(port), target["host"], timeout)
            try:
                connection.request("GET", "/" + path, headers={"Host": target["host"]})
                response = connection.getresponse()
                if response.status != 200:
                    return f"error: HTTP {response.status}"
                return response.read(4096).decode(errors="replace").strip()
            finally:
                connection.close()
        request = urllib.request.Request(url, headers={"Host": target["host"]})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode(errors="replace").strip()
    except urllib.error.HTTPError as exc:
        return f"error: HTTP {exc.code}"
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return f"error: {type(exc).__name__}"

def vhost_health(gen, targets, seconds=20):
    """Every listed vhost answers its health path with this generation's ID; returns the failures."""
    deadline = time.monotonic() + seconds
    failing = targets
    while True:
        failing = []
        for target in targets:
            body = health_body(target)
            if body != f"{gen} {target['vhost']}":
                failing.append({"vhost": target["vhost"], "got": body[:120]})
        if not failing or time.monotonic() > deadline:
            return failing
        time.sleep(0.5)

def switch(gen):
    tmp = f"{STATE}/active.new-{uuid.uuid4().hex}"
    os.symlink(f"{GEN_ROOT}/{gen}", tmp)
    os.rename(tmp, ACTIVE)  # atomic replacement of the single pointer
    fsync_dir(STATE)

def running():
    return subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "ols-cpanel.service"]).returncode == 0

def reload():
    """Graceful restart (SIGUSR1 through lswsctrl) when running, start otherwise; never of a stale generation (a
    transaction that finds OLS stopped by enforcement does not bring back what a restriction removed)."""
    if stale(pointer() or None):
        return 1
    if running():
        return subprocess.run(["/usr/bin/systemctl", "reload", "ols-cpanel.service"], capture_output=True).returncode
    return subprocess.run(["/usr/bin/systemctl", "start", "ols-cpanel.service"], capture_output=True).returncode

def wait_for(gen, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if served() == gen:
            return True
        time.sleep(0.25)
    return False

def transactions():
    """All journal records in transaction order."""
    records = []
    for name in os.listdir(JOURNAL):
        if name.endswith(".json"):
            with open(f"{JOURNAL}/{name}") as handle:
                records.append(json.load(handle))
    return sorted(records, key=lambda tx: (tx.get("seq", 0), tx.get("started", 0)))

def committed():
    """The generation of the last committed transaction."""
    done = [tx for tx in transactions() if tx.get("state") == "committed"]
    return done[-1]["new"] if done else None

def stage(gen, src):
    target = f"{GEN_ROOT}/{gen}"
    if os.path.exists(target):
        raise SystemExit(f"generation {gen} exists (generations are immutable)")
    tmp = f"{GEN_ROOT}/.staging-{gen}"
    shutil.copytree(src, tmp)
    digests = {}
    for root, dirs, files in os.walk(tmp):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as handle:
                digests[os.path.relpath(path, tmp)] = hashlib.sha256(handle.read()).hexdigest()
                os.fsync(handle.fileno())
            os.chmod(path, 0o444)  # OLS workers (nobody) read the marker; no secrets live here
        for name in dirs:
            os.chmod(os.path.join(root, name), 0o755)
        fsync_dir(root)
    with open(f"{tmp}/MANIFEST.json", "w") as handle:
        json.dump({"generation": gen, "files": digests}, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o755)
    os.rename(tmp, target)
    fsync_dir(GEN_ROOT)
    return {"generation": gen, "files": len(digests)}

def validate(gen):
    """Validate the staged tree and record the verdict for exactly this tree and binary."""
    tree = tree_sha256(gen)
    result = subprocess.run([sys.executable, "-I", VALIDATOR, f"{GEN_ROOT}/{gen}"], capture_output=True, text=True)
    record = {"generation": gen, "valid": result.returncode == 0 and tree_sha256(gen) == tree,
              "exit_code": result.returncode, "tree_sha256": tree, "binary_sha256": file_sha256(BINARY),
              "validator_sha256": file_sha256(VALIDATOR), "health_targets": len(health_targets(gen) or []),
              "time": time.time()}
    write_durable(f"{VALIDATIONS}/{gen}.json", json.dumps(record, sort_keys=True))
    out = {**record, "report": result.stdout[-2000:], "stderr": result.stderr[-1000:]}
    # The findings come before the output tail, so the report's tail alone loses the cause: carried whole.
    try:
        report = json.loads(result.stdout)
    except ValueError:
        report = None
    if isinstance(report, dict) and isinstance(report.get("findings"), list):
        out["findings"] = report["findings"]
    return out

def validation_problem(gen):
    """Why this generation may not be activated, or None (review RV-02)."""
    try:
        with open(f"{VALIDATIONS}/{gen}.json") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        return "not validated"
    if not record.get("valid"):
        return "validation failed"
    if record.get("tree_sha256") != tree_sha256(gen):
        return "generation changed after validation"
    if record.get("binary_sha256") != file_sha256(BINARY):
        return "OLS binary changed after validation"
    if not health_targets(gen):
        return "no vhost health targets"
    if stale(gen):
        try:
            intents = pending_intents()
        except EpochError as exc:
            return str(exc)
        if intents:
            return f"restriction intent {intents[0][0]} not yet folded into the epoch"
        return f"generation epoch {generation_epoch(gen)} predates restriction epoch {_epoch_or_none()}"
    return None

def activate(gen, crash_after=None):
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _recover_locked()  # never start a transaction over an interrupted one (review finding 8)
        problem = validation_problem(gen)
        if problem:
            return {"result": "refused", "generation": gen, "reason": problem}
        previous = pointer()
        tx = {"id": uuid.uuid4().hex, "seq": next_seq(), "new": gen, "previous": previous, "started": time.time()}
        journal(tx, state="intent")
        if crash_after == "intent":
            os._exit(9)
        switch(gen)
        journal(tx, state="switched")
        if crash_after == "switched":
            os._exit(9)
        code = reload()
        journal(tx, state="reloaded", reload_exit=code)
        if crash_after == "reloaded":
            os._exit(9)
        if wait_for(gen):
            failing = vhost_health(gen, health_targets(gen))
            if not failing:
                journal(tx, state="committed")
                return {"tx": tx["id"], "result": "committed", "generation": gen}
            journal(tx, state="unhealthy", failing=failing)
            return {"tx": tx["id"], "failing": failing, **rollback(tx)}
        return {"tx": tx["id"], **rollback(tx)}

def fresh_target(tx):
    """The rollback target: the previous generation, else the newest committed one, never one from an
    older restriction epoch and never the failing generation itself."""
    candidates = [tx.get("previous")] + [t["new"] for t in reversed(transactions()) if t.get("state") == "committed"]
    # Validation binding (same tree and OLS binary) and the current epoch are both required (review 2, item 4).
    return next((g for g in candidates if g and g != tx["new"] and not validation_problem(g)), None)

def rollback(tx):
    target = fresh_target(tx)
    if not target and not (tx.get("previous") or committed()):
        journal(tx, state="failed_no_previous")
        return {"result": "failed_no_previous"}
    if not target:
        if not validation_problem(tx["new"]) and served() == tx["new"]:
            # Older generations would revive privileges a newer restriction removed: keep the new one
            # (compiled with the current restrictions, and actually serving) and alert.
            journal(tx, state="rollback_refused_stale", epoch=_epoch_or_none())
            return {"result": "rollback_refused_stale", "generation": tx["new"]}
        # Nothing current is serving (e.g. the reload failed and the old process lives on): stop serving
        # rather than serve stale rights, and verify the stop (review finding 3).
        stopped = stop_serving()
        journal(tx, state="stopped_no_fresh_generation", epoch=_epoch_or_none(), stopped=stopped)
        return {"result": "stopped_no_fresh_generation", "stopped": stopped}
    switch(target)
    reload()
    ok = wait_for(target) and not vhost_health(target, health_targets(target))
    if not ok:
        stopped = stop_serving()  # neither the new nor the previous generation serves correctly
        journal(tx, state="rollback_failed", restored=target, stopped=stopped)
        return {"result": "rollback_failed", "generation": target, "stopped": stopped}
    journal(tx, state="rolled_back", restored=target)
    return {"result": "rolled_back", "generation": target}

FINAL = ("committed", "rolled_back", "aborted", "rollback_failed", "failed_no_previous", "rollback_refused_stale",
         "stopped_no_fresh_generation", "superseded")

def _epoch_or_none():
    try:
        return current_epoch()
    except EpochError:
        return None

def ols_running():
    """Any OLS main or worker process, whatever the marker says."""
    return subprocess.run(["/usr/bin/pgrep", "-f", "^openlitespeed \\(lshttpd"], capture_output=True).returncode == 0 \
        or running()

def stop_serving():
    """Stop OLS and confirm that no OLS process is left (an unreachable marker proves nothing)."""
    subprocess.run(["/usr/bin/systemctl", "stop", "ols-cpanel.service"], capture_output=True)
    for _ in range(40):
        if not ols_running():
            return True
        time.sleep(0.5)
    subprocess.run(["/usr/bin/pkill", "-KILL", "-f", "^openlitespeed \\(lshttpd"], capture_output=True)
    time.sleep(1)
    return not ols_running()

def first_unapplied_restriction(epoch):
    """Time of the earliest restriction newer than `epoch` (what a generation of that epoch still lacks),
    or None when unknown; later restrictions never move this deadline (review 2, item 7). Unfolded restriction
    intents count from their time."""
    try:
        times = [when for _, when in pending_intents()]
    except EpochError:
        return None
    try:
        with open(EPOCH) as handle:
            history = json.load(handle).get("history") or []
    except FileNotFoundError:
        history = []  # a fresh installation: nothing recorded in the epoch yet
    except (OSError, ValueError, AttributeError):
        return None
    try:
        times += [float(h["time"]) for h in history if type(h.get("epoch")) is int and h["epoch"] > epoch]
        return min(times) if times else None
    except (ValueError, KeyError, TypeError, AttributeError):
        return None

def enforce(grace=0):
    """Under LOCK: never keep serving a generation older than the restriction epoch for longer than `grace`
    seconds after the earliest restriction it lacks (HR-D11: 300 s); used by recovery (grace 0) and by the
    reconciler's independent enforcement thread. An unknown runtime (OLS running, marker silent) or an
    unknown epoch gets no grace (review findings 3 and 4, review 2 items 1, 2, 7, 9)."""
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # activation holds it only for bounded operations
        return _enforce_locked(grace)

def _enforce_locked(grace=0):
    if not ols_running():
        return None
    live = served()
    unknown_epoch = _epoch_or_none() is None
    if live is None:
        # Running but the marker does not answer: what serves is unknown. Only a current pointer is trusted.
        current = pointer()
        if current and not stale(current):
            return None
        live_epoch = generation_epoch(current) if current else -1
    elif not stale(live):
        return None
    else:
        live_epoch = generation_epoch(live)
    since = None if unknown_epoch else first_unapplied_restriction(live_epoch)
    if grace and since is not None and time.time() - since < grace:
        return "within-grace"
    current = pointer()
    if current and current != live and not stale(current) and not validation_problem(current):
        reload()
        if wait_for(current) and not vhost_health(current, health_targets(current) or []):
            return "reloaded-current"
    return "stopped" if stop_serving() else "stop-failed"

def recover(grace=0):
    """Finish or undo every interrupted transaction, then enforce the restriction epoch (with `grace`
    seconds since the earliest unapplied restriction: 0 for boot/operator recovery, HR-D11's 300 s when the
    reconciler is about to activate a replacement, so one suspension does not stop every site first)."""
    actions = []
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            actions = _recover_locked()
        except EpochError as exc:
            actions.append({"action": "recover", "error": str(exc)})
        finally:
            enforced = _enforce_locked(grace)
            if enforced:
                actions.append({"action": "enforce", "result": enforced})
    return {"actions": actions, **status()}

def _recover_locked():
    """Recovery body; the caller holds LOCK."""
    actions = []
    history = transactions()
    for position, tx in enumerate(history):
        state = tx.get("state")
        if state in FINAL:
            continue
        if any(later.get("state") == "committed" for later in history[position + 1:]):
            # A later activation committed after this one was interrupted: it owns the pointer now.
            journal(tx, state="superseded")
            actions.append({"tx": tx["id"], "action": "superseded"})
            continue
        if stale(tx["new"]) and pointer() == tx["new"]:
            # Interrupted activation of a generation a newer restriction made stale: undo it.
            result = rollback(tx)
            actions.append({"tx": tx["id"], "action": result["result"]})
            continue
        if state == "intent" and pointer() != tx["new"]:
            journal(tx, state="aborted")  # the pointer never moved: nothing to undo
            actions.append({"tx": tx["id"], "action": "aborted"})
            continue
        # The pointer moved to a staged generation: complete forward only if its validation still binds
        # (same tree and OLS binary, review finding 9) and it serves; otherwise roll back.
        if validation_problem(tx["new"]):
            result = rollback(tx)
            actions.append({"tx": tx["id"], "action": result["result"], "reason": "validation no longer binds"})
            continue
        if served() != tx["new"]:
            reload()
        targets = health_targets(tx["new"])
        if wait_for(tx["new"]) and targets and not vhost_health(tx["new"], targets):
            journal(tx, state="committed", recovered=True)
            actions.append({"tx": tx["id"], "action": "completed"})
        else:
            result = rollback(tx)
            actions.append({"tx": tx["id"], "action": result["result"]})
    # Coherence: what the pointer selects is what OLS serves, but never by (re)starting a generation
    # that a newer restriction made stale: that stays stopped until a current one is activated.
    current = pointer()
    if current and not stale(current) and served() != current and not validation_problem(current):
        reload()
        wait_for(current)
    return actions

def status():
    current, live = pointer(), served()
    epoch, active_epoch = _epoch_or_none(), generation_epoch(current) if current else None
    return {"pointer": current, "served": live, "committed": committed(), "epoch": epoch,
            "active_epoch": active_epoch,
            "coherent": current is not None and current == live == committed() and epoch is not None
                        and active_epoch >= epoch}

def main():
    os.makedirs(GEN_ROOT, mode=0o755, exist_ok=True)
    os.makedirs(JOURNAL, mode=0o700, exist_ok=True)
    os.makedirs(VALIDATIONS, mode=0o700, exist_ok=True)
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "stage":
        out = stage(sys.argv[2], sys.argv[3])
    elif command == "validate":
        out = validate(sys.argv[2])
    elif command == "activate":
        crash = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--crash-after" else None
        if crash and crash not in CRASH_POINTS:
            raise SystemExit("unknown crash point")
        out = activate(sys.argv[2], crash)
    elif command == "recover":
        out = recover()
    elif command == "status":
        out = status()
    elif command == "health":
        # The active generation's vhost health (what the reconciler checks before keeping it unchanged).
        seconds = int(sys.argv[sys.argv.index("--seconds") + 1]) if "--seconds" in sys.argv else 5
        current = pointer()
        out = {"generation": current, "failing": vhost_health(current, health_targets(current) or [], seconds) if current else []}
    elif command == "restrict":
        out = restrict(" ".join(sys.argv[2:]) or "unspecified")
    else:
        raise SystemExit(__doc__)
    print(json.dumps(out, sort_keys=True))

if __name__ == "__main__":
    main()
