#!/usr/bin/python3 -I
"""cPanel event pipeline prototype (plan sections 14 and 15; G0-F, RV-21, HR-D11, RV-03). Runs as root.

hook       cPanel script hook (JSON on stdin). Durably records the event in the spool; for security events
           (suspension, account or domain removal) it raises the restriction epoch before cPanel's
           operation is acknowledged, so no rollback can serve the old rights; when that fails it leaves a
           durable restriction intent (RESTRICTIONS) that enforcement and reconciliation fold into the
           epoch first (review RV-29, finding 5). Answers exactly "1".
reconcile  Compiles the current cPanel state; when it differs from the active generation (or the active
           one is stale), stages, validates and activates a new generation; marks the events done.
watch      Service loop: reconcile when events are pending, otherwise every --interval seconds (the
           fallback for changes without a hook, e.g. edited .htaccess files, and for HR-D11's 300 s).
Lab prototype on the test listeners, not the product broker."""
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import ols_generation as activator

STATE = activator.STATE
SPOOL = STATE + "/events"
DONE = SPOOL + "/done"
# Restriction intents: one root 0600 JSON file per restriction the hook could not record in the epoch,
# {"event", "reason", "time", "user"}, named like spool entries (docs/product-interfaces.md; PHP HookEntry).
RESTRICTIONS = STATE + "/restrictions"
INTENT_NAME = re.compile(r"[0-9]{1,24}-[0-9a-f]{32}\.json")
LOCK = STATE + "/reconcile.lock"
SOURCE = "SOURCE_SHA256"  # digest of the compiled content and epoch, inside each generation
# Deployment profile written at cutover (root-owned): {"production": bool, "hybrid_ports": [http, https] | null}.
# Without it the lab test listeners are compiled; a malformed profile stops reconciliation (review RV-27, 5).
PROFILE = STATE + "/profile.json"
# Events after which serving the previous configuration would keep rights cPanel just removed.
RESTRICTING = {"Accounts::suspendacct", "Accounts::Remove", "Api2::SubDomain::delsubdomain",
               "Api2::AddonDomain::deladdondomain", "Api2::Park::unpark", "UAPI::SubDomain::delete_subdomain"}

# Verified product registrations (category, event), all at post.
EVENTS = [('Whostmgr', 'Accounts::Create'),
 ('Whostmgr', 'Accounts::Modify'),
 ('Whostmgr', 'Accounts::SiteIP::set'),
 ('PkgAcct', 'Restore'),
 ('Whostmgr', 'Transfers::Session'),
 ('Whostmgr', 'Accounts::Remove'),
 ('Whostmgr', 'Accounts::suspendacct'),
 ('Whostmgr', 'Accounts::unsuspendacct'),
 ('Whostmgr', 'Accounts::change_package'),
 ('Whostmgr', 'Lang::PHP::set_vhost_versions'),
 ('Whostmgr', 'SSL::installssl'),
 ('Whostmgr', 'SSL::delssl'),
 ('Whostmgr', 'AutoSSL::installssl'),
 ('Cpanel', 'UAPI::SubDomain::addsubdomain'),
 ('Cpanel', 'UAPI::SubDomain::delete_subdomain'),
 ('Cpanel', 'Api2::SubDomain::addsubdomain'),
 ('Cpanel', 'Api2::SubDomain::delsubdomain'),
 ('Cpanel', 'Api2::SubDomain::changedocroot'),
 ('Cpanel', 'Api2::AddonDomain::addaddondomain'),
 ('Cpanel', 'Api2::AddonDomain::deladdondomain'),
 ('Cpanel', 'Api2::Park::park'),
 ('Cpanel', 'Api2::Park::unpark'),
 ('Cpanel', 'UAPI::LangPHP::php_set_vhost_versions'),
 ('Cpanel', 'UAPI::LangPHP::php_ini_set_user_basic_directives'),
 ('Cpanel', 'UAPI::DirectoryPrivacy::configure_directory_protection'),
 ('Cpanel', 'UAPI::SSL::install_ssl'),
 ('Cpanel', 'UAPI::SSL::delete_ssl'),
 ('Cpanel', 'UAPI::Mime::add_redirect'),
 ('Cpanel', 'UAPI::Fileman::save_file_content')]
OBJCACHE_EVENTS = ['Accounts::suspendacct',
 'Accounts::unsuspendacct',
 'Accounts::Remove',
 'Accounts::change_package',
 'Accounts::Create',
 'Accounts::Modify',
 'Restore',
 'Transfers::Session']
TRUST_EVENTS = ['Accounts::SiteIP::set', 'Accounts::Modify', 'Restore', 'Transfers::Session']

def write_durable(path, text, mode=None):
    tmp = f"{path}.tmp-{uuid.uuid4().hex}"
    with open(tmp, "x") as handle:
        if mode is not None:
            os.fchmod(handle.fileno(), mode)  # before anything is written
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.rename(tmp, path)
    activator.fsync_dir(os.path.dirname(path))

def hook():
    """Always answers exactly "1" (cPanel treats anything else, even "1\\n", as a failure message)."""
    try:
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            payload = {}
        context = payload.get("context") if isinstance(payload, dict) else None
        if not isinstance(context, dict) or not context:
            return  # registry maintenance runs the script without an event
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        event = {"time": time.time(), "category": context.get("category"), "event": context.get("event"),
                 "stage": context.get("stage"), "user": context.get("user") or data.get("user") or data.get("username")}
        if event["event"] in RESTRICTING:
            reason = f"{event['event']} {event['user']}"[:200]
            try:
                event["epoch"] = activator.restrict(reason)["epoch"]
            except Exception as exc:
                # Never acknowledged without a durable enforcement obligation (review RV-29, finding 5).
                sys.stderr.write(f"ols-cpanel event hook: restriction epoch not raised: {type(exc).__name__}: {exc}\n")
                try:
                    name = record_intent(event, reason)
                    sys.stderr.write(f"ols-cpanel event hook: restriction kept as the durable intent {name}\n")
                except Exception as failure:
                    sys.stderr.write(f"ols-cpanel event hook: restriction intent not recorded: {type(failure).__name__}: {failure}\n")
        old, new = data.get("user"), data.get("newuser")
        valid_user = lambda u: isinstance(u, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,31}", u) and ".." not in u and u != "root"
        if event["category"] == "Whostmgr" and event["event"] == "Accounts::Modify" and valid_user(old) and valid_user(new) and old != new:
            event.update(olduser=old, newuser=new)
            directory = STATE + "/account-renames"
            os.makedirs(directory, mode=0o700, exist_ok=True)
            write_durable(f"{directory}/{time.time_ns()}-{uuid.uuid4().hex}.json", json.dumps({"olduser": old, "newuser": new}), mode=0o600)
        for events, service in [(TRUST_EVENTS, "ols-cpanel-hybrid-trust.service"), (OBJCACHE_EVENTS, "ols-cpanel-objcache.service")]:
            if event["event"] in events:
                try:
                    started = run("hook-trigger", ["/usr/bin/systemctl", "start", "--no-block", service], 20)
                    if started["exit_code"] != 0:
                        sys.stderr.write(f"ols-cpanel event hook: {service} not started; the timer applies it\n")
                except Exception as exc:
                    sys.stderr.write(f"ols-cpanel event hook: service trigger: {type(exc).__name__}: {exc}\n")
        os.makedirs(SPOOL, mode=0o700, exist_ok=True)
        write_durable(f"{SPOOL}/{time.time_ns()}-{uuid.uuid4().hex}.json", json.dumps(event, sort_keys=True))
    except Exception as exc:  # never fail the cPanel operation; the periodic reconcile catches up
        sys.stderr.write(f"ols-cpanel event hook: {type(exc).__name__}: {exc}\n")
    finally:
        sys.stdout.write("1")

def record_intent(event, reason):
    """The durable restriction intent of a restriction the epoch could not record; returns its file name."""
    os.makedirs(RESTRICTIONS, mode=0o700, exist_ok=True)
    name = f"{time.time_ns()}-{uuid.uuid4().hex}.json"
    user = event["user"] if isinstance(event["user"], str) and event["user"] else None
    intent = {"event": event["event"] if isinstance(event["event"], str) else None, "reason": reason, "time": event["time"],
              "user": user}
    write_durable(f"{RESTRICTIONS}/{name}", json.dumps(intent, sort_keys=True), mode=0o600)
    return name

def intent_reason(path, name):
    """The restrict reason of an intent; an unreadable or malformed one is still a restriction (fail closed)."""
    try:
        if os.path.islink(path):
            raise OSError("symbolic link")
        with open(path, "rb") as handle:
            data = handle.read(65537)
        intent = json.loads(data) if len(data) <= 65536 else None
        reason = intent.get("reason") if isinstance(intent, dict) else None
    except (OSError, ValueError):
        reason = None
    # Printable ASCII, one "?" per other UTF-8 byte (as the PHP engine does it), at most 200 bytes.
    reason = re.sub(rb"[^\x20-\x7e]", b"?", reason.encode(errors="surrogatepass"))[:200].decode() if isinstance(reason, str) else ""
    return reason or f"restriction intent {name} (malformed)"

def fold_restrictions():
    """Raise the epoch for every restriction intent, oldest first, removing each only once the raised epoch is
    durable (activator.restrict writes it with fsync). Returns the names folded."""
    try:
        names = sorted((n for n in os.listdir(RESTRICTIONS) if INTENT_NAME.fullmatch(n)), key=lambda n: (len(n), n))
    except FileNotFoundError:
        return []
    for name in names:
        activator.restrict(intent_reason(f"{RESTRICTIONS}/{name}", name))
        os.unlink(f"{RESTRICTIONS}/{name}")
        activator.fsync_dir(RESTRICTIONS)
    return names

def pending():
    try:
        return sorted(p for p in os.listdir(SPOOL) if p.endswith(".json"))
    except FileNotFoundError:
        return []

def run(name, command, limit=300):
    """Local command runner with the result shape the lab compiler expects."""
    result = subprocess.run(command, capture_output=True, text=True, timeout=limit, check=False,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin", "LANG": "C", "LC_ALL": "C"})
    return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

# Certificates and keys by extension or under /var/cpanel/ssl/; password files whatever their name (review RV-29,
# finding 11): any location under a home's .htpasswds/ on a /home<suffix> mount (cpanel_vhosts.HOME_MOUNT) and the
# location of every realm userDB the .htaccess translator emits. Identical to Events\SourceDigest::REFERENCED.
REFERENCED = re.compile(r"^\s*(?:keyFile|certFile|location)\s+(/\S+\.(?:pem|crt|key|combined)|/var/cpanel/ssl/\S+)\s*$|"
                        r"^\s*location\s+(/home[A-Za-z0-9_-]*/[^/\s]+/\.htpasswds/\S+)\s*$|"
                        r"^\s*userDB\s*\{\s*location\s+(/\S+)\s*$", re.M)

def referenced_paths(compiled):
    """The certificate, key and password files the configuration names, sorted."""
    return sorted({match.group(1) or match.group(2) or match.group(3)
                   for text in [compiled["config"], *compiled["vhconf"].values()] for match in REFERENCED.finditer(text)})

def referenced_files(compiled):
    """Digest of every certificate, key and password file the configuration names: OLS reads them only when
    it loads the configuration, so a changed file (AutoSSL renewal, a new password) needs an activation even
    though the compiled text is unchanged (RV-21)."""
    out = {}
    for path in referenced_paths(compiled):
        try:
            out[path] = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
        except OSError:
            out[path] = None
    return out

def load_profile():
    try:
        text = pathlib.Path(PROFILE).read_text()
    except FileNotFoundError:
        return {"production": False, "hybrid_ports": None}
    profile = json.loads(text)
    ports = profile.get("hybrid_ports") if isinstance(profile, dict) else None
    if (not isinstance(profile, dict) or set(profile) != {"production", "hybrid_ports"} or not isinstance(profile["production"], bool)
            or not (ports is None or (isinstance(ports, list) and len(ports) == 2
                                      and all(type(p) is int and 0 < p < 65536 and p not in (80, 443) for p in ports)))):
        raise ValueError("malformed deployment profile " + PROFILE)
    return {"production": profile["production"], "hybrid_ports": tuple(ports) if ports else None}

def active_source():
    current = activator.pointer()
    try:
        return pathlib.Path(activator.GEN_ROOT, current, SOURCE).read_text().strip() if current else None
    except OSError:
        return None

def reconcile(force=False):
    """One reconciliation; returns a summary of what it did."""
    import ols_generation_probe as gp
    import tenant_isolation_probe as iso
    os.makedirs(DONE, mode=0o700, exist_ok=True)
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        folded = fold_restrictions()  # before the epoch is read: no restriction is left out of this pass
        events = pending()
        started = time.time()
        epoch = activator.current_epoch()  # read first: a restriction during compilation makes this stale
        profile = load_profile()
        summary = {}
        compiled = iso.compile_lab(run, summary, production=profile["production"], hybrid_ports=profile["hybrid_ports"])
        source = hashlib.sha256(json.dumps({"config": compiled["config"], "vhconf": compiled["vhconf"], "epoch": epoch,
                                            "files": referenced_files(compiled)}, sort_keys=True).encode()).hexdigest()
        result = {"events": len(events), "epoch": epoch, "compile_seconds": round(time.time() - started, 1),
                  "hybrid_vhosts": summary.get("hybrid_vhosts", [])}
        if folded:
            result["restrictions_folded"] = folded
        state = activator.status()
        if not state["coherent"]:
            # Repair runtime divergence (interrupted switch, stopped server) before trusting the pointer.
            # Repair interrupted transactions, but leave HR-D11's grace for the replacement compiled below:
            # one suspension must not stop every site before its replacement is ready (review 2, item 12).
            result["recovered"] = activator.recover(grace=300)["actions"]
            state = activator.status()
        current = activator.pointer()
        healthy = state["coherent"] and not activator.vhost_health(current, activator.health_targets(current) or [], seconds=5)
        if not force and source == active_source() and healthy:
            result["action"] = "unchanged"
        else:
            gen = "r" + time.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
            with tempfile.TemporaryDirectory(dir="/var/tmp") as temp:
                tree = pathlib.Path(temp, gen)
                gp.generation_tree(tree, gen, compiled, epoch=epoch, production=profile["production"])
                (tree / SOURCE).write_text(source + "\n")
                os.chmod(temp, 0o755)
                activator.stage(gen, str(tree))
            validation = activator.validate(gen)
            result.update(generation=gen, valid=validation["valid"])
            outcome = activator.activate(gen) if validation["valid"] else {"result": "invalid"}
            result["action"] = outcome.get("result")
            if outcome.get("result") != "committed":
                result["reason"] = outcome.get("reason") or outcome.get("failing")
                return result  # events stay pending; the next pass retries
        for name in events:
            os.rename(f"{SPOOL}/{name}", f"{DONE}/{name}")
        result["seconds"] = round(time.time() - started, 1)
        return result

def enforcement_loop():
    """Deadline enforcement independent of compilation and activation (review 2, item 8): every 5 s, a
    restriction older than 300 s that the served generation lacks stops OLS."""
    while True:
        try:
            folded = fold_restrictions()  # an intent is a restriction no generation has applied
            if folded:
                print(json.dumps({"time": time.time(), "restrictions_folded": folded}), flush=True)
            enforced = activator.enforce(300)
            if enforced and enforced != "within-grace":
                print(json.dumps({"time": time.time(), "enforced": enforced}), flush=True)
        except Exception as exc:
            print(json.dumps({"time": time.time(), "enforce_error": f"{type(exc).__name__}: {exc}"[:300]}), flush=True)
        time.sleep(5)

def watch(interval):
    threading.Thread(target=enforcement_loop, daemon=True).start()
    last = 0.0
    while True:
        if pending() or time.time() - last >= interval:
            try:
                print(json.dumps({"time": time.time(), **reconcile()}, sort_keys=True), flush=True)
            except Exception as exc:
                print(json.dumps({"time": time.time(), "error": f"{type(exc).__name__}: {exc}"[:500]}), flush=True)
            last = time.time()
        time.sleep(1)

def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "hook":
        hook()
    elif command == "reconcile":
        os.makedirs(activator.GEN_ROOT, mode=0o755, exist_ok=True)
        os.makedirs(activator.JOURNAL, mode=0o700, exist_ok=True)
        os.makedirs(activator.VALIDATIONS, mode=0o700, exist_ok=True)
        print(json.dumps(reconcile(force="--force" in sys.argv), sort_keys=True))
    elif command == "watch":
        interval = int(sys.argv[sys.argv.index("--interval") + 1]) if "--interval" in sys.argv else 60
        watch(interval)
    else:
        raise SystemExit(__doc__)

if __name__ == "__main__":
    main()
