#!/usr/bin/python3
"""LSCache (feature vertical FV-01, plan §20.3 and §21.6): the OLS 1.9.3 cache module policy the compiler
emits, and the storage primitives (path, purge, statistics) behind the administrator's purge and the
cache views. The product port is src/Ols/Compiler/CachePolicy.php and src/Ols/Cache/CacheStorage.php
(byte-identical text and equal results, checked by tests/compiler_equivalence.py and tests/lscache.py).

Behaviour derived from the OLS 1.9.3 source (src/modules/cache/):
- The module is prelinked ("cache" is internal, lsiapi/modulemanager.cpp loadModule); its parameters are
  the lines of a "module cache { ... }" block (cache.cpp paramArray). Server level "ls_enabled 0" switches
  its hooks off for every vhost that does not enable it in its own block (vhost level ls_enabled is
  honoured by ModuleConfig::parseConfig; only context level is ignored).
- Nothing is cached without the application's instruction: with "enableCache 0"/"enablePrivateCache 0"
  the per-request control starts as no-cache (cache.cpp getControlFlag) and only an
  X-LiteSpeed-Cache-Control response header or a rewrite-set Cache-Control environment value
  (rewriteengine.cpp expandEnv, cache.cpp checkCtrlEnv) turns it on. A plain Cache-Control header is only
  read when the default age is 0 (cache.cpp createEntry), so expireInSeconds stays non-zero.
- "checkPublicCache 1"/"checkPrivateCache 1" make the module look entries up for every GET/HEAD (cache.cpp
  checkAssignHandler, URI_MAP hook). That hook runs after the vhost rewrite rules (httpsession.cpp
  processVHostRewrite -> processContextRewrite -> HSPS_HKPT_URI_MAP), so a redirect or [F] at vhost level
  (cPanel's suspended page, the PURGE refusal below) answers before any cache lookup.
- Numeric limits are not inherited from the server level (CacheConfig::inherit copies only the flags and
  the store; apply() is never called), so every block repeats the full parameter set.
- A vhost block with "storagePath" gets its own store (cache.cpp parseStoragePath, DirHashCacheStore). OLS
  creates only the last path component (0770, then chown to the server user and chmod 2770); missing parents
  would be created 0770 root and the workers could not reach them, so CACHE_ROOT itself must exist (root
  0711, ensure_root) before the configuration is loaded. Store layout: <store>/<h>/<h>/<h>/<16 hex>[.S|.tmp]
  for public entries, <store>/priv/<h>/<h>/<h>/<16 hex> for private ones (cachestore.cpp getCacheDirPath,
  dirhashcachestore.cpp buildCacheLocation), plus the shared-memory index .cacheman.shm/.cacheman.lock
  (shmcachemanager.cpp init).
- An entry file that disappears is a miss on the next lookup (dirhashcachestore.cpp getCacheEntry,
  isChanged), so deleting entry files purges; the shared-memory index is left alone.
- The PURGE and REFRESH methods are honoured from 127.0.0.1 or a trusted address without authentication
  (cache.cpp handlerProcess), so any local account could purge any site's cache; enabled vhosts refuse
  them in their rewrite rules. Applications purge through X-LiteSpeed-Purge response headers, which act
  only on the store of the vhost that answers (cache.cpp processPurge2 -> the vhost's CacheStore).
- The environment handler that consumes Cache-Control from rewrite rules is global (cache.cpp init), so a
  vhost with the module disabled can still create entries in its configured store; every native vhost
  therefore gets its own store even when disabled, and lookups (the only way to serve an entry) happen
  only where the module is enabled."""
import errno
import hashlib
import json
import os
import re
import stat
import sys

CACHE_ROOT = "/var/lib/ols-cpanel/cache"
# The server-level store: never used for lookups (the module is disabled at server level); a name no
# vhost store can take (stores contain "@").
SERVER_STORE = "server"
# Server and vhost parameters, in emission order (cache.cpp paramArray names).
PARAMS = (("checkPublicCache", "1"), ("checkPrivateCache", "1"), ("enableCache", "0"), ("enablePrivateCache", "0"),
          ("qsCache", "1"), ("reqCookieCache", "1"), ("respCookieCache", "1"), ("ignoreReqCacheCtrl", "1"),
          ("ignoreRespCacheCtrl", "0"), ("expireInSeconds", "3600"), ("privateExpireInSeconds", "3600"),
          ("maxStaleAge", "200"), ("maxCacheObjSize", "10000000"))
USER = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
# A store name: "<user>@<vhost>", or "<user>@h-<sha256 of vhost>" when that exceeds one path component.
STORE = re.compile(r"^([a-z0-9][a-z0-9_.-]*)@([a-z0-9][a-z0-9.-]*)$")
NAME_MAX = 255
# Entry files: 16 hex digits (cachehash.h HASH_KEY_LEN 8), ".S" marks a stale copy, ".tmp" one being written.
ENTRY = re.compile(r"^[0-9a-f]{16}(\.S)?$")
TMP = re.compile(r"^[0-9a-f]{16}\.tmp$")
# Entries modified within this many seconds are never removed by a cleanup (OLS may be writing or just wrote them).
YOUNG = 60
# Cleanup margin past the longest lifetime the policy gives an entry (an application may set a longer one itself).
CLEAN_MARGIN = 86400
MIN_ENTRY_AGE = 691200  # never expire before eight days (LiteSpeed Cache for WordPress defaults to one week)
HASH_DIR = re.compile(r"^[0-9a-f]$")
PRIVATE_DIR = "priv"

def _line(key, value):
    return f"    {key:<20} {value}\n"

def _block(enabled, storage):
    params = "".join(_line(k, v) for k, v in PARAMS)
    return f"module cache {{\n{_line('ls_enabled', '1' if enabled else '0')}{params}{_line('storagePath', storage)}}}\n"

def server_block(root=CACHE_ROOT):
    """Server level: module off for every vhost that does not enable it, the product's parameters, and a
    store inside the root-owned tree instead of OLS's default $SERVER_ROOT/cachedata/."""
    return _block(False, f"{root}/{SERVER_STORE}")

def cache_enabled(v, suspended=False):
    """A native vhost serves from its cache unless its account is suspended or the per-vhost "cache" plan
    field (configuration overrides, FV-06) is anything but true; absent means on."""
    return v.get("cache", True) is True and not suspended

def vhost_block(v, suspended=False, root=CACHE_ROOT):
    """A native tenant vhost: its own store, lookups only when enabled."""
    return _block(cache_enabled(v, suspended), storage_path(v["user"], v["name"], root))

def disabled_block():
    """A vhost that never uses the cache (the hybrid pass-through vhosts <domain> and tls.<domain>)."""
    return "module cache {\n" + _line("ls_enabled", "0") + "}\n"

def vhost_rules(v, suspended=False):
    """Vhost-level rewrite rules of an enabled vhost: PURGE/REFRESH requests are refused before the cache
    module could honour them from a local address (cache.cpp handlerProcess)."""
    if not cache_enabled(v, suspended):
        return ""
    return "RewriteCond %{REQUEST_METHOD} ^(PURGE|REFRESH)$ [NC]\nRewriteRule ^ - [F]\n"

def summary(plan, suspended_users, root=CACHE_ROOT):
    """Per account vhost: whether OLS serves it from cache and its store (None for hybrid vhosts)."""
    out = {}
    for name, v in plan.items():
        native = v.get("mode", "native") != "apache"
        out[name] = {"enabled": native and cache_enabled(v, v["user"] in suspended_users),
                     "storage": storage_path(v["user"], name, root) if native else None}
    return out

def store_name(user, vhost):
    if not USER.match(user or "") or not DOMAIN.match(vhost or ""):
        raise ValueError(f"invalid cache store owner {user!r} or vhost {vhost!r}")
    name = f"{user}@{vhost}"
    if len(name.encode()) > NAME_MAX:
        name = f"{user}@h-{hashlib.sha256(vhost.encode()).hexdigest()}"
    if len(name.encode()) > NAME_MAX:
        raise ValueError(f"cache store name for {user!r} is too long")
    return name

def storage_path(user, vhost, root=CACHE_ROOT):
    return f"{root}/{store_name(user, vhost)}"

# Storage primitives. They run as root on a tree only root and the OLS workers ("nobody") can write: every
# path below the root is opened relative to its parent directory without following symbolic links
# (O_NOFOLLOW, dir_fd), so a planted link is removed as a link and never traversed.

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def _open_root(root, owner):
    fd = os.open(root, _DIR_FLAGS)
    info = os.fstat(fd)
    if info.st_uid != owner or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError(f"{root} must be owned by uid {owner} and not group/other writable")
    return fd

def ensure_root(root=CACHE_ROOT, owner=0):
    """Create the cache root (0711: the OLS workers traverse it, tenants cannot list it) if missing and
    verify it. The parent must exist."""
    try:
        os.mkdir(root, 0o711)
        os.chmod(root, 0o711)
    except FileExistsError:
        pass
    os.close(_open_root(root, owner))

def _selected(root_fd, account, vhost):
    """Store names to act on, sorted: one vhost's store, every store of an account, or every store plus the
    server store. Names that are not stores (or are links) are never selected."""
    if vhost is not None:
        if account is None:
            raise ValueError("a vhost store needs its account")
        return [store_name(account, vhost)]
    if account is not None and not USER.match(account):
        raise ValueError(f"invalid account {account!r}")
    names = []
    for entry in os.scandir(root_fd):
        match = STORE.match(entry.name)
        if (match and (account is None or match.group(1) == account)) or (account is None and entry.name == SERVER_STORE):
            names.append(entry.name)
    return sorted(names)

def _open_store(root_fd, name):
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError(f"cache store {name} is not a directory") from None
        raise

def _failed(counts, _error):
    """A removal that did not happen (RV-31 item 12): counted, never reported as removed. ENOENT is the caller's business
    (somebody else removed it first: neither removed nor failed)."""
    counts["failed"] += 1

def _rmdir(name, dir_fd, counts):
    try:
        os.rmdir(name, dir_fd=dir_fd)
    except OSError as error:
        # ENOENT: gone already; ENOTEMPTY: an entry was written meanwhile (or a failure below, already counted).
        if error.errno not in (errno.ENOENT, errno.ENOTEMPTY):
            _failed(counts, error)

def _walk(dir_fd, private, counts, remove):
    """Count (and with remove, delete) everything below dir_fd; links and other non-directories are
    unlinked, never followed. With remove, an entry is counted only once its unlink succeeded; an unlink or rmdir that
    fails for any reason but "already gone" is counted in counts["failed"]."""
    try:
        listing = list(os.scandir(dir_fd))
    except OSError as error:
        if not remove:
            raise
        _failed(counts, error)
        return
    for entry in listing:
        if entry.is_dir(follow_symlinks=False):
            try:
                child = os.open(entry.name, _DIR_FLAGS, dir_fd=dir_fd)
            except FileNotFoundError:
                continue
            except OSError as error:
                if not remove:
                    raise
                _failed(counts, error)
                continue
            try:
                _walk(child, private, counts, remove)
            finally:
                os.close(child)
            if remove:
                _rmdir(entry.name, dir_fd, counts)
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        removed = True
        if remove:
            try:
                os.unlink(entry.name, dir_fd=dir_fd)
            except FileNotFoundError:
                removed = False
            except OSError as error:
                removed = False
                _failed(counts, error)
        if removed and stat.S_ISREG(info.st_mode) and ENTRY.match(entry.name):
            key = "private" if private else "public"
            counts[key + "_entries"] += 1
            counts[key + "_bytes"] += info.st_size

def _store(root_fd, name, remove):
    counts = {"public_entries": 0, "public_bytes": 0, "private_entries": 0, "private_bytes": 0}
    if remove:
        counts["failed"] = 0
    fd = _open_store(root_fd, name)
    if fd is None:
        return dict(counts, present=False)
    try:
        for entry in sorted(os.scandir(fd), key=lambda e: e.name):
            # Only the hash directories hold entries; the shared-memory index and anything else stay.
            if not (HASH_DIR.match(entry.name) or entry.name == PRIVATE_DIR):
                continue
            if not entry.is_dir(follow_symlinks=False):
                if remove:
                    try:
                        os.unlink(entry.name, dir_fd=fd)
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        _failed(counts, error)
                continue
            try:
                child = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                continue
            except OSError as error:
                if not remove:
                    raise
                _failed(counts, error)
                continue
            try:
                _walk(child, entry.name == PRIVATE_DIR, counts, remove)
            finally:
                os.close(child)
            if remove:
                _rmdir(entry.name, fd, counts)
    finally:
        os.close(fd)
    return dict(counts, present=True)

def max_entry_age():
    """Age in seconds after which an entry file is certainly expired: the longest default lifetime of PARAMS plus the stale
    window (maxStaleAge) plus CLEAN_MARGIN. Equal to CachePolicy::maxEntryAge()."""
    values = {k: int(v) for k, v in PARAMS}
    return max(MIN_ENTRY_AGE, max(values["expireInSeconds"], values["privateExpireInSeconds"]) + values["maxStaleAge"] + CLEAN_MARGIN)

def _collect(dir_fd, rel, found, dirs):
    """Entry files below a hash directory or priv: relative path -> (mtime, size). Links and non-regular files are skipped."""
    dirs.append(rel)
    for entry in os.scandir(dir_fd):
        path = rel + "/" + entry.name
        if entry.is_dir(follow_symlinks=False):
            try:
                child = os.open(entry.name, _DIR_FLAGS, dir_fd=dir_fd)
            except OSError:
                continue
            try:
                _collect(child, path, found, dirs)
            finally:
                os.close(child)
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode) and (ENTRY.match(entry.name) or TMP.match(entry.name)):
            found[path] = (int(info.st_mtime), info.st_size)

def _unlink_counted(rel, fd, size, result):
    parent, _, name = rel.rpartition("/")
    parent_fd = _open_rel(fd, parent) if parent else None
    try:
        os.unlink(name, dir_fd=parent_fd if parent_fd is not None else fd)
    except FileNotFoundError:
        return True
    except OSError:
        result["failed"] += 1
        return False
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
    result["files"] += 1
    result["bytes"] += size
    return True

def _open_rel(fd, rel):
    cur = os.dup(fd)
    for part in rel.split("/"):
        nxt = os.open(part, _DIR_FLAGS, dir_fd=cur)
        os.close(cur)
        cur = nxt
    return cur

def trim_store(root, name, cutoff, cap_bytes, now, owner=0):
    """Cleanup of one store (twin of CacheStorage::trimStore): entries with mtime < cutoff are removed, then the oldest entries
    (mtime, then relative path) until at most cap_bytes remain; an entry modified in the last YOUNG seconds before now is never
    removed; emptied directories go. Control files and anything that is not an entry are never touched."""
    if not (STORE.match(name) or name == SERVER_STORE):
        raise ValueError(f"invalid cache store name {name!r}")
    result = {"files": 0, "bytes": 0, "failed": 0, "remaining_files": 0, "remaining_bytes": 0, "present": False}
    root_fd = _open_root(root, owner)
    try:
        fd = _open_store(root_fd, name)
        if fd is None:
            return result
        result["present"] = True
        try:
            found, dirs = {}, []
            for entry in sorted(os.scandir(fd), key=lambda e: e.name):
                if not (HASH_DIR.match(entry.name) or entry.name == PRIVATE_DIR) or not entry.is_dir(follow_symlinks=False):
                    continue
                try:
                    child = os.open(entry.name, _DIR_FLAGS, dir_fd=fd)
                except OSError:
                    continue
                try:
                    _collect(child, entry.name, found, dirs)
                finally:
                    os.close(child)
            young = now - YOUNG
            keep = {}
            for rel, (mtime, size) in found.items():
                if mtime < cutoff and mtime <= young and _unlink_counted(rel, fd, size, result):
                    continue
                keep[rel] = (mtime, size)
            total = sum(size for _, size in keep.values())
            if total > cap_bytes:
                for rel in sorted(keep, key=lambda r: (keep[r][0], r)):
                    if total <= cap_bytes:
                        break
                    if keep[rel][0] <= young and _unlink_counted(rel, fd, keep[rel][1], result):
                        total -= keep[rel][1]
                        del keep[rel]
            result["remaining_files"] = len(keep)
            result["remaining_bytes"] = sum(size for _, size in keep.values())
            touched = set()
            for rel in set(found) - set(keep):
                d = rel.rpartition("/")[0]
                while d:
                    touched.add(d)
                    d = d.rpartition("/")[0]
            for d in sorted(touched, key=lambda x: (-len(x), x)):
                parent, _, leaf = d.rpartition("/")
                try:
                    parent_fd = _open_rel(fd, parent) if parent else os.dup(fd)
                except OSError:
                    continue
                try:
                    os.rmdir(leaf, dir_fd=parent_fd)
                except OSError:
                    pass
                finally:
                    os.close(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
    return result

def _run(root, owner, account, vhost, remove):
    root_fd = _open_root(root, owner)
    try:
        return {name: _store(root_fd, name, remove) for name in _selected(root_fd, account, vhost)}
    finally:
        os.close(root_fd)

def stats(root=CACHE_ROOT, account=None, vhost=None, owner=0):
    """Entries and bytes per store: {store: {public_entries, public_bytes, private_entries, private_bytes,
    present}}. Entries being written (.tmp) are not counted."""
    return _run(root, owner, account, vhost, False)

def purge(root=CACHE_ROOT, account=None, vhost=None, owner=0):
    """Delete every entry of one vhost's store, of every store of an account, or of every store; returns what
    was actually removed per store, plus "failed" (removals that failed for a reason other than "already gone").
    The stores and their shared-memory index stay."""
    return _run(root, owner, account, vhost, True)

def main(argv):
    """Root command line for the lab experiment: lscache.py stats|purge <root> [<account> [<vhost>]]."""
    if len(argv) < 3 or argv[1] not in ("stats", "purge") or len(argv) > 5:
        print("usage: lscache.py stats|purge <root> [<account> [<vhost>]]", file=sys.stderr)
        return 64
    action, root = argv[1], argv[2]
    account, vhost = (argv[3:] + [None, None])[:2]
    result = (purge if action == "purge" else stats)(root, account, vhost, owner=os.geteuid())
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
