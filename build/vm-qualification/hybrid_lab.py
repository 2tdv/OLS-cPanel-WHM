"""Hybrid profile host changes for the production experiment (HR-D08, reviews RV-27 and RV-28).

Apache moves to cPanel's backend ports (81/444, as with ea-nginx) and keeps serving the domains OLS
cannot reproduce; OLS proxies them. The host changes are:

- the cPanel tweak settings apache_port / apache_ssl_port (captured values are restored, not defaults);
- a mod_remoteip include trusting only X-OLS-Client-IP (OLS patch 0010 sets it and drops any client
  copy), from the local addresses OLS connects from;
- an nftables table admitting connections to the backend ports only over loopback and only from root
  and OLS's user ("nobody"). That user is not exclusive to OLS: Apache itself and, with the "dso" PHP
  handler or CGI without suEXEC, tenant code run as "nobody" too, so the compiler refuses a hybrid vhost
  with the dso handler and cutover requires suEXEC (RV-28). Socket cgroup matching was rejected: nftables
  binds the cgroup at load time, and every OLS restart creates a new one;
- lab-only tenant changes (the untranslatable directive, a diagnostic page, an ACME-path copy of it).

Every change has a backup in a root-only directory and one recovery script undoes all of them. Tenant
files are captured and restored as the tenant, so a symlink planted by the tenant gives no root write.
The script is armed in a systemd timer before the first change and is also what the experiment runs on
its normal return path, so the emergency path is exercised on every run. It holds a lock (one recovery
at a time; the product's script holds the deployment lock, review RV-29), bounds every command, keeps the firewall until Apache owns 80/443 again and the backend
ports are closed, verifies every captured invariant, and retries until all hold."""
import re
import shlex

import http3

NFT_TABLE = "ols_cpanel_hybrid"
REMOTEIP_CONF = "/etc/apache2/conf.d/ols-cpanel-remoteip.conf"
OLS_USER = "nobody"  # OLS worker processes (httpd_config.conf "user")
LOCK = "/run/ols-cpanel-recover.lock"
BACKEND_PORTS = (81, 444)  # cPanel's backend ports for Apache behind a front server (as with ea-nginx)
# The product's cutover recovery (src/Deployment/RecoveryScript.php, byte-identical) also stops and disables the
# reconciler and OLS for good and removes the deployment profile, so it works with a broken product installation.
# The product changes no tenant file, so its script has none to restore.
LAB_UNITS = ("ols-cpanel.service", "ols-cpanel-logs.service")
PRODUCT_UNITS = ("ols-cpanel-reconciler.service", "ols-cpanel.service", "ols-cpanel-logs.service")
PRODUCT_PROFILE = "/var/lib/ols-cpanel/profile.json"
# The product's script takes the deployment lock exclusively (docs/product-interfaces.md, "Locks, deadlines and
# recovery"): no cutover, return, uninstall or reconcile pass runs beside it. A holder of that lock that runs the
# script synchronously exports OLS_CPANEL_DEPLOYMENT_LOCK=held, so the script does not wait for its own caller.
DEPLOYMENT_LOCK = "/var/lib/ols-cpanel/deployment.lock"
DEPLOYMENT_LOCK_HELD = "OLS_CPANEL_DEPLOYMENT_LOCK"
TWEAK_VALUE = re.compile(r"(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{1,5}")

def nft_ruleset(ports):
    ports = ", ".join(str(p) for p in ports)
    return (f"table inet {NFT_TABLE} {{\n"
            "    chain input {\n        type filter hook input priority -10; policy accept;\n"
            f"        tcp dport {{ {ports} }} iifname != \"lo\" drop\n    }}\n"
            "    chain output {\n        type filter hook output priority -10; policy accept;\n"
            f"        tcp dport {{ {ports} }} fib daddr type local meta skuid != {{ 0, {OLS_USER} }} reject with tcp reset\n"
            "    }\n}\n")

def remoteip_conf(proxies):
    return ("# OLS-cPanel hybrid profile: requests reach Apache through OpenLiteSpeed on this server, which sends\n"
            "# the client address in X-OLS-Client-IP. The backend ports admit only local connections from OLS.\n"
            "<IfModule remoteip_module>\n    RemoteIPHeader X-OLS-Client-IP\n"
            f"    RemoteIPInternalProxy {' '.join(proxies)}\n</IfModule>\n")

FIREWALL_DIR = "firewall"  # in the backup: the original csf.conf (FV-04)

def _csf_digests(firewall):
    for key in ("before_sha256", "after_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", firewall.get(key, "")):
            raise ValueError("the csf recovery needs the sha256 of the original and of the changed csf.conf")
    return firewall["before_sha256"], firewall["after_sha256"]

def _firewalld_zone(firewall):
    zone = firewall.get("zone", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", zone):
        raise ValueError("the firewalld recovery needs the recorded zone")
    if not firewall.get("runtime") and not firewall.get("permanent"):
        raise ValueError("the firewalld recovery needs the state(s) the product added")
    return zone

def firewall_restore_lines(firewall):
    """The recovery lines that undo the UDP 443 change (FV-04). csf (RV-31 item 6): "file restored" and "firewall applied"
    are separate facts. The captured csf.conf goes back byte for byte, but only while the file still is what the cutover
    wrote (a later administrator edit is never overwritten); csf restarts whenever the original file is in place and no
    restart has succeeded in this run (CSF_APPLIED), so an attempt that restored the file but failed to restart retries
    the restart. firewalld (items 3-5): exactly the runtime and/or permanent port the product added, in the recorded
    zone, no reload."""
    if firewall["type"] == "csf":
        before, after = _csf_digests(firewall)
        conf = shlex.quote(http3.CSF_CONF)
        total = f"h=$(sha256sum < {conf} | cut -d' ' -f1)"
        return ['    if [ "${CSF_APPLIED:-}" != 1 ]; then', f"        {total}",
                f"        if [ \"$h\" = {after} ]; then cat \"$B/{FIREWALL_DIR}/csf.conf\" > {conf}; {total}; fi",
                f"        if [ \"$h\" = {before} ]; then $T {http3.CSF} -r >/dev/null 2>&1 && CSF_APPLIED=1; fi", "    fi"]
    if firewall["type"] == "firewalld":
        zone = shlex.quote(_firewalld_zone(firewall))
        lines = []
        if firewall.get("runtime"):
            lines.append(f"    $T firewall-cmd --zone={zone} --remove-port=443/udp >/dev/null 2>&1")
        if firewall.get("permanent"):
            lines.append(f"    $T firewall-cmd --permanent --zone={zone} --remove-port=443/udp >/dev/null 2>&1")
        return lines
    raise ValueError(f"unknown firewall type {firewall['type']!r}")

def firewall_health_lines(firewall):
    """The healthy() lines of the firewall change: csf must have restarted successfully on the original file, unless the
    file is neither the cutover's nor the original (an administrator's edit is never fought)."""
    if firewall["type"] != "csf":
        return []
    before, after = _csf_digests(firewall)
    conf = shlex.quote(http3.CSF_CONF)
    return [f"    [ \"${{CSF_APPLIED:-}}\" = 1 ] || {{ h=$(sha256sum < {conf} | cut -d' ' -f1); "
            f"[ \"$h\" != {after} ] && [ \"$h\" != {before} ]; }} || return 1"]

def recovery_script(backup, originals, tenant_files, created_dirs, hybrid, tenant_user=None, expected=None,
                    product=False, backend_ports=BACKEND_PORTS, firewall=None):
    """POSIX shell run as root. originals: tweak key -> captured value. tenant_files: path -> True when a
    copy exists in <backup>/files/<n> (n = index in sorted order), False when the file did not exist.
    expected: path -> sha256 of the original content (verified after the restore). created_dirs:
    directories the experiment created (removed when empty). Tenant paths are handled as tenant_user.
    product: the product's cutover recovery (DEPLOYMENT_LOCK held unless the caller holds it, PRODUCT_UNITS stopped
    and disabled, PRODUCT_PROFILE removed and verified absent; no tenant files). backend_ports: Apache's hybrid ports, which must be closed again.
    firewall: the UDP 443 change of the cutover (FV-04) to undo, {"type": "csf", "before_sha256", "after_sha256"} or
    {"type": "firewalld", "zone", "runtime", "permanent"};
    None leaves the script exactly as without HTTP/3."""
    q = shlex.quote
    expected = expected or {}
    if product and (tenant_files or created_dirs):
        raise ValueError("the product's recovery restores no tenant files")
    units = " ".join(PRODUCT_UNITS if product else LAB_UNITS)
    if hybrid:
        if tenant_files and not tenant_user:
            raise ValueError("tenant files need the tenant user")
        for key, value in originals.items():
            if key not in ("apache_port", "apache_ssl_port") or not TWEAK_VALUE.fullmatch(value):
                raise ValueError(f"unexpected tweak setting {key}={value!r}")
    as_tenant = f"timeout 60 runuser -u {q(tenant_user or 'nobody')} --"
    lines = ["#!/bin/sh", "# OLS-cPanel recovery: Apache back on 80/443, every cutover change undone." if product
             else "# OLS-cPanel lab recovery: Apache back on 80/443, every experiment change undone.",
             f"B={q(backup)}", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "T='timeout 120'",
             *([f"if [ \"${{{DEPLOYMENT_LOCK_HELD}:-}}\" != held ]; then", f"    exec 9>{DEPLOYMENT_LOCK}",
                "    flock -w 900 9 || { echo 'a deployment operation holds the deployment lock' >&2; exit 1; }", "fi"]
               if product else
               [f"exec 9>{LOCK}", "flock -w 900 9 || { echo 'another recovery holds the lock' >&2; exit 1; }"]),
             "restore() {", f"    $T systemctl stop {units} 2>/dev/null"]
    if product:
        # One unit per call: a unit file missing from a broken installation must not keep the others enabled.
        lines += [f"    for u in {units}; do $T systemctl disable \"$u\" 2>/dev/null; done", f"    rm -f {q(PRODUCT_PROFILE)}"]
    if hybrid:
        lines.append(f"    rm -f {q(REMOTEIP_CONF)}")
        for number, (path, existed) in enumerate(sorted(tenant_files.items())):
            lines.append(f"    {as_tenant} sh -c 'cat > \"$1\"' sh {q(path)} < \"$B/files/{number}\"" if existed
                         else f"    {as_tenant} rm -f -- {q(path)}")
        for path in sorted(created_dirs, reverse=True):
            lines.append(f"    {as_tenant} rmdir -- {q(path)} 2>/dev/null")
        for key, value in sorted(originals.items()):
            lines.append(f"    $T /usr/local/cpanel/bin/whmapi1 set_tweaksetting key={key} value={q(value)} >/dev/null")
        lines.append("    $T /usr/local/cpanel/scripts/rebuildhttpdconf >/dev/null")
    if firewall is not None:
        lines += firewall_restore_lines(firewall)
    lines += ["    $T /usr/local/cpanel/bin/whmapi1 configureservice service=httpd enabled=1 monitored=1 >/dev/null",
              "    $T /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1", "}", "healthy() {",
              "    for p in 80 443; do",
              "        ss -H -ltnp \"( sport = :$p )\" | grep -q '\"httpd\"' || return 1", "    done"]
    if firewall is not None:
        lines += firewall_health_lines(firewall)
    if hybrid:
        ports = " ".join(str(v.rsplit(":", 1)[-1]) for v in originals.values())
        lines += [f"    for p in {' '.join(str(p) for p in backend_ports)}; do case \" {ports} \" in *\" $p \"*) continue;; esac",
                  "        ss -H -ltn \"( sport = :$p )\" | grep -q . && return 1", "    done",
                  f"    test -e {q(REMOTEIP_CONF)} && return 1"]
        for key, value in sorted(originals.items()):
            lines.append(f"    $T /usr/local/cpanel/bin/whmapi1 --output=json get_tweaksetting key={key} "
                         f"| grep -qF {q(chr(34) + 'value' + chr(34) + ':' + chr(34) + value + chr(34))} || return 1")
        for path, existed in sorted(tenant_files.items()):
            if existed and path in expected:
                lines.append(f"    [ \"$({as_tenant} sh -c 'sha256sum < \"$1\"' sh {q(path)} | cut -d' ' -f1)\" = "
                             f"{q(expected[path])} ] || return 1")
            elif not existed:
                lines.append(f"    {as_tenant} test ! -e {q(path)} || return 1")
        for path in sorted(created_dirs):
            lines.append(f"    test ! -e {q(path)} || return 1")
    if product:
        lines.append(f"    test ! -e {q(PRODUCT_PROFILE)} || return 1")
    lines += ["    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/)",
              "    case \"$code\" in [1-4]??) return 0;; esac", "    return 1", "}",
              "for attempt in 1 2 3 4 5 6 7 8; do", "    restore", "    sleep 5", "    if healthy; then"]
    if hybrid:
        # Only now, with Apache back on its own ports, may the backend-port firewall go.
        lines += [f"        nft list table inet {NFT_TABLE} >/dev/null 2>&1 && $T nft delete table inet {NFT_TABLE}",
                  f"        if nft list table inet {NFT_TABLE} >/dev/null 2>&1; then sleep 15; continue; fi"]
        if product:
            # The persisted copy goes with the table, or the next boot would close the ports of an Apache that owns 80/443 again.
            lines += ["        rm -f /var/lib/ols-cpanel/hybrid.nft",
                      "        $T systemctl disable ols-cpanel-hybrid-firewall.service 2>/dev/null"]
    lines += ["        $T /usr/local/cpanel/scripts/enablefileprotect >/dev/null 2>&1", "        echo recovered", "        exit 0",
              "    fi", "    sleep 15", "done", "echo 'recovery incomplete' >&2", "exit 1", ""]
    return "\n".join(lines)
