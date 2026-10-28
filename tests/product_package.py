#!/usr/bin/python3
"""Offline checks of the ols-cpanel package and the one-command installer (build/product). Changes nothing
on the server: units are only parsed, the installer only runs as a modified copy in a temporary directory
with stubbed package manager and CLI, and package.py runs on a temporary copy of the repository."""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
HERE = ROOT / "build/product"
UNITS = ["ols-cpanel-broker.service", "ols-cpanel-reconciler.service", "ols-cpanel-objcache@.service",
         "ols-cpanel-objcache.service", "ols-cpanel-objcache.timer", "ols-cpanel-cache-clean.service",
         "ols-cpanel-cache-clean.timer", "ols-cpanel-notify.service", "ols-cpanel-notify.timer",
         "ols-cpanel-schedule.service", "ols-cpanel-schedule.timer", "ols-cpanel-php.path", "ols-cpanel-php.service", "ols-cpanel-php.timer",
         "ols-cpanel-hybrid-firewall.service", "ols-cpanel-hybrid-trust.service", "ols-cpanel-hybrid-trust.timer",
         "ols-cpanel-upgrade.service"]


def load_package(root):
    spec = importlib.util.spec_from_file_location(f"product_package_{abs(hash(str(root)))}",
                                                  root / "build/product/package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def code_lines(path):
    """(number, text) of non-comment lines."""
    return [(n, line) for n, line in enumerate(path.read_text().splitlines(), 1)
            if line.strip() and not line.lstrip().startswith("#")]


def directives(path):
    return [line.strip() for _, line in code_lines(path)]


def refuses(function, *args, contains):
    try:
        function(*args)
    except SystemExit as error:
        assert contains in str(error), (contains, str(error))
        return
    raise AssertionError(f"expected a refusal containing {contains!r}")


# --- Spec: files only -------------------------------------------------------------------------------------------
spec = (HERE / "ols-cpanel.spec").read_text()
assert not re.search(r"^%(pre|post|preun|postun|pretrans|posttrans|verifyscript|trigger\w*|filetrigger\w*)\b",
                     spec, re.M), "the spec must not contain scriptlets"
for word in ("systemctl", "%systemd_", "%sysusers_create", "useradd", "groupadd", "register_appconfig",
             "install_plugin", "manage_hooks"):
    assert word not in spec, f"the spec must not run {word}"
assert "AutoReqProv:    no" in spec and "Requires:       ols-cpanel-openlitespeed" in spec
# The PHP redis extension (prebuilt builds and pinned source) is a package of its own that the product requires.
assert "Requires:       ols-cpanel-php-redis" in spec and "Requires:       valkey" in spec
assert "ols-cpanel-php.path" in spec and "ols-cpanel-php-ext" not in spec
assert "Release:        %{product_release}%{?dist}" in spec

# --- Units ------------------------------------------------------------------------------------------------------
broker = directives(HERE / "ols-cpanel-broker.service")
reconciler = directives(HERE / "ols-cpanel-reconciler.service")
assert "ExecStart=/usr/local/ols-cpanel/libexec/ols-cpanel-broker /run/ols-cpanel-broker" in broker
assert "RuntimeDirectory=ols-cpanel-broker" in broker and "RuntimeDirectoryMode=0755" in broker
# RV-20: systemd re-applies RuntimeDirectory ownership for every command; the broker runs ExecStart only.
assert not [d for d in broker if re.match(r"Exec(StartPre|StartPost|Reload|Stop|StopPost|Condition)=", d)]
assert not [d for d in broker if d.startswith(("User=", "Group=", "DynamicUser=", "StateDirectory="))]
assert "NoNewPrivileges=yes" in broker and "ProtectSystem=full" in broker and "PrivateTmp=yes" in broker
rw = next(d for d in broker if d.startswith("ReadWritePaths=")).split("=", 1)[1].split()
assert "/var/lib/ols-cpanel" in rw and "/run/ols-cpanel-broker" in rw and "/usr/local/lsws/conf" in rw
assert not [d for d in broker if d.startswith("ProtectHome=")], "the broker reads and writes tenant files as the tenant"
assert "User=olscpanel" in reconciler and "Group=olscpanel" in reconciler
assert "ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel sync --watch" in reconciler
assert "Requires=ols-cpanel-broker.service" in reconciler and "After=ols-cpanel-broker.service" in reconciler
assert "NoNewPrivileges=yes" in reconciler and "ProtectSystem=strict" in reconciler and "ProtectHome=yes" in reconciler
assert not [d for d in reconciler if d.startswith("ReadWritePaths=")]
for unit in (broker, reconciler):
    assert "WantedBy=multi-user.target" in unit
# RV-40 hybrid firewall: loaded at boot, before the network and Apache; only with the persisted ruleset.
firewall = directives(HERE / "ols-cpanel-hybrid-firewall.service")
for needle in ("Type=oneshot", "RemainAfterExit=yes", "DefaultDependencies=no", "After=local-fs.target",
               "Before=network-pre.target httpd.service ols-cpanel.service", "Wants=network-pre.target",
               "ConditionPathExists=/var/lib/ols-cpanel/hybrid.nft", "ExecStart=/usr/sbin/nft -f /var/lib/ols-cpanel/hybrid.nft",
               "WantedBy=multi-user.target", "NoNewPrivileges=yes", "ProtectSystem=strict"):
    assert needle in firewall, needle
assert "ols-cpanel-hybrid-firewall.service" in spec, "the spec ships the firewall unit"
# FV-09 object cache: template instance per account, run as that account, Unix socket only, hardened.
objcache = directives(HERE / "ols-cpanel-objcache@.service")
assert "User=%i" in objcache and "Group=%i" in objcache and "RestrictAddressFamilies=AF_UNIX" in objcache
assert "ExecStart=/usr/bin/valkey-server /var/lib/ols-cpanel/objcache/%i/valkey.conf" in objcache
assert "ConditionPathExists=/var/lib/ols-cpanel/objcache/%i/valkey.conf" in objcache
for needle in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes", "PrivateDevices=yes",
               "CapabilityBoundingSet=", "RestrictNamespaces=yes", "Restart=on-failure", "MemorySwapMax=0"):
    assert needle in objcache, needle
# Everything that varies per account is in the CLI's drop-in, never in the template.
assert not [d for d in objcache if d.startswith(("ReadWritePaths=", "MemoryMax=", "WantedBy="))]
assert "[Install]" not in (HERE / "ols-cpanel-objcache@.service").read_text(), "instances are started by the CLI only"
engine_php = (ROOT / "src/ObjectCache/ValkeyConfig.php").read_text()
assert "public const SERVER = '/usr/bin/valkey-server';" in engine_php and "UNIT_PREFIX = 'ols-cpanel-objcache@'" in engine_php
objcache_sync = directives(HERE / "ols-cpanel-objcache.service")
assert "Type=oneshot" in objcache_sync and not [d for d in objcache_sync if d.startswith(("User=", "WantedBy="))]
assert "ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel objcache reconcile --format=json" in objcache_sync
assert "ProtectSystem=full" in objcache_sync and "ProtectHome=yes" not in objcache_sync and "NoNewPrivileges=yes" in objcache_sync
assert any(d.startswith("ReadWritePaths=") and "/var/lib/ols-cpanel" in d and "/etc/systemd/system" in d for d in objcache_sync)
timer = directives(HERE / "ols-cpanel-objcache.timer")
assert "OnBootSec=60" in timer and "OnUnitActiveSec=60" in timer and "WantedBy=timers.target" in timer
# FV-10 PHP environment: a root oneshot run by the rpm-lock path unit and a timer; never started by the package.
php_sync = directives(HERE / "ols-cpanel-php.service")
assert "Type=oneshot" in php_sync and not [d for d in php_sync if d.startswith(("User=", "WantedBy="))]
assert "ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel php env sync --format=json" in php_sync
assert "NoNewPrivileges=yes" in php_sync and not [d for d in php_sync if d.startswith("ProtectSystem=")], "dnf writes /usr"
assert "StartLimitIntervalSec=0" in php_sync and "ConditionPathExists=/usr/local/ols-cpanel/bin/ols-cpanel" in php_sync and "TimeoutStartSec=3600" in php_sync
php_path = directives(HERE / "ols-cpanel-php.path")
assert "PathChanged=/var/lib/rpm/.rpm.lock" in php_path and "Unit=ols-cpanel-php.service" in php_path and "WantedBy=paths.target" in php_path
assert not (HERE / "ols-cpanel-php-ext.path").exists() and not (HERE / "ols-cpanel-php-ext.service").exists(), "merged into the PHP environment units"
php_timer = directives(HERE / "ols-cpanel-php.timer")
assert "OnBootSec=180" in php_timer and "OnUnitActiveSec=900" in php_timer and "WantedBy=timers.target" in php_timer
# FV-01 LSCache cleanup: a root oneshot (idle IO, nice) run hourly by its timer; the deletions are the unprivileged helper's.
clean = directives(HERE / "ols-cpanel-cache-clean.service")
assert "Type=oneshot" in clean and not [d for d in clean if d.startswith(("User=", "WantedBy="))]
assert "ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel cache clean --format=json" in clean
assert "Nice=19" in clean and "IOSchedulingClass=idle" in clean and "NoNewPrivileges=yes" in clean and "ProtectSystem=strict" in clean
assert "ReadWritePaths=/var/lib/ols-cpanel" in clean and "PrivateTmp=yes" in clean
clean_timer = directives(HERE / "ols-cpanel-cache-clean.timer")
assert "OnBootSec=10min" in clean_timer and "OnUnitActiveSec=1h" in clean_timer and "RandomizedDelaySec=5min" in clean_timer
assert "WantedBy=timers.target" in clean_timer
assert "ols-cpanel-cache-clean.timer" in spec and "ols-cpanel-cache-clean.service" in spec
# FV-07 operations: the notification pass (every five minutes; webhook and local mail) and the maintenance-window pass (every
# minute; admin socket only). Both are root oneshots enabled by prepare and upgrade, never started by the package.
notify = directives(HERE / "ols-cpanel-notify.service")
assert "Type=oneshot" in notify and not [d for d in notify if d.startswith(("User=", "WantedBy="))]
assert "ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel notify run --format=json" in notify
assert "NoNewPrivileges=yes" in notify and "ProtectSystem=full" in notify and "ReadWritePaths=/var/lib/ols-cpanel" in notify
assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in notify and "UMask=0077" in notify
notify_timer = directives(HERE / "ols-cpanel-notify.timer")
assert "OnUnitActiveSec=5min" in notify_timer and "WantedBy=timers.target" in notify_timer
schedule = directives(HERE / "ols-cpanel-schedule.service")
assert "Type=oneshot" in schedule and not [d for d in schedule if d.startswith(("User=", "WantedBy="))]
assert "ExecStart=/usr/local/ols-cpanel/bin/ols-cpanel schedule run --format=json" in schedule
assert "RestrictAddressFamilies=AF_UNIX" in schedule and "ProtectSystem=strict" in schedule and "NoNewPrivileges=yes" in schedule
schedule_timer = directives(HERE / "ols-cpanel-schedule.timer")
assert "OnUnitActiveSec=1min" in schedule_timer and "WantedBy=timers.target" in schedule_timer
for unit in ("notify", "schedule"):
    assert f"ols-cpanel-{unit}.timer" in spec and f"ols-cpanel-{unit}.service" in spec
sysusers = directives(HERE / "ols-cpanel.sysusers")
assert sysusers == ['u olscpanel - "OLS-cPanel reconciler"'], sysusers
launcher = (HERE / "ols-cpanel.sh").read_text()
assert launcher.startswith("#!/bin/sh\n") and 'exec "$PHP" -n "$CLI" "$@"' in launcher
subprocess.run(["sh", "-n", str(HERE / "ols-cpanel.sh")], check=True)

analyze = shutil.which("systemd-analyze")
if analyze:
    with tempfile.TemporaryDirectory() as temp:
        paths = [shutil.copy(HERE / unit, pathlib.Path(temp) / unit) for unit in UNITS]
        result = subprocess.run([analyze, "verify", "--man=no", "--recursive-errors=no", *paths],
                                capture_output=True, text=True)
        if "recursive-errors" in result.stderr and result.returncode != 0 and "unrecognized" in result.stderr:
            result = subprocess.run([analyze, "verify", "--man=no", *paths], capture_output=True, text=True)
        ours = [line for line in (result.stdout + result.stderr).splitlines()
                if any(unit in line for unit in UNITS)]
        # The product executables are not installed on a build host; everything else must be clean.
        unexpected = [line for line in ours if not re.search(
            r"Command (/usr/local/ols-cpanel/(bin|libexec)|/usr/bin)/[\w.-]+ is not executable", line)]
        assert not unexpected, unexpected
    print("systemd-analyze verify: units parse (product executables not installed here).")
else:
    print("systemd-analyze not available: unit verification SKIPPED.")

# --- Installer: static checks -----------------------------------------------------------------------------------
installer = HERE / "install.sh"
text = installer.read_text()
subprocess.run(["sh", "-n", str(installer)], check=True)
lines = text.splitlines()
assert lines[0] == "#!/bin/sh" and "set -eu" in [line.strip() for line in lines[:30]]
assert not re.search(r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|da|k|z)?sh\b", text), "no download piped into a shell"
assert not re.search(r"^\s*(eval|\.|source)\s", text, re.M), "nothing is sourced or evaluated"
assert 'RELEASE_BASE_URL="RELEASE_BASE_URL"' in text and 'RELEASE_VERSION="RELEASE_VERSION"' in text
assert "# BEGIN OLS-CPANEL RELEASE KEY" in text and "# END OLS-CPANEL RELEASE KEY" in text
assert "RELEASE KEY PLACEHOLDER" in text and "--prepare-only" in text and "--help" in text
assert "--proto '=https'" in text and "--proto-redir '=https'" in text


def first(pattern):
    found = [n for n, line in code_lines(installer) if re.search(pattern, line)]
    assert found, pattern
    return found[0]


package_manager = first(r"(^|[\s$(])(/usr/bin/)?(dnf|rpm|yum)\s+-")
trap = first(r"^trap cleanup EXIT$")
mktemp = first(r"mktemp -d ")
gnupghome = first(r'^GNUPGHOME="\$WORK/gnupg"$')
verify = first(r"gpg .*--verify ")
validsig = first(r"VALIDSIG")
digests = first(r"sha256sum --check")
fetch_call = first(r"^fetch ")
assert trap < mktemp < fetch_call, "temporary directory under a cleanup trap before any download"
assert gnupghome < verify < validsig < digests < package_manager, \
    "signature and digest verification must precede every package-manager call"
assert first(r'"\$CLI" install --prepare') > package_manager
assert first(r"rm -rf -- \"\$WORK\"") < trap and "/var/tmp/ols-cpanel-install.*)" in text
print("Installer: syntax, no download pipe, HTTPS only, mktemp + trap, signature and digests before dnf/rpm.")

# --- Installer: behavior of a modified copy (throwaway key, local files, stubbed system tools) -------------------
gpg = shutil.which("gpg")
if not gpg:
    print("gpg not available: installer behavior checks SKIPPED.")
else:
    with tempfile.TemporaryDirectory() as temp:
        t = pathlib.Path(temp)
        for name in ("keys", "other", "rel", "work", "bin", "state"):
            (t / name).mkdir(mode=0o700)
        quiet = {"capture_output": True, "check": True}
        for home, uid in ((t / "keys", "Test Release <release@example.invalid>"), (t / "other", "Other <o@example.invalid>")):
            subprocess.run([gpg, "--homedir", str(home), "--batch", "--passphrase", "", "--quick-gen-key", uid,
                            "ed25519", "sign", "never"], **quiet)
        colons = subprocess.run([gpg, "--homedir", str(t / "keys"), "--with-colons", "--fingerprint"], **quiet).stdout
        fpr = next(line.split(":")[9] for line in colons.decode().splitlines() if line.startswith("fpr:"))
        key = subprocess.run([gpg, "--homedir", str(t / "keys"), "--armor", "--export", fpr], **quiet).stdout.decode()
        calls = t / "calls"
        stubs = {"dnf": "",
                 # install --prepare --format=json reports the plan id the cutover approves.
                 "cli": 'case "$*" in *--prepare*) printf \'{\\n    "result": "prepared",\\n    "plan": "p20261022120000-0a1b2c",\\n    "x": 1\\n}\\n\';; esac\n',
                 # Installed state comes from the file "installed" (absent: nothing installed).
                 "rpm": (f'case "$*" in *--quiet*) [ -f "{t}/installed" ];; -qp*NAME*) echo name;; -qp*EPOCHNUM*) echo 0:1-1;; '
                         f'-qp*) echo name-1-1.x86_64;; -q*EPOCHNUM*) sed "s/^name-\\(.*\\)-\\(.*\\)\\.x86_64$/0:\\1-\\2/" "{t}/installed";; '
                         f'--eval*0:0.9-1*) echo -1;; --eval*) echo 1;; *) cat "{t}/installed";; esac\n'),
                 "cpanel": "echo 11.130.0.1\n"}
        for name, body in stubs.items():
            (t / "bin" / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "{calls}"\n{body}')
        (t / "os-release").write_text('ID="almalinux"\nVERSION_ID="9.6"\n')
        copy = text
        for old, new in [('RELEASE_VERSION="RELEASE_VERSION"', 'RELEASE_VERSION="0.2.0"'),
                         ('RELEASE_BASE_URL="RELEASE_BASE_URL"', 'RELEASE_BASE_URL="https://release.example.invalid"'),
                         ('RELEASE_KEY_FINGERPRINT="RELEASE_KEY_FINGERPRINT"', f'RELEASE_KEY_FINGERPRINT="{fpr}"'),
                         ("RELEASE KEY PLACEHOLDER: replace this line with the ASCII-armored release public key.\n", key),
                         ('[ "$(id -u)" = 0 ]', "true"), ("/etc/os-release", str(t / "os-release")),
                         ('[ "$(uname -m)" = x86_64 ]', "true"),
                         ("[ -x /usr/local/cpanel/cpanel ]", "true"),
                         ("$(/usr/local/cpanel/cpanel -V 2>/dev/null)", f"$(sh {t}/bin/cpanel -V)"),
                         ("[ -x /usr/local/cpanel/3rdparty/php/84/bin/php ]", "true"),
                         ("/var/tmp/ols-cpanel-install.", f"{t}/work/ols-cpanel-install."),
                         ("/usr/bin/dnf --assumeyes", f"sh {t}/bin/dnf --assumeyes"),
                         ("/usr/bin/rpm ", f"sh {t}/bin/rpm "),
                         ("CLI=/usr/local/ols-cpanel/bin/ols-cpanel", f"CLI={t}/bin/cli"), ("PROFILE=/var/lib/ols-cpanel/profile.json", f"PROFILE={t}/profile.json"),
                         ("STATE_DIR=/var/lib/ols-cpanel", f"STATE_DIR={t}/state"),
                         ('[ -x "$CLI" ]', "true"), ('"$CLI" install', 'sh "$CLI" install'),
                         ("    /usr/bin/curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent "
                          "--show-error --location \\\n        --retry 3 --connect-timeout 20 --max-filesize "
                          '"$MAX_DOWNLOAD" --output "$2" "$1" \\\n', f'    cp "{t}/rel/${{1##*/}}" "$2" \\\n')]:
            assert old in copy, old
            copy = copy.replace(old, new)
        (t / "install.sh").write_text(copy)
        packages = {"ols-cpanel-openlitespeed-1.9.3-1.olscp7.el9.x86_64.rpm": b"server",
                    "ols-cpanel-php-redis-6.3.0-1.olscp1.el9.x86_64.rpm": b"phpredis",
                    "ols-cpanel-0.2.0-1.olscp1.el9.x86_64.rpm": b"product"}
        manifest_name = "ols-cpanel-0.2.0.el9.x86_64.manifest"
        good = ["ols-cpanel-release-manifest 1", "version 0.2.0", "platform el9.x86_64",
                *[f"artifact {hashlib.sha256(data).hexdigest()} {name}" for name, data in packages.items()]]

        def release(manifest_lines, signer="keys", tamper=None, sign=True):
            for path in (t / "rel").iterdir():
                path.unlink()
            for name, data in packages.items():
                (t / "rel" / name).write_bytes(data)
            manifest = t / "rel" / manifest_name
            manifest.write_text("\n".join(manifest_lines) + "\n")
            if sign:
                subprocess.run([gpg, "--homedir", str(t / signer), "--batch", "--yes", "--armor", "--detach-sign",
                                "-o", f"{manifest}.asc", str(manifest)], **quiet)
            if tamper:
                tamper()

        def run(label, expected, *args, forbidden=("dnf", "rpm", "cli")):
            calls.unlink(missing_ok=True)
            result = subprocess.run(["sh", str(t / "install.sh"), "--prepare-only", *args], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=120)
            recorded = calls.read_text().split("\n") if calls.exists() else []
            assert result.returncode == expected, (label, result.returncode, result.stderr[-500:])
            assert not list((t / "work").iterdir()), (label, "temporary directory left behind")
            changed = [c for c in recorded if c.startswith(forbidden)]
            if expected != 0:
                assert not changed, (label, "a package-manager or CLI call after a failed verification", changed)
            return recorded, result

        release(good)
        recorded, result = run("verified release", 0)
        assert any(c.startswith("dnf --assumeyes") and c.endswith(".rpm") for c in recorded), recorded
        assert recorded.index(next(c for c in recorded if c.startswith("dnf"))) < recorded.index("cli install --prepare --format=json")
        assert "install --cutover --plan=p20261022120000-0a1b2c" in result.stdout
        # The release key is offered to the rpm database before dnf; the stub refuses it here, so dnf does not check rpm signatures.
        assert recorded.index(next(c for c in recorded if c.startswith("rpm --import"))) < recorded.index(next(c for c in recorded if c.startswith("dnf")))
        assert any("--setopt=localpkg_gpgcheck=False" in c for c in recorded if c.startswith("dnf")), recorded
        # The verified-release record: root-only JSON naming exactly the verified packages and the signed manifest's digest.
        record_path = t / "state/installed-release.json"
        record = json.loads(record_path.read_text())
        assert record_path.stat().st_mode & 0o777 == 0o600 and set(record) == {"version", "platform", "manifest_sha256", "packages", "installed_at"}
        assert (record["version"], record["platform"]) == ("0.2.0", "el9.x86_64")
        assert record["manifest_sha256"] == hashlib.sha256((t / "rel" / manifest_name).read_bytes()).hexdigest()
        assert record["packages"] == [name[:-4] for name in packages], record
        assert [p.name for p in (t / "state").iterdir()] == ["installed-release.json"]
        record_path.unlink()
        (t / "installed").write_text("name-1-1.x86_64\n")
        recorded, _ = run("same build already installed (resume)", 0)
        (t / "profile.json").write_text("{}")
        run("same build installed and serving: nothing to do", 0, forbidden=("dnf", "cli"))
        (t / "profile.json").unlink()
        assert any(c.startswith("dnf --assumeyes") for c in recorded), recorded
        (t / "installed").write_text("name-0.9-1.x86_64\n")
        run("an older build installed: upgraded, the product applies it by itself", 0, forbidden=("cli",))
        (t / "installed").write_text("name-9.9-1.x86_64\n")
        assert (t / "state/installed-release.json").is_file(), "an upgrade records the verified release"
        (t / "state/installed-release.json").unlink()
        run("a newer build installed: never downgraded", 70, forbidden=("dnf", "cli"))
        assert not (t / "state/installed-release.json").exists(), "a refused run records nothing"
        (t / "installed").unlink()
        release(good, signer="other")
        run("manifest signed by another key", 65)
        release(good, tamper=lambda: (t / "rel" / manifest_name).open("a").write("artifact x y\n"))
        run("manifest changed after signing", 65)
        release(good, sign=False)
        run("signature missing", 70)
        release([line.replace("version 0.2.0", "version 0.1.9") for line in good])
        run("signed manifest of another release", 65)
        release([line.replace("platform el9", "platform el8") for line in good])
        run("signed manifest of another platform", 65)
        release(good + [f"artifact {'0' * 64} ../escape.el9.x86_64.rpm"])
        run("path in an artifact name", 65)
        release([line for line in good if "openlitespeed" not in line])
        run("OLS package missing from the manifest", 65)
        release([line for line in good if "php-redis" not in line])
        run("PHP redis package missing from the manifest", 65)
        release(good, tamper=lambda: (t / "rel" / "ols-cpanel-0.2.0-1.olscp1.el9.x86_64.rpm").write_bytes(b"evil"))
        run("artifact does not match the signed digest", 65)
        (t / "os-release").write_text('ID="ubuntu"\nVERSION_ID="22.04"\n')
        release(good)
        run("unsupported operating system", 69)
        (t / "os-release").write_text('ID="almalinux"\nVERSION_ID="7.9"\n')
        run("unsupported release", 69)
        (t / "os-release").write_text('ID="rocky"\nVERSION_ID="9.6"\n')
        run("Rocky Linux (not tested for this release)", 69)
        (t / "os-release").write_text('ID="almalinux"\nVERSION_ID="8.10"\n')
        run("release 8 (not built or tested for this release)", 69)
        subprocess.run([shutil.which("gpgconf") or "/usr/bin/gpgconf", "--homedir", str(t / "keys"), "--kill", "all"],
                       capture_output=True)
        subprocess.run([shutil.which("gpgconf") or "/usr/bin/gpgconf", "--homedir", str(t / "other"), "--kill", "all"],
                       capture_output=True)
    print("Installer behavior: verified release installs then prepares; bad signature, foreign key, tampered "
          "manifest or artifact, wrong release/platform, unsupported OS and another installed build change nothing and leave no files.")

for args, code in ((["--help"], 0), (["--bogus"], 64)):
    result = subprocess.run(["sh", str(installer), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert result.returncode == code, (args, result.returncode)
if os.geteuid() != 0:
    result = subprocess.run(["sh", str(installer)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert result.returncode == 77 and "root" in result.stderr, result
print("Installer entry: --help, usage errors and non-root refusal.")

# --- Operator guide: a template only, never an advertised working command (INST-02) ---------------------------
guide = (ROOT / "docs/installation.md").read_text()
assert "Use the command from the release notes" in guide and "Do not run the template as it is" in guide
command = next(line for line in guide.splitlines() if line.startswith("d=$(mktemp -d)"))
assert all(p in command for p in ("RELEASE_BASE_URL", "RELEASE_VERSION", "INSTALLER_SHA256", "sha256sum -c"))
assert not re.search(r"\|\s*(sudo\s+)?(ba)?sh\b", command) and "--proto '=https'" in command
assert not re.search(r"https://(?!example\.invalid)", guide)

# --- package.py on a temporary copy of the repository ------------------------------------------------------------
package = load_package(ROOT)
product = json.loads((HERE / "product.json").read_text())
assert set(product) == {"schema_version", "name", "version", "product_release", "release_inputs_sha256"}
assert product["name"] == "ols-cpanel" and re.fullmatch(r"[0-9]+(\.[0-9]+)*", product["version"])
assert package.builder_image() == json.loads((ROOT / "build/ols-source/source.json").read_text())["builder_image"]
with tempfile.TemporaryDirectory() as temp:
    copy = pathlib.Path(temp) / "repo"
    for name in [*package.RELEASE_INPUTS, "build/product", "build/ols-source/source.json"]:
        source, target = ROOT / name, copy / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "node_modules"))
        else:
            shutil.copy2(source, target)
    module = load_package(copy)
    recorded = dict(product, release_inputs_sha256=module.release_inputs_sha256(copy, activator=False))
    assert module.release(recorded, copy, activator=False) == f"1.olscp{product['product_release']}"
    refuses(module.release, recorded, copy, True, contains="bump product_release")
    bootstrap = copy / "src/bootstrap.php"
    bootstrap.write_text(bootstrap.read_text() + "\n// changed\n")
    refuses(module.release, recorded, copy, False, contains="bump product_release")
    refuses(module.release, dict(recorded, product_release=recorded["product_release"] + 1), copy, False,
            contains="record release_inputs_sha256")
    recorded["release_inputs_sha256"] = module.release_inputs_sha256(copy, activator=False)
    assert module.release(recorded, copy, activator=False)

    # Artifacts: missing, inconsistent and stale ones are refused with a clear message.
    payload = pathlib.Path(temp) / "payload"
    refuses(module.assemble, payload, copy, contains="run build/broker/build.sh first")
    broker_dir, ui = copy / "artifacts/broker", copy / "artifacts/ui"
    broker_dir.mkdir(parents=True)
    (broker_dir / "ols-cpanel-broker").write_bytes(b"\x7fELF broker")
    (broker_dir / "ols-cpanel-broker.sha256").write_text(
        hashlib.sha256(b"\x7fELF broker").hexdigest() + "  ols-cpanel-broker\n")
    refuses(module.assemble, payload, copy, contains="run build/ui/build.sh first")
    (ui / "assets").mkdir(parents=True)
    (ui / ".vite").mkdir()
    (ui / "assets/whm-1.js").write_text("whm")
    (ui / "assets/cpanel-1.js").write_text("cpanel")
    (ui / ".vite/manifest.json").write_text("{}")
    (ui / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((ui / n).read_bytes()).hexdigest()}  ./{n}\n"
                                           for n in ("assets/whm-1.js", "assets/cpanel-1.js", ".vite/manifest.json")))
    future = time.time() + 3600
    for path in [*broker_dir.iterdir(), ui / "SHA256SUMS"]:
        os.utime(path, (future, future))
    (ui / "assets/extra.js").write_text("unlisted")
    refuses(module.assemble, payload, copy, contains="does not match its SHA256SUMS")
    (ui / "assets/extra.js").unlink()
    (broker_dir / "ols-cpanel-broker").write_bytes(b"other")
    os.utime(broker_dir / "ols-cpanel-broker", (future, future))
    refuses(module.assemble, payload, copy, contains="does not match")
    (broker_dir / "ols-cpanel-broker").write_bytes(b"\x7fELF broker")
    os.utime(broker_dir / "ols-cpanel-broker", (future + 10, future + 10))
    os.utime(copy / "broker/src/main.rs", (future + 20, future + 20))
    refuses(module.assemble, payload, copy, contains="older than the broker sources")
    os.utime(broker_dir / "ols-cpanel-broker", (future + 30, future + 30))

    artifacts, activator = module.assemble(payload, copy)
    assert not activator and set(artifacts) == {"ols-cpanel-broker", "ui/SHA256SUMS"}
    prefix = payload / "usr/local/ols-cpanel"
    expect = {"bin/ols-cpanel": 0o755, "libexec/ols-cpanel.php": 0o644, "libexec/ols-cpanel-broker": 0o755,
              "lib/bootstrap.php": 0o644, "share/ui/SHA256SUMS": 0o644,
              "share/release-key.asc": 0o644, "share/release-key.fingerprint": 0o644, "share/ui/.vite/manifest.json": 0o644,
              "plugins/whm/index.cgi": 0o755, "plugins/whm/ols-cpanel.conf": 0o644,
              "plugins/whm/lib/BrokerClient.php": 0o644, "plugins/whm/lib/AssetManifest.php": 0o644,
              "plugins/whm/manifest.json": 0o644, "plugins/whm/assets/whm-1.js": 0o644,
              "plugins/cpanel/index.live.php": 0o644, "plugins/cpanel/install.json": 0o644,
              "plugins/cpanel/lib/HtaccessTranslator.php": 0o644, "plugins/cpanel/lib/HtaccessRewrite.php": 0o644,
              "plugins/cpanel/lib/i18n.htaccess.en.json": 0o644}
    for name, mode in expect.items():
        assert (prefix / name).is_file() and (prefix / name).stat().st_mode & 0o777 == mode, name
    # Updates from WHM trust only the release key shipped in the package: the committed public key and its fingerprint.
    assert (prefix / "share/release-key.asc").read_bytes() == (ROOT / "build/release/ols-cpanel-release-key.asc").read_bytes()
    assert (prefix / "share/release-key.fingerprint").read_text().strip() == "118DFA42F66A585D176C0B5148E26833CB82EAD1"
    cli = (prefix / "libexec/ols-cpanel.php").read_text()
    assert package.PACKAGED_BOOTSTRAP in cli and package.CLI_BOOTSTRAP not in cli
    for unit in UNITS:
        assert (payload / "usr/lib/systemd/system" / unit).read_bytes() == (HERE / unit).read_bytes()
    assert (payload / "usr/lib/sysusers.d/ols-cpanel.conf").is_file()
    assert all(p.stat().st_mode & 0o777 == 0o755 for p in payload.rglob("*") if p.is_dir())
    assert not [p for p in payload.rglob("*") if p.is_symlink() or p.name == "__pycache__"]

    # Every payload file is listed in %files, and every %files path exists in the payload.
    entries = []
    for line in spec.split("%files", 1)[1].splitlines():
        line = re.sub(r"%(attr|defattr)\([^)]*\)|%dir|%config\([^)]*\)|%license", "", line).strip()
        if line.startswith("/") or line.startswith("%{prefix_dir}"):
            entries.append(line.replace("%{prefix_dir}", "/usr/local/ols-cpanel"))
    files = ["/" + p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file()]
    uncovered = [f for f in files if not any(f == e or f.startswith(e + "/") for e in entries)]
    assert not uncovered, uncovered
    missing = [e for e in entries if not (payload / e.lstrip("/")).exists() and "activator" not in e]
    assert not missing, missing
print("package.py: release guard refuses changed inputs without a new release and recorded digest; payload "
      "layout, modes, CLI bootstrap path and %files coverage checked on a temporary copy.")

current = package.release_inputs_sha256(ROOT)
if current == product["release_inputs_sha256"]:
    print(f"ols-cpanel packaging inputs match release {product['product_release']}.")
else:
    print(f"NOTE: ols-cpanel packaging inputs changed since release {product['product_release']}; package.py will "
          "refuse until product_release is bumped and the new release_inputs_sha256 is recorded.")
