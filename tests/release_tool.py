#!/usr/bin/python3
"""build/release/release.py: a release built with a throwaway key installs through the installer it produced
(stubbed host, like tests/product_package.py), and the tool refuses every malformed input. The committed release
key is a public key only and matches its fingerprint. The packages are rpm-signed before the manifests are written
(a stand-in signer here; the real one is rpmsign in the pinned builder image, whose command line is checked)."""
import hashlib
import importlib.util
import os
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release", ROOT / "build/release/release.py")
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)
quiet = {"capture_output": True, "check": True}

# The committed key: public only, 40-character fingerprint, and the fingerprint is the key's own.
key_text = rel.PUBLIC_KEY.read_text()
assert "PRIVATE" not in key_text and key_text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
fpr = rel.FINGERPRINT.read_text().strip()
with tempfile.TemporaryDirectory() as home:
    os.chmod(home, 0o700)
    env = {"PATH": "/usr/bin:/bin", "GNUPGHOME": home}
    subprocess.run(["gpg", "--batch", "--import", str(rel.PUBLIC_KEY)], env=env, **quiet)
    listed = subprocess.run(["gpg", "--batch", "--with-colons", "--fingerprint"], env=env, **quiet).stdout.decode()
    assert [l.split(":")[9] for l in listed.splitlines() if l.startswith("fpr:")][0] == fpr
    assert subprocess.run(["gpg", "--batch", "--list-secret-keys"], env=env, **quiet).stdout == b""

with tempfile.TemporaryDirectory() as tmp:
    t = pathlib.Path(tmp)
    keys = t / "keys"
    (keys / "gnupg").mkdir(parents=True)
    os.chmod(keys / "gnupg", 0o700)
    (keys / "passphrase.txt").write_text("test passphrase\n")
    genv = {"PATH": "/usr/bin:/bin", "GNUPGHOME": str(keys / "gnupg")}
    subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-file", str(keys / "passphrase.txt"),
                    "--quick-generate-key", "Test Release <test@example.invalid>", "rsa2048", "sign", "1d"], env=genv, **quiet)
    colons = subprocess.run(["gpg", "--batch", "--with-colons", "--fingerprint"], env=genv, **quiet).stdout.decode()
    test_fpr = [l.split(":")[9] for l in colons.splitlines() if l.startswith("fpr:")][0]
    (t / "pub.asc").write_bytes(subprocess.run(["gpg", "--batch", "--armor", "--export", test_fpr], env=genv, **quiet).stdout)
    (t / "fpr").write_text(test_fpr + "\n")
    rel.PUBLIC_KEY, rel.FINGERPRINT = t / "pub.asc", t / "fpr"
    pkgs = t / "pkgs"
    pkgs.mkdir()
    rpms = {"ols-cpanel-openlitespeed-1.9.3-1.olscp9.el9.x86_64.rpm": b"server",
            "ols-cpanel-php-redis-6.3.0-1.olscp1.el9.x86_64.rpm": b"phpredis",
            "ols-cpanel-0.2.0-1.olscp38.el9.x86_64.rpm": b"product"}
    for name, data in rpms.items():
        (pkgs / name).write_bytes(data)
    paths = [pkgs / n for n in rpms]

    def refused(label, *args, **kwargs):
        try:
            rel.build(*args, **kwargs)
        except rel.ReleaseError:
            return
        raise AssertionError(f"not refused: {label}")

    base = "https://release.example.invalid"
    refused("malformed version", "0.2.0-beta", base, paths, keys, t / "o1")
    refused("http base URL", "0.2.0", "http://x.invalid", paths, keys, t / "o2")
    refused("product of another version", "0.3.0", base, paths, keys, t / "o3")
    refused("redis package missing", "0.2.0", base, paths[::2], keys, t / "o4")
    refused("not a package name", "0.2.0", base, [*paths, t / "fpr"], keys, t / "o5")
    other = t / "other"
    (other / "gnupg").mkdir(parents=True)
    os.chmod(other / "gnupg", 0o700)
    (other / "passphrase.txt").write_text("x\n")
    subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "x", "--quick-generate-key",
                    "Other <o@example.invalid>", "rsa2048", "sign", "1d"], env={**genv, "GNUPGHOME": str(other / "gnupg")}, **quiet)
    refused("a key directory without the committed key", "0.2.0", base, paths, other, t / "o6")
    assert not any((t / f"o{i}").exists() for i in range(1, 7)), "a refusal left files behind"

    # The rpm signer: a stand-in that appends a marker (rpmsign changes the package file in place), and the key id it leaves.
    signed_calls = []

    def fake_signer(files, key_dir, signer_fpr):
        signed_calls.append(([f.name for f in files], key_dir, signer_fpr))
        for f in files:
            with open(f, "ab") as handle:
                handle.write(b"+rpmsig")

    def fake_key_id(path):
        return test_fpr[-16:].lower() if path.read_bytes().endswith(b"+rpmsig") else None

    refused("a signer that leaves a package unsigned", "0.2.0", base, paths, keys, t / "o7", signer=lambda *a: None, key_id=fake_key_id)
    assert not (t / "o7").exists(), "a failed signature left a release directory behind"
    out = t / "release"
    result = rel.build("0.2.0", base, paths, keys, out, signer=fake_signer, key_id=fake_key_id)
    refused("an existing release directory", "0.2.0", base, paths, keys, out)
    assert result["platforms"] == ["el9"] and result["fingerprint"] == test_fpr and result["rpm_signed"] is True
    assert signed_calls == [(list(rpms), keys, test_fpr)], signed_calls
    assert all((pkgs / n).read_bytes() == data for n, data in rpms.items()), "the input packages are never changed"
    manifest = out / "ols-cpanel-0.2.0.el9.x86_64.manifest"
    lines = manifest.read_text().splitlines()
    assert lines[:3] == ["ols-cpanel-release-manifest 1", "version 0.2.0", "platform el9.x86_64"]
    # The manifest lists the digests of the signed packages, the ones published.
    assert lines[3:] == [f"artifact {hashlib.sha256(rpms[n] + b'+rpmsig').hexdigest()} {n}" for n in rpms]
    unsigned = rel.build("0.2.0", base, paths, keys, t / "unsigned", signer=False)
    assert unsigned["rpm_signed"] is False and (t / "unsigned/ols-cpanel-0.2.0-1.olscp38.el9.x86_64.rpm").read_bytes() == b"product"
    # The real signer: rpmsign in the pinned builder image, the key directory read-only and never relabelled.
    argv = rel.sign_command(rel.signer_image(), keys, out, test_fpr, list(rpms))
    assert argv[:2] == ["podman", "run"] and "--rm" in argv and argv[argv.index("--security-opt") + 1] == "label=disable"
    assert f"{keys}:/key:ro" in argv and f"{out}:/rpms" in argv and re.fullmatch(r".+@sha256:[0-9a-f]{64}", argv[argv.index(f"{out}:/rpms") + 1])
    assert argv[-4:] == [test_fpr, *rpms] and "rpmkeys --checksig" in rel.SIGN_SCRIPT and "--passphrase-file /key/passphrase.txt" in rel.SIGN_SCRIPT
    for bad in (["x.rpm"], ["ols-cpanel-0.2.0-1.el9.x86_64.rpm; id"]):
        try:
            rel.sign_command("img@sha256:" + "0" * 64, keys, out, test_fpr, bad)
            raise AssertionError(f"not refused: {bad}")
        except rel.ReleaseError:
            pass
    installer = (out / "install.sh").read_text()
    assert not any(old in installer for old, _ in rel.PLACEHOLDERS) and 'RELEASE_VERSION="0.2.0"' in installer
    assert f'RELEASE_BASE_URL="{base}"' in installer
    assert f'RELEASE_KEY_FINGERPRINT="{test_fpr}"' in installer and (t / "pub.asc").read_text() in installer
    sums = dict(reversed(l.split("  ")) for l in (out / "SHA256SUMS").read_text().splitlines())
    assert set(sums) == {p.name for p in out.iterdir()} - {"SHA256SUMS", "RELEASE-NOTES.md"}
    assert all(hashlib.sha256((out / n).read_bytes()).hexdigest() == d for n, d in sums.items())
    assert result["installer_sha256"] in (out / "RELEASE-NOTES.md").read_text()
    subprocess.run(["sh", "-n", str(out / "install.sh")], check=True)
    # The installer's own signature verifies against the release key alone (the stricter command of the release notes).
    with tempfile.TemporaryDirectory() as vhome:
        os.chmod(vhome, 0o700)
        venv = {"PATH": "/usr/bin:/bin", "GNUPGHOME": vhome}
        subprocess.run(["gpg", "--batch", "--import", str(t / "pub.asc")], env=venv, **quiet)
        status = subprocess.run(["gpg", "--batch", "--status-fd", "1", "--verify", str(out / "install.sh.asc"), str(out / "install.sh")],
                                env=venv, **quiet).stdout.decode()
        assert any(l.split()[1:2] == ["VALIDSIG"] and l.split()[-1] == test_fpr for l in status.splitlines() if l.startswith("[GNUPG:]"))
    assert f"--recv-keys {test_fpr}" in (out / "RELEASE-NOTES.md").read_text()

    # The produced installer verifies and installs the produced release (host stubbed; downloads are copies).
    (t / "bin").mkdir()
    calls = t / "calls"
    stubs = {"dnf": "", "cpanel": "echo 11.138.0.19\n",
             "cli": 'case "$*" in *--prepare*) printf \'{\\n    "result": "prepared",\\n    "plan": "p20261028120000-0a1b2c"\\n}\\n\';; esac\n',
             "rpm": 'case "$*" in *--quiet*) exit 1;; -qp*NAME*) echo name;; -qp*) echo name-1-1.x86_64;; esac\n'}
    for name, body in stubs.items():
        (t / "bin" / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "{calls}"\n{body}')
    (t / "os-release").write_text('ID="almalinux"\nVERSION_ID="9.8"\n')
    (t / "work").mkdir()
    copy = installer
    for old, new in [('[ "$(id -u)" = 0 ]', "true"), ("/etc/os-release", str(t / "os-release")),
                     ('[ "$(uname -m)" = x86_64 ]', "true"), ("[ -x /usr/local/cpanel/cpanel ]", "true"),
                     ("$(/usr/local/cpanel/cpanel -V 2>/dev/null)", f"$(sh {t}/bin/cpanel -V)"),
                     ("[ -x /usr/local/cpanel/3rdparty/php/84/bin/php ]", "true"),
                     ("/var/tmp/ols-cpanel-install.", f"{t}/work/ols-cpanel-install."),
                     ("/usr/bin/dnf --assumeyes", f"sh {t}/bin/dnf --assumeyes"), ("/usr/bin/rpm ", f"sh {t}/bin/rpm "),
                     ("CLI=/usr/local/ols-cpanel/bin/ols-cpanel", f"CLI={t}/bin/cli"), ('[ -x "$CLI" ]', "true"),
                     ('"$CLI" install', 'sh "$CLI" install'),
                     ("    /usr/bin/curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent "
                      "--show-error --location \\\n        --retry 3 --connect-timeout 20 --max-filesize "
                      '"$MAX_DOWNLOAD" --output "$2" "$1" \\\n', f'    cp "{out}/${{1##*/}}" "$2" \\\n')]:
        assert old in copy, old
        copy = copy.replace(old, new)
    (t / "install.sh").write_text(copy)
    run = subprocess.run(["sh", str(t / "install.sh"), "--prepare-only"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert run.returncode == 0, run.stderr[-800:]
    assert f"release manifest signature verified (key {test_fpr})" in run.stderr, run.stderr[-800:]
    assert "dnf --assumeyes" in calls.read_text() and "cli install --prepare" in calls.read_text()
    # A package changed after the release was signed is refused before anything is installed.
    calls.unlink()
    (out / paths[2].name).write_bytes(b"tampered")
    run = subprocess.run(["sh", str(t / "install.sh"), "--prepare-only"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert run.returncode == 65 and not re.search(r"^dnf ", calls.read_text() if calls.exists() else "", re.M), run.stderr[-400:]
print("Release tool: rpm-signed packages, signed manifests of the signed packages, filled installer and digests; the produced "
      "installer verifies and installs its release and refuses a changed package; malformed inputs and foreign keys refused; "
      "the committed key is public only.")
