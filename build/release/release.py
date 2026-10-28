#!/usr/bin/python3
"""Build a signed public release of OLS-cPanel-WHM (plan 18.2: INST-01/02/03).

Input: the release version and the built packages (ols-cpanel, ols-cpanel-openlitespeed and ols-cpanel-php-redis for
each platform row, el8 and/or el9). Output, in artifacts/release/<version>/, everything a GitHub release of that tag
carries:

  install.sh                                  the installer with the version, base URL, fingerprint and public key filled in
  install.sh.asc                              its detached signature by the release key
  <package>.rpm                               the packages, unchanged
  ols-cpanel-<version>.<el9>.x86_64.manifest  one manifest per platform row (the format install.sh parses)
  ....manifest.asc                            its detached signature by the release key
  SHA256SUMS                                  digests of every file above
  RELEASE-NOTES.md                            the one-command install line with the installer's digest

Trust: install.sh trusts only the key embedded in it, which is the public key committed in this directory
(ols-cpanel-release-key.asc); the tool refuses a signing key that is not that key, so a release can never be
signed by another key by mistake. The secret key never enters the repository: it lives in the release owner's key
directory (default ~/ols-cpanel-release-key-2tdv: gnupg/ home, passphrase.txt), used through gpg with that home only.
Nothing is uploaded; the owner attaches the files to the GitHub release named exactly <version>.
"""
import argparse
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
PUBLIC_KEY = HERE / "ols-cpanel-release-key.asc"
FINGERPRINT = HERE / "ols-cpanel-release-key.fingerprint"
INSTALLER = ROOT / "build/product/install.sh"
DEFAULT_BASE = "https://github.com/2tdv/OLS-cPanel-WHM/releases/download"
DEFAULT_KEY_DIR = pathlib.Path.home() / "ols-cpanel-release-key-2tdv"
MANIFEST_FORMAT = "ols-cpanel-release-manifest 1"
VERSION = re.compile(r"[0-9]+(\.[0-9]+)*")
# The package names install.sh accepts (its manifest check), by platform row.
RPM = re.compile(r"(?P<name>ols-cpanel(?:-openlitespeed|-php-redis)?)-(?P<version>[0-9][A-Za-z0-9._+]*)-"
                 r"[A-Za-z0-9._+]+\.(?P<el>el[89])\.x86_64\.rpm")
PLACEHOLDERS = [('RELEASE_VERSION="RELEASE_VERSION"', 'RELEASE_VERSION="{version}"'),
                ('RELEASE_BASE_URL="RELEASE_BASE_URL"', 'RELEASE_BASE_URL="{base}"'),
                ('RELEASE_KEY_FINGERPRINT="RELEASE_KEY_FINGERPRINT"', 'RELEASE_KEY_FINGERPRINT="{fpr}"'),
                ("RELEASE KEY PLACEHOLDER: replace this line with the ASCII-armored release public key.\n", "{key}")]


class ReleaseError(Exception):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def gpg(key_dir, *args, data=None):
    """gpg with the key directory's own home only (never the caller's keyring)."""
    env = {"PATH": "/usr/bin:/bin", "GNUPGHOME": str(key_dir / "gnupg"), "LC_ALL": "C"}
    result = subprocess.run(["/usr/bin/gpg", "--batch", "--no-tty", *args], input=data, capture_output=True, env=env)
    if result.returncode != 0:
        raise ReleaseError("gpg failed: " + result.stderr.decode(errors="replace").strip()[-400:])
    return result.stdout


def committed_key():
    fpr = FINGERPRINT.read_text().strip()
    if not re.fullmatch(r"[0-9A-F]{40}", fpr):
        raise ReleaseError(f"{FINGERPRINT} does not hold a 40-character fingerprint")
    key = PUBLIC_KEY.read_text()
    if not key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n") or not key.endswith("-----END PGP PUBLIC KEY BLOCK-----\n"):
        raise ReleaseError(f"{PUBLIC_KEY} is not an ASCII-armored public key")
    return fpr, key


def group_packages(rpms, version):
    """{el9: [paths]} with exactly one of each package per row, the product at the release version."""
    rows = {}
    for path in rpms:
        match = RPM.fullmatch(path.name)
        if match is None or not path.is_file():
            raise ReleaseError(f"not a release package file: {path}")
        row = rows.setdefault(match["el"], {})
        if match["name"] in row:
            raise ReleaseError(f"two {match['name']} packages for {match['el']}")
        if match["name"] == "ols-cpanel" and match["version"] != version:
            raise ReleaseError(f"{path.name} is not version {version}")
        row[match["name"]] = path
    if not rows:
        raise ReleaseError("no packages given")
    for el, row in rows.items():
        missing = {"ols-cpanel", "ols-cpanel-openlitespeed", "ols-cpanel-php-redis"} - set(row)
        if missing:
            raise ReleaseError(f"{el}: missing {', '.join(sorted(missing))}")
    return {el: [row[n] for n in ("ols-cpanel-openlitespeed", "ols-cpanel-php-redis", "ols-cpanel")] for el, row in sorted(rows.items())}


def build(version, base, rpms, key_dir, out):
    if not VERSION.fullmatch(version):
        raise ReleaseError(f"malformed version {version!r}")
    if not re.fullmatch(r"https://[A-Za-z0-9._~/-]+", base) or base.endswith("/"):
        raise ReleaseError(f"the base URL must be https without a trailing slash: {base!r}")
    fpr, key = committed_key()
    passphrase = key_dir / "passphrase.txt"
    if not passphrase.is_file():
        raise ReleaseError(f"{passphrase} is missing")
    listed = [line.split(":")[9] for line in gpg(key_dir, "--with-colons", "--fingerprint", "--list-secret-keys").decode().splitlines()
              if line.startswith("fpr:")]
    if fpr not in listed:
        raise ReleaseError(f"the key directory has no secret key {fpr} (the committed release key)")
    rows = group_packages(rpms, version)
    if out.exists():
        raise ReleaseError(f"{out} exists; a release directory is never overwritten")
    out.mkdir(parents=True)
    installer = INSTALLER.read_text()
    for old, new in PLACEHOLDERS:
        if installer.count(old) != 1:
            raise ReleaseError(f"install.sh placeholder not found exactly once: {old.strip()}")
        installer = installer.replace(old, new.format(version=version, base=base, fpr=fpr, key=key))
    (out / "install.sh").write_text(installer)
    # The installer itself is signed too, so it can be verified before it runs with a key obtained independently of the
    # release page (a key server, by fingerprint): replacing install.sh and its published digest together is caught.
    gpg(key_dir, "--pinentry-mode", "loopback", "--passphrase-file", str(passphrase), "--local-user", fpr,
        "--armor", "--detach-sign", "--output", str(out / "install.sh.asc"), str(out / "install.sh"))
    for el, paths in rows.items():
        lines = [MANIFEST_FORMAT, f"version {version}", f"platform {el}.x86_64"]
        for path in paths:
            shutil.copyfile(path, out / path.name)
            lines.append(f"artifact {sha256(out / path.name)} {path.name}")
        manifest = out / f"ols-cpanel-{version}.{el}.x86_64.manifest"
        manifest.write_text("\n".join(lines) + "\n")
        gpg(key_dir, "--pinentry-mode", "loopback", "--passphrase-file", str(passphrase), "--local-user", fpr,
            "--armor", "--detach-sign", "--output", f"{manifest}.asc", str(manifest))
        status = gpg(key_dir, "--status-fd", "1", "--verify", f"{manifest}.asc", str(manifest)).decode()
        if not any(l.split()[1:2] == ["VALIDSIG"] and l.split()[-1] == fpr for l in status.splitlines() if l.startswith("[GNUPG:]")):
            raise ReleaseError(f"{manifest.name}: the signature does not verify against {fpr}")
    files = sorted(p for p in out.iterdir() if p.is_file())
    (out / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    digest = sha256(out / "install.sh")
    (out / "RELEASE-NOTES.md").write_text(
        f"## OLS-cPanel-WHM {version}\n\nInstall on a cPanel/WHM server (AlmaLinux "
        f"{' and '.join(el[2:] for el in rows)}, x86_64), as root:\n\n```sh\n"
        f"d=$(mktemp -d) && curl --proto '=https' --tlsv1.2 -fsSL -o \"$d/install.sh\" \"{base}/{version}/install.sh\" "
        f"&& echo \"{digest}  $d/install.sh\" | sha256sum -c - && sh \"$d/install.sh\"; rm -rf \"$d\"\n```\n\n"
        f"Installer SHA-256: `{digest}`\n\nRelease signing key fingerprint: `{fpr}`\n"
        "(the same key as `build/release/ols-cpanel-release-key.asc` in the repository).\n\n"
        "Stricter: verify the installer's own signature with the release key fetched from keyserver.ubuntu.com by its\n"
        "fingerprint (independent of this page) before running it:\n\n```sh\n"
        f"d=$(mktemp -d) && mkdir -m 700 \"$d/g\" && export GNUPGHOME=\"$d/g\" && "
        f"curl --proto '=https' --tlsv1.2 -fsSL -o \"$d/install.sh\" \"{base}/{version}/install.sh\" && "
        f"curl --proto '=https' --tlsv1.2 -fsSL -o \"$d/install.sh.asc\" \"{base}/{version}/install.sh.asc\" && "
        f"gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys {fpr} && gpg --verify \"$d/install.sh.asc\" \"$d/install.sh\" && "
        "sh \"$d/install.sh\"; unset GNUPGHOME; rm -rf \"$d\"\n```\n")
    return {"version": version, "directory": str(out), "fingerprint": fpr, "installer_sha256": digest,
            "platforms": sorted(rows), "files": sorted(p.name for p in out.iterdir())}


def main():
    parser = argparse.ArgumentParser(description="Build a signed OLS-cPanel-WHM release directory (nothing is uploaded).")
    parser.add_argument("--version", required=True, help="release version, the ols-cpanel package version (e.g. 0.2.0)")
    parser.add_argument("--base-url", default=DEFAULT_BASE, help=f"download base, the tag is appended (default {DEFAULT_BASE})")
    parser.add_argument("--key-dir", type=pathlib.Path, default=DEFAULT_KEY_DIR, help="release owner's key directory")
    parser.add_argument("--out", type=pathlib.Path, help="output directory (default artifacts/release/<version>)")
    parser.add_argument("rpm", nargs="+", type=pathlib.Path, help="the package files")
    args = parser.parse_args()
    if os.geteuid() == 0:
        print("Run as the release owner, not root.", file=sys.stderr)
        return 77
    try:
        result = build(args.version, args.base_url, args.rpm, args.key_dir, args.out or ROOT / "artifacts/release" / args.version)
    except (ReleaseError, OSError) as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 1
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
