#!/usr/bin/python3
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/vm-qualification"))
import ols_package_audit as audit

ok = audit.parse_checksig("""x.rpm:
    Header V4 DSA/SHA256 Signature, key ID 83084d0e: OK
    Header SHA256 digest: OK
    Payload SHA256 digest: OK
""")
assert ok["verified"] and ok["weak_algorithm"]
for text in ["Header V4 DSA/SHA256 Signature, key ID 83084d0e: NOKEY\nHeader SHA256 digest: OK",
             "Header V4 RSA/SHA256 Signature, key ID eda1f085: OK\nPayload SHA256 digest: BAD",
             "Header SHA256 digest: OK"]:
    assert not audit.parse_checksig(text)["verified"]
try:
    audit.parse_checksig("unexpected output")
    raise AssertionError("Unknown checksig output accepted")
except ValueError:
    pass

listeners = audit.parse_listeners("""listener Default{
    address                  *:8088
    secure                   0
}
listener Local {
  address 127.0.0.1:8089
}""")
assert [(l["name"], l["address"], l["wildcard"]) for l in listeners] == [
    ("Default", "*:8088", True), ("Local", "127.0.0.1:8089", False)]
try:
    audit.parse_listeners("listener Open{\n address *:1\n")
    raise AssertionError("Unterminated listener accepted")
except ValueError:
    pass

risks = audit.classify_scriptlets("""useradd -r lsadm
$LSWS_HOME/admin/misc/rc-inst.sh > /dev/null 2>&1
  echo "WebAdmin user/password is admin/$ADMIN_PASS" > "$PASSFILE"
posttrans scriptlet: systemctl restart lsws > /dev/null 2>&1""")
assert risks == ["creates-system-user", "enables-boot-service", "prints-admin-secret", "starts-service"]
assert audit.classify_scriptlets("exit 0") == []

blocked = audit.verdict(ok, risks, listeners, ["lsphp83"])
assert not blocked["vendor_install_allowed"] and blocked["payload_candidate"]
assert {"scriptlet-starts-service", "default-wildcard-listener", "hard-requires-vendor-lsphp",
        "weak-signature-algorithm-requires-pinned-digest"} <= set(blocked["reasons"])
clean = audit.verdict(dict(ok, weak_algorithm=False), [], listeners[1:], [])
assert clean["vendor_install_allowed"] and not clean["reasons"]
assert not audit.verdict(dict(ok, verified=False), [], [], [])["payload_candidate"]

with tempfile.NamedTemporaryFile() as fake:
    fake.write(b"not an rpm")
    fake.flush()
    try:
        audit.audit(pathlib.Path(fake.name), "0" * 64, [])
        raise AssertionError("Digest mismatch accepted")
    except ValueError as exc:
        assert "digest mismatch" in str(exc)
result = subprocess.run([sys.executable, str(ROOT / "build/vm-qualification/ols_package_audit.py"),
                         "--rpm", "/nonexistent", "--sha256", "XYZ", "--key", "/nonexistent"],
                        capture_output=True, text=True)
assert result.returncode == 64 and not result.stdout
print("OLS package audit parsing, verdict and digest-refusal checks passed.")
