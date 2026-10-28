#!/usr/bin/python3
"""Compare two parity probe results; report every difference and classify expected SAPI ones."""
import json
import sys

# Differences inherent to the server API rather than tenant-visible configuration.
EXPECTED_TOP = {"sapi"}
EXPECTED_INI_PREFIXES = ("cgi.", "fastcgi.", "cli.")
EXPECTED_SERVER = {"GATEWAY_INTERFACE", "REDIRECT_STATUS", "PATH_TRANSLATED"}
# The SAPI registers itself as an extension under its own name.
SAPI_EXTENSIONS = {"cgi-fcgi", "litespeed", "apache2handler", "fpm-fcgi", "cli"}
# EA4's litespeed SAPI build also loads readline (source of the cli.* ini entries); it has no
# web-facing effect but is reported by name in the summary rather than silently dropped.
SAPI_BUNDLED = {"readline"}

def _absolute(path, cwd):
    """suPHP reports files of a "." scan directory as "./name"; they are the same files under cwd."""
    return cwd.rstrip("/") + path[1:] if isinstance(path, str) and path.startswith("./") and cwd else path

def _normalized(result):
    cwd = result.get("cwd")
    out = dict(result)
    out["ini_loaded"] = _absolute(result.get("ini_loaded"), cwd)
    if isinstance(result.get("ini_scanned"), list):
        out["ini_scanned"] = [_absolute(p, cwd) for p in result["ini_scanned"]]
    return out

def compare(reference, candidate, test_binding=None, expected_fields=()):
    """test_binding maps server fields to the value the experiment's test listener must produce;
    expected_fields are top-level fields whose difference is known and documented for this case."""
    test_binding = test_binding or {}
    reference, candidate = _normalized(reference), _normalized(candidate)
    diffs = []
    for key in sorted(set(reference) | set(candidate)):
        if key in ("ini", "server"):
            continue
        left, right = reference.get(key), candidate.get(key)
        if key == "extensions" and isinstance(left, list) and isinstance(right, list):
            left = sorted(set(left) - SAPI_EXTENSIONS - SAPI_BUNDLED)
            right = sorted(set(right) - SAPI_EXTENSIONS - SAPI_BUNDLED)
        if left != right:
            diffs.append({"field": key, "reference": reference.get(key), "candidate": candidate.get(key),
                          "expected": key in EXPECTED_TOP or key in expected_fields})
    for section, expected in (("ini", lambda k: k.startswith(EXPECTED_INI_PREFIXES)),
                              ("server", lambda k: k in EXPECTED_SERVER
                               or candidate.get("server", {}).get(k) == test_binding.get(k, object()))):
        left, right = reference.get(section, {}), candidate.get(section, {})
        for key in sorted(set(left) | set(right)):
            if left.get(key) != right.get(key):
                diffs.append({"field": section + "." + key, "reference": left.get(key),
                              "candidate": right.get(key), "expected": expected(key)})
    return {"equivalent": not any(not d["expected"] for d in diffs), "differences": diffs}

if __name__ == "__main__":
    with open(sys.argv[1]) as a, open(sys.argv[2]) as b:
        report = compare(json.load(a), json.load(b))
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["equivalent"] else 1)
