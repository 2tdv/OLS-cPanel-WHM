#!/usr/bin/python3
"""Product-side structural validation of a generated OLS plain configuration (OLS-05).
Runs before the binary test: OLS 1.9.3 `-t` does not configure listeners, so it cannot
reject invalid listener addresses. Also enforces the product's mandatory server policy."""
import ipaddress
import json
import pathlib
import re
import sys

REQUIRED_SERVER = {"disableWebAdmin": "1", "autoDetectCdn": "0", "enableUpdateCheck": "0"}
REQUIRED_BLOCKS = ["CGIRLimit"]

def parse(text):
    """Return (root, errors). Nodes are dicts: {"type", "name", "values": {k: [v]}, "children": []}."""
    root = {"type": "root", "name": "", "values": {}, "children": [], "line": 0}
    stack, errors = [root], []
    for number, raw in enumerate(text.splitlines(), 1):
        # Only whole-line comments: values such as rewrite rules may contain "#".
        line = "" if raw.lstrip().startswith("#") else raw.strip()
        if not line:
            continue
        if line == "}":
            if len(stack) == 1:
                errors.append(f"line {number}: unexpected '}}'")
            else:
                stack.pop()
            continue
        if line.endswith("{"):
            head = line[:-1].split()
            node = {"type": head[0] if head else "", "name": " ".join(head[1:]), "values": {},
                    "children": [], "line": number}
            stack[-1]["children"].append(node)
            stack.append(node)
            continue
        key, _, value = line.partition(" ")
        stack[-1]["values"].setdefault(key, []).append(value.strip())
    for node in stack[1:]:
        errors.append(f"line {node['line']}: block '{node['type']} {node['name']}' is not closed")
    return root, errors

def valid_address(address):
    host, sep, port = address.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        return False
    if host in ("*", "[ANY]"):
        return True
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def lint(text, require_policy=True):
    root, errors = parse(text)
    for node in root["children"]:
        if node["type"] == "listener":
            address = (node["values"].get("address") or [""])[0]
            if not valid_address(address):
                errors.append(f"line {node['line']}: listener {node['name']} has invalid address '{address}'")
            if (node["values"].get("secure") or ["0"])[0] == "1":
                for key in ("keyFile", "certFile"):
                    if not node["values"].get(key):
                        errors.append(f"line {node['line']}: secure listener {node['name']} lacks {key}")
    if require_policy:
        for key, expected in REQUIRED_SERVER.items():
            actual = root["values"].get(key)
            if actual != [expected]:
                errors.append(f"server directive {key} must be exactly '{expected}' (found {actual})")
        present = {child["type"] for child in root["children"]}
        for block in REQUIRED_BLOCKS:
            if block not in present:
                errors.append(f"required server block {block} is missing")
    return errors

if __name__ == "__main__":
    problems = lint(pathlib.Path(sys.argv[1]).read_text())
    print(json.dumps({"valid": not problems, "errors": problems}, indent=2))
    sys.exit(0 if not problems else 1)
