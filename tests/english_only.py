#!/usr/bin/python3
"""The product is English-only (plan UIX-05): no Arabic-script text in any tracked or new file."""
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARABIC_SCRIPT = re.compile(r"[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufeff]")
files = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard", "-z"],
                       capture_output=True, check=True).stdout.decode().split("\0")
found = []
for name in filter(None, files):
    path = ROOT / name
    if not path.is_file():
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for number, line in enumerate(text.splitlines(), 1):
        if ARABIC_SCRIPT.search(line):
            found.append(f"{name}:{number}")
            break
assert not found, "non-English (Arabic-script) text in: " + ", ".join(found)
print("English-only check passed.")
