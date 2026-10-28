#!/usr/bin/python3
"""Records every input the lab compiler reads from cPanel (command, argv, exit code, output) and the
compiled result, so the product compiler can be checked byte-for-byte against the lab-proven one on real
data. Read-only on the server. Usage: record_compile_inputs.py <out.json> [--production] [--security=<input.json>]
--security (FV-02) also records the WAF and security inputs (cPanel's ModSecurity files, every included vendor
configuration and data file) with that product security input; the recording then carries it as "security"
(tests/compile_replay.php passes it to the product builder)."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ols_ownership_probe as owner
import tenant_isolation_probe as iso

def main():
    out, production = pathlib.Path(sys.argv[1]), "--production" in sys.argv[2:]
    options = [a for a in sys.argv[2:] if a.startswith("--security=")]
    security = json.loads(pathlib.Path(options[0].split("=", 1)[1]).read_text()) if options else None
    calls = []

    def step(name, command, limit=300):
        record = owner.invoke(command, limit)
        calls.append({"name": name, "argv": command, "exit_code": record["exit_code"], "stdout": record["stdout"]})
        return record

    summary = {}
    compiled = iso.compile_lab(step, summary, production=production, security=security)
    extra = {} if security is None else {"security": security}
    out.write_text(json.dumps({"production": production, "calls": calls, "summary": summary, **extra,
                               "compiled": {"config": compiled["config"], "vhconf": compiled["vhconf"]}},
                              indent=1, sort_keys=True))
    print(f"{len(calls)} calls recorded")

if __name__ == "__main__":
    main()
