#!/usr/bin/python3
import json
import pathlib
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "build/vm-qualification/ws_echo.py"
sys.path.insert(0, str(TOOL.parent))
import ws_echo

assert ws_echo.accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="  # RFC 6455 example
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
server = subprocess.Popen([sys.executable, "-I", str(TOOL), "server", "--port", str(port)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 1).close()
            break
        except OSError:
            time.sleep(0.1)
    # A path and nonce long enough to need the 16-bit frame length.
    path, nonce = "/x/" + "a" * 200 + "?q=1", "n" * 150
    out = subprocess.run([sys.executable, "-I", str(TOOL), "client", "--connect", f"127.0.0.1:{port}", "--host", "h.test",
                          "--path", path, "--nonce", nonce], capture_output=True, text=True, check=True).stdout
    report = json.loads(out)
    assert report["status"] == "101" and report["accept_ok"] and report["echo_ok"], report
    assert report["backend_saw"]["request_line"] == f"GET {path} HTTP/1.1" and report["backend_saw"]["host"] == "h.test"
finally:
    server.terminate()
    server.wait(10)
print("WebSocket echo tool handshake and framing checks passed.")
