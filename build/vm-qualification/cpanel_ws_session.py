#!/usr/bin/python3
"""Authenticated cPanel WebSocket check (G0-E, OLS-17), owner-approved for the lab tenant olscpa:
create a cPanel session through WHM, log in via the cpanel.<domain> proxy name, and request a
WebSocket upgrade (e.g. the Terminal, /websocket/Shell) with that session.
Usage: cpanel_ws_session.py <connect-ip> <port> <host> <ws-path-suffix>
The session token and cookies are never printed or stored; only statuses and frame metadata."""
import base64, http.client, json, os, socket, ssl, subprocess, sys, urllib.parse

ip, port, host, suffix = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
data = json.loads(subprocess.run(["/usr/bin/sudo", "-n", "/usr/local/cpanel/bin/whmapi1", "--output=json",
                                  "create_user_session", "user=olscpa", "service=cpaneld"],
                                 capture_output=True, text=True, check=True).stdout)["data"]
url = urllib.parse.urlsplit(data["url"])
security = url.path.split("/")[1]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def connect():
    sock = socket.create_connection((ip, port), timeout=15)
    return ctx.wrap_socket(sock, server_hostname=host) if port == 443 else sock

conn = http.client.HTTPSConnection(ip, port, context=ctx, timeout=15) if port == 443 else http.client.HTTPConnection(ip, port, timeout=15)
conn.sock = connect()
conn.request("GET", url.path + "?" + url.query, headers={"Host": host})
resp = conn.getresponse(); resp.read()
cookies = "; ".join(c.split(";", 1)[0] for k, c in resp.getheaders() if k.lower() == "set-cookie" and "=" in c)
report = {"login_status": resp.status, "session_cookie": "cpsession=" in cookies}
sock = connect()
key = base64.b64encode(os.urandom(16)).decode()
sock.sendall((f"GET /{security}{suffix} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://{host}\r\nCookie: {cookies}\r\n\r\n").encode())
raw = b""
while b"\r\n\r\n" not in raw:
    chunk = sock.recv(4096)
    if not chunk:
        break
    raw += chunk
head, _, rest = raw.partition(b"\r\n\r\n")
report["ws_status"] = head.split(b"\r\n")[0].decode("latin-1")
if b" 101 " in head:
    sock.settimeout(10)
    try:
        while len(rest) < 2:
            rest += sock.recv(4096)
        report["first_frame_opcode"] = rest[0] & 0x0F
        length = rest[1] & 0x7F
        report["first_frame_length"] = length if length < 126 else "extended"
        if (rest[0] & 0x0F) == 8 and len(rest) >= 4:
            report["close_code"] = int.from_bytes(rest[2:4], "big")
    except socket.timeout:
        report["first_frame_opcode"] = None
sock.close()
print(json.dumps(report, sort_keys=True))
