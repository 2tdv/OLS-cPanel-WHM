#!/usr/bin/python3
"""Minimal RFC 6455 echo server and client for the OLS WebSocket proxy test (G0-E, OLS-17).

The server (lab backend, loopback only) answers one upgrade per connection: it sends the request
headers it received as a JSON text frame, then echoes one client frame. The client performs the
upgrade through a web server, checks the 101 handshake and Sec-WebSocket-Accept, and prints a JSON
report. Standard library only; frames up to 65535 bytes, no fragmentation."""
import argparse
import base64
import hashlib
import json
import os
import socket
import socketserver
import ssl
import sys

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def accept_key(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()

def read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return lines[0], headers, rest

def frame(payload, mask):
    data = payload.encode()
    if len(data) > 65535:
        raise ValueError("frame too large for this test tool")
    bit = 0x80 if mask else 0
    head = bytes([0x81, bit | len(data)]) if len(data) < 126 else bytes([0x81, bit | 126]) + len(data).to_bytes(2, "big")
    if not mask:
        return head + data
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(data))

def read_frame(sock, buffered=b""):
    data = buffered

    def fill(size):
        nonlocal data
        while len(data) < size:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed inside a frame")
            data += chunk

    fill(2)
    length, masked, start = data[1] & 0x7F, data[1] & 0x80, 2
    if length == 127:
        raise ValueError("unexpected 64-bit frame length")
    if length == 126:
        fill(4)
        length, start = int.from_bytes(data[2:4], "big"), 4
    offset = start + (4 if masked else 0)
    need = offset + length
    fill(need)
    payload = data[offset:need]
    if masked:
        key = data[start:offset]
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return data[0] & 0x0F, payload.decode("utf-8", "replace"), data[need:]

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        request_line, headers, rest = read_head(self.request)
        if headers.get("upgrade", "").lower() != "websocket" or "sec-websocket-key" not in headers:
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        self.request.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                              f"Sec-WebSocket-Accept: {accept_key(headers['sec-websocket-key'])}\r\n\r\n").encode())
        seen = {"request_line": request_line, **{k: headers.get(k) for k in ("host", "x-forwarded-for", "origin")}}
        self.request.sendall(frame(json.dumps(seen, sort_keys=True), mask=False))
        _, message, _ = read_frame(self.request, rest)
        self.request.sendall(frame("echo:" + message, mask=False))

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def client(args):
    host, _, port = args.connect.rpartition(":")
    report = {"status": None, "accept_ok": False, "backend_saw": None, "echo_ok": False}
    sock = socket.create_connection((host, int(port)), timeout=10)
    try:
        if args.tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # lab test listener; certificates are compared elsewhere
            context.set_alpn_protocols(["http/1.1"])
            sock = context.wrap_socket(sock, server_hostname=args.host)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((f"GET {args.path} HTTP/1.1\r\nHost: {args.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                      f"Origin: {'https' if args.tls else 'http'}://{args.host}\r\n\r\n").encode())
        status_line, headers, rest = read_head(sock)
        report["status"] = status_line.split(" ")[1] if " " in status_line else status_line
        report["accept_ok"] = headers.get("sec-websocket-accept") == accept_key(key)
        if report["status"] == "101":
            _, seen, rest = read_frame(sock, rest)
            report["backend_saw"] = json.loads(seen)
            sock.sendall(frame("ping-" + args.nonce, mask=True))
            _, echo, _ = read_frame(sock, rest)
            report["echo_ok"] = echo == "echo:ping-" + args.nonce
    except (OSError, ValueError, ConnectionError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    print(json.dumps(report, sort_keys=True))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    serve = sub.add_parser("server")
    serve.add_argument("--port", type=int, required=True)
    run = sub.add_parser("client")
    run.add_argument("--connect", required=True, help="address:port of the web server")
    run.add_argument("--host", required=True)
    run.add_argument("--path", required=True)
    run.add_argument("--nonce", required=True)
    run.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    if args.mode == "server":
        with Server(("127.0.0.1", args.port), Handler) as server:
            print("listening", flush=True)
            server.serve_forever()
    else:
        client(args)

if __name__ == "__main__":
    sys.exit(main())
