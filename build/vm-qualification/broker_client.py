#!/usr/bin/python3 -I
"""Minimal broker client for lab probes: sends one request to the broker socket argv[1] and prints the
reply line. argv[2] is the JSON request, or:
  @size:N         send N bytes of padding (size limit)
  @trickle:S      send one byte per second for up to S seconds without a newline (total deadline)
  @idle:N:S       open N connections, send nothing, hold them S seconds (connection slots)"""
import socket
import sys
import time

def connect(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect(path)
    return sock

def read_reply(sock):
    reply = b""
    while not reply.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        reply += chunk
    return reply

def main():
    path, payload = sys.argv[1], sys.argv[2]
    if payload.startswith("@idle:"):
        count, seconds = (int(x) for x in payload[6:].split(":"))
        held = [connect(path) for _ in range(count)]
        time.sleep(seconds)
        for sock in held:
            sock.close()
        print("{}")
        return
    with connect(path) as sock:
        if payload.startswith("@trickle:"):
            started = time.monotonic()
            sock.setblocking(False)
            reply = b""
            while time.monotonic() - started < int(payload[9:]) and not reply.endswith(b"\n"):
                try:
                    sock.send(b"{")
                except OSError:
                    pass
                time.sleep(1)
                try:
                    reply += sock.recv(65536)
                except BlockingIOError:
                    pass
            sys.stdout.write(reply.decode())
            return
        data = (b"x" * int(payload[6:]) + b"\n") if payload.startswith("@size:") else (payload + "\n").encode()
        try:
            sock.sendall(data)
        except BrokenPipeError:
            pass
        sys.stdout.write(read_reply(sock).decode())

if __name__ == "__main__":
    main()
