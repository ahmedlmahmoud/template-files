#!/usr/bin/env python3
"""Hostless egress relay: one RFC6455 websocket -> one raw TCP backend conn.

This is a RELAY, not a probe. No boot-time dials, no probe endpoints that hit
the backend, no unbounded thread explosion. Hostless injects PORT.

  GET /health -> ok <egress-ip>   (cheap, cached, never touches the backend)
  GET /ws?h=<host>&p=<port>       -> RFC6455 binary tunnel to host:port
"""
import base64
import hashlib
import os
import select
import socket
import socketserver
import sys
import threading
import time
import urllib.request
from urllib.parse import parse_qs, urlsplit

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 8 * 1024 * 1024
CONNECT_TIMEOUT = 8.0
HANDSHAKE_TIMEOUT = 20.0

_egress_cache = {"ip": None, "at": 0.0}
_log_lock = threading.Lock()
_conn_sem = threading.BoundedSemaphore(256)


def stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(tag, msg):
    # One line per write. Concurrency-safe so logs never get coalesced.
    with _log_lock:
        sys.stdout.write(f"{stamp()} {tag} {msg}\n")
        sys.stdout.flush()


def egress_ip():
    now = time.time()
    if _egress_cache["ip"] and now - _egress_cache["at"] < 300:
        return _egress_cache["ip"]
    ip = "unknown"
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                v = r.read().decode("utf-8", "replace").strip()
                if v and len(v) < 64:
                    ip = v
                    break
        except Exception:
            pass
    _egress_cache["ip"] = ip
    _egress_cache["at"] = now
    return ip


def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    return buf


def read_frame(conn):
    b0, b1 = recv_exact(conn, 2)
    fin = (b0 & 0x80) != 0
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) != 0
    length = b1 & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(conn, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(conn, 8), "big")
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    mask = recv_exact(conn, 4) if masked else None
    payload = recv_exact(conn, length) if length else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def send_frame(conn, opcode, payload, lock):
    header = bytearray([0x80 | (opcode & 0x0F)])
    n = len(payload)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += n.to_bytes(2, "big")
    else:
        header.append(127)
        header += n.to_bytes(8, "big")
    body = bytes(header) + payload
    with lock:
        conn.sendall(body)


def read_http_request(conn):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        c = conn.recv(4096)
        if not c:
            return None
        buf += c
    if b"\r\n\r\n" not in buf:
        return None
    head, _ = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    if not lines:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return parts[0], parts[1], hdrs


def send_http(conn, code, body=b"", ctype="text/plain"):
    reasons = {101: "Switching Protocols", 200: "OK", 400: "Bad Request",
               404: "Not Found", 503: "Service Unavailable"}
    reason = reasons.get(code, "OK")
    if isinstance(body, str):
        body = body.encode()
    conn.sendall(
        f"HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    )


def safe_host(raw):
    if not raw or len(raw) > 253:
        return None
    # Reject anything that is not a plain hostname / IPv4 literal.
    # In particular reject embedded ':' (IPv6 or host:port) and whitespace.
    if any(c in raw for c in " \r\n\t/\\:[]"):
        return None
    return raw


def parse_port(raw):
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return None
    return v if 1 <= v <= 65535 else None


def relay(client, host, port):
    if not _conn_sem.acquire(blocking=False):
        log("WS", f"overload {host}:{port}")
        try:
            send_http(client, 503, "relay at capacity")
        except Exception:
            pass
        return
    backend = None
    try:
        backend = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client.settimeout(None)
        backend.settimeout(None)
        log("WS", f"open {host}:{port}")
        stop = threading.Event()
        lock = threading.Lock()

        def pump():
            try:
                while not stop.is_set():
                    data = backend.recv(16384)
                    if not data:
                        break
                    send_frame(client, 0x2, data, lock)
            except Exception:
                pass
            finally:
                stop.set()

        threading.Thread(target=pump, daemon=True).start()
        frag = b""
        while not stop.is_set():
            ready, _, _ = select.select([client], [], [], 1.0)
            if not ready:
                continue
            fin, opcode, payload = read_frame(client)
            if opcode == 0x8:
                break
            if opcode == 0x9:
                send_frame(client, 0xA, payload, lock)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x1, 0x2):
                if fin:
                    backend.sendall(payload)
                else:
                    frag = payload
            elif opcode == 0x0:
                frag += payload
                if fin:
                    backend.sendall(frag)
                    frag = b""
    except Exception as e:
        log("WS", f"relay-end {type(e).__name__}")
    finally:
        for s in (backend, client):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        _conn_sem.release()
        log("WS", f"close {host}:{port}")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        conn = self.connection
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(HANDSHAKE_TIMEOUT)
            req = read_http_request(conn)
            if not req:
                return
            method, target, headers = req
            parts = urlsplit(target)
            path = parts.path or "/"
            qs = parse_qs(parts.query)
            if method != "GET":
                send_http(conn, 400, "GET only")
                return
            if path in ("/health", "/"):
                send_http(conn, 200, f"ok {egress_ip()}")
                return
            if path != "/ws":
                send_http(conn, 404, "not found")
                return
            if headers.get("upgrade", "").lower() != "websocket":
                send_http(conn, 400, "websocket upgrade required")
                return
            if headers.get("sec-websocket-version", "") != "13":
                send_http(conn, 400, "version 13 required")
                return
            key = headers.get("sec-websocket-key", "")
            if not key:
                send_http(conn, 400, "missing key")
                return
            host = safe_host((qs.get("h") or [""])[0])
            port = parse_port((qs.get("p") or [""])[0])
            if not host or port is None:
                send_http(conn, 400, "need valid h and p")
                return
            conn.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\n" f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n").encode("ascii")
            )
            relay(conn, host, port)
        except Exception as e:
            log("HTTP", f"handler {type(e).__name__}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256
    block_on_close = False


def main():
    port = int(os.environ.get("PORT", "0") or "0")
    if not port:
        log("WORKER", "no PORT set; staying up as idle worker")
        while True:
            time.sleep(60)
    log("SERVE", f"listening on 0.0.0.0:{port} backlog={Server.request_queue_size} cap=256")
    Server(("0.0.0.0", port), Handler).serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
