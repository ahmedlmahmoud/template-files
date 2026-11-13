"""Hostless exit probe + duplex tunnel to Floppy.

Endpoints (PORT from the environment, bind 0.0.0.0):
  GET /health                         -> ok <egress-ip>
  GET /probe                          -> unauthenticated Floppy status line
  GET /auth                           -> authenticated status line, or no-seat
  GET /hs?c=<host>&p=<port>           -> dial host:port, return first status line
  GET /ws[?h=<host>&p=<port>]         -> RFC6455 binary tunnel (no subprotocol)

Default tunnel backend is 170.23.130.191:10080. No seat secret is read by
/hs or /ws. Proxy-Authorization, if any, is only bytes inside the tunnel.
"""
import base64
import hashlib
import os
import select
import socket
import socketserver
import threading
import time
import urllib.request
from urllib.parse import parse_qs, urlsplit

FLOPPY_HOST = "170.23.130.191"
FLOPPY_PORT = 10080
PORTS = (10080, 10443, 10800)
REQ = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 8 * 1024 * 1024


def stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(tag, msg):
    print(f"{stamp()} {tag} {msg}", flush=True)


def egress_ip():
    forced = os.environ.get("EGRESS_IP", "").strip()
    if forced:
        return forced
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                v = r.read().decode("utf-8", "replace").strip()
                if v and len(v) < 64:
                    return v
        except Exception:
            pass
    return "unknown"


def dial(host, port, auth=False):
    extra = ""
    if auth:
        u = os.environ.get("SEAT_USER", "")
        p = os.environ.get("SEAT_PASS", "")
        if not u or not p:
            return "no-seat", ""
        token = base64.b64encode(f"{u}:{p}".encode()).decode()
        extra = f"Proxy-Authorization: Basic {token}\r\n"
    s = socket.socket()
    s.settimeout(12)
    try:
        s.connect((host, port))
        s.sendall((REQ + extra + "\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8000:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        if not data:
            return "connected-no-bytes", ""
        if b"\r\n\r\n" in data:
            head, body = data.split(b"\r\n\r\n", 1)
        else:
            head, body = data, b""
        while len(body) < 200:
            try:
                chunk = s.recv(200 - len(body))
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        line = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        snippet = body[:200].decode("latin1", "replace").replace("\r", " ").replace("\n", " ")
        return line, snippet
    except Exception as e:
        return f"{type(e).__name__}: {e}", ""
    finally:
        s.close()


def boot_evidence():
    ip = egress_ip()
    log("EGRESS", ip)
    line, _ = dial(FLOPPY_HOST, FLOPPY_PORT, auth=False)
    log("REACH", line)
    line, body = dial(FLOPPY_HOST, FLOPPY_PORT, auth=True)
    log("AUTH", f"{line} | BODY {body}")
    for port in (10443, 10800):
        line, _ = dial(FLOPPY_HOST, port, auth=False)
        log(f"REACH_{port}", line)
    return ip


def send_http(conn, code, text):
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found"}.get(code, "OK")
    body = text.encode("utf-8", "replace")
    head = (
        f"HTTP/1.1 {code} {reason}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    conn.sendall(head + body)


def read_http_request(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(1024)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 16384:
            return None
    head, _rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1", "replace").split("\r\n")
    if not lines or " " not in lines[0]:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    method, target = parts[0].upper(), parts[1]
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return method, target, headers


def parse_port(raw, default):
    if raw is None or raw == "":
        return default
    try:
        port = int(raw)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    return port


def safe_host(raw):
    if not raw or len(raw) > 253:
        return None
    if any(c in raw for c in " \r\n\t/\\"):
        return None
    return raw


def ws_accept(key):
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


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


def send_frame(conn, opcode, payload):
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
    conn.sendall(bytes(header) + payload)


def relay(client, host, port):
    try:
        backend = socket.create_connection((host, port), timeout=12)
    except Exception as e:
        log("WS", f"dial-fail {host}:{port} {type(e).__name__}")
        try:
            send_frame(client, 0x8, (1001).to_bytes(2, "big"))
        except Exception:
            pass
        return
    backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    backend.settimeout(None)
    client.settimeout(None)
    log("WS", f"open {host}:{port}")
    stop = threading.Event()
    lock = threading.Lock()

    def pump():
        try:
            while not stop.is_set():
                data = backend.recv(16384)
                if not data:
                    break
                with lock:
                    send_frame(client, 0x2, data)
        except Exception:
            pass
        finally:
            stop.set()

    threading.Thread(target=pump, daemon=True).start()
    frag = b""
    try:
        while not stop.is_set():
            ready, _, _ = select.select([client], [], [], 1.0)
            if not ready:
                continue
            fin, opcode, payload = read_frame(client)
            if opcode == 0x8:
                break
            if opcode == 0x9:
                with lock:
                    send_frame(client, 0xA, payload)
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
        stop.set()
        for s in (backend, client):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        log("WS", f"close {host}:{port}")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        conn = self.connection
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(20)
        try:
            req = read_http_request(conn)
        except Exception:
            return
        if not req:
            return
        method, target, headers = req
        if method != "GET":
            send_http(conn, 400, "GET only")
            return
        parts = urlsplit(target)
        path = parts.path or "/"
        qs = parse_qs(parts.query)
        if path == "/health":
            send_http(conn, 200, f"ok {egress_ip()}")
        elif path == "/probe":
            line, _ = dial(FLOPPY_HOST, FLOPPY_PORT, auth=False)
            send_http(conn, 200, line)
        elif path == "/auth":
            line, body = dial(FLOPPY_HOST, FLOPPY_PORT, auth=True)
            send_http(conn, 200, f"{line} | BODY {body}")
        elif path == "/hs":
            host = safe_host((qs.get("c") or [""])[0])
            port = parse_port((qs.get("p") or [""])[0], None)
            if not host or port is None:
                send_http(conn, 400, "need c and p")
                return
            line, _ = dial(host, port, auth=False)
            send_http(conn, 200, line)
        elif path == "/ws":
            self._upgrade(conn, headers, qs)
        elif path == "/":
            send_http(conn, 200, "ok")
        else:
            send_http(conn, 404, "not found")

    def _upgrade(self, conn, headers, qs):
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
        host = safe_host((qs.get("h") or [FLOPPY_HOST])[0]) or FLOPPY_HOST
        port = parse_port((qs.get("p") or [""])[0], FLOPPY_PORT)
        if port is None:
            send_http(conn, 400, "bad port")
            return
        accept = ws_accept(key)
        # No Sec-WebSocket-Protocol: subprotocol stays none.
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        conn.sendall(resp.encode("ascii"))
        relay(conn, host, port)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    port = int(os.environ.get("PORT", "0") or "0")
    if not port:
        boot_evidence()
        log("WORKER", "no PORT set; staying up as idle worker")
        while True:
            time.sleep(60)
    # Bind before the Floppy dials. A health check must not wait on the
    # backend, and a stuck dial must not keep the process from listening.
    log("SERVE", f"listening on 0.0.0.0:{port}")
    server = Server(("0.0.0.0", port), Handler)
    threading.Thread(target=boot_evidence, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
