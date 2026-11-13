"""Canonical Floppy egress-door probe. SAME FILE on all 4 providers.

Boot behaviour (identical everywhere):
  - log EGRESS <ip>
  - log REACH <status line>   (unauthenticated GET to Floppy)
  - log AUTH  <status line> | BODY <first 200 bytes>   (authenticated GET)
  - then stay up: HTTP server on $PORT if set, otherwise idle loop.

Endpoints when $PORT is set:
  /health -> ok <egress-ip>
  /probe  -> current unauthenticated status line
  /auth   -> current authenticated status line + first 200 body bytes

Secrets come ONLY from env SEAT_USER / SEAT_PASS. Never logged, never printed.
"""
import base64
import os
import socket
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLOPPY_HOST = "170.23.130.191"
PORTS = (10080, 10443, 10800)
REQ = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"


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


def dial(port, auth=False):
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
        s.connect((FLOPPY_HOST, port))
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
    line, _ = dial(10080, auth=False)
    log("REACH", line)
    line, body = dial(10080, auth=True)
    log("AUTH", f"{line} | BODY {body}")
    # extra ports, for providers whose outbound firewall is selective
    for port in (10443, 10800):
        line, _ = dial(port, auth=False)
        log(f"REACH_{port}", line)
    return ip


class Handler(BaseHTTPRequestHandler):
    def _send(self, text):
        b = text.encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send(f"ok {egress_ip()}")
        elif path == "/probe":
            line, _ = dial(10080, auth=False)
            self._send(line)
        elif path == "/auth":
            line, body = dial(10080, auth=True)
            self._send(f"{line} | BODY {body}")
        else:
            self._send("ok")

    def log_message(self, fmt, *args):
        return


def main():
    ip = boot_evidence()
    port = int(os.environ.get("PORT", "0") or "0")
    if port:
        log("SERVE", f"listening on 0.0.0.0:{port}")
        ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
    else:
        log("WORKER", "no PORT set; staying up as idle worker")
        while True:
            time.sleep(60)


if __name__ == "__main__":
    main()
