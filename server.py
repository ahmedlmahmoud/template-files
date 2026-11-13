import base64, os, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLOPPY = ("170.23.130.191", 10080)
REQ = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"


def floppy(auth=False):
    extra = ""
    if auth:
        user = os.environ.get("SEAT_USER", "")
        pw = os.environ.get("SEAT_PASS", "")
        if not user or not pw:
            return "no-seat"
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        extra = f"Proxy-Authorization: Basic {token}\r\n"
    s = socket.socket()
    s.settimeout(12)
    try:
        s.connect(FLOPPY)
        s.sendall((REQ + extra + "\r\n").encode())
        data = b""
        while len(data) < 500:
            chunk = s.recv(500)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        if not data:
            return "connected-no-bytes"
        line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if not line.startswith("HTTP/1.1 200") and b"\r\n\r\n" in data:
            body = data.split(b"\r\n\r\n", 1)[1][:90].decode("latin1", "replace")
            body = body.replace("\r", " ").replace("\n", " ").strip()
            if body:
                line = line + " | " + body
        return line
    except Exception as e:
        return type(e).__name__
    finally:
        s.close()


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/probe":
            body = floppy(False).encode()
        elif path == "/seat":
            body = floppy(True).encode()
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


port = int(os.environ.get("PORT", "8080"))
ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
