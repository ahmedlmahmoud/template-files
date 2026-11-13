import os, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def floppy():
    s = socket.socket()
    s.settimeout(8)
    try:
        s.connect(("170.23.130.191", 10080))
        s.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = b""
        while len(data) < 180:
            c = s.recv(180)
            if not c:
                break
            data += c
            if b"\r\n" in data:
                break
        line = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else "connected-no-bytes"
        return line
    except Exception as e:
        return type(e).__name__
    finally:
        s.close()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok" if self.path.split("?", 1)[0] != "/probe" else floppy().encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return

port = int(os.environ.get("PORT", "8080"))
ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
