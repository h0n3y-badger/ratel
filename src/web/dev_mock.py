#!/usr/bin/env python3
"""Dev server for the ratel web frontend (stdlib only).

    python3 src/web/dev_mock.py [port] [--auth] [--shot-delay=MS]

Serves the SPA from src/web/ and the GET API from data/web-sample/*.json, with
the production CSP so violations show up in the browser console. Binds to
127.0.0.1 only. With --auth, /api/* needs the ratel_session cookie (log in at
/login with token "dev", or set RATEL_MOCK_TOKEN) so the 401 -> /login flow
can be tested.
"""
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.normpath(os.path.join(HERE, "..", "..", "data", "web-sample"))
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
       "script-src 'self'; frame-ancestors 'none'")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/login": ("login.html", "text/html; charset=utf-8"),
}
SEV = {"low": 1, "medium": 2, "high": 3}
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
REQUIRE_LOGIN = "--auth" in sys.argv
# --shot-delay=MS: headless `firefox --screenshot` captures at the load event,
# before the SPA's fetches land. This holds the load event back with a hidden
# slow image injected into index.html (dev only).
SHOT_DELAY = next((int(a.split("=", 1)[1]) for a in sys.argv if a.startswith("--shot-delay=")), 0)
GIF = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")
TOKEN = os.environ.get("RATEL_MOCK_TOKEN", "dev")
COOKIE = "ratel_session=mock-session"
ACKS = {}  # incident id -> ack dict, in-memory overlay for POST /api/ack


def load(name):
    with open(os.path.join(SAMPLE, name), encoding="utf-8") as f:
        return json.load(f)


def csrf_token():
    return load("session.json")["csrf"]


def base_dest(dest):
    # alerts write "ip (name)"; suppressions key on the address
    return (dest or "*").split(" (")[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "ratel-mock"
    sys_version = ""

    def headers_common(self, ctype, length):
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def send(self, code, body, ctype, extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.headers_common(ctype, len(body))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, code, obj, extra=None):
        self.send(code, json.dumps(obj), "application/json", extra)

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def logged_in(self):
        if not REQUIRE_LOGIN:
            return True
        cookies = [c.strip() for c in self.headers.get("Cookie", "").split(";")]
        return COOKIE in cookies

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise ValueError("body too large")
        return self.rfile.read(n) if n else b""

    def csrf_ok(self):
        return self.headers.get("X-Ratel-CSRF", "") == csrf_token()

    # ---------- GET ----------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlsplit(self.path)
        path, q = url.path, parse_qs(url.query)
        if path in STATIC:
            name, ctype = STATIC[path]
            with open(os.path.join(HERE, name), "rb") as f:
                data = f.read()
            if SHOT_DELAY and name == "index.html":
                data = data.replace(b"</body>", b'<img src="/__hold" alt="" hidden>\n</body>')
            return self.send(200, data, ctype)
        if path == "/__hold" and SHOT_DELAY:
            time.sleep(SHOT_DELAY / 1000)
            return self.send(200, GIF, "image/gif")
        if path == "/favicon.ico":
            return self.send(204, b"", "text/plain")
        if not path.startswith("/api/"):
            return self.send(404, "not found\n", "text/plain; charset=utf-8")
        if not self.logged_in():
            return self.json(401, {"error": "login"})
        try:
            return self.api_get(path, q)
        except FileNotFoundError:
            return self.json(404, {"error": "not found"})

    def api_get(self, path, q):
        simple = {"/api/status": "status.json", "/api/live": "live.json",
                  "/api/session": "session.json"}
        if path in simple:
            return self.json(200, load(simple[path]))
        if path == "/api/alerts":
            d = load("alerts.json")
            since = float(q.get("since", ["86400"])[0] or 86400)
            mn = SEV.get(q.get("min", ["low"])[0], 1)
            # sample data is old: measure "since" back from the newest alert
            ref = max((a["t"] for a in d["alerts"]), default=0)
            d["alerts"] = [a for a in d["alerts"]
                           if a["t"] >= ref - since and SEV.get(a["severity"], 1) >= mn]
            d["counts"] = {s: sum(a["severity"] == s for a in d["alerts"]) for s in SEV}
            return self.json(200, d)
        if path == "/api/incidents":
            d = load("incidents.json")
            limit = int(q.get("limit", ["200"])[0] or 200)
            for inc in d["incidents"]:
                if inc["id"] in ACKS:
                    inc["ack"] = ACKS[inc["id"]]
            d["incidents"] = d["incidents"][:limit]
            return self.json(200, d)
        m = re.match(r"^/api/incident/([^/]+)$", path)
        if m and ID_RE.match(m.group(1)):
            d = load("incident-%s.json" % m.group(1))
            if m.group(1) in ACKS:
                d["ack"] = ACKS[m.group(1)]
            return self.json(200, d)
        return self.json(404, {"error": "not found"})

    # ---------- POST ----------
    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            raw = self.body()
        except ValueError:
            return self.json(413, {"error": "too large"})
        if path == "/login":
            token = parse_qs(raw.decode("utf-8", "replace")).get("token", [""])[0]
            if token == TOKEN:
                return self.redirect("/", COOKIE + "; HttpOnly; SameSite=Strict; Path=/")
            return self.redirect("/login?error=1#error")
        if path == "/logout":
            if not self.csrf_ok():
                return self.json(403, {"error": "csrf"})
            return self.json(200, {"ok": True}, {
                "Set-Cookie": "ratel_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"})
        if path == "/api/ack":
            if not self.logged_in():
                return self.json(401, {"error": "login"})
            if not self.csrf_ok():
                return self.json(403, {"error": "csrf"})
            try:
                req = json.loads(raw or b"{}")
                inc_id = str(req["id"])
            except (ValueError, KeyError, TypeError):
                return self.json(400, {"error": "bad request"})
            if not ID_RE.match(inc_id):
                return self.json(404, {"error": "not found"})
            try:
                inc = load("incident-%s.json" % inc_id)
            except FileNotFoundError:
                return self.json(404, {"error": "not found"})
            fp = bool(req.get("fp"))
            suppress = []
            if fp:
                for a in inc.get("alerts", []):
                    row = [a.get("entity", "?"),
                           "*" if req.get("any_dest") else base_dest(a.get("dest")),
                           a.get("kind", "?")]
                    if row not in suppress:
                        suppress.append(row)
            ACKS[inc_id] = {"t": time.time(), "fp": fp, "note": str(req.get("note") or "")[:500]}
            return self.json(200, {"ok": True, "suppress": suppress})
        return self.json(404, {"error": "not found"})


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    port = int(args[0]) if args else 8765
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("ratel mock on http://127.0.0.1:%d/  (samples: %s%s)"
          % (port, SAMPLE, ", --auth: token %r" % TOKEN if REQUIRE_LOGIN else ""), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
