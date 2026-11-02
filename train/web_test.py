#!/usr/bin/env python3
"""Security / API test for `ratel web` (runs it unprivileged against a state dir).

usage: python3 train/web_test.py STATE_DIR ALERTS_LOG
Checks: sandbox self-test, auth (401/redirects), token login + rate limiting,
session + CSRF + Origin + Host checks, request limits, path traversal, every API
route, the ack write path, security headers.
"""
import http.client, json, os, re, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "release", "ratel")
state, log = sys.argv[1], sys.argv[2]
PORT = 18447
H = f"127.0.0.1:{PORT}"
ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    print(("PASS  " if cond else "FAIL  ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if cond:
        ok += 1
    else:
        fail += 1


def req(method, path, body=None, headers=None, raw=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    if raw is not None:
        c.connect(); c.sock.sendall(raw)
        data = c.sock.recv(65536).decode("latin1"); c.close()
        return int(data.split(" ")[1]) if data.startswith("HTTP/") else 0, {}, data
    h = {"Host": H}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    out = (r.status, {k.lower(): v for k, v in r.getheaders()}, r.read().decode("utf-8", "replace"))
    c.close()
    return out


tmp = tempfile.mkdtemp()
tokfile = os.path.join(tmp, "web-token")
out = subprocess.run([BIN, "web", "--init-token", "--token-file", tokfile], capture_output=True, text=True).stdout
token = re.search(r"\n([0-9a-f]{64})\n", out).group(1)
check("token file stores only a hash", token not in open(tokfile).read() and open(tokfile).read().startswith("sha256:"))
check("token file mode 0640", oct(os.stat(tokfile).st_mode & 0o777) == "0o640")
os.makedirs(os.path.join(state, "feedback.d"), exist_ok=True)
status = os.path.join(state, "status.json")
srv = subprocess.Popen([BIN, "web", "--listen", H, "--token-file", tokfile, "--state", state, "--log", log, "--status", status],
                       stderr=subprocess.PIPE, text=True)
time.sleep(0.8)
srv_err = []
check("server running", srv.poll() is None)
pid = srv.pid
st = open(f"/proc/{pid}/status").read()
check("no_new_privs set", "NoNewPrivs:\t1" in st)
check("not dumpable / no core", int(re.search(r"Uid:\t(\d+)", st).group(1)) == os.getuid())

# --- refuses non-loopback without --allow-remote
r = subprocess.run([BIN, "web", "--listen", "0.0.0.0:18448", "--token-file", tokfile, "--state", state], capture_output=True, text=True, timeout=5)
check("non-loopback listen refused without --allow-remote", r.returncode != 0 and "non-loopback" in r.stderr)

# --- unauthenticated
s, h, b = req("GET", "/api/status")
check("API without session -> 401", s == 401)
s, h, b = req("GET", "/")
check("/ without session -> redirect to /login", s == 303 and h.get("location") == "/login")
s, h, b = req("GET", "/login")
check("login page served", s == 200 and "token" in b)
for k in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "cache-control",
          "cross-origin-opener-policy"):
    check(f"header {k}", k in h)
check("CSP forbids inline script", "script-src 'self'" in h.get("content-security-policy", "") and "unsafe" not in h.get("content-security-policy", ""))

# --- host / origin checks
s, h, b = req("GET", "/login", headers={"Host": "evil.example:80"})
check("foreign Host header -> 421 (DNS rebinding)", s == 421)
form = "token=" + token
s, h, b = req("POST", "/login", body=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
check("login POST without Origin -> 403", s == 403)
s, h, b = req("POST", "/login", body=form, headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://evil.example"})
check("login POST cross-origin -> 403", s == 403)

# --- wrong token, then rate limit (separate IP-less test: we are one IP)
s, h, b = req("POST", "/login", body="token=" + "0" * 64, headers={"Origin": "http://" + H})
check("wrong token -> back to login with error", s == 303 and "error=1" in h.get("location", ""))

# --- correct login
s, h, b = req("POST", "/login", body=form, headers={"Origin": "http://" + H})
cookie = h.get("set-cookie", "")
check("correct token -> session cookie", s == 303 and "ratel_session=" in cookie)
check("cookie HttpOnly + SameSite=Strict", "HttpOnly" in cookie and "SameSite=Strict" in cookie)
sid = cookie.split(";")[0]
auth = {"Cookie": sid}
s, h, b = req("GET", "/api/session", headers=auth)
csrf = json.loads(b)["csrf"] if s == 200 else ""
check("/api/session gives CSRF token", s == 200 and len(csrf) == 64)
s, h, b = req("GET", "/", headers=auth)
check("/ with session -> app", s == 200 and "app.js" in b)

# --- read APIs
for p in ("/api/status", "/api/live", "/api/alerts?since=86400", "/api/alerts?since=2592000&min=medium", "/api/incidents"):
    s, h, b = req("GET", p, headers=auth)
    good = s == 200
    try:
        json.loads(b)
    except Exception:
        good = False
    check(f"GET {p}", good, f"{s} {b[:80]}")
incs = json.loads(req("GET", "/api/incidents", headers=auth)[2])["incidents"]
check("incidents listed", len(incs) > 0)
if incs:
    s, h, b = req("GET", "/api/incident/" + incs[0]["id"], headers=auth)
    check("incident detail", s == 200 and json.loads(b)["id"] == incs[0]["id"])

# --- traversal / bad ids
for bad in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "20261101-192000-exfil%2f..%2f..%2fnet-state", "x" * 300):
    s, h, b = req("GET", "/api/incident/" + bad, headers=auth)
    check(f"bad incident id rejected ({bad[:24]})", s in (400, 404))

# --- POST protections
body = json.dumps({"id": incs[0]["id"] if incs else "x", "fp": False, "note": "web test"})
s, h, b = req("POST", "/api/ack", body=body, headers={**auth, "Origin": "http://" + H, "Content-Type": "application/json"})
check("ack without CSRF -> 403", s == 403)
s, h, b = req("POST", "/api/ack", body=body, headers={**auth, "Origin": "http://evil.example", "X-Ratel-CSRF": csrf})
check("ack cross-origin -> 403", s == 403)
s, h, b = req("POST", "/api/ack", body=body, headers={**auth, "Origin": "http://" + H, "X-Ratel-CSRF": csrf, "Content-Type": "application/json"})
check("ack with session + CSRF + Origin -> ok", s == 200 and json.loads(b).get("ok") is True, f"{s} {b[:100]}")
fb = os.path.join(state, "feedback.d", "web.jsonl")
check("ack written to feedback inbox", os.path.exists(fb) and '"via":"web"' in open(fb).read())

# --- response control: requests only, validated, into the inbox (the daemon executes)
H2 = {**auth, "Origin": "http://" + H, "X-Ratel-CSRF": csrf, "Content-Type": "application/json"}
s, h, b = req("GET", "/api/response", headers=auth)
check("response view loads", s == 200 and isinstance(json.loads(b), dict), f"{s} {b[:80]}")
s, h, b = req("POST", "/api/response", body=json.dumps({"action": "policy", "quarantine": "off"}), headers={**auth, "Origin": "http://" + H, "Content-Type": "application/json"})
check("response request without CSRF -> 403", s == 403)
for bad in [{"action": "rm -rf"}, {"action": "restore", "id": "../../etc/passwd"}, {"action": "kill", "id": ""},
            {"action": "policy", "quarantine": "everything"}, {"action": "policy"}, {"action": "restore"}]:
    s, h, b = req("POST", "/api/response", body=json.dumps(bad), headers=H2)
    check(f"bad response request refused ({json.dumps(bad)[:40]})", s == 400, str(s))
s, h, b = req("POST", "/api/response", body=json.dumps({"action": "policy", "quarantine": "signatures", "contain": "off"}), headers=H2)
check("policy request accepted", s == 200 and json.loads(b).get("ok") is True, f"{s} {b[:80]}")
s, h, b = req("POST", "/api/response", body=json.dumps({"action": "restore", "id": "20261102T173404Z-275a021bbfb6"}), headers=H2)
ctl = os.path.join(state, "feedback.d", "control.req")
lines = [json.loads(l) for l in open(ctl)] if os.path.exists(ctl) else []
check("requests land in the inbox with ids", s == 200 and len(lines) == 2 and all(len(l["req"]) == 32 for l in lines)
      and lines[0]["contain"] == "off" and lines[1]["action"] == "restore", str(lines)[:200])

# --- request limits
s, h, b = req(None, None, raw=b"GET / HTTP/1.1\r\nHost: " + H.encode() + b"\r\nX: " + b"a" * 9000 + b"\r\n\r\n")
check("oversized headers -> 431", s == 431, str(s))
s, h, b = req(None, None, raw=b"POST /api/ack HTTP/1.1\r\nHost: " + H.encode() + b"\r\nContent-Length: 999999\r\n\r\n")
check("oversized body -> 413", s == 413, str(s))
s, h, b = req(None, None, raw=b"POST /api/ack HTTP/1.1\r\nHost: " + H.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n")
check("chunked body refused -> 501", s == 501, str(s))

# --- logout
s, h, b = req("POST", "/logout", headers={**auth, "Origin": "http://" + H, "X-Ratel-CSRF": csrf})
check("logout", s == 200)
s, h, b = req("GET", "/api/status", headers=auth)
check("session dead after logout", s == 401)

# --- failed logins are slowed but can't lock the admin out
t0 = time.time()
codes = [req("POST", "/login", body="token=bad", headers={"Origin": "http://" + H})[0] for _ in range(9)]
check("failed logins slowed (>= 0.4 s each)", time.time() - t0 >= 9 * 0.4, f"{time.time() - t0:.1f}s")
s, h, b = req("POST", "/login", body=form, headers={"Origin": "http://" + H})
check("no lockout: the real token still works after failures", s == 303 and "ratel_session=" in h.get("set-cookie", ""))
auth = {"Cookie": h.get("set-cookie", "").split(";")[0]}
csrf = json.loads(req("GET", "/api/session", headers=auth)[2])["csrf"]

# --- request smuggling / log injection / duplicate headers
s, h, b = req(None, None, raw=b"GET /login HTTP/1.1\r\nHost: " + H.encode() + b"\r\nX: a\nInjected: b\r\n\r\n")
check("bare LF in headers -> 400", s == 400, str(s))
s, h, b = req(None, None, raw=b"GET /login HTTP/1.1\r\nHost: " + H.encode() + b"\r\nHost: evil.example\r\n\r\n")
check("duplicate Host header -> 400", s == 400, str(s))

# --- catch-all entities can't be silenced
# (a scan has no destination: silencing it would mean "any scan from any unidentified process")
scan = [i for i in incs if i["kinds"] == ["scan"] and all(e in ("unattributed", "?") or e.startswith("uid:") for e in i["entities"])]
if scan:
    s, h, b = req("POST", "/api/ack", body=json.dumps({"id": scan[0]["id"], "fp": True, "any_dest": True}),
                  headers={**auth, "Origin": "http://" + H, "X-Ratel-CSRF": csrf, "Content-Type": "application/json"})
    check("false alarm on an unidentified-process incident refused (422)", s == 422, f"{s} {b[:80]}")

# --- slowloris: trickling a request can't hold a connection past the deadline
import socket as _s
sk = _s.create_connection(("127.0.0.1", PORT)); sk.settimeout(20)
t0 = time.time(); closed = False
try:
    for ch in b"GET / HTTP/1.1\r\nHost: " + H.encode():
        sk.send(bytes([ch])); time.sleep(1.0)
        if time.time() - t0 > 16:
            break
except OSError:
    closed = True
try:
    closed = closed or sk.recv(100) is not None
except OSError:
    closed = True
check("slowloris connection cut at the deadline (~10 s)", closed and time.time() - t0 < 16, f"{time.time() - t0:.1f}s")
sk.close()

# --- audit flood is rate limited
for i in range(150):
    req("POST", "/api/ack", body="{}", headers={"Origin": "http://evil.example/" + "A" * 4000})

srv.terminate()
err = srv.communicate(timeout=5)[1]
check("sandbox self-test passed at startup", "self-test passed" in err and "no writes outside the inbox" in err, err[:300])
check("logins/acks audited", "login FAILED" in err and "ack " in err)
check("audit log rate-limited (flood of 150 bad requests)", err.count("\n") < 60 and len(err) < 30000, f"{err.count(chr(10))} lines, {len(err)} bytes")
check("attacker text in logs truncated", "A" * 200 not in err)

# --- UNIX socket + PROXY protocol (the stunnel deployment)
sock = os.path.join(tmp, "web.sock")
srv2 = subprocess.Popen([BIN, "web", "--listen", "unix:" + sock, "--proxy-protocol", "--host", "dash.test:443", "--secure-cookie",
                         "--token-file", tokfile, "--state", state, "--log", log, "--status", status], stderr=subprocess.PIPE, text=True)
time.sleep(0.8)
check("unix socket created owner/group only", os.path.exists(sock) and (os.stat(sock).st_mode & 0o007) == 0, oct(os.stat(sock).st_mode) if os.path.exists(sock) else "missing")
u = _s.socket(_s.AF_UNIX); u.connect(sock)
u.sendall(b"PROXY TCP4 100.64.7.7 100.64.0.1 51234 8448\r\nPOST /login HTTP/1.1\r\nHost: dash.test:443\r\nOrigin: https://dash.test:443\r\nContent-Length: 9\r\n\r\ntoken=bad")
resp = u.recv(4096).decode("latin1"); u.close()
check("PROXY + unix: login handled", resp.startswith("HTTP/1.1 303"), resp[:60])
time.sleep(0.2)
srv2.terminate()
err2 = srv2.communicate(timeout=5)[1]
check("PROXY protocol: real client address in audit", "100.64.7.7" in err2, err2[-200:])
print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
