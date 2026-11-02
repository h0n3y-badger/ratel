#!/usr/bin/env python3
"""Synthetic network event traces for training ratel's network models.

Each trace simulates one server for 8-48 hours: a mix of benign services
modelled on a homelab (web server, reverse proxy to containers, a p2p router,
an overlay VPN, pollers that "beacon" legitimately, backups, package updates,
git pushes, ssh, background DNS including look-alike patterns such as reverse
lookups, DNS blocklists, antivirus hash lookups and CDN hostnames) plus, in most
traces, attack episodes from several technique families, annotated with Label
events. Traces are piped straight into `ratel watch --replay - --emit ...`, so
features come from the same Rust engine that runs live.

usage: gen_traces.py --out DIR --n 600 --seed 1 [--jobs 12]
"""
import argparse
import base64
import json
import os
import random
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RATEL = os.path.join(ROOT, "target", "release", "ratel")
H = 3600.0

# attack families: (unit, family) -- leave-family-out evaluation holds whole families out
FLOW_FAMILIES = ["exfil_https_cloud", "exfil_direct_ip", "exfil_oddport", "exfil_parallel", "exfil_pull_inbound",
                 "exfil_udp", "exfil_staged", "slow_drip", "beacon_regular", "beacon_jitter", "beacon_long_sleep",
                 "beacon_named", "beacon_tasks", "revshell", "compromised_service_exfil", "spam_bot", "ddos_http",
                 "ddos_udp", "webhook_exfil", "ws_c2", "exfil_backup_time", "low_and_slow", "miner", "lateral",
                 "beacon_backoff", "exfil_rclone", "heartbeat_c2"]
DNS_FAMILIES = ["dns_tunnel_fast", "dns_tunnel_slow", "dns_txt_c2", "dns_exfil_a", "dns_exfil_b64", "dns_beacon", "dns_idle_poll"]
# Parameter ranges below follow published defaults / reports where available:
# Cobalt Strike 60 s / 0% default, profiles 30-60 s at 10-50% jitter; Mythic 10 s / 20%;
# Havoc 2 s / 15%; Meterpreter HTTPS backs off when idle; Mirai 2-byte heartbeat / 60 s;
# iodine pings every 4 s; dnscat2 polls <= 1 s in hex; CS DNS: one short A query per sleep;
# rclone 4 transfers, 5 MiB chunks; MITRE T1030 chunk sizes 384-512 KB, <1 MB, 3 MB;
# XMR stratum ~41 packets/min of ~105 B over one long connection.
CLOUD = ["s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com", "transfer.sh", "mega.nz", "ngrok.io",
         "api.telegram.org", "discord.com", "pastebin.com", "dropboxapi.com", "workers.dev", "trycloudflare.com"]
WORDS = ["api", "cdn", "update", "static", "img", "push", "auth", "status", "mirror", "dl", "edge", "app", "files", "rss"]
TLDS = ["com", "net", "org", "io", "dev", "de", "nl", "fr", "co.uk", "info", "xyz", "top", "site", "online"]


class Trace:
    def __init__(self, rng, t0, hours, caps):
        self.r = rng
        self.t0 = t0
        self.t1 = t0 + hours * H
        self.ev = []
        self.caps = caps  # (dns, syn, udp)
        self.next_id = 1
        self.ev.append((t0, {"e": "caps", "t": t0, "dns": caps[0], "syn": caps[1], "udp": caps[2]}))

    def add(self, t, d):
        if self.t0 <= t <= self.t1 + 120:
            d["t"] = t
            self.ev.append((t, d))

    # ---- addresses and names
    def pub_ip(self):
        r = self.r
        while True:
            a = r.randint(2, 223)
            if a not in (10, 100, 127, 169, 172, 192, 198, 203):
                return f"{a}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"

    def domain(self, cloud=False):
        r = self.r
        if cloud:
            z = r.choice(CLOUD)
            return (f"{rand_label(r, r.randint(6, 14))}.{z}" if z.count(".") >= 1 and r.random() < 0.7 else z)
        return f"{r.choice(WORDS)}.{rand_word(r)}.{r.choice(TLDS)}"

    def resolve(self, t, name, ips, ent=None, qtype=1):
        if not self.caps[0]:
            return
        q = {"e": "dns", "ent": ent, "name": name, "qtype": qtype}
        self.add(t, q)
        self.add(t + 0.02, {"e": "dns", "name": name, "qtype": qtype, "resp": True, "rcode": 0, "answers": ips})

    # ---- one TCP connection: SYN, periodic counter snapshots, final counters at close
    def conn(self, t, ent, rip, rport, dur, out, inn, inbound=False, step=None, pid=0):
        cid = self.next_id
        self.next_id += 1
        lport = self.r.randint(32768, 60999) if not inbound else rport
        if inbound:
            rport = self.r.randint(32768, 60999)
        if not inbound and self.caps[1]:
            self.add(t, {"e": "syn", "sport": lport, "rip": rip, "rport": rport})
        dur = max(dur, 0.05)
        step = step or (30.0 if dur > 60 else None)
        base = {"e": "tcp", "id": cid, "ent": ent, "pid": pid, "lport": lport, "rip": rip, "rport": rport, "inbound": inbound}
        if step:
            k = 1
            while k * step < dur:
                f = k * step / dur
                self.add(t + k * step, dict(base, sent=int(out * f), recv=int(inn * f)))
                k += 1
        self.add(t + dur, dict(base, sent=int(out), recv=int(inn), closed=True))

    def udp(self, t, ent, rip, rport, nbytes, pkt=1200, back=0.0, back_pkt=120):
        """Sampled packets (1/16), like the live capture; `back` = bytes flowing in
        from the peer (acks, replies) as a fraction of nbytes."""
        if not self.caps[2]:
            return
        for nb, pk, inbound in ((nbytes, pkt, False), (nbytes * back, back_pkt, True)):
            n = int(nb / pk / 16)
            for i in range(max(n, 1 if self.r.random() < nb / pk / 16 else 0)):
                d = {"e": "udp", "ent": ent, "rip": rip, "rport": rport, "len": pk, "scale": 16}
                if inbound:
                    d["inbound"] = True
                self.add(t + self.r.random() * 60, d)

    def label(self, ent, dest, t0, t1, kind):
        self.ev.append((t0, {"e": "label", "ent": ent, "dest": dest, "t0": t0, "t1": t1, "kind": kind}))


def rbytes(r, n):
    return r.getrandbits(8 * n).to_bytes(n, "big")


def rand_label(r, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(r.choice(alphabet) for _ in range(n))


def rand_word(r):
    syl = ["ka", "lo", "mi", "ne", "ru", "ta", "vo", "zen", "bri", "cor", "dex", "fin", "gal", "hub", "lyn", "mar", "net",
           "pix", "qua", "sol", "tron", "vel", "wix", "yar"]
    return "".join(r.choice(syl) for _ in range(r.randint(2, 3)))


# ports that look "suspicious" but that p2p peers pick by chance
ODDISH = [1337, 3389, 4444, 5555, 7777, 9999, 12345, 54321, 3333, 14444, 8888, 6667, 5900, 1080, 31337]


def peer_port(r):
    """A p2p peer's listening port: random over the whole range (sometimes an 'odd' one)."""
    return r.choice(ODDISH) if r.random() < 0.02 else r.randint(1025, 65535)


def lognorm(r, mean, sigma=1.0):
    import math
    return r.lognormvariate(math.log(max(mean, 1)) - sigma * sigma / 2, sigma)


def poisson_times(r, t0, t1, per_hour):
    t = t0
    out = []
    if per_hour <= 0:
        return out
    while True:
        t += r.expovariate(per_hour / H)
        if t >= t1:
            return out
        out.append(t)


# ------------------------------------------------------------------ benign services

def svc_web(tr, ent="/usr/sbin/nginx"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    clients = [tr.pub_ip() for _ in range(r.randint(20, 400))]
    rate = r.choice([5, 20, 60, 200])
    for t in poisson_times(r, tr.t0, tr.t1, rate):
        c = r.choice(clients) if r.random() < 0.7 else tr.pub_ip()
        big = r.random() < 0.003
        out = lognorm(r, 2e8 if big else 6e4, 1.2)
        tr.conn(t, ent, c, 443, out / 2e6 + r.random() * 3, out, lognorm(r, 900), inbound=True)
    # reverse proxy to containers
    if r.random() < 0.7:
        for t in poisson_times(r, tr.t0, tr.t1, rate * 0.8):
            tr.conn(t, ent, f"172.17.0.{r.randint(2, 9)}", r.choice([3000, 8080, 8443]), 0.3, lognorm(r, 800), lognorm(r, 5e4))


def svc_p2p(tr, ent="/usr/local/sbin/i2pd"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    t = tr.t0
    port = r.randint(10000, 30000)
    while t < tr.t1:
        t += r.expovariate(r.choice([20, 60, 200]) / H)
        peer = tr.pub_ip()
        dur = lognorm(r, 900, 1.0)
        rate_o, rate_i = lognorm(r, 3000, 1.2), lognorm(r, 3000, 1.2)
        inbound = r.random() < 0.4
        tr.conn(t, ent, peer, peer_port(r) if not inbound else port, dur, rate_o * dur, rate_i * dur, inbound=inbound, step=60)
        if r.random() < 0.3:
            tr.udp(t, ent, tr.pub_ip(), peer_port(r), lognorm(r, 2e5, 1.0), back=r.uniform(0.3, 1.5))


def svc_vpn(tr, ent="/usr/sbin/tailscaled"):
    r = tr.r
    derps = [tr.pub_ip() for _ in range(3)]
    for i, d in enumerate(derps):
        tr.resolve(tr.t0 + i, f"derp{i + 1}.tailscale.com", [d])
    period = r.choice([25, 30, 60, 120])
    t = tr.t0 + 5
    d = derps[0]
    while t < tr.t1:
        dur = min(lognorm(r, 3 * H, 0.8), tr.t1 - t)
        tr.conn(t, ent, d, 443, dur, dur / period * 120, dur / period * 200, step=120)
        t += dur + r.random() * 10
        if r.random() < 0.2:
            d = r.choice(derps)
    for t in poisson_times(r, tr.t0, tr.t1, 4):
        tr.conn(t, ent, f"100.{r.randint(64, 127)}.{r.randint(0, 255)}.{r.randint(1, 254)}", 41641, lognorm(r, 60), lognorm(r, 2e5), lognorm(r, 2e6))
    # direct WireGuard path to a peer's public address: big UDP both ways (not a flood)
    peer = tr.pub_ip()
    for t in poisson_times(r, tr.t0, tr.t1, 1):
        tr.udp(t, ent, peer, 41641, lognorm(r, 5e7, 1.2), pkt=1300, back=r.uniform(0.05, 2.0), back_pkt=1300)


def svc_poller(tr, ent=None):
    """Legitimate beacons: health checks, update checks, metrics pushes."""
    r = tr.r
    ent = ent or r.choice(["/usr/bin/curl", "/usr/local/bin/hc-ping", "/usr/sbin/crond", "/usr/bin/node [uptime.js]",
                           "ctr:5a1b2c3d4e5f:/app/agent", "/usr/libexec/update-check"])
    name = tr.domain()
    ip = tr.pub_ip()
    period = r.choice([30, 60, 120, 300, 600, 900, 3600])
    jit = r.choice([0.0, 0.01, 0.05])
    t = (tr.t0 if r.random() < 0.7 else late(tr)) + r.random() * period
    while t < tr.t1:
        if r.random() < 0.05:
            tr.resolve(t - 0.1, name, [ip])
        tr.conn(t, ent, ip, 443, 0.2 + r.random(), lognorm(r, 900, 0.3), lognorm(r, 4000, 0.3))
        t += period * (1 + r.uniform(-jit, jit))
    tr.resolve(tr.t0, name, [ip])


def svc_backup(tr):
    r = tr.r
    ent = r.choice(["/usr/bin/restic", "/usr/bin/rsync", "/usr/bin/rclone", "/usr/bin/borg"])
    named = r.random() < 0.6
    ip = tr.pub_ip() if named else f"192.168.{r.randint(0, 255)}.{r.randint(2, 254)}"
    name = tr.domain(cloud=True) if named else None
    every = r.choice([6, 12, 24])
    first = tr.t0 + r.uniform(0.2, min(every, 20)) * H  # first run inside the learning window
    size = lognorm(r, r.choice([5e8, 3e9, 2e10]), 0.6)
    t = first
    while t < tr.t1:
        if name:
            tr.resolve(t - 0.5, name, [ip], ent)
        s = size * r.uniform(0.3, 1.2)
        dur = s / lognorm(r, 2e7, 0.5)
        tr.conn(t, ent, ip, 443 if named else 22, dur, s, s / 200, step=60)
        t += every * H * r.uniform(0.98, 1.02)


def svc_pkg(tr):
    r = tr.r
    ent = r.choice(["/sbin/apk", "/usr/bin/pacman", "/usr/bin/docker", "/usr/bin/containerd"])
    mirror = tr.pub_ip()
    for t in poisson_times(r, tr.t0, tr.t1, 0.5):
        tr.resolve(t - 0.2, "dl-cdn.alpinelinux.org", [mirror], ent)
        size = lognorm(r, 3e7, 1.5)
        tr.conn(t, ent, mirror, 443, size / 1e7 + 1, lognorm(r, 3000), size, step=60)


def svc_git(tr):
    r = tr.r
    ent = "/usr/bin/ssh" if r.random() < 0.5 else "/usr/lib/git-core/git-remote-https"
    ip = tr.pub_ip()
    for t in poisson_times(r, tr.t0, tr.t1, 0.3):
        tr.resolve(t - 0.2, "github.com", [ip], ent)
        up = lognorm(r, 3e6, 1.8)
        tr.conn(t, ent, ip, 22 if "ssh" in ent else 443, up / 3e6 + 2, up, lognorm(r, 5e4))


def svc_ssh(tr, ent="/usr/sbin/sshd"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    admin = f"100.{r.randint(64, 127)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    for t in poisson_times(r, tr.t0, tr.t1, 0.5):
        dur = lognorm(r, 1200)
        big = r.random() < 0.1  # scp of a big file to the admin laptop
        tr.conn(t, ent, admin, 22, dur, lognorm(r, 5e8 if big else 2e5), lognorm(r, 5e4), inbound=True, step=60)
    # internet noise: brute force attempts, short, from random IPs
    for t in poisson_times(r, tr.t0, tr.t1, r.choice([0, 5, 50])):
        tr.conn(t, ent, tr.pub_ip(), 22, 2 + r.random() * 5, 2500, 1500, inbound=True)


def svc_dns(tr, ent=None):
    """Benign resolver traffic, including patterns that look like tunnelling."""
    r = tr.r
    if not tr.caps[0]:
        return
    common = [tr.domain() for _ in range(40)]
    for t in poisson_times(r, tr.t0, tr.t1, r.choice([30, 120, 600])):
        u = r.random()
        if u < 0.6:
            name, qt = r.choice(common), r.choice([1, 1, 28])
        elif u < 0.75:  # CDN hostnames with random-looking labels
            name, qt = f"r{r.randint(1, 9)}---sn-{rand_label(r, 8)}.googlevideo.com", 1
        elif u < 0.85:  # reverse lookups
            name, qt = ".".join(str(r.randint(0, 255)) for _ in range(4)) + ".in-addr.arpa", 12
        elif u < 0.92:  # antivirus / reputation hash lookups (some products use long encoded labels)
            if r.random() < 0.5:
                name, qt = f"{rand_label(r, 32, '0123456789abcdef')}.hashes.{r.choice(['avqs-example', 'rep-check'])}.com", 1
            else:
                lab = base64.b32encode(rbytes(r, r.randint(20, 36))).decode().lower().rstrip("=")
                name, qt = f"{lab[:63]}.{rand_label(r, 4)}.{r.choice(['p', 'q', 'f'])}.avlookup-example.net", 16
        elif u < 0.97:  # DNS blocklists (mail servers)
            name, qt = ".".join(str(r.randint(0, 255)) for _ in range(4)) + ".zen.spamhaus.org", 1
        else:  # ACME DNS-01 challenges / SPF / DKIM TXT
            name, qt = r.choice([f"_acme-challenge.{rand_word(r)}.duckdns.org", f"selector1._domainkey.{rand_word(r)}.com"]), 16
        tr.add(t, {"e": "dns", "ent": ent, "name": name, "qtype": qt})
        if r.random() < 0.1:
            tr.add(t + 0.03, {"e": "dns", "name": name, "qtype": qt, "resp": True, "rcode": 3, "answers": []})


def late(tr):
    """Start time for a service that appears mid-trace (new install, new cron job, a user's command)."""
    return tr.t0 + tr.r.uniform(0.05, 0.95) * (tr.t1 - tr.t0)


def svc_user_tool(tr):
    """One-off commands: downloads, an upload to a known service, an API call burst."""
    r = tr.r
    ent = r.choice(["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/python3.12 [fetch.py]", "/usr/bin/rsync", "/usr/bin/scp",
                    "/usr/bin/git", "/usr/bin/docker", "/usr/bin/pip3", "/usr/bin/cargo", "/usr/bin/go",
                    "/usr/local/bin/yt-dlp", "/usr/bin/rclone"])
    for _ in range(r.randint(1, 4)):
        t = late(tr)
        name = tr.domain(cloud=r.random() < 0.3)
        ip = tr.pub_ip()
        tr.resolve(t - 0.2, name, [ip], ent)
        if r.random() < 0.75:   # download
            size = lognorm(r, 5e7, 1.5)
            tr.conn(t, ent, ip, 443, size / 5e6 + 1, lognorm(r, 2000), size, step=30)
        else:                   # upload to a named service (paste, share, artifact)
            size = lognorm(r, 5e6, 1.5)
            tr.conn(t, ent, ip, 443, size / 2e6 + 1, size, lognorm(r, 3000), step=30)


def svc_fetcher(tr):
    """Feed reader / metasearch / scraper container: many named sites, in >> out."""
    r = tr.r
    ent = r.choice(["ctr:1c2d3e4f5a6b:/usr/local/bin/omnisearch", "ctr:7a8b9c0d1e2f:/usr/bin/freshrss", "/usr/bin/newsboat",
                    "ctr:3f4e5d6c7b8a:/app/scraper"])
    start = tr.t0 if r.random() < 0.6 else late(tr)
    sites = [(tr.domain(), tr.pub_ip()) for _ in range(r.randint(20, 300))]
    for t in poisson_times(r, start, tr.t1, r.choice([20, 60, 300])):
        name, ip = r.choice(sites) if r.random() < 0.8 else (tr.domain(), tr.pub_ip())
        if r.random() < 0.3:
            tr.resolve(t - 0.1, name, [ip])
        tr.conn(t, ent, ip, 443, 0.5 + r.random() * 2, lognorm(r, 1500), lognorm(r, 8e4, 1.2))


def svc_browse(tr):
    """Workstation-style browsing: bursts to many new named hosts, CDNs, video."""
    r = tr.r
    ent = r.choice(["/usr/lib/librewolf/librewolf", "/usr/lib/firefox/firefox", "/opt/google/chrome/chrome", "host:browser"])
    for t in poisson_times(r, tr.t0, tr.t1, r.choice([30, 120, 400])):
        name, ip = tr.domain(), tr.pub_ip()
        tr.resolve(t - 0.05, name, [ip])
        video = r.random() < 0.03
        if r.random() < 0.3:  # HTTP/3 (QUIC): mostly download, acks up
            tr.udp(t, ent, ip, 443, lognorm(r, 2e4), pkt=80, back=lognorm(r, 200, 1.0), back_pkt=1350)
            continue
        tr.conn(t, ent, ip, 443, lognorm(r, 600 if video else 20), lognorm(r, 2e4), lognorm(r, 3e8 if video else 3e5, 1.2), step=60)
        if r.random() < 0.02:   # form / photo / attachment upload
            tr.conn(t + 5, ent, ip, 443, 10, lognorm(r, 5e6, 1.0), 4000)


def svc_mail(tr, ent="/usr/libexec/postfix/smtp"):
    """A real mail server: SMTP to many MX hosts is its job (spam-rule hard negative)."""
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    for t in poisson_times(r, tr.t0, tr.t1, r.choice([5, 30, 120])):
        mx = tr.pub_ip()
        tr.resolve(t - 0.1, f"mx{r.randint(1, 3)}.{rand_word(r)}.{r.choice(TLDS)}", [mx], ent, qtype=15)
        tr.conn(t, ent, mx, 25, 2 + r.random() * 3, lognorm(r, 3e4, 1.2), 1500)
    for t in poisson_times(r, tr.t0, tr.t1, 20):
        tr.conn(t, ent, tr.pub_ip(), 25, 3, 1500, lognorm(r, 2e4, 1.2), inbound=True)


def svc_syncthing(tr, ent="/usr/bin/syncthing"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    peers = [f"100.{r.randint(64, 127)}.{r.randint(0, 255)}.{r.randint(1, 254)}" for _ in range(r.randint(1, 3))] + \
            ([tr.pub_ip()] if r.random() < 0.5 else [])
    for t in poisson_times(r, tr.t0, tr.t1, 2):
        p = r.choice(peers)
        up = lognorm(r, 2e7, 1.5)
        tr.conn(t, ent, p, 22000, up / 5e6 + 5, up, up * r.uniform(0.01, 1.0), step=60)


def svc_registry_push(tr):
    r = tr.r
    ent = r.choice(["/usr/bin/docker", "/usr/bin/podman", "ctr:aa11bb22cc33:/usr/bin/kaniko", "/usr/bin/buildah"])
    ip = tr.pub_ip()
    t = tr.t0 + r.uniform(0.1, 0.8) * min(24 * H, tr.t1 - tr.t0)
    while t < tr.t1:
        tr.resolve(t - 0.2, r.choice(["registry-1.docker.io", "ghcr.io", "quay.io", "registry.gitlab.com"]), [ip], ent)
        size = lognorm(r, 3e8, 0.8)
        tr.conn(t, ent, ip, 443, size / 2e7 + 3, size, size / 300, step=30)
        t += r.choice([12, 24, 48]) * H * r.uniform(0.8, 1.2)


def svc_stream(tr, ent="/usr/lib/jellyfin/jellyfin"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    clients = [f"100.{r.randint(64, 127)}.{r.randint(0, 255)}.{r.randint(1, 254)}" for _ in range(3)] + [tr.pub_ip()]
    for t in poisson_times(r, tr.t0, tr.t1, 0.4):
        dur = lognorm(r, 3000, 0.6)
        tr.conn(t, ent, r.choice(clients), 8096, dur, dur * lognorm(r, 6e5, 0.5), dur * 300, inbound=True, step=60)


def svc_prometheus(tr, ent="ctr:5e6f7a8b9c0d:/bin/prometheus"):
    r = tr.r
    targets = [f"172.18.0.{r.randint(2, 20)}" for _ in range(r.randint(3, 10))]
    t = tr.t0
    period = r.choice([15, 30, 60])
    while t < tr.t1:
        for tg in targets:
            tr.conn(t + r.random(), ent, tg, r.choice([9100, 9090, 8080]), 0.1, 300, lognorm(r, 2e4, 0.3))
        t += period


def svc_tor(tr, ent="/usr/bin/tor"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    for t in poisson_times(r, tr.t0, tr.t1, r.choice([30, 100])):
        dur = lognorm(r, 1800, 1.0)
        rate = lognorm(r, 2e4, 1.2)
        tr.conn(t, ent, tr.pub_ip(), r.choice([9001, 443, 9030, peer_port(r)]), dur, rate * dur, rate * dur * r.uniform(0.8, 1.2),
                inbound=r.random() < 0.5, step=60)


def svc_torrent(tr, ent="/usr/bin/qbittorrent-nox"):
    r = tr.r
    tr.add(tr.t0, {"e": "listen", "ent": ent})
    for t in poisson_times(r, tr.t0, tr.t1, r.choice([20, 80])):
        dur = lognorm(r, 900, 1.0)
        up = lognorm(r, 3e7, 1.3)  # seeding: mostly upload
        tr.conn(t, ent, tr.pub_ip(), peer_port(r), dur, up, up * r.uniform(0.001, 0.3), inbound=r.random() < 0.5, step=60)
        if r.random() < 0.3:
            tr.udp(t, ent, tr.pub_ip(), peer_port(r), lognorm(r, 5e6, 1.0), back=0.03)


def svc_websocket(tr):
    """Legitimate long-lived connections with keepalives (home automation, chat, push)."""
    r = tr.r
    ent = r.choice(["ctr:ab12cd34ef56:/usr/local/bin/hass", "/usr/bin/gotify", "/usr/lib/ntfy/ntfy", "/usr/bin/element-bot"])
    name, ip = tr.domain(), tr.pub_ip()
    tr.resolve(tr.t0 + 1, name, [ip], ent)
    t = tr.t0 + 2
    ka = r.choice([20, 30, 60, 300])
    while t < tr.t1:
        dur = min(lognorm(r, 6 * H, 0.8), tr.t1 - t)
        n = dur / ka
        tr.conn(t, ent, ip, 443, dur, n * lognorm(r, 200, 0.3), n * lognorm(r, 400, 0.5), step=ka)
        t += dur + r.random() * 30


def svc_ntp(tr):
    r = tr.r
    for t in poisson_times(r, tr.t0, tr.t1, 4):
        tr.udp(t, "/usr/sbin/chronyd", tr.pub_ip(), 123, 96 * 16, pkt=76)


BENIGN = [(svc_web, 0.7), (svc_p2p, 0.5), (svc_vpn, 0.6), (svc_poller, 0.9), (svc_poller, 0.6), (svc_poller, 0.3),
          (svc_backup, 0.6), (svc_pkg, 0.7), (svc_git, 0.3), (svc_ssh, 0.8), (svc_dns, 0.95), (svc_ntp, 0.6),
          (svc_user_tool, 0.7), (svc_user_tool, 0.4), (svc_fetcher, 0.4), (svc_browse, 0.2), (svc_mail, 0.15),
          (svc_syncthing, 0.25), (svc_registry_push, 0.2), (svc_stream, 0.25), (svc_prometheus, 0.3), (svc_tor, 0.1),
          (svc_torrent, 0.15), (svc_websocket, 0.4), (svc_websocket, 0.15)]

# ------------------------------------------------------------------ attacks


def attack_entity(tr, kind):
    r = tr.r
    if kind == "compromised_service_exfil" or r.random() < 0.3:
        return r.choice(["/usr/sbin/nginx", "/usr/sbin/php-fpm83", "/usr/bin/postgres", "ctr:9f8e7d6c5b4a:/app/server",
                         "/usr/bin/python3.12 [app.py]"])
    e = r.choice(["/tmp/.cache/kworkerd", "memfd:x", "/usr/bin/curl", "/usr/bin/python3.12 [-c]", "/dev/shm/.s",
                  "/usr/bin/wget", "/var/www/uploads/.sys", "/usr/bin/perl [-c]", "/usr/bin/socat", "/usr/bin/openssl",
                  "/usr/bin/nc", "/root/.local/bin/updater", "/usr/bin/bash"])
    if r.random() < 0.4 and (e.startswith(("/tmp", "memfd", "/dev/shm")) or ".sys" in e):
        rule = "fileless_exe" if e.startswith("memfd") else "exe_in_temp"
        tr.add(tr.t0 + 1, {"e": "proc", "ent": e, "pid": r.randint(300, 30000), "rule": rule, "sev": 3, "detail": e})
    return e


def a_flow(tr, fam, start):
    r = tr.r
    ent = attack_entity(tr, fam)
    ip = tr.pub_ip()
    dest = ip
    end = start
    named = fam in ("exfil_https_cloud", "beacon_named") or (fam.startswith("exfil") and r.random() < 0.3)
    if named:
        tr.resolve(start - 0.3, tr.domain(cloud=fam == "exfil_https_cloud" or r.random() < 0.5), [ip], None)
    if fam in ("exfil_https_cloud", "exfil_direct_ip", "exfil_oddport", "compromised_service_exfil"):
        size = lognorm(r, r.choice([3e7, 2e8, 1e9, 5e9]), 0.8)
        speed = lognorm(r, r.choice([1e6, 5e6, 3e7]), 0.5)
        port = r.choice([443, 443, 80]) if fam != "exfil_oddport" else r.choice([4444, 8443, 9001, 31337, 2222, 8080, 53, 21])
        dur = size / speed
        tr.conn(start, ent, ip, port, dur, size, size / r.uniform(50, 2000), step=30)
        end = start + dur
    elif fam == "exfil_parallel":
        size = lognorm(r, 1e9, 0.8)
        n = r.randint(2, 8)
        for i in range(n):
            dur = size / n / lognorm(r, 5e6, 0.5)
            tr.conn(start + i * 0.2, ent, ip, 443, dur, size / n, size / n / 500, step=30)
            end = max(end, start + dur)
    elif fam == "exfil_pull_inbound":
        ent = r.choice(["/usr/sbin/sshd", "/usr/sbin/nginx", "/usr/sbin/vsftpd"])
        size = lognorm(r, 1e9, 0.8)
        dur = size / lognorm(r, 1e7, 0.5)
        tr.conn(start, ent, ip, 22 if "ssh" in ent else 443, dur, size, size / 300, inbound=True, step=30)
        end = start + dur
    elif fam == "exfil_udp":
        size = lognorm(r, 3e8, 0.7)
        dur = size / lognorm(r, 3e6, 0.5)
        port = r.choice([443, 53, 9999, 51820])
        t = start
        while t < start + dur:
            tr.udp(t, ent, ip, port, size / max(dur / 60, 1))
            t += 60
        end = start + dur
    elif fam == "exfil_staged":
        chunk = r.choice([r.uniform(384e3, 512e3), r.uniform(2e5, 1e6), 3e6, 5.24e6, lognorm(r, 2e7, 0.6)])
        every = r.choice([60, 300, 600])
        for i in range(r.randint(5, 30)):
            t = start + i * every * r.uniform(0.8, 1.2)
            tr.conn(t, ent, ip, 443, chunk / 5e6, chunk, 2000)
            end = t + chunk / 5e6
    elif fam == "slow_drip":
        every = r.choice([120, 300, 900, 1800])
        n = r.randint(8, 40)
        for i in range(n):
            t = start + i * every * r.uniform(0.5, 1.5)
            tr.conn(t, ent, ip, r.choice([443, 80, 8080]), 1 + r.random(), lognorm(r, 2e5, 0.8), lognorm(r, 400))
            end = t
    elif fam == "webhook_exfil":
        host = r.choice(["discord.com", "api.telegram.org", "hooks.slack.com", "webhook.site", "pipedream.net"])
        tr.resolve(start - 0.2, host, [ip], ent)
        every = r.choice([30, 120, 600])
        for i in range(r.randint(10, 120)):
            t = start + i * every * r.uniform(0.7, 1.3)
            if t > tr.t1:
                break
            tr.conn(t, ent, ip, 443, 1 + r.random(), lognorm(r, 2e5, 0.8), lognorm(r, 1500, 0.3))
            end = t
    elif fam == "ws_c2":
        if r.random() < 0.5:
            tr.resolve(start - 0.2, tr.domain(), [ip], ent)
        period = r.choice([5, 10, 30, 60])
        dur = min(lognorm(r, 3 * H, 0.6), tr.t1 - start)
        n = dur / period
        tr.conn(start, ent, ip, r.choice([443, 443, 8443, 80]), dur, n * lognorm(r, 300, 0.3) + lognorm(r, 2e6, 1.0),
                n * lognorm(r, 200, 0.3), step=period)
        end = start + dur
    elif fam == "exfil_backup_time":
        size = lognorm(r, 2e9, 0.6)
        dur = size / lognorm(r, 2e7, 0.4)
        tr.conn(start, ent, ip, 443, dur, size, size / 300, step=30)
        end = start + dur
    elif fam == "low_and_slow":
        t = start
        while t < min(tr.t1, start + 48 * H):
            tr.conn(t, ent, ip, r.choice([443, 80]), 1 + r.random(), lognorm(r, 3e4, 0.8), lognorm(r, 500, 0.3))
            end = t
            t += r.uniform(0.3, 2.0) * H
    elif fam == "miner":
        pool = r.choice(["pool.supportxmr.com", "xmr.2miners.com", "gulf.moneroocean.stream", "rx.unmineable.com", None])
        if pool:
            tr.resolve(start - 0.2, pool, [ip], None)
        dur = min(lognorm(r, 6 * H, 0.6), tr.t1 - start)
        port = r.choice([3333, 3334, 4444, 5555, 5556, 7777, 7778, 8220, 10128, 14444, 442, 443, 80])
        # ~41 packets/min of ~105 B each way over one long connection
        tr.conn(start, ent, ip, port, dur, dur * lognorm(r, 70, 0.3), dur * lognorm(r, 75, 0.3), step=60)
        end = start + dur
    elif fam == "lateral":
        targets = [f"192.168.{r.randint(0, 3)}.{x}" for x in range(1, 255)]
        for k, tg in enumerate(r.sample(targets, r.randint(70, 250))):
            t = start + k * r.uniform(0.05, 0.6)
            tr.add(t, {"e": "syn", "ent": ent, "sport": r.randint(32768, 60999), "rip": tg, "rport": r.choice([22, 445, 3389, 5900])})
        for tg in r.sample(targets, r.randint(2, 6)):
            t = start + r.uniform(60, 600)
            tr.conn(t, ent, tg, 22, lognorm(r, 300), lognorm(r, 2e5), lognorm(r, 5e4))
            tr.label(ent, tg, t, t + 600, fam)
        end = start + 600
    elif fam == "beacon_backoff":
        # HTTPS polling that slows down while idle and snaps back when tasked
        gap, t = r.choice([1, 2, 5]), start
        for i in range(r.randint(40, 300)):
            tasked = r.random() < 0.05
            tr.conn(t, ent, ip, 443, 0.3, lognorm(r, 3e5 if tasked else 500, 0.5), lognorm(r, 2000, 0.5))
            end = t
            gap = 1 if tasked else min(gap * r.uniform(1.1, 1.6), r.choice([30, 60, 300]))
            t += gap
            if t > tr.t1:
                break
    elif fam == "exfil_rclone":
        host = r.choice(["mega.nz", "g.api.mega.co.nz", "s3.amazonaws.com", "storage.googleapis.com", "pcloud.com"])
        tr.resolve(start - 0.2, host, [ip], ent)
        size = lognorm(r, 4e9, 0.8)
        rate = r.choice([5e6, 1.2e7, 3e7])  # incl. --bwlimit throttling
        dur = size / rate
        for k in range(4):  # 4 parallel transfers
            tr.conn(start + k * 0.3, ent, ip, 443, dur, size / 4, size / 4 / 400, step=60)
        end = start + dur
    elif fam == "heartbeat_c2":
        # long-lived connection with tiny periodic heartbeats (Mirai: 2 bytes / 60 s; IRC bots)
        port = r.choice([23, 6667, 9090, 4444, 1337, 8080])
        dur = min(lognorm(r, 6 * H, 0.6), tr.t1 - start)
        hb = r.choice([30, 60, 120])
        tr.conn(start, ent, ip, port, dur, dur / hb * r.choice([2, 60, 120]), dur / hb * r.choice([2, 60, 200]), step=hb)
        end = start + dur
    elif fam == "spam_bot":
        mx = [tr.pub_ip() for _ in range(r.randint(50, 400))]
        dur = lognorm(r, 3600, 0.6)
        for t in poisson_times(r, start, start + dur, r.choice([300, 1000, 3000])):
            d = r.choice(mx)
            tr.conn(t, ent, d, r.choice([25, 25, 587]), 2 + r.random() * 3, lognorm(r, 8000), 600)
            tr.label(ent, d, t, t + 60, fam)
        return start + dur
    elif fam in ("ddos_http", "ddos_udp"):
        dur = lognorm(r, 900, 0.6)
        port = r.choice([80, 443]) if fam == "ddos_http" else r.choice([53, 123, 80, 27015])
        t = start
        while t < start + dur:
            if fam == "ddos_http":
                for _ in range(r.randint(300, 1500)):
                    tr.conn(t + r.random() * 60, ent, ip, port, 0.5, 400, 0)
            else:
                tr.udp(t, ent, ip, port, lognorm(r, 1e8, 0.5), pkt=r.choice([64, 512, 1400]))
            t += 60
        end = start + dur
    elif fam.startswith("beacon") or fam == "revshell":
        period = {"beacon_regular": r.choice([2, 5, 10, 30, 60, 60]), "beacon_jitter": r.choice([10, 30, 45, 60, 120, 300]),
                  "beacon_long_sleep": r.choice([600, 900, 1800]), "beacon_named": r.choice([30, 60, 300]),
                  "beacon_tasks": r.choice([10, 60, 120]), "revshell": 0}[fam]
        if fam == "revshell":
            pid = r.randint(300, 30000)
            tr.add(start, {"e": "proc", "ent": ent, "pid": pid, "rule": "reverse_shell", "sev": 3, "detail": "sh"})
            dur = lognorm(r, 1800, 0.8)
            tr.conn(start, ent, ip, r.choice([4444, 443, 1337, 9001]), dur, lognorm(r, 3e4), lognorm(r, 5e3), step=30, pid=pid)
            end = start + dur
        else:
            jit = r.uniform(0.1, 0.5) if fam == "beacon_jitter" else r.choice([0.0, 0.0, r.uniform(0, 0.15)])
            port = r.choice([443, 443, 80, 8080, 4444, 8443])
            n = r.randint(12, 200)
            t = start
            for i in range(n):
                task = fam == "beacon_tasks" and r.random() < 0.15
                out = lognorm(r, 5e6 if task else 600, 0.5)
                tr.conn(t, ent, ip, port, 0.3 + r.random(), out, lognorm(r, 1500, 0.4))
                end = t
                t += period * (1 + r.uniform(-jit, jit))
                if t > tr.t1:
                    break
    tr.label(ent, dest, start, end + 60, fam)
    return end


def a_dns(tr, fam, start):
    r = tr.r
    if not tr.caps[0]:
        return start
    base = f"{rand_word(r)}{r.choice(['', '-cdn', '-api'])}.{r.choice(['com', 'net', 'xyz', 'top', 'info', 'site'])}"
    ent = None if r.random() < 0.7 else attack_entity(tr, fam)
    rate = {"dns_tunnel_fast": r.choice([2, 5, 20]), "dns_tunnel_slow": r.choice([0.05, 0.1, 0.3]),
            "dns_txt_c2": r.choice([0.1, 0.2, 1]), "dns_exfil_a": r.choice([0.5, 1, 3]), "dns_exfil_b64": r.choice([0.3, 1, 5]),
            "dns_beacon": 1 / r.choice([10, 30, 60, 60, 120]), "dns_idle_poll": r.choice([1, 2, 0.25])}[fam]
    dur = lognorm(r, {"dns_tunnel_fast": 1200, "dns_tunnel_slow": 7200, "dns_beacon": 6 * 3600}.get(fam, 3600), 0.6)
    n = min(int(rate * dur), 6000)
    t = start
    for i in range(n):
        if fam in ("dns_tunnel_fast", "dns_tunnel_slow"):
            labels = [base64.b32encode(rbytes(r, r.randint(20, 38))).decode().lower().rstrip("=") for _ in range(r.randint(1, 3))]
            labels = [l[:63] for l in labels]
            qt = r.choice([10, 16, 5, 1, 15])
        elif fam == "dns_txt_c2":
            labels = [r.choice(["", "a", "b"]) + format(r.getrandbits(48), "x"), format(i, "x")]
            qt = 16
        elif fam == "dns_beacon":
            labels = [r.choice(["cdn", "www", "api", "www6", "post"]), format(r.getrandbits(32), "x")]
            qt = r.choice([1, 1, 28, 16])
        elif fam == "dns_idle_poll":
            labels = [rbytes(r, r.randint(8, 24)).hex()]
            qt = r.choice([16, 15, 5, 1, 28])
        elif fam == "dns_exfil_a":
            labels = [rbytes(r, r.randint(12, 31)).hex()[:62]]
            qt = r.choice([1, 28])
        else:
            labels = [base64.urlsafe_b64encode(rbytes(r, r.randint(15, 40))).decode().rstrip("=").replace("_", "-")[:63]]
            qt = 1
        name = ".".join(l for l in labels if l) + "." + base
        tr.add(t, {"e": "dns", "ent": ent, "name": name, "qtype": qt})
        if fam == "dns_beacon":
            t += (1 / rate) * (1 + r.uniform(-0.2, 0.2))  # timer-driven
        else:
            t += r.expovariate(rate)
        if t > tr.t1:
            break
    tr.label(ent or "?", base, start, t + 60, fam)
    return t


def make_trace(i, seed, hold):
    r = random.Random(seed * 100_003 + i)
    hours = r.choice([8, 12, 24, 36, 48, 72, 96])
    t0 = 1_780_000_000 + r.randint(0, 200) * 86400 + r.randint(0, 86399)
    caps = (True, True, True) if r.random() < 0.8 else (False, False, False)
    tr = Trace(r, t0, hours, caps)
    for f, p in BENIGN:
        if r.random() < p:
            f(tr)
    fams = []
    if r.random() < 0.75:
        for _ in range(r.randint(1, 2)):
            unit = "dns" if (r.random() < 0.3 and caps[0]) else "flow"
            fams.append((unit, r.choice(DNS_FAMILIES if unit == "dns" else FLOW_FAMILIES)))
    for unit, fam in fams:
        start = t0 + r.uniform(0.5, hours - 1.5) * H
        (a_dns if unit == "dns" else a_flow)(tr, fam, start)
    tr.ev.sort(key=lambda x: x[0])
    return tr, fams


def run_one(args):
    i, seed, out_dir, learn = args
    tr, fams = make_trace(i, seed, None)
    rows = os.path.join(out_dir, f"t{i:05d}.rows.jsonl")
    p = subprocess.Popen([RATEL, "watch", "--replay", "-", "--emit", rows, "--emit-thin", "15", "--learn-hours", str(learn), "--json"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    body = "\n".join(json.dumps(d, separators=(",", ":")) for _, d in tr.ev) + "\n"
    alerts, _ = p.communicate(body)
    with open(os.path.join(out_dir, f"t{i:05d}.meta.json"), "w") as fh:
        json.dump({"i": i, "families": fams, "caps": tr.caps, "events": len(tr.ev), "hours": (tr.t1 - tr.t0) / H,
                   "alerts": [json.loads(l) for l in alerts.splitlines() if l.startswith("{")]}, fh)
    return len(tr.ev)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--learn-hours", type=float, default=24)
    ap.add_argument("--start", type=int, default=0, help="first trace index (to add traces to an existing set)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    with ProcessPoolExecutor(a.jobs) as ex:
        n = sum(ex.map(run_one, [(i, a.seed, a.out, a.learn_hours) for i in range(a.start, a.start + a.n)]))
    print(f"{a.n} traces, {n} events -> {a.out}")


if __name__ == "__main__":
    sys.exit(main())
