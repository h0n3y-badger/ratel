#!/usr/bin/env python3
"""Convert CTU-13 labelled bidirectional NetFlow (.binetflow) into ratel events
and replay them through the engine to get feature rows with labels.

CTU-13 (Garcia et al., 2014): real traffic of a university network with hosts
infected by real botnets (Neris, Rbot, Virut, Menti, Sogou, Murlo, NSIS.ay).
Only the flow records are used: no malware, no packet payloads.

Hosts inside the university (147.32.0.0/16) whose flows are labelled Botnet or
Normal become entities ("host:IP"); everything labelled Botnet from an infected
host is a positive ("botnet") for that (host, destination) pair. Background
flows (unlabelled) are skipped.

usage: ctu.py data/net/ctu/ctu42.binetflow ... --out data/net/ctu-rows
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RATEL = os.path.join(ROOT, "target", "release", "ratel")


def ts(s):
    return datetime.datetime.strptime(s, "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc).timestamp()


def internal(ip):
    return ip.startswith("147.32.")


def convert(path):
    ev = []
    labels = defaultdict(lambda: [float("inf"), 0.0])
    nid = 1
    with open(path, errors="replace") as fh:
        head = fh.readline().strip().split(",")
        ix = {k: i for i, k in enumerate(head)}
        for line in fh:
            c = line.rstrip("\n").split(",")
            if len(c) < len(head):
                continue
            lab = c[ix["Label"]]
            bot = "Botnet" in lab
            if not (bot or "Normal" in lab):
                continue
            src, dst = c[ix["SrcAddr"]], c[ix["DstAddr"]]
            if not internal(src) or internal(dst):
                continue
            try:
                t = ts(c[ix["StartTime"]])
                dur = float(c[ix["Dur"]])
                tot, sb = int(c[ix["TotBytes"]]), int(c[ix["SrcBytes"]])
                dport = int(c[ix["Dport"]], 0) if c[ix["Dport"]] else 0
                sport = int(c[ix["Sport"]], 0) if c[ix["Sport"]] else 0
            except ValueError:
                continue
            proto = c[ix["Proto"]]
            ent = f"host:{src}"
            rb = max(tot - sb, 0)
            if proto == "tcp":
                ev.append((t, {"e": "syn", "t": t, "ent": ent, "sport": sport, "rip": dst, "rport": dport}))
                base = {"e": "tcp", "id": nid, "ent": ent, "lport": sport, "rip": dst, "rport": dport}
                nid += 1
                if dur > 60:
                    ev.append((t + dur / 2, dict(base, t=t + dur / 2, sent=sb // 2, recv=rb // 2)))
                ev.append((t + dur, dict(base, t=t + dur, sent=sb, recv=rb, closed=True)))
            elif proto == "udp" and dport != 53:
                n = max(1, int(dur // 60))
                for k in range(n):
                    tt = t + k * 60
                    ev.append((tt, {"e": "udp", "t": tt, "ent": ent, "rip": dst, "rport": dport, "len": max(sb // n, 1), "scale": 1}))
            elif proto == "icmp":
                pk = max(int(c[ix["TotPkts"]] or 1) // 2, 1)
                for k in range(min(pk, 50)):
                    tt = t + dur * k / min(pk, 50)
                    ev.append((tt, {"e": "icmp", "t": tt, "rip": dst, "len": max(sb // pk - 8, 0)}))
            else:
                continue
            if bot:
                l = labels[(ent, dst)]
                l[0] = min(l[0], t)
                l[1] = max(l[1], t + dur)
    ev.sort(key=lambda x: x[0])
    t0 = ev[0][0] if ev else 0
    out = [{"e": "caps", "t": t0, "dns": False, "syn": True, "udp": True}]
    for (ent, dst), (a, b) in labels.items():
        out.append({"e": "label", "ent": ent, "dest": dst, "t0": a, "t1": b + 60, "kind": "botnet"})
    out.extend(d for _, d in ev)
    return out, len(labels)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for f in a.files:
        name = os.path.basename(f).split(".")[0]
        evs, nl = convert(f)
        rows = os.path.join(a.out, f"{name}.rows.jsonl")
        # learn-hours 0: the captures are a few hours long; novelty starts counting at once
        p = subprocess.Popen([RATEL, "watch", "--replay", "-", "--emit", rows, "--learn-hours", "1", "--json"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        alerts, _ = p.communicate("\n".join(json.dumps(e, separators=(",", ":")) for e in evs) + "\n")
        al = [json.loads(l) for l in alerts.splitlines() if l.startswith("{")]
        with open(os.path.join(a.out, f"{name}.meta.json"), "w") as fh:
            json.dump({"file": f, "events": len(evs), "labelled_pairs": nl, "alerts": al}, fh)
        print(f"{name}: {len(evs)} events, {nl} botnet pairs, {len(al)} rule alerts")


if __name__ == "__main__":
    sys.exit(main())
