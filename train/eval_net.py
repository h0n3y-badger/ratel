#!/usr/bin/env python3
"""Alert-level evaluation of `ratel watch` (rules + embedded model, cooldowns,
evidence gating): exactly what would reach the XMPP chat.

* synthetic held-out traces (split from models/net-report.json), regenerated
  deterministically and replayed: per-family episode recall on families never
  trained on, and benign alerts per host-day
* CTU-13 (all captures; never trained on except normal hosts of 5 captures):
  infected hosts alerted, normal hosts alerted
* the desktop recording: alerts per hour

usage: eval_net.py [--binary target/release/ratel]
"""
import argparse
import glob
import json
import os
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "train", "net"))
import gen_traces  # noqa: E402

BIN = os.path.join(ROOT, "target", "release", "ratel")
SEED = 1


def replay(events, learn=24):
    p = subprocess.run([BIN, "watch", "--replay", "-", "--json", "--learn-hours", str(learn)],
                       input="\n".join(json.dumps(e, separators=(",", ":")) for e in events) + "\n",
                       capture_output=True, text=True)
    return [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]


def synth_one(i):
    tr, fams = gen_traces.make_trace(i, SEED, None)
    evs = [d for _, d in tr.ev]
    labels = [e for e in evs if e["e"] == "label"]
    alerts = [a for a in replay(evs) if a["severity"] in ("medium", "high")]
    bad_ents = {l["ent"] for l in labels}
    hit = defaultdict(bool)
    fp = []
    for a in alerts:
        dest = a["dest"].split(" ")[0]
        match = [l for l in labels if l["ent"] == a["entity"] and (l["dest"] == dest or not a["dest"])]
        match += [l for l in labels if l["ent"] == "?" and l["dest"] == dest]
        if match:
            for l in match:
                hit[l["kind"]] = True
        elif a["entity"] in bad_ents:
            pass  # e.g. the process alert of an attack entity: true, but not an episode
        elif a["entity"] == "unattributed" and a["kind"] in ("flood", "scan") and any(l["kind"].startswith("ddos") for l in labels):
            hit["ddos_http"] = hit.get("ddos_http", False) or any(l["kind"] == "ddos_http" for l in labels)
        else:
            fp.append(a)
    return i, [f for _, f in fams], dict(hit), fp, (tr.t1 - tr.t0) / 3600


def main():
    global BIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=BIN)
    a = ap.parse_args()
    BIN = a.binary
    os.chdir(ROOT)
    rep = json.load(open("models/net-report.json"))
    split = rep["split"]
    test_f = set(rep["test_families"])
    test_idx = [int(k[1:6]) for k, v in split.items() if k.startswith("t") and v == "test"]
    out = {"binary": BIN}

    with ProcessPoolExecutor(os.cpu_count()) as ex:
        res = list(ex.map(synth_one, sorted(test_idx)))
    fam_tot, fam_hit = defaultdict(int), defaultdict(int)
    fps, hours = [], 0.0
    for i, fams, hit, fp, h in res:
        hours += h
        fps += fp
        for f in fams:
            fam_tot[f] += 1
            fam_hit[f] += bool(hit.get(f))
    out["synthetic"] = {
        "traces": len(res), "host_days": round(hours / 24, 1),
        "held_out_family_recall": {f: f"{fam_hit[f]}/{fam_tot[f]}" for f in sorted(fam_tot) if f in test_f},
        "other_family_recall": {f: f"{fam_hit[f]}/{fam_tot[f]}" for f in sorted(fam_tot) if f not in test_f},
        "false_alerts_per_host_day": round(len(fps) / max(hours / 24, 1e-9), 3),
        "false_alert_kinds": dict(sorted(defaultdict(int, {k: sum(1 for x in fps if x["kind"] == k) for k in {x["kind"] for x in fps}}).items())),
        "false_alert_examples": [f"{x['severity']} {x['title']} | {x['evidence'][0] if x['evidence'] else ''}" for x in fps[:12]],
    }

    # ---- CTU-13
    sys.path.insert(0, os.path.join(ROOT, "train", "net"))
    import ctu
    ctu_rep = {}
    for f in sorted(glob.glob("data/net/ctu/*.binetflow")):
        name = os.path.basename(f).split(".")[0]
        evs, _ = ctu.convert(f)
        labels = [e for e in evs if e["e"] == "label"]
        infected = {l["ent"] for l in labels}
        hosts = {e["ent"] for e in evs if e.get("ent", "").startswith("host:")}
        al = [x for x in replay(evs, learn=1) if x["severity"] in ("medium", "high")]
        inf_hit = {x["entity"] for x in al if x["entity"] in infected}
        norm_hit = {x["entity"] for x in al if x["entity"] in hosts - infected}
        norm_kinds = defaultdict(int)
        for x in al:
            if x["entity"] in hosts - infected:
                norm_kinds[x["title"].split(":")[0] + " | " + (x["evidence"][0][:60] if x["evidence"] else "")] += 1
        kinds = defaultdict(int)
        for x in al:
            if x["entity"] in infected:
                kinds[x["kind"]] += 1
        ctu_rep[name] = {"split": split.get(f"{name}.rows.jsonl", "?"), "infected_detected": f"{len(inf_hit)}/{len(infected)}",
                         "normal_hosts_alerted": f"{len(norm_hit)}/{len(hosts - infected)}",
                         "alerts_on_normal_hosts": sum(1 for x in al if x["entity"] in hosts - infected),
                         "kinds_on_infected": dict(kinds), "normal_host_alerts": dict(norm_kinds)}
    out["ctu13"] = ctu_rep

    # ---- desktop recording (anonymised, unprivileged: no DNS/SYN capture)
    for f in sorted(glob.glob("data/net/desktop-*.done.jsonl")):
        if f.endswith(".rows.jsonl"):
            continue
        evs = [json.loads(l) for l in open(f)]
        if not evs:
            continue
        al = [x for x in replay(evs) if x["severity"] in ("medium", "high")]
        span = (evs[-1]["t"] - evs[0]["t"]) / 3600
        out[f"desktop:{os.path.basename(f)}"] = {"hours": round(span, 2), "alerts": len(al),
                                                  "examples": [f"{x['severity']} {x['title']}" for x in al[:8]]}
    print(json.dumps(out, indent=1))
    with open("models/net-eval.json", "w") as fh:
        json.dump(out, fh, indent=1)


if __name__ == "__main__":
    sys.exit(main())
