#!/usr/bin/env python3
"""Decision-level comparison of two ratel binaries on legitimate software.

Runs `ratel scan --json` (what a user actually sees: model + rules + roles) on the
held-out legit tools (by category), the Alpine holdout and the flatpak holdout,
and prints the share of files each binary calls suspicious/high and the
per-capability detection rate. Files are downloaded packages / other distros,
so package trust never applies here: this measures the model and roles alone.

usage: eval_legit.py OLD_BINARY NEW_BINARY
"""
import collections
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from train import LEGIT_EVAL_ONLY, LEGIT_EVAL_ORIGINS  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPS = ["anti_debug", "anti_vm", "obfuscation", "packed", "crypto", "network"]


def scan(binary, paths):
    out = {}
    for i in range(0, len(paths), 2000):
        r = subprocess.run([binary, "scan", "--json", "--no-pkg-trust", "-j", "12", *paths[i:i + 2000]],
                           capture_output=True, text=True)
        if "unknown option" in r.stderr:  # binaries from before provenance support
            r = subprocess.run([binary, "scan", "--json", "-j", "12", *paths[i:i + 2000]], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            j = json.loads(line)
            out[j["path"]] = j
    return out


def summarize(res, paths):
    n = len([p for p in paths if p in res])
    bad = sum(res[p]["verdict"] in ("suspicious", "high") for p in paths if p in res)
    det = collections.Counter()
    for p in paths:
        if p in res:
            excused = res[p].get("excused", {})
            for c in res[p]["detected"]:
                if c not in excused:
                    det[c] += 1
    return n, bad / max(n, 1), {c: det[c] / max(n, 1) for c in CAPS}


def main():
    old, new = sys.argv[1], sys.argv[2]
    os.chdir(ROOT)
    sets = collections.defaultdict(list)
    for line in open("data/legit_tools.jsonl"):
        r = json.loads(line)
        if r["category"] in LEGIT_EVAL_ONLY or r["origin"] in LEGIT_EVAL_ORIGINS:
            sets[f"legit-eval/{r['category']}"].append(r["path"])
        else:
            sets[f"legit-train/{r['category']}"].append(r["path"])
    sets["alpine-holdout"] = [l.strip() for l in open("data/alpine_holdout.txt") if l.strip()]
    sets["flatpak-holdout"] = [l.strip() for l in open("data/real_holdout.txt") if l.strip()]
    allp = sorted({p for v in sets.values() for p in v})
    ro, rn = scan(old, allp), scan(new, allp)
    report = {}
    print(f"{'set':28s} {'n':>5s}  {'susp+high old→new':>18s}   detected (not excused) old→new")
    for name in sorted(sets):
        _, bo, do = summarize(ro, sets[name])
        n, bn, dn = summarize(rn, sets[name])
        caps = " ".join(f"{c[:8]}={do[c]:.2f}→{dn[c]:.2f}" for c in CAPS if do[c] or dn[c])
        print(f"{name:28s} {n:5d}  {bo:8.3f} → {bn:.3f}   {caps}")
        report[name] = {"n": n, "susp_high_old": bo, "susp_high_new": bn, "detected_old": do, "detected_new": dn}
    with open("models/legit_eval.json", "w") as fh:
        json.dump(report, fh, indent=1)


if __name__ == "__main__":
    sys.exit(main())
