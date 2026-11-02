#!/usr/bin/env python3
"""Turn false alarms acknowledged on the server into training negatives.

On the server:  ratel ack <incident> --fp
Copy back:      scp homelab:/var/lib/ratel/feedback.jsonl homelab:/var/lib/ratel/incidents/*.jsonl data/net/feedback-in/
Then:           python3 -I train/net/import_feedback.py data/net/feedback-in && train/net/pipeline.sh

Every incident marked --fp has its recorded events (the 15 minutes before and the
two hours after the alert) replayed through the engine; the resulting rows are
benign training data, so the next model learns that this pattern is normal.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RATEL = os.path.join(ROOT, "target", "release", "ratel")


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "data/net/feedback-in")
    out = os.path.join(ROOT, "data/net/feedback")
    os.makedirs(out, exist_ok=True)
    fps = set()
    with open(os.path.join(src, "feedback.jsonl")) as fh:
        for line in fh:
            v = json.loads(line)
            if v.get("fp"):
                fps.add(v["id"])
    n = 0
    for inc in sorted(fps):
        f = os.path.join(src, f"{inc}.jsonl")
        if not os.path.exists(f):
            print(f"  {inc}: incident file missing, skipped")
            continue
        evs = []
        for line in open(f):
            v = json.loads(line)
            if v.get("type") in ("before", "after"):
                evs.append(v["ev"])
        evs.sort(key=lambda e: e["t"])
        rows = os.path.join(out, f"{inc}.rows.jsonl")
        p = subprocess.run([RATEL, "watch", "--replay", "-", "--emit", rows, "--emit-all", "--learn-hours", "0"],
                           input="\n".join(json.dumps(e) for e in evs) + "\n", capture_output=True, text=True)
        print(f"  {inc}: {len(evs)} events -> {rows}")
        n += 1
    print(f"{n} false-alarm incident(s) imported as benign training rows")


if __name__ == "__main__":
    sys.exit(main())
