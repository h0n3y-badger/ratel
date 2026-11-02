#!/usr/bin/env python3
"""Static (binary) model: learning curve + hyperparameter sweep, scored on the
validation technique families only. Runs train.py with --summary in parallel.
Writes models/static-sweep.json and models/static-params.json (best)."""
import itertools
import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(ROOT, ".venv", "bin", "python")
GRID = {"n_estimators": [90, 200, 400], "max_depth": [3, 4, 5], "learning_rate": [0.05, 0.12], "min_samples_leaf": [6, 12]}


def run(params, frac=1.0):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as t:
        out = t.name
    subprocess.run([PY, "train/train.py", "--params", json.dumps(params), "--train-frac", str(frac), "--summary", out],
                   cwd=ROOT, capture_output=True, text=True, check=True)
    r = json.load(open(out))
    os.unlink(out)
    caps = r["caps"]
    r["mean_val_f1"] = sum(c["val_f1"] for c in caps.values()) / len(caps)
    r["mean_test_system_recall"] = sum(c["system_recall"] for c in caps.values() if c["system_recall"] is not None) / len(caps)
    return r


def main():
    res = {"curve": [], "sweep": []}
    # each train.py already uses 6 processes (one per capability)
    with ThreadPoolExecutor(int(os.environ.get("JOBS", "3"))) as ex:
        for frac, r in zip((0.25, 0.5, 1.0), ex.map(lambda f: run({}, f), (0.25, 0.5, 1.0))):
            res["curve"].append({"frac": frac, "mean_val_f1": r["mean_val_f1"], "mean_test_system_recall": r["mean_test_system_recall"]})
            print("curve", res["curve"][-1], flush=True)
        combos = [dict(zip(GRID, c)) for c in itertools.product(*GRID.values())]
        for p, r in zip(combos, ex.map(run, combos)):
            res["sweep"].append({"params": p, "mean_val_f1": r["mean_val_f1"], "mean_test_system_recall": r["mean_test_system_recall"],
                                 "caps": r["caps"]})
            print("sweep", p, round(r["mean_val_f1"], 4), round(r["mean_test_system_recall"], 4), flush=True)
    best = max(res["sweep"], key=lambda x: (round(x["mean_val_f1"], 3), -x["params"]["n_estimators"] * 2 ** x["params"]["max_depth"]))
    res["best"] = best
    json.dump(res, open(os.path.join(ROOT, "models/static-sweep.json"), "w"), indent=1)
    json.dump(best["params"], open(os.path.join(ROOT, "models/static-params.json"), "w"), indent=1)
    print("best", best["params"], best["mean_val_f1"])


if __name__ == "__main__":
    sys.exit(main())
