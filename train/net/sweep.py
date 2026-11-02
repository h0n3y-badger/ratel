#!/usr/bin/env python3
"""How good can the network models get on this data?

1. Learning curve: validation quality vs. how much training data the model sees
   (10% .. 100% of the training traces). A flat curve means more synthetic data
   of the same kind won't help.
2. Hyperparameter sweep: model capacity, learning rate, regularisation. Scored on
   the validation families only (never the test families), by the alert-level
   F1 at the false-alarm budget used in production (train_net.SYS_FPR).

Writes models/net-params.json (best per unit) and models/net-sweep.json.
"""
import itertools
import json
import os
import random
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import train_net as T  # noqa: E402

GRID = {
    "max_iter": [160, 400, 800],
    "max_depth": [4, 6, 8],
    "learning_rate": [0.05, 0.1],
    "min_samples_leaf": [20, 80],
    "l2_regularization": [1.0],
}


def main():
    ds = T.load_dataset()
    out = {"grid": GRID, "units": {}}
    best_all = {}
    for unit in ("flow", "dns"):
        nm = ds["names"][unit]
        use = [i for i, n in enumerate(nm) if n not in T.EXCLUDE[unit]]
        Xv, yv, rcv, _ = T.rows(ds, unit, {"val"}, use)
        train_files = sorted(f for f, s in ds["split"].items() if s in ("train", "feedback"))
        res = {"learning_curve": [], "sweep": []}
        # ---- learning curve with the default parameters
        rng = random.Random(7)
        shuffled = train_files[:]
        rng.shuffle(shuffled)
        for frac in (0.1, 0.25, 0.5, 1.0):
            sub = set(shuffled[:max(1, int(len(shuffled) * frac))])
            Xtr, ytr = T.train_matrices(ds, unit, use, sub)
            if ytr.sum() == 0:
                continue
            t0 = time.time()
            _, _, _, val = T.fit_and_threshold(Xtr, ytr, Xv, yv, rcv, T.HGB, nm, use)
            row = {"frac": frac, "train_rows": int(len(ytr)), "pos": int(ytr.sum()), **val, "secs": round(time.time() - t0, 1)}
            res["learning_curve"].append(row)
            print(unit, "curve", row, flush=True)
        # ---- successive halving: every combination on 25% of the training traces,
        # the best six on all of them
        keys = list(GRID)
        combos = [dict(zip(keys, c)) for c in itertools.product(*(GRID[k] for k in keys))]
        quarter = set(shuffled[:max(1, len(shuffled) // 4)])
        Xq, yq = T.train_matrices(ds, unit, use, quarter)
        stage1 = []
        for c in combos:
            t0 = time.time()
            _, mj, _, val = T.fit_and_threshold(Xq, yq, Xv, yv, rcv, dict(T.HGB, **c), nm, use)
            row = {"stage": 1, "params": c, **val, "secs": round(time.time() - t0, 1)}
            res["sweep"].append(row)
            stage1.append((val["f1"], c))
            print(unit, "sweep", row, flush=True)
        stage1.sort(key=lambda x: -x[0])
        Xtr, ytr = T.train_matrices(ds, unit, use)
        best = None
        for _, c in stage1[:6]:
            t0 = time.time()
            _, mj, _, val = T.fit_and_threshold(Xtr, ytr, Xv, yv, rcv, dict(T.HGB, **c), nm, use)
            size = len(json.dumps(mj, separators=(",", ":")))
            row = {"stage": 2, "params": c, **val, "model_kib": size // 1024, "secs": round(time.time() - t0, 1)}
            res["sweep"].append(row)
            print(unit, "final", row, flush=True)
            score = (round(val["f1"], 3), -size)  # quality first; then the smaller model
            if best is None or score > best[0]:
                best = (score, c, val)
        res["best"] = {"params": best[1], **best[2]}
        best_all[unit] = best[1]
        out["units"][unit] = res
        with open("models/net-sweep.json", "w") as fh:
            json.dump(out, fh, indent=1)
    with open("models/net-params.json", "w") as fh:
        json.dump(best_all, fh, indent=1)
    print("best:", json.dumps(best_all))


if __name__ == "__main__":
    sys.exit(main())
