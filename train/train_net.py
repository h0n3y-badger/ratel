#!/usr/bin/env python3
"""Train ratel's network models (flow: exfiltration / C2; dns: tunnelling).

Inputs: feature rows emitted by the Rust engine (`ratel watch --replay --emit`):
  data/net/synth/t*.rows.jsonl          synthetic server traces with labelled attacks
  data/net/ctu-rows/*.rows.jsonl        CTU-13: real botnet + normal hosts (flow records)
  data/net/desktop-*.done.rows.jsonl    this desktop's own traffic, anonymised (eval only)
  data/net/feedback/*.rows.jsonl        acknowledged false alarms from deployment (benign, train)

Evaluation:
  * synthetic: leave-attack-family-out (test families never seen in training);
    validation families pick the threshold
  * CTU-13: real botnets; infected hosts are never trained on, normal hosts of
    the training captures are negatives
"System" = what `ratel watch` alerts on: model (gated: needs rule evidence
unless very confident) OR rules.

Hyperparameters come from models/net-params.json when present (train/net/sweep.py).
Output: models/ratel-net-model.json (embedded), models/net-report.json
"""
import datetime
import glob
import hashlib
import json
import os
import pickle
import random
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "train", "net"))
from gen_traces import DNS_FAMILIES, FLOW_FAMILIES  # noqa: E402

KEEP_BENIGN = 0.35          # benign row sampling (all positives kept); the engine already thins benign rows 1/15
# CTU-13 infected hosts are never trained on (every one of their rows "looks like a 2011
# university capture" and a model learns that as a shortcut). Normal hosts of the
# training captures are negatives; held-out captures test unseen botnet families.
CTU_TEST = {"ctu46", "ctu49", "ctu53", "ctu54"}
TARGET_FPR = 0.0005         # model-only FPR floor per benign row
SYS_FPR = 0.00004           # extra false alarms the model may add on top of the rules, per benign validation row
HGB = dict(max_iter=160, max_depth=4, learning_rate=0.1, l2_regularization=1.0, min_samples_leaf=40,
           max_bins=255, early_stopping=False, random_state=0)
# Features that only identify the data source, not behaviour.
EXCLUDE = {"flow": {"history_log", "dns_visible"}, "dns": {"history_log"}}
CACHE = "data/net/cache.pkl"


def keep(key):
    return int(hashlib.blake2b(key.encode(), digest_size=4).hexdigest(), 16) / 2**32 < KEEP_BENIGN


def load_file(path):
    acc = {u: {"X": [], "y": [], "rc": [], "ent": [], "dest": [], "t": []} for u in ("flow", "dns")}
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            y = r["y"]
            if y is None and not keep(f"{path}|{r['t']}|{r['ent']}|{r['dest']}"):
                continue
            a = acc[r["u"]]
            a["X"].append(r["x"]); a["y"].append(y); a["rc"].append(r["rc"]); a["ent"].append(r["ent"])
            a["dest"].append(r["dest"]); a["t"].append(r["t"])
    for a in acc.values():
        a["X"] = np.array(a["X"], dtype=np.float32)
        a["rc"] = np.array(a["rc"], dtype=np.float64)
        a["t"] = np.array(a["t"], dtype=np.float64)
    return path, acc


def load_dataset():
    """All rows, split assignment and metadata; cached on disk (13 GB of JSON otherwise)."""
    os.chdir(ROOT)
    names = json.loads(subprocess.run(["target/release/ratel", "net-feature-names"], capture_output=True, text=True, check=True).stdout)
    synth = sorted(glob.glob("data/net/synth/t*.rows.jsonl"))
    ctu = sorted(glob.glob("data/net/ctu-rows/*.rows.jsonl"))
    desk = sorted(glob.glob("data/net/desktop-*.done.rows.jsonl"))
    fb = sorted(glob.glob("data/net/feedback/*.rows.jsonl"))
    files = synth + ctu + desk + fb
    key = hashlib.sha256(json.dumps([(f, os.path.getsize(f), int(os.path.getmtime(f))) for f in files] + [KEEP_BENIGN, names]).encode()).hexdigest()
    if os.path.exists(CACHE):
        with open(CACHE, "rb") as fh:
            c = pickle.load(fh)
        if c["key"] == key:
            return c
    data = {}
    with ProcessPoolExecutor(os.cpu_count()) as ex:
        for p, o in ex.map(load_file, files, chunksize=4):
            data[p] = o
    meta = {f: json.load(open(f.replace(".rows.jsonl", ".meta.json"))) for f in synth}
    rng = random.Random(4321)
    test_f, val_f = set(), set()
    for f in FLOW_FAMILIES + DNS_FAMILIES:
        u = rng.random()
        (test_f if u < 0.25 else val_f if u < 0.45 else set()).add(f)
    split = {}
    for f in synth:
        fs = {x[1] for x in meta[f]["families"]}
        if fs & test_f:
            split[f] = "test"
        elif fs & val_f:
            split[f] = "val"
        elif fs:
            split[f] = "train"
        else:
            u = rng.random()
            split[f] = "test" if u < 0.25 else "val" if u < 0.45 else "train"
    for f in ctu:
        split[f] = "ctu_test" if os.path.basename(f).split(".")[0] in CTU_TEST else "ctu_train"
    for f in desk:
        split[f] = "desktop"
    for f in fb:
        split[f] = "feedback"
    c = {"key": key, "names": names, "data": data, "split": split, "hours": {f: meta[f]["hours"] for f in synth},
         "families": {f: meta[f]["families"] for f in synth}, "test_f": sorted(test_f), "val_f": sorted(val_f)}
    with open(CACHE, "wb") as fh:
        pickle.dump(c, fh, protocol=pickle.HIGHEST_PROTOCOL)
    return c


def rows(ds, unit, which, use, files=None, with_meta=False):
    X, y, rc, mr = [], [], [], []
    for f, d in ds["data"].items():
        if ds["split"][f] not in which or (files is not None and f not in files):
            continue
        a = d[unit]
        if len(a["y"]) == 0:
            continue
        X.append(a["X"][:, use]); y.append(np.array([0 if v is None else 1 for v in a["y"]])); rc.append(a["rc"])
        if with_meta:
            mr += [(f, a["y"][i], a["ent"][i], a["dest"][i], a["t"][i]) for i in range(len(a["y"]))]
    if not X:
        return np.zeros((0, len(use)), np.float32), np.zeros(0, int), np.zeros(0), mr
    return np.vstack(X), np.concatenate(y), np.concatenate(rc), mr


def calibrate(p, thr):
    thr = min(max(thr, 0.01), 0.99)
    return np.where(p < thr, 0.5 * p / thr, 0.5 + 0.5 * (p - thr) / (1 - thr))


def system(p, rc, thr):
    c = calibrate(p, thr)
    c = np.where((rc == 0) & (c < 0.97), np.minimum(c, 0.49), c)
    return np.maximum(c, rc) >= 0.5


def export(m, names, use):
    """HistGradientBoosting predictors -> ratel's tree JSON (x <= t goes left)."""
    trees = []
    for it in m._predictors:
        f, t, l, r, v, n = [], [], [], [], [], []
        for nd in it[0].nodes:
            leaf = bool(nd["is_leaf"])
            f.append(-1 if leaf else int(nd["feature_idx"]))
            t.append(0.0 if leaf else float(nd["num_threshold"]))
            l.append(0 if leaf else int(nd["left"]))
            r.append(0 if leaf else int(nd["right"]))
            v.append(float(nd["value"]))
            n.append(int(nd["count"]))
        trees.append({"f": f, "t": t, "l": l, "r": r, "v": v, "n": n})
    return {"features": [names[i] for i in use], "base": float(np.ravel(m._baseline_prediction)[0]), "trees": trees}


def raw_predict(mj, X):
    raw = np.full(len(X), mj["base"])
    for tr in mj["trees"]:
        f, th, l, r, v = (np.array(tr[k]) for k in "ftlrv")
        node = np.zeros(len(X), dtype=int)
        for _ in range(64):
            leaf = f[node] < 0
            if leaf.all():
                break
            xv = X[np.arange(len(X)), np.where(leaf, 0, f[node])].astype(np.float64)
            node = np.where(leaf, node, np.where(xv <= th[node], l[node], r[node]))
        raw += v[node]
    return 1 / (1 + np.exp(-raw))


def pick_threshold_sys(p_val, rc_val, y_val):
    """Best-F1 threshold whose alert decision (rules + gated model) stays under SYS_FPR
    on benign validation rows."""
    best, bf = 0.98, -1
    neg, pos = y_val == 0, y_val == 1
    # the model may add at most SYS_FPR of false alarms on top of what the rules alone raise
    budget = float((rc_val[neg] >= 0.5).mean()) + SYS_FPR if neg.any() else SYS_FPR
    cands = np.unique(np.concatenate([np.linspace(0.02, 0.98, 97), np.quantile(p_val, np.linspace(0, 1, 400))]))
    for t in cands:
        if not 0.02 <= t <= 0.98:
            continue
        d = system(p_val, rc_val, t)
        if d[neg].mean() > budget:
            continue
        tp = (d & pos).sum(); fp = (d & neg).sum(); fn = (~d & pos).sum()
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        if f1 > bf + 1e-9 or (abs(f1 - bf) <= 1e-9 and t < best):
            best, bf = float(t), f1
    return best, bf


def pick_threshold(p_neg, p_val, y_val):
    floor = float(np.quantile(p_neg, 1 - TARGET_FPR, method="higher")) + 1e-6 if len(p_neg) else 0.5
    best, bf = max(floor, 0.5), -1
    if len(p_val) and (y_val == 1).any():
        for t in np.unique(np.concatenate([np.linspace(0.05, 0.98, 94), p_val])):
            if t < floor or t > 0.98:
                continue
            pr = p_val >= t
            tp = (pr & (y_val == 1)).sum(); fp = (pr & (y_val == 0)).sum(); fn = (~pr & (y_val == 1)).sum()
            f1 = 2 * tp / max(2 * tp + fp + fn, 1)
            if f1 > bf + 1e-9:
                best, bf = float(t), f1
    return min(max(best, floor, 0.05), 0.98)


def weights(y):
    return np.where(y == 1, min((y == 0).sum() / max(y.sum(), 1), 20.0), 1.0)


def train_matrices(ds, unit, use, train_files=None):
    Xtr, ytr, _, _ = rows(ds, unit, {"train", "feedback"}, use, train_files)
    if unit == "flow":  # CTU training captures: normal hosts only, as negatives
        Xn, yn, _, _ = rows(ds, unit, {"ctu_train"}, use)
        Xtr, ytr = np.vstack([Xtr, Xn[yn == 0]]), np.concatenate([ytr, yn[yn == 0]])
    return Xtr, ytr


def fit_and_threshold(Xtr, ytr, Xv, yv, rcv, params, names, use):
    m = HistGradientBoostingClassifier(**params).fit(Xtr, ytr, sample_weight=weights(ytr))
    mj = export(m, names, use)
    pv = raw_predict(mj, Xv)
    t_sys, f1 = pick_threshold_sys(pv, rcv, yv)
    thr = max(pick_threshold(pv[yv == 0], pv, yv), t_sys)
    d = system(pv, rcv, thr)
    val = {"f1": float(f1), "recall": float(d[yv == 1].mean()) if (yv == 1).any() else None,
           "fpr": float(d[yv == 0].mean()) if (yv == 0).any() else None, "threshold": thr}
    return m, mj, thr, val


def params_for(unit):
    p = dict(HGB)
    if os.path.exists("models/net-params.json"):
        p.update(json.load(open("models/net-params.json")).get(unit, {}))
    return p


def main():
    ds = load_dataset()
    names, split = ds["names"], ds["split"]
    test_f, val_f = set(ds["test_f"]), set(ds["val_f"])
    print("test families:", sorted(test_f))
    print("val families:", sorted(val_f))
    model = {"version": 1, "trained": datetime.date.today().isoformat(), "units": {}}
    report = {"trained": model["trained"], "test_families": sorted(test_f), "val_families": sorted(val_f),
              "ctu_test": sorted(CTU_TEST), "units": {}, "split": {os.path.basename(f): v for f, v in split.items()}}
    for unit in ("flow", "dns"):
        nm = names[unit]
        use = [i for i, n in enumerate(nm) if n not in EXCLUDE[unit]]
        params = params_for(unit)
        Xtr, ytr = train_matrices(ds, unit, use)
        Xv, yv, rcv, _ = rows(ds, unit, {"val"}, use)
        Xt, yt, rct, mt = rows(ds, unit, {"test"}, use, with_meta=True)
        print(f"[{unit}] train {len(ytr)} ({ytr.sum()} pos)  val {len(yv)} ({yv.sum()} pos)  test {len(yt)} ({yt.sum()} pos)  params {params}")
        if ytr.sum() == 0:
            continue
        m, mj, thr, val = fit_and_threshold(Xtr, ytr, Xv, yv, rcv, params, nm, use)
        assert np.allclose(m.predict_proba(Xv[:500])[:, 1], raw_predict(mj, Xv[:500]), atol=1e-9), "export mismatch"

        def evaluate(X, y, rc):
            p = raw_predict(mj, X)
            sysd = system(p, rc, thr)
            out = {"n": int(len(y)), "pos": int(y.sum())}
            if (y == 1).any():
                out.update(model_recall=float((p[y == 1] >= thr).mean()), rules_recall=float((rc >= 0.5)[y == 1].mean()),
                           system_recall=float(sysd[y == 1].mean()))
            if (y == 0).any():
                out.update(model_fpr=float((p[y == 0] >= thr).mean()), rules_fpr=float((rc >= 0.5)[y == 0].mean()),
                           system_fpr=float(sysd[y == 0].mean()))
            return out, p, sysd

        rep = {"threshold": thr, "params": params, "validation": val}
        rep["synthetic_test"], pt, st = evaluate(Xt, yt, rct)
        ep = defaultdict(bool)
        for (f, yy, ent, dest, t), s in zip(mt, st):
            if yy is not None:
                ep[(f, yy, ent, dest)] |= bool(s)
        fam_hit = defaultdict(lambda: [0, 0])
        for (f, yy, _, _), hit in ep.items():
            fam_hit[yy][0] += hit
            fam_hit[yy][1] += 1
        rep["test_family_episode_recall"] = {k: round(v[0] / v[1], 3) for k, v in sorted(fam_hit.items())}
        if unit == "flow":
            Xc, yc, rcc, mc = rows(ds, unit, {"ctu_test"}, use, with_meta=True)
            rep["ctu_test"], pc, sc = evaluate(Xc, yc, rcc)
            hosts_pos = {(f, ent) for (f, yy, ent, d, t) in mc if yy}
            hosts_hit = {(f, ent) for (f, yy, ent, d, t), s in zip(mc, sc) if yy and s}
            rep["ctu_test_infected_hosts_detected"] = f"{len(hosts_hit)}/{len(hosts_pos)}"
            neg_hosts = {(f, ent) for (f, yy, ent, d, t) in mc if not yy} - hosts_pos
            rep["ctu_test_normal_hosts_alerted"] = f"{len({(f, e) for (f, yy, e, d, t), s in zip(mc, sc) if s and (f, e) in neg_hosts})}/{len(neg_hosts)}"
        print(json.dumps({k: v for k, v in rep.items() if k != "params"}, indent=1))
        # ---- final model on train + val, threshold from validation
        Xa = np.vstack([Xtr, Xv]); ya = np.concatenate([ytr, yv])
        mf = HistGradientBoostingClassifier(**params).fit(Xa, ya, sample_weight=weights(ya))
        fj = export(mf, nm, use)
        fj["threshold"] = thr
        rep["n_trees"] = len(fj["trees"])
        model["units"][unit] = fj
        report["units"][unit] = rep
    js = json.dumps(model, separators=(",", ":"))
    with open("models/ratel-net-model.json", "w") as fh:
        fh.write(js)
    report["model_bytes"] = len(js)
    with open("models/net-report.json", "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"net model: {len(js) / 1024:.0f} KiB -> models/ratel-net-model.json")


if __name__ == "__main__":
    sys.exit(main())
