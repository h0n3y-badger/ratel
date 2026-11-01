#!/usr/bin/env python3
"""Train ratel's per-capability gradient-boosted tree models.

Inputs (all produced by the ratel binary itself, so train/scan features match):
  data/synth/labels.jsonl + data/synth.feats.jsonl   synthetic, ground-truth labels
  data/real_train.feats.jsonl                         real binaries, weak labels
  data/real_holdout.feats.jsonl                       real binaries (other distro), FPR check only
  data/real_games.feats.jsonl                         Steam game binaries, report only

Outputs:
  models/ratel-model.json   embedded into the scanner at build time
  models/report.json        evaluation numbers

Evaluation is leave-technique-family-out: whole families (e.g. every ptrace
variant) are held out, so the score measures generalisation to unseen
implementations rather than memorised variants.

Deterministic: fixed seeds everywhere; the same data gives the same model.
"""
import argparse
import datetime
import hashlib
import json
import os
import random
import subprocess
import sys

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import roc_auc_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPS = ["anti_debug", "anti_vm", "obfuscation", "packed", "crypto", "network"]
# Features that only tell "real-world build" from "synthetic sample" (or scale with
# program size) — excluded so the model can't learn that shortcut.
EXCLUDE = {"size_log2", "code_bytes_log2", "n_insn_log2", "n_imports_log", "n_libs", "is_dll", "signed",
           "is_dotnet", "strings_per_kb", "n_sections"}
TARGET_FPR = 0.005  # on real binaries (calibration split)
GB = dict(n_estimators=90, max_depth=3, learning_rate=0.12, subsample=0.8, min_samples_leaf=12, random_state=0)


def ratel_bin():
    return os.path.join(ROOT, "target", "release", "ratel")


def feature_names():
    return subprocess.run([ratel_bin(), "feature-names"], capture_output=True, text=True, check=True).stdout.split()


def load_feats(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            out[r["path"]] = (np.array(r["features"], dtype=np.float32), r["rules"])
    return out


def weak_labels(x, rules, fi):
    """Labels for real binaries: evasion caps are negative unless a strong rule fires
    (then unknown); network/crypto come from imports/constants."""
    g = lambda n: x[fi[n]]
    lab = {}
    for c in ["anti_debug", "anti_vm", "obfuscation", "packed"]:
        lab[c] = None if rules[CAPS.index(c)] >= 2 else 0
    crypto_any = sum(g(n) for n in fi if n.startswith("cc_") and n not in ("cc_base64", "cc_crc32")) \
        + g("imm_tea") + g("imm_sha") + g("imm_md5") + g("imm_chacha") + g("aesni") + g("sha_ni") + g("api_crypto")
    lab["crypto"] = 1 if rules[CAPS.index("crypto")] >= 2 else (0 if crypto_any == 0 else None)
    net_imp = g("api_net") >= 2 or g("api_http") > 0 or g("api_socket") > 0
    if net_imp:
        lab["network"] = 1
    elif g("api_net") == 0 and g("urls") == 0 and g("is_static") == 0 and g("str_net") == 0:
        lab["network"] = 0
    else:
        lab["network"] = None
    return lab


def export_tree(t, lr):
    tr = t.tree_
    f = [int(v) if tr.children_left[i] != -1 else -1 for i, v in enumerate(tr.feature)]
    return {"f": f, "t": [float(v) for v in tr.threshold], "l": [max(int(v), 0) for v in tr.children_left],
            "r": [max(int(v), 0) for v in tr.children_right], "v": [float(v) * lr for v in tr.value[:, 0, 0]]}


def raw_predict(m_json, X):
    """Reference implementation of the exported model (mirrors src/model.rs)."""
    raw = np.full(len(X), m_json["base"])
    for t in m_json["trees"]:
        f, th, l, r, v = (np.array(t[k]) for k in "ftlrv")
        node = np.zeros(len(X), dtype=int)
        for _ in range(16):
            leaf = f[node] < 0
            if leaf.all():
                break
            xv = X[np.arange(len(X)), np.where(leaf, 0, f[node])].astype(np.float64)
            node = np.where(leaf, node, np.where(xv <= th[node], l[node], r[node]))
        raw += v[node]
    return 1 / (1 + np.exp(-raw))


def fit(X, y, w):
    m = GradientBoostingClassifier(**GB)
    m.fit(X, y, sample_weight=w)
    return m


def to_json(m, X_any):
    base = float(m._raw_predict_init(X_any[:1])[0, 0])
    return {"base": base, "trees": [export_tree(e[0], m.learning_rate) for e in m.estimators_]}


def pick_threshold(p_neg_real, p_val, y_val, target=TARGET_FPR):
    """Best-F1 threshold on synthetic validation families, subject to FPR <= target
    on real negatives (calibration split)."""
    floor = float(np.quantile(p_neg_real, 1 - target, method="higher")) + 1e-6 if len(p_neg_real) else 0.05
    best, best_f1 = max(floor, 0.5), -1.0
    if p_val is not None and len(p_val) and (y_val == 1).any():
        for t in np.unique(np.concatenate([np.linspace(0.05, 0.95, 91), p_val])):
            if t < floor or t < 0.05 or t > 0.95:
                continue
            pred = p_val >= t
            tp = (pred & (y_val == 1)).sum(); fp = (pred & (y_val == 0)).sum(); fn = (~pred & (y_val == 1)).sum()
            f1 = 2 * tp / max(2 * tp + fp + fn, 1)
            if f1 > best_f1 + 1e-9:
                best, best_f1 = float(t), f1
    return min(max(best, floor, 0.05), 0.95)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--synth", default="data/synth")
    ap.add_argument("--holdout-frac", type=float, default=0.25)
    a = ap.parse_args()
    os.chdir(ROOT)
    names = feature_names()
    fi = {n: i for i, n in enumerate(names)}
    use = [i for i, n in enumerate(names) if n not in EXCLUDE]
    used_names = [names[i] for i in use]

    # ---- synthetic
    sfeats = load_feats(f"{a.synth}.feats.jsonl")
    rows = [json.loads(l) for l in open(f"{a.synth}/labels.jsonl")]
    S = []
    for r in rows:
        p = os.path.join(a.synth, r["path"])
        if p in sfeats:
            S.append((sfeats[p][0], r["labels"], r["groups"], r))
    # ---- real
    real_tr = load_feats("data/real_train.feats.jsonl")
    real_ho = load_feats("data/real_holdout.feats.jsonl")
    real_games = load_feats("data/real_games.feats.jsonl")
    R = [(x, weak_labels(x, ru, fi), p) for p, (x, ru) in sorted(real_tr.items())]
    print(f"synthetic {len(S)}, real train {len(R)}, real holdout {len(real_ho)}, games {len(real_games)}")

    # ---- family holdout split (deterministic)
    rng = random.Random(1234)
    fams = sorted({g for s in S for g in s[2]})
    test_fams, val_fams = set(), set()
    for f in fams:
        u = rng.random()
        if u < a.holdout_frac:
            test_fams.add(f)
        elif u < 2 * a.holdout_frac:
            val_fams.add(f)
    s_train, s_val, s_test = [], [], []
    for s in S:
        g = set(s[2])
        if g & test_fams:
            s_test.append(s)
        elif g & val_fams:
            s_val.append(s)
        elif g:
            s_train.append(s)
        else:  # technique-free samples: random split
            u = rng.random()
            (s_test if u < a.holdout_frac else s_val if u < 2 * a.holdout_frac else s_train).append(s)
    r_idx = list(range(len(R)))
    rng.shuffle(r_idx)
    r_cal = set(r_idx[: len(R) // 5])
    r_train = [R[i] for i in r_idx if i not in r_cal]
    r_calib = [R[i] for i in sorted(r_cal)]
    print(f"test families ({len(test_fams)}): {sorted(test_fams)}")
    print(f"validation families ({len(val_fams)}): {sorted(val_fams)}")

    def mat(items, cap, real):
        X, y, w = [], [], []
        for it in items:
            lab = it[1][cap]
            if lab is None:
                continue
            X.append(it[0][use])
            y.append(int(lab))
            w.append(1.0 if not real else 1.5)
        return np.array(X, dtype=np.float32).reshape(-1, len(use)), np.array(y), np.array(w)

    Xho = np.array([x[use] for x, _ in real_ho.values()], dtype=np.float32)
    ho_lab = [weak_labels(x, ru, fi) for x, ru in real_ho.values()]
    Xg = np.array([x[use] for x, _ in real_games.values()], dtype=np.float32)
    games_paths = list(real_games.keys())

    report = {"trained": datetime.date.today().isoformat(), "params": GB, "target_fpr": TARGET_FPR,
              "held_out_families": sorted(test_fams), "counts": {"synth": len(S), "real_train": len(R),
              "real_holdout": len(real_ho), "games": len(real_games)}, "caps": {}}
    model = {"version": 1, "trained": report["trained"], "features": used_names, "caps": {}}
    for cap in CAPS:
        Xs, ys, ws = mat(s_train, cap, False)
        Xr, yr, wr = mat(r_train, cap, True)
        X = np.vstack([Xs, Xr]); y = np.concatenate([ys, yr]); w = np.concatenate([ws, wr])
        # balance classes
        pw = (y == 0).sum() / max((y == 1).sum(), 1)
        w = w * np.where(y == 1, min(pw, 10.0), 1.0)
        m = fit(X, y, w)
        mj = to_json(m, X)
        # threshold on the calibration split of real files
        Xc, yc, _ = mat(r_calib, cap, True)
        pc = raw_predict(mj, Xc)
        Xsv, ysv, _ = mat(s_val, cap, False)
        thr = pick_threshold(pc[yc == 0], raw_predict(mj, Xsv), ysv)
        Xst, yst, _ = mat(s_test, cap, False)
        pst = raw_predict(mj, Xst)
        # parity check: exported trees == sklearn
        ref = m.predict_proba(Xst[:200])[:, 1]
        assert np.allclose(ref, pst[:200], atol=1e-9), f"{cap}: export mismatch"
        # metrics
        rec = float((pst[yst == 1] >= thr).mean()) if (yst == 1).any() else None
        sfpr = float((pst[yst == 0] >= thr).mean()) if (yst == 0).any() else None
        auc = float(roc_auc_score(yst, pst)) if len(set(yst)) == 2 else None
        pho = raw_predict(mj, Xho)
        yho = np.array([l[cap] if l[cap] is not None else -1 for l in ho_lab])
        ho_fpr = float((pho[yho == 0] >= thr).mean()) if (yho == 0).any() else None
        ho_rec = float((pho[yho == 1] >= thr).mean()) if (yho == 1).any() else None
        pg = raw_predict(mj, Xg)
        top = sorted(zip(pg, games_paths), reverse=True)[:8]
        imp = sorted(zip(m.feature_importances_, used_names), reverse=True)[:10]
        report["caps"][cap] = {
            "threshold": thr, "heldout_family_recall": rec, "heldout_family_auc": auc, "synthetic_neg_fpr": sfpr,
            "real_holdout_fpr": ho_fpr, "real_holdout_weak_recall": ho_rec,
            "n_train": int(len(y)), "n_pos": int((y == 1).sum()), "n_test_pos": int((yst == 1).sum()),
            "games_flagged": int((pg >= thr).sum()), "games_top": [[round(float(p), 3), q] for p, q in top],
            "top_features": [[n, round(float(v), 4)] for v, n in imp],
        }
        print(f"{cap:12s} thr={thr:.3f} famrecall={rec if rec is None else round(rec, 3)} auc={auc if auc is None else round(auc, 4)} "
              f"synthFPR={sfpr if sfpr is None else round(sfpr, 4)} realFPR={ho_fpr if ho_fpr is None else round(ho_fpr, 4)} "
              f"games={int((pg >= thr).sum())}/{len(pg)}")

        # ---- final model on everything (same params), keeps the CV threshold
        extra = (mat(s_val, cap, False), mat(s_test, cap, False), mat(r_calib, cap, True))
        Xa = np.vstack([X, *[mm[0] for mm in extra]])
        ya = np.concatenate([y, *[mm[1] for mm in extra]])
        wa = np.concatenate([w, *[mm[2] * np.where(mm[1] == 1, min(pw, 10.0), 1.0) for mm in extra]])
        mf = fit(Xa, ya, wa)
        fj = to_json(mf, Xa)
        pfin = raw_predict(fj, Xc)
        # Re-pick the threshold for the final model on the (now seen) calibration split, but never below the CV one.
        thr_final = max(thr, pick_threshold(pfin[yc == 0], None, None))
        fj["threshold"] = thr_final
        report["caps"][cap]["threshold_final"] = thr_final
        model["caps"][cap] = fj

    os.makedirs("models", exist_ok=True)
    js = json.dumps(model, separators=(",", ":"))
    with open("models/ratel-model.json", "w") as fh:
        fh.write(js)
    report["model_bytes"] = len(js)
    report["model_sha256"] = hashlib.sha256(js.encode()).hexdigest()
    with open("models/report.json", "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"model: {len(js) / 1024:.0f} KiB, {sum(len(c['trees']) for c in model['caps'].values())} trees -> models/ratel-model.json")


if __name__ == "__main__":
    sys.exit(main())
