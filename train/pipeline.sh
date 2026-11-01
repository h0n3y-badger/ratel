#!/bin/sh
# Full retrain, reproducible: corpus -> features -> models -> rebuild with the new model.
# Usage: train/pipeline.sh [N_SAMPLES] [SEED]
set -eu
cd "$(dirname "$0")/.."
N=${1:-16000}
SEED=${2:-1}
cargo build --release
[ -x .venv/bin/python ] || { python3 -m venv .venv && .venv/bin/pip install -q scikit-learn numpy; }
python3 -I train/corpus_real.py
if [ ! -s data/synth/labels.jsonl ]; then
    python3 -I train/gen/generate.py --out data/synth --n "$N" --seed "$SEED" --jobs "$(nproc)"
fi
find data/synth/bin -type f | sort > data/synth.list
for n in real_train real_holdout real_games; do
    target/release/ratel features --jobs 8 --list "data/$n.txt" >| "data/$n.feats.jsonl"
done
target/release/ratel features --jobs 8 --list data/synth.list >| data/synth.feats.jsonl
.venv/bin/python train/train.py --random-split   # known-technique numbers (no model written)
.venv/bin/python train/train.py                  # leave-family-out eval + final model
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl
echo "done: target/x86_64-unknown-linux-musl/release/ratel (static), report in models/report.json"
