#!/bin/sh
# Network model retrain: synthetic traces + CTU-13 + desktop recording -> rows
# (through the Rust engine) -> models -> rebuild -> alert-level evaluation.
set -eu
cd "$(dirname "$0")/../.."
cargo build --release
[ -s data/net/ctu/ctu42.binetflow ] || sh train/net/fetch_ctu.sh
rm -rf data/net/synth data/net/ctu-rows
python3 -I train/net/gen_traces.py --out data/net/synth --n "${N:-900}" --seed "${SEED:-1}" --jobs "$(nproc)"
python3 -I train/net/ctu.py data/net/ctu/*.binetflow --out data/net/ctu-rows
for f in data/net/desktop-*.done.jsonl; do
    case "$f" in *.rows.jsonl) continue ;; esac
    [ -s "$f" ] && target/release/ratel watch --replay "$f" --emit "${f%.jsonl}.rows.jsonl" --emit-all >/dev/null
done
.venv/bin/python train/train_net.py
cargo build --release
.venv/bin/python train/eval_net.py > /dev/null
cargo build --release --target x86_64-unknown-linux-musl
echo "done: models/net-report.json (rows), models/net-eval.json (alerts)"
