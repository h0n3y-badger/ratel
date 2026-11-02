#!/bin/sh
# Download the CTU-13 labelled bidirectional NetFlow files (text only: no
# malware, no packet captures). ~1.8 GB.
set -eu
mkdir -p "$(dirname "$0")/../../data/net/ctu"
cd "$(dirname "$0")/../../data/net/ctu"
for p in "42 capture20110810" "43 capture20110811" "46 capture20110815-2" "49 capture20110816-3" "50 capture20110817" \
         "51 capture20110818" "52 capture20110818-2" "53 capture20110819" "54 capture20110815-3"; do
    set -- $p
    [ -s "ctu$1.binetflow" ] || curl -sfL --retry 3 -o "ctu$1.binetflow" \
        "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-$1/detailed-bidirectional-flow-labels/$2.binetflow"
done
ls -la
