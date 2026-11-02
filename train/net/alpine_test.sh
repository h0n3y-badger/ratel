#!/usr/bin/env bash
# Integration test: the static musl `ratel` inside a real Alpine userland, without root.
#
#   train/net/alpine_test.sh            (from anywhere; paths are resolved from this file)
#
# 1. Downloads the latest-stable Alpine x86_64 minirootfs into data/alpine-rootfs/
#    (sha256 checked against latest-releases.yaml; a verified tarball is reused).
# 2. Builds target/x86_64-unknown-linux-musl/release/ratel and copies it into a
#    freshly extracted rootfs (the rootfs is recreated on every run).
# 3. Runs ratel chrooted into that rootfs inside unprivileged user+mount(+net+pid)
#    namespaces: apk provenance, --integrity counts, tamper detection, allowlist,
#    and a short `ratel watch` + `ratel status`.
# Prints PASS/FAIL per check; exits 1 if any check failed, 2 on setup errors.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BASE="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64"
DL="$ROOT/data/alpine-rootfs"
R="$DL/root"                       # extracted rootfs (fresh each run)
BIN="$ROOT/target/x86_64-unknown-linux-musl/release/ratel"
IN_BIN=/usr/local/bin/ratel        # where ratel lives inside the rootfs
OUT="$DL/out"                      # captured outputs of this run
PY="python3 -I"

fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
info() { printf 'INFO  %s\n' "$*"; }
die()  { printf 'ERROR %s\n' "$*" >&2; exit 2; }

mkdir -p "$DL" || die "cannot create $DL"

# ---------------------------------------------------------------- 1. download
yaml=$(curl -fsSL --retry 3 "$BASE/latest-releases.yaml") || die "cannot fetch latest-releases.yaml"
read -r FILE SHA < <(printf '%s\n' "$yaml" | awk '
    /^-/ { f=0 }
    /flavor: alpine-minirootfs$/ { f=1 }
    f && $1=="file:" { file=$2 }
    f && $1=="sha256:" { sha=$2 }
    END { print file, sha }')
[[ "$FILE" == alpine-minirootfs-*-x86_64.tar.gz && "$SHA" =~ ^[0-9a-f]{64}$ ]] \
    || die "could not parse minirootfs entry from latest-releases.yaml (got '$FILE' '$SHA')"
TARBALL="$DL/$FILE"
have_sha() { [[ -f "$TARBALL" ]] && [[ $(sha256sum "$TARBALL" | cut -d' ' -f1) == "$SHA" ]]; }
if have_sha; then
    info "reusing $FILE"
else
    curl -fsSL --retry 3 -o "$TARBALL.part" "$BASE/$FILE" || die "download of $FILE failed"
    mv -f "$TARBALL.part" "$TARBALL"
fi
if have_sha; then pass "minirootfs $FILE sha256 matches release file"; else
    rm -f "$TARBALL"; die "sha256 mismatch for $FILE (deleted)"; fi

# ---------------------------------------------------------------- 2. build
( cd "$ROOT" && cargo build --release --target x86_64-unknown-linux-musl -j 4 ) >"$DL/build.log" 2>&1 \
    || { tail -20 "$DL/build.log" >&2; die "cargo build failed (see $DL/build.log)"; }
[[ -x "$BIN" ]] || die "no binary at $BIN"
if file -b "$BIN" | grep -q 'static'; then pass "binary is static ($(stat -c %s "$BIN") bytes)"
else fail "binary is not static: $(file -b "$BIN")"; fi

# Fresh rootfs. Extract as namespace-root so modes (incl. setuid) are kept; all files
# end up owned by us, which maps back to uid 0 inside the namespace.
if [[ -e "$R" ]]; then chmod -R u+rwX "$R" 2>/dev/null; rm -rf "$R" || die "cannot remove old $R"; fi
mkdir -p "$R" "$OUT" && rm -f "$OUT"/*
unshare -r tar --no-same-owner -xzf "$TARBALL" -C "$R" || die "extract failed"
install -D -m 0755 "$BIN" "$R$IN_BIN" || die "copy into rootfs failed"
[[ -f "$R/lib/apk/db/installed" ]] || die "rootfs has no /lib/apk/db/installed"

# Run a shell snippet chrooted into the rootfs, in fresh user+mount namespaces.
#   in_root [unshare flags...] -- 'sh -c snippet run inside the chroot'
# /dev is bind-mounted from the host; /proc is a new procfs for a new pid namespace.
in_root() {
    local flags=() ; while [[ $1 != -- ]]; do flags+=("$1"); shift; done; shift
    unshare -r -m -p -f "${flags[@]}" /bin/sh -c '
        set -e
        R=$1; shift
        mount --rbind /dev "$R/dev"
        mount -t proc proc "$R/proc"
        if [ -n "${NETUP:-}" ]; then ip link set lo up; fi
        exec chroot "$R" /bin/sh -c "$1"
    ' in_root "$R" "$1"
}

# json lines on stdin -> "path<TAB>kind<TAB>pkg<TAB>verdict<TAB>first-rule" per line
jsum() {
    $PY -c '
import json, sys
for l in sys.stdin:
    l = l.strip()
    if not l.startswith("{"): continue
    j = json.loads(l); o = j.get("origin") or {}
    f = j.get("findings") or [{}]
    print("\t".join([j["path"], o.get("kind", "none"), o.get("pkg", ""), j["verdict"], f[0].get("rule", "")]))
'
}

# ---------------------------------------------------------------- 3a. provenance
APKV=$(awk -v RS= '/\nP:apk-tools\n/' "$R/lib/apk/db/installed" | sed -n 's/^V://p')
info "Alpine $(cat "$R/etc/alpine-release"), apk-tools $APKV"
declare -A WANT=([/bin/busybox]=busybox [/sbin/apk]=apk-tools [/lib/ld-musl-x86_64.so.1]=musl)
for mode in plain integrity; do
    flag=""; [[ $mode == integrity ]] && flag="--integrity"
    in_root -n -- "$IN_BIN scan --all --json $flag /bin/busybox /sbin/apk /lib/ld-musl-x86_64.so.1" \
        >"$OUT/prov-$mode.jsonl" 2>"$OUT/prov-$mode.err"
    jsum <"$OUT/prov-$mode.jsonl" >"$OUT/prov-$mode.tsv"
    for p in "${!WANT[@]}"; do
        got=$(awk -F'\t' -v p="$p" '$1==p {print $2" "$3" ("$4")"}' "$OUT/prov-$mode.tsv")
        if [[ $got == "package ${WANT[$p]} "* ]]; then pass "scan --all $flag $p -> $got"
        elif [[ $mode == plain && $got == "none  (clean)" ]]; then
            # By design: without --integrity only non-clean files (risk >= 0.25) are hashed
            # (src/main.rs scan_files), so a clean file is printed with origin null.
            info "scan --all $p -> clean, origin not computed (not hashed without --integrity)"
        else fail "scan --all $flag $p -> '${got:-no output}', want package ${WANT[$p]}"; fi
    done
done

# ---------------------------------------------------------------- 3b. integrity counts
in_root -n -- "$IN_BIN scan --integrity --json /bin /sbin /lib /usr" \
    >"$OUT/integrity.jsonl" 2>"$OUT/integrity.err"
jsum <"$OUT/integrity.jsonl" >"$OUT/integrity.tsv"
total=$(wc -l <"$OUT/integrity.tsv")
counts=$(cut -f2 "$OUT/integrity.tsv" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')
info "integrity scan: $total ELF files: $counts"
awk -F'\t' '$2!="package" {print "      " $2 "\t" $1 "\t" $4}' "$OUT/integrity.tsv"
npkg=$(awk -F'\t' '$2=="package"' "$OUT/integrity.tsv" | wc -l)
nmod=$(awk -F'\t' '$2=="modified"' "$OUT/integrity.tsv" | wc -l)
nother=$(awk -F'\t' '$2!="package" && $1!="'"$IN_BIN"'"' "$OUT/integrity.tsv" | wc -l)
if (( total > 0 && nmod == 0 && nother == 0 )); then
    pass "integrity: all $npkg ELF files package-verified (besides $IN_BIN), 0 modified"
else
    fail "integrity: $nmod modified, $nother non-package (besides $IN_BIN) of $total"
fi
self=$(awk -F'\t' -v p="$IN_BIN" '$1==p {print $2}' "$OUT/integrity.tsv")
if [[ $self == unknown ]]; then pass "integrity: $IN_BIN (not in apk db) -> unknown"
else fail "integrity: $IN_BIN -> '${self:-missing}', want unknown"; fi

# ---------------------------------------------------------------- 3c. allowlist
in_root -n -- "$IN_BIN allow /bin/busybox > /tmp/allow.list && $IN_BIN scan --allow /tmp/allow.list --all /bin/busybox" \
    >"$OUT/allow.txt" 2>"$OUT/allow.err"
want_sha=$(sha256sum "$R/bin/busybox" | cut -d' ' -f1)
if grep -q "^$want_sha  /bin/busybox$" "$R/tmp/allow.list"; then pass "allow: prints sha256 line for /bin/busybox"
else fail "allow: allow.list is '$(cat "$R/tmp/allow.list")'"; fi
if grep -q '^ALLOWED .*/bin/busybox.*(allowlisted)' "$OUT/allow.txt"; then pass "scan --allow: $(head -1 "$OUT/allow.txt")"
else fail "scan --allow: '$(cat "$OUT/allow.txt" "$OUT/allow.err")'"; fi

# ---------------------------------------------------------------- 3d. watch + status
# Runs watch in the background, checks `status` while it runs and after it stopped.
NETUP=1 in_root -n -- "
    $IN_BIN watch --duration 8 --loopback --no-notify --no-scan-exes --state /tmp/st --log /tmp/a.jsonl 2>/tmp/watch.err &
    w=\$!
    sleep 3
    ping -c 3 -i 0.3 127.0.0.1 >/dev/null 2>&1 || true
    wget -q -T 1 -O /dev/null http://127.0.0.1:9/ 2>/dev/null || true
    sleep 1
    $IN_BIN status --state /tmp/st >/tmp/status-live.txt 2>&1; echo \$? >/tmp/status-live.rc
    wait \$w; echo \$? >/tmp/watch.rc
    $IN_BIN status --state /tmp/st >/tmp/status-after.txt 2>&1; echo \$? >/tmp/status-after.rc
" >"$OUT/watch.out" 2>&1
cp -f "$R"/tmp/watch.err "$R"/tmp/status-*.txt "$OUT"/ 2>/dev/null
werr=$(cat "$R/tmp/watch.err" 2>/dev/null)
wrc=$(cat "$R/tmp/watch.rc" 2>/dev/null)
if grep -q 'running (capture on' <<<"$werr"; then pass "watch: $(grep -m1 'running (' <<<"$werr" | sed 's/^ratel watch: //')"
else fail "watch did not start with capture on: $werr"; fi
if [[ $wrc == 0 ]] && grep -q 'ratel watch: stopped' <<<"$werr"; then pass "watch: stopped cleanly (exit 0)"
else fail "watch: exit '$wrc', stderr: $werr"; fi
if grep -qiE 'panic|error' <<<"$werr"; then info "watch stderr has error lines:"; sed 's/^/      /' <<<"$werr"; fi
live=$(cat "$R/tmp/status-live.txt" 2>/dev/null); live_rc=$(cat "$R/tmp/status-live.rc" 2>/dev/null)
if [[ $live_rc == 0 ]] && grep -q '^ratel watch: running' <<<"$live" && grep -q 'events' <<<"$live"; then
    pass "status (live): $(head -1 <<<"$live")"; sed -n '2,$s/^/      /p' <<<"$live"
else fail "status (live) rc=$live_rc: $live"; fi
after=$(cat "$R/tmp/status-after.txt" 2>/dev/null); after_rc=$(cat "$R/tmp/status-after.rc" 2>/dev/null)
# After a clean stop the final status is written: "stopped cleanly" (exit 1: not running).
if grep -q '^ratel watch: stopped cleanly' <<<"$after" && grep -q 'events' <<<"$after" && [ "$after_rc" = 1 ]; then
    pass "status (after stop, rc=$after_rc): $(head -1 <<<"$after")"
else fail "status (after stop) rc=$after_rc: $after"; fi

# The status file is only rewritten every 30 s, so it can't show the traffic of an 8 s
# run. A second short run with --record checks that loopback capture sees packets.
NETUP=1 in_root -n -- "
    $IN_BIN watch --duration 5 --loopback --no-notify --no-scan-exes --state /tmp/st2 --log /tmp/b.jsonl --record /tmp/rec.jsonl 2>/tmp/watch2.err &
    sleep 2
    ping -c 3 -i 0.3 127.0.0.1 >/dev/null 2>&1 || true
    wget -q -T 1 -O /dev/null http://127.0.0.1:9/ 2>/dev/null || true
    nslookup -timeout=1 example.com 127.0.0.1 >/dev/null 2>&1 || true
    wait
" >"$OUT/watch2.out" 2>&1
cp -f "$R/tmp/rec.jsonl" "$OUT/" 2>/dev/null
ev=$(grep -o '"e":"[a-z]*"' "$R/tmp/rec.jsonl" 2>/dev/null | sort | uniq -c | awk '{printf "%s%s ", $2, $1}' | tr -d '"')
if grep -q '"e":"icmp"' "$R/tmp/rec.jsonl" && grep -q '"e":"syn".*"rport":9' "$R/tmp/rec.jsonl" \
   && grep -q '"e":"dns".*example.com' "$R/tmp/rec.jsonl"; then pass "watch --record: lo capture saw icmp+syn+dns ($ev)"
else fail "watch --record: missing icmp/syn/dns events ($ev): $(cat "$R/tmp/watch2.err")"; fi

# ---------------------------------------------------------------- 3e. tamper
# Last, since it modifies the rootfs. Two kinds: a different package's ELF copied over
# a package ELF, and one byte appended to a package-owned shared library.
over=$(cd "$R" && ls usr/bin/scanelf usr/bin/getconf usr/bin/iconv 2>/dev/null | head -1)
lib=$(cd "$R" && ls usr/lib/libz.so.1.* lib/libz.so.1.* usr/lib/libcrypto.so.* lib/libcrypto.so.* 2>/dev/null | head -1)
[[ -n $over && -n $lib ]] || die "no tamper targets found"
over=/$over; lib=/$lib
over_pkg=$(awk -F'\t' -v p="$over" '$1==p {print $3}' "$OUT/integrity.tsv")
lib_pkg=$(awk -F'\t' -v p="$lib" '$1==p {print $3}' "$OUT/integrity.tsv")
cp -f "$R/bin/busybox" "$R$over"
printf 'X' >>"$R$lib"
in_root -n -- "$IN_BIN scan --integrity --json /bin /sbin /lib /usr" >"$OUT/tamper.jsonl" 2>"$OUT/tamper.err"
jsum <"$OUT/tamper.jsonl" >"$OUT/tamper.tsv"
for t in "$over:$over_pkg" "$lib:$lib_pkg"; do
    p=${t%%:*}; pkg=${t#*:}
    got=$(awk -F'\t' -v p="$p" '$1==p {print $2" "$3" "$4" "$5}' "$OUT/tamper.tsv")
    if [[ $got == "modified $pkg high modified_package_file" ]]; then pass "tamper $p -> $got"
    else fail "tamper $p -> '${got:-no output}', want 'modified $pkg high modified_package_file'"; fi
done
others=$(awk -F'\t' -v a="$over" -v b="$lib" '$2=="modified" && $1!=a && $1!=b' "$OUT/tamper.tsv" | wc -l)
if (( others == 0 )); then pass "tamper: no other file reported modified"
else fail "tamper: $others unrelated files reported modified"; fi
in_root -n -- "$IN_BIN scan --integrity $over $lib" >"$OUT/tamper.txt" 2>&1; trc=$?
if (( $(grep -c '^HIGH .*(MODIFIED pkg' "$OUT/tamper.txt") == 2 )) && grep -q modified_package_file "$OUT/tamper.txt" && (( trc == 1 )); then
    pass "tamper (text): 2x HIGH + MODIFIED pkg + modified_package_file, exit 1"
else fail "tamper (text) exit $trc: $(cat "$OUT/tamper.txt")"; fi

echo
if (( fails )); then echo "$fails check(s) FAILED (outputs in $OUT)"; exit 1; fi
echo "all checks passed (outputs in $OUT)"
