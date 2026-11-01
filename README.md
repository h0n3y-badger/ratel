# ratel

A small static "NGAV-lite": it looks at ELF and PE binaries and reports
**capabilities** — anti-debugging, anti-VM/sandbox checks, obfuscation,
packing, crypto, networking — with the evidence for each, plus a `/proc`-based
network view of running processes. No ransomware rollback, no kernel driver,
no cloud: one 1.6 MB static binary.

It is a capability detector, **not** a malware classifier. There is no malware
in the training data, so it can't learn "malicious"; it learns "this binary
detects debuggers / hides its code / probes for VMs". Commercial DRM and
anti-cheat legitimately score high (EasyAntiCheat's installer is flagged for
anti-debug, correctly).

## Use

```sh
ratel scan /usr/local/bin /opt /tmp            # human output, non-clean files only
ratel scan --all --explain FILE                # every rule finding with addresses
ratel scan --json -j 2 /srv | jq .             # JSON lines; exit 1 if any risk >= 0.75
ratel net                                      # who owns which socket + red flags (run as root)
ratel net --watch 300 --interval 1000          # also look for periodic reconnects (beacons)
ratel net --scan-exes --json                   # statically scan every networked process's binary
ratel info                                     # embedded model info
```

Example:

```
LOW        0.43  .../EasyAntiCheat/EasyAntiCheat_EOS_Setup.exe  [anti_debug(0.75) crypto(0.99) network(1.00)]
    anti_debug   int2d_icebp                INT 2D / ICEBP debugger traps (first at 0x43f169)
    anti_debug   peb_access                 reads PEB directly (fs:[30h]/gs:[60h]) x5 (first at 0x40ca35)
```

Verdicts: `clean` < 0.25 ≤ `low` < 0.5 ≤ `suspicious` < 0.75 ≤ `high`. Risk is a
fixed formula (see `src/report.rs`): per-capability weights, plus floors when
evasion (anti-debug/anti-VM) combines with hiding (obfuscation/packing), and
again with networking. A single capability alone stays `low`.

`net` flags: memfd/fileless executables (high), binaries in /tmp, /var/tmp,
/dev/shm (high), deleted-on-disk binaries (medium; also normal after package
upgrades), hidden binary names, fake kernel-thread names, raw/packet sockets,
many half-open connections, root processes fanning out to many hosts, and with
`--watch`, connections re-established on a regular period (<25% jitter, ≥5
reconnects). Sampling `/proc` misses connections shorter than the interval.

## How it works

```
file ──► features.rs ──► 151 numeric features ──► model.rs (6 GBDTs) ──┐
             │                                                          ├─► report.rs ─► verdict
             └──────────► rule findings (with evidence) ────────────────┘
```

* **Features** (`src/features.rs`, tables in `src/indicators.rs`): format/section
  anomalies (W+X, packer section names, entry point outside code, overlay,
  resources), windowed entropy, import groups and key APIs, API names present as
  strings but not imported (dynamic resolution), case-insensitive VM/sandbox/
  debugger/network/crypto strings (ASCII + UTF-16, word-bounded), findcrypt-style
  constant tables, and an x86 linear sweep with iced-x86: CPUID with hypervisor
  leaf/bit context, RDTSC, inline INT3/INT 2D/ICEBP, SIDT/SGDT/STR, VMware backdoor
  port I/O, trap-flag PUSHF/POPF, PEB/TEB/KUSER_SHARED_DATA reads, raw syscalls by
  number (ptrace, memfd_create, mprotect, …), AES-NI/SHA-NI, crypto round
  immediates, ROR13 API hashing, stack strings, random-constant compare density
  (control-flow flattening), complementary-jcc anti-disassembly, byte-wise decode
  loops. Rare instructions only count when the surrounding ±8 instructions decode
  like real code, so data embedded in `.text` doesn't produce false hits.
  Non-x86 and .NET binaries skip the disassembly part.
* **Models**: one scikit-learn `GradientBoostingClassifier` per capability (90 trees,
  depth 3), exported to JSON (295 KiB) and embedded with `include_str!`. Inference
  is comparisons and additions — deterministic; the Rust and Python
  implementations agree to 2e-16. Each capability's model only sees features that
  can carry evidence for it (no "XOR density decides anti-debug" shortcuts).
* **Decision**: capability confidence = max(model, rules). A model score with no
  supporting rule finding is capped below the detection line unless it is very
  confident, so every detection comes with a reason (tagged `model-only` otherwise).

## Training (done on the desktop, never on the server)

```sh
train/pipeline.sh            # corpus → features → models → rebuild (≈15 min on 16 cores)
```

1. `train/gen/generate.py` compiles labeled synthetic programs: 197 technique
   snippets in 37 families (Linux + Windows), mixed with 24 benign fillers and 16
   hard negatives (CPUID feature probing, a real ptrace-based tracer, sysinfo
   printers, benchmark timing, plugin loaders, CRC/base64, random lookup tables,
   help text naming hypervisors…). Six toolchains (gcc, clang, musl-gcc, zig
   linux-musl, zig windows x86_64 and x86), four opt levels, stripped or not.
   13% are packed: the inner program is XOR/LCG/RC4-encrypted into an array,
   a custom section or an overlay of a stub that decodes it and remaps it
   executable — the stub never jumps into it. **Nothing generated is ever run.**
2. Real binaries from this machine are negatives with weak labels
   (`train/corpus_real.py`): /usr, Proton, half of the Steam games. Evasion
   labels are masked (unknown) where a strong rule fires; network/crypto labels
   come from imports and constants.
3. `train/train.py` evaluates with **leave-technique-family-out** splits, picks
   thresholds on a separate validation set of families (best F1 subject to ≤0.5%
   FPR on real files and ≤2% on synthetic negatives), then trains the final
   models on everything.

### Results

Latest run (`models/report.json`): 15,859 synthetic samples, 8,739 real
training binaries, 5,278 held-out real binaries from flatpak runtimes (a
different distro's builds), 448 binaries from held-out games.

System = what `ratel scan` reports (model OR a rule of strength ≥ 2).

| capability  | recall, unseen technique families | recall, known techniques | FPR synthetic negatives | flag rate, held-out real binaries |
|-------------|-----:|-----:|-----:|-----:|
| anti_debug  | 0.59 | 0.66 | 2.2% | 0.7% |
| anti_vm     | 0.47 | 0.65 | 0.0% | 0.8% |
| obfuscation | 0.22 | 0.39 | 2.2% | 1.3% |
| packed      | 0.60 | 1.00 | 0.5% | 2.3% |
| crypto      | 0.67 | 0.76 | 1.4% | 6.3%* |
| network     | 0.96 | 1.00 | 1.4% | 7.9%* |

\* real binaries really do crypto and networking; those rates are mostly true positives.

On this machine's /usr (13.6k files): 7 `high`, 40 `suspicious`, the rest `low`/`clean`.
The highs are libc (implements ptrace/memfd syscalls), the kernel image, zig,
firejail, qbittorrent and libcap — capabilities they really have.

Footprint (static musl build, scanning /usr/bin + /usr/lib, 13.6k files):
1.6 MB binary, ~30 MiB heap regardless of thread count (files are mmapped; RSS
including mapped file pages is 130 MiB with `-j1`), 108 s single-threaded, 28 s
with 4 threads, ~30 ms for one small file. Runs on baseline x86-64 (no AVX
required; memchr/aho-corasick pick SIMD at runtime).

### Known limits

* Synthetic training data: techniques are single functions inside small programs.
  Whole-program obfuscators (OLLVM, VMProtect) leave much stronger traces than the
  corpus, so obfuscation recall here is pessimistic, but the model has never seen
  a real protector except through rules (packer section names, entropy, W+X…).
* Environment fingerprinting (uptime, disk size, process count, screen size,
  sleep-skew) and generic time-delta checks look like ordinary code statically;
  they are mostly missed. That's a static-analysis limit, not a tuning issue.
* `IsDebuggerPresent` alone is deliberately ignored: the MSVC CRT imports it in
  almost every Windows binary.
* No allowlist yet: legit tools with real capabilities (qemu, udevadm, gdb) show
  as `suspicious`. A hash-based allowlist is the obvious next step for a server.
* `net` needs root for a full view and only sees the current network namespace
  (containers need `nsenter`).

## Server deployment (not done)

`cargo build --release --target x86_64-unknown-linux-musl` gives a static binary
that runs on Alpine as-is. Nothing has been deployed; a cron job like
`ratel scan --json --min-risk 0.5 -j 2 /usr/local /opt /tmp /home | xmpp-notify`
and `ratel net --json` would be the natural first step.
