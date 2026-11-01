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
ratel scan --integrity /usr                    # also find package files modified after install
ratel allow /opt/myapp >> /etc/ratel/allow.list   # baseline: trust these exact files (sha256)
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

## Telling legitimate software apart

A hypervisor contains every VM vendor string, a debugger reads TracerPid, a
container runtime re-executes itself from a memfd. Those are true capabilities,
so the scanner still reports them, but three layers keep them from alerting:

1. **Provenance** (`src/trust.rs`): for every non-clean file, ratel hashes it and
   checks the package database: pacman's mtree SHA-256 on Arch/Artix, apk's
   SHA-1 on Alpine. A file that matches what its package installed is capped at
   `low` and tagged `(pkg NAME)`. A package-owned file that **doesn't** match was
   modified after installation and becomes `high` (`modified_package_file`).
   `--integrity` hashes every file, not only non-clean ones. Hash allowlists
   (`/etc/ratel/allow.list`, `~/.config/ratel/allow.list`, `--allow FILE`; lines
   of `<sha256> [comment]`, produced by `ratel allow PATH`) make a file `allowed`:
   hidden, and never counted in the exit code. Only hashes are trusted, never
   paths or names. On this desktop, 13,589 of 13,601 binaries in /usr verified
   against pacman, 0 were reported modified, and the 12 unowned ones are local
   builds.
2. **Roles** (`ROLES` in `src/indicators.rs`): several distinct markers of
   *implementing* the thing evasion code checks for (`/dev/kvm` + `KVM_CREATE_VM`
   for a hypervisor, `libthread_db` + `PTRACE_GETREGS` + DWARF for a debugger,
   `pivot_root` + `cgroup.procs` + `newuidmap` for a container runtime, Wine's
   builtin-DLL markers). A role *excuses* the capability it explains: the
   capability is still shown, tagged `excused: hypervisor`, but counts a quarter
   toward risk. Roles are ignored when the binary also hides its code
   (obfuscation, or packing evidence other than memfd re-exec), because "I'm a
   hypervisor" from a packed binary isn't believable. Markers are strings, so
   they can be faked; that's why roles only discount and never clear a file.
3. **Training**: legitimate implementers are labelled negatives for what they
   implement (see below), so the models themselves learned that "VM vendor
   strings + /dev/kvm" isn't anti-VM evasion.

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
3. `train/corpus_legit.py` downloads, but never installs or runs, packages from
   the Arch/Artix mirrors and the Alpine v3.24 CDN:
   * hypervisors: qemu, VirtualBox, Firecracker, libvirt
   * container runtimes: docker, podman, crun, runc, lxc, containerd
   * debuggers: gdb, lldb, strace, ltrace, valgrind, radare2, rizin
   * Wine
   * VM guest tools and sysinfo tools, for evaluation only, because they really
     do detect VMs

   Implementers are labelled negatives for the capability they implement (weight
   3). A further 450 random Alpine packages, the server's own musl builds, are
   ordinary weak-label negatives plus a holdout.
4. `train/train.py` evaluates with **leave-technique-family-out** splits, picks
   thresholds on a separate validation set of families (best F1 subject to ≤0.5%
   FPR on real files and ≤2% on synthetic negatives), then trains the final
   models on everything. The six models train in parallel (≈10 s on 16 cores). A GPU
   wouldn't help at this size (26k rows × 155 features: transfer overhead exceeds the work), and
   most of the pipeline's ≈15 min is compiling the synthetic corpus and extracting
   features.
5. `train/eval_legit.py OLD NEW` compares two scanner builds at the verdict level on
   held-out legitimate software (`models/legit_eval.json`).

### Results

Latest run (`models/report.json`): 15,859 synthetic samples; 10,278 real
training binaries, including 1,002 Alpine binaries and 537 legit-tool binaries;
5,278 held-out flatpak runtime binaries (a different distro's builds); 513
held-out Alpine binaries; 448 binaries from held-out games.

System = what `ratel scan` reports (model OR a rule of strength ≥ 2).

| capability  | recall, unseen technique families | recall, known techniques | FPR synthetic negatives | flag rate, flatpak holdout | flag rate, Alpine holdout |
|-------------|-----:|-----:|-----:|-----:|-----:|
| anti_debug  | 0.61 | 0.63 | 2.2% | 0.6% | 1.8% |
| anti_vm     | 0.46 | 0.71 | 0.0% | 0.6% | 1.4% |
| obfuscation | 0.22 | 0.38 | 2.0% | 1.3% | 0.6% |
| packed      | 0.55 | 0.99 | 0.5% | 0.2% | 0.4% |
| crypto      | 0.66 | 0.77 | 1.3% | 6.1%* | 9.6%* |
| network     | 0.96 | 1.00 | 1.4% | 7.9%* | 14.6%* |

\* real binaries really do crypto and networking; those rates are mostly true positives.

Legitimate software from projects held out of training, `suspicious`/`high`
verdict rate, previous build → this one (no package trust; these are downloaded
files):

| held-out set | files | susp+high | not-excused detections that dropped |
|---|---:|---|---|
| debuggers (lldb, rizin, ltrace) | 57 | 0% → 0% | anti_debug 18% → 0% |
| hypervisors (VirtualBox, Firecracker) | 66 | 16.7% → 6.1% | anti_vm 45% → 23% |
| container runtimes (podman, crun) | 12 | 33% → 17% | anti_vm 50% → 17% |
| VM guest tools (eval only, really detect VMs) | 80 | 7.5% → 7.5% | anti_vm 59% → 47% |
| Alpine holdout | 513 | 1.8% → 1.0% | |

On this machine's /usr (13.6k files), `high`/`suspicious` went from 7/40 to 2/22
without package trust: libc and musl libc stay `high` because they implement
ptrace and memfd. With package trust, nothing is above `low`, because every one of
those files is verified against pacman.

Footprint (static musl build, scanning /usr/bin + /usr/lib, 13.6k files):
1.7 MB binary, ~30 MiB heap regardless of thread count (files are mmapped; RSS
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
* Package trust is only as good as the package database: root can rewrite
  both a binary and its database entry. It protects against dropped and
  replaced files, not against an attacker who already owns root and is careful.
  Debian's dpkg (MD5 only) isn't supported.
* Without provenance, podman still scores `high`: it reads TracerPid and
  re-executes itself from a memfd, which is exactly what a fileless loader
  looks like. The evasion + memfd floor is kept deliberately.
* Roles are string-based and can be faked. That's why they only discount, and
  are void when code is hidden.
* There's no Authenticode verification for PE files: signed Windows software is
  only trusted via the hash allowlist.
* `net` needs root for a full view and only sees the current network namespace
  (containers need `nsenter`).

## Server deployment (not done)

`cargo build --release --target x86_64-unknown-linux-musl` gives a static binary
that runs on Alpine as-is and verifies against `/lib/apk/db/installed` there.
Nothing has been deployed; a cron job like
`ratel scan --json --min-risk 0.5 -j 2 /usr/local /opt /tmp /home | xmpp-notify`
and `ratel net --json` would be the natural first step.
