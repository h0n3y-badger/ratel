# ratel

A small "NGAV-lite" in one 4 MB static binary:

* `ratel scan`: looks at ELF and PE binaries and reports **capabilities**
  (anti-debugging, anti-VM/sandbox checks, obfuscation, packing, crypto,
  networking) with the evidence for each.
* `ratel watch`: a network behaviour monitor that sends alerts to XMPP. It
  covers data exfiltration, C2 beaconing, DNS and ICMP tunnels, DGA lookups,
  scanning, floods, spam bots, reverse shells, fileless networked processes and
  periodic static scans.
* `ratel net`: a one-shot `/proc` network view.

No ransomware rollback, no kernel driver, no eBPF toolchain, no cloud.

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

## Network monitoring: `ratel watch`

```sh
ratel watch                                   # as root: full view, alerts to XMPP + /var/log/ratel/alerts.jsonl
ratel watch --config contrib/watch.conf       # same options from a file (see contrib/)
ratel watch --record ev.jsonl --anonymize     # also record every event (pseudonymised IPs/names/processes)
ratel watch --replay ev.jsonl                 # run the engine on a recording; prints the alerts
```

**What it sees.** All of it is cheap kernel interfaces; no packet goes to
userspace unless a filter in the kernel asks for it.
* **Per-connection byte counters**: `NETLINK_SOCK_DIAG`, the interface `ss -ti`
  uses, dumped every 2 s.
* **Final counters of every TCP socket the moment it closes**: the kernel's
  socket-destroy notifications, so a sub-second 80 MB upload is still counted.
* **Docker containers**: both of the above are repeated inside every network
  namespace.
* **One AF_PACKET socket** with a hand-assembled classic BPF filter, which
  passes only:
  * DNS (query names and answers)
  * outbound TCP SYNs (every connection attempt, exactly timed)
  * ICMP echo requests
  * 1 in 16 UDP headers (to estimate QUIC and custom UDP volume)
* **Process attribution** via `/proc/*/fd`. Entities are the executable path,
  plus the container ID, plus the script name for interpreters
  (`/usr/bin/python3.12 [backup.py]`), so baselines don't mix.

**What it learns, per process**, persisted in `/var/lib/ratel/net-state.json`:
* hourly upload volume
* destinations it normally talks to (by /24 or /48)
* how often it meets new destinations, and how many of them never came from a
  DNS lookup (p2p routers such as i2pd learn this quickly)
* the largest volume it has ever sent to one host in an hour
* whether it's a server, and whether it ever connects out
* its active hours

Novelty rules only start after `learn-hours` (default 24).

**What it alerts on.** Each alert carries its evidence.

| kind | evidence |
|---|---|
| exfil | large or upload-heavy transfers to new destinations; above the process's own baseline; to addresses no DNS lookup returned; slow drips; large pulls by new clients |
| beacon | ≥10 connections with <20% period jitter; strong only toward bare IPs that weren't learned as normal |
| dns | long, high-entropy, ever-changing subdomains; volume encoded in query names; TXT/NULL channels |
| dga | ≥25 random-looking domains failing to resolve in 10 minutes |
| icmp | echo requests with large payloads (ICMP tunnels) |
| scan / flood / spam | SYN fan-out over hosts or ports; SYN floods; connection floods; one-way UDP volume; SMTP fan-out from a process that isn't a mail server |
| process | stdin/stdout of a shell or interpreter connected to a remote host (reverse shell); executables running from a memfd, /tmp or /dev/shm, hidden names, fake kernel-thread names |
| file | `--scan-path`: a binary scoring `high`, or a package file modified after installation (once per file version) |

Two gradient-boosted models (`flow`: exfiltration and C2 per process→host
pair; `dns`: tunnelling per base domain) score every unit once a minute.

As in `scan`, the model needs a reason:
* model plus at least weak rule evidence: up to `medium`
* `high`: needs strong rule evidence
* model alone: only a `low`, which is logged but not sent

**Alerts** go to the homelab notify socket (`/run/prosody/notify.sock`, the
protocol from `~/Projects/notify-sdk`):
* batched for 30 s (5 s when something is `high`)
* at most one message every 10 s and 60 a day
* each alert key repeats at most every 6 h, sooner only if it gets worse
* `medium` and up by default
* falls back to syslog when the socket is down

`contrib/` has an OpenRC service, a config and a logrotate file. **Nothing has
been deployed.**

Footprint, measured in a network namespace while pushing 2 GB of TCP, 300k
UDP packets and 2,000 short connections through it:
* 0.27 s of CPU
* 12 MB peak RSS (both model sets loaded)

Recording this desktop unprivileged (every 2 s, writing JSON) costs about 1%
of one core and 11.5 MB.

### After an alert: incidents, context, review, health

Detection is the first step. This is what happens after it:

* **Incidents.** Every `medium`/`high` alert opens an incident, or joins one
  already open for the same process, destination or domain in the last hour.
  The incident is a JSON-lines file, `/var/lib/ratel/incidents/<id>.jsonl`,
  holding:
  * the alerts and the context captured when it opened
  * that process's events from the **flight recorder**, a ring buffer of the
    last ~15 minutes of events, so you see what led up to it
  * every event of that process / host / domain for the **next two hours**,
    so you see what it did next

  Incident files are kept 90 days.
* **Context captured at alert time:**
  * the process tree up to init, user, command line, working directory, start
    time, container, and the number of open file descriptors
  * the executable's sha256, and whether it's an unmodified package file,
    modified, allowlisted or unknown
  * what ratel had learned about the process: first seen, usual upload,
    largest hour to one host, static-scan verdict
  * the destination: its DNS name or "no DNS lookup returned it", and when this
    process and this machine first contacted it

  Model scores come with the features that pushed them up ("model score 0.98
  because of: bytes sent (1 h) (+2.3), host new for this process (+1.1), …"),
  computed from the trees themselves. `ratel scan --explain` does the same for
  binaries.
* **XMPP messages** carry the incident ID, so you can run
  `ratel explain <id>` when you see it.
* **Review on the server:**
  ```sh
  ratel alerts --since 24h --min medium    # timeline, grouped by incident
  ratel explain exfil                      # any unique part of an incident id
  ratel ack <id>                           # reviewed
  ratel ack <id> --fp [--any-dest]         # false alarm: suppressed within a minute, no restart
  ratel status                             # running? learning? capture drops? last alert?
  ```
* **Feedback into training.** `ratel ack --fp` records which incidents were
  false alarms. `train/net/import_feedback.py` replays their recorded events
  through the engine into benign training rows. `train/net/pipeline.sh` then
  learns from your real false alarms, not only simulated ones.
* **Health:**
  * `/run/ratel/status.json` is rewritten every 30 s (`ratel status` reads it)
  * kernel packet-drop counters are checked: >1% drops in 10 minutes raises a
    health alert
  * a daemon that wasn't stopped cleanly (crash, kill, power loss) raises an
    alert on its next start
  * OpenRC's `supervise-daemon` restarts it
  * failed XMPP deliveries are counted and go to syslog
* **Daily digest** at 09:00 (`digest-hour`):
  * the last 24 h of alerts
  * the top uploaders
  * processes that started using the network for the first time
  * monitor health and learning state

  It means a quiet day still produces one message, so silence never means
  "ratel died".
* **Logs:**
  * `/var/log/ratel/alerts.jsonl` holds every alert, including `low`
  * `/var/log/ratel/watch.log` holds daemon messages
  * both are rotated by `contrib/ratel.logrotate`



`train/net/pipeline.sh` takes about an hour on this desktop with the
defaults. Every source goes through the same Rust engine
(`ratel watch --replay --emit`), so training features and live features are
computed by the same code.

* **Synthetic server traces** (`train/net/gen_traces.py`): 4,000 simulated
  servers × 8–96 h, 1.2 billion events.
  * **Benign services modelled on the homelab:**
    * a web server and reverse proxy
    * a p2p router, a Tor relay and torrent seeding, with peers on random
      ports, including "suspicious" ones by chance
    * Tailscale, including direct WireGuard UDP
    * legitimate pollers and websockets that *do* beacon
    * backups, registry pushes, Syncthing and media streaming
    * package updates, git, ssh with scp downloads
    * a mail server, Prometheus scrapes, feed fetchers
    * one-off user uploads, browsing, including QUIC
    * DNS that looks like tunnelling: reverse lookups, DNS blocklists,
      antivirus reputation lookups with long encoded names, CDN hostnames,
      ACME TXT records
  * **Attacks:** 34 labelled families (27 flow, 7 DNS). Timing and sizes
    follow published tool defaults and reports where available:
    * Cobalt Strike / Mythic / Havoc beacon sleep and jitter
    * Meterpreter HTTPS back-off
    * Mirai / IRC heartbeats
    * iodine, dnscat2 and Cobalt Strike DNS
    * rclone parallel uploads, MITRE T1030 chunk sizes
    * webhook exfiltration, XMR stratum traffic
* **CTU-13:** real traffic from a university network with hosts infected by
  Neris, Rbot, Virut, Murlo and NSIS.ay.
  * Only the labelled NetFlow records are used (`train/net/fetch_ctu.sh`):
    no malware, no payloads.
  * Normal hosts of 5 captures are training negatives.
  * Infected hosts are **never** trained on: an earlier attempt that did
    learned "looks like a 2011 university capture" and flagged 30 of 107
    normal hosts.
* **This desktop's own traffic:** 2 h, unprivileged, anonymised, used for
  evaluation only. It caught a simulator gap. Real p2p peers sometimes listen
  on "RAT" ports such as 3389 and 7777, and the first model alerted 136 times
  in 2 h. With realistic peer ports in the simulator it alerts once.
* **Your false alarms:** `ratel ack --fp` on the server plus
  `train/net/import_feedback.py` turn real false alarms into training data.

Evaluation counts what would actually reach XMPP: rules plus gated model,
cooldowns and per-process caps (`train/eval_net.py`). Whole attack families
are held out of training, and the threshold is chosen on separate validation
families. Results are split into the **learning day** (first 24 h after
install, with no baselines yet) and **steady state** (every day after):

| | steady state (1,513 server-days) | learning day (1,342 server-days) |
|---|---:|---:|
| attack episodes detected, all families | **96.2%** (682/709) | 63% (959/1530) |
| attack episodes detected, families never trained on | **95.5%** (472/494) | |
| false alarms per server per day | **0.028** (≈ 1 per 36 days) | 0.024 |

Steady-state detection per family:
* **Every episode caught:**
  * beacons: regular, jittered, back-off, named-host, tasking
  * DNS beacons, dnscat2-style polling, DNS tunnels and DNS exfiltration
  * exfiltration: odd ports, parallel streams, rclone, staged chunks, cloud,
    direct IP, inbound pulls, backup-time disguise
  * HTTP floods, reverse shells, miners, spam bots, lateral movement
* **Nearly all caught:**
  * slow drip 39/41
  * webhook exfiltration 41/43
  * low-and-slow 7/8
  * websocket C2 8/9
  * long-sleep beacons 7/8
* **Weak spots:**
  * UDP flood 31/49: the misses are hosts without packet capture
  * UDP exfiltration 2/4

How the false alarms were cut 30× (0.84 → 0.028 per server per day) without
lowering steady-state detection:
* **Long-known peers:** "never resolved by DNS" counts only for hosts that
  aren't long-known peers. Syncthing and WireGuard peers never get a DNS name.
* **Above-baseline uploads** ignore downloads served on inbound connections.
* **p2p-like processes:** a process talking to 100+ hosts per hour gets no
  "odd port", "stratum port" or "new host" evidence.
* **Learning day:** while learning, weak evidence alerts only if the model is
  very sure.
* **Per-process cap:** at most 3 alerts of one kind per process per 6 h.
* **Model alone:** never sends to XMPP. It only logs a `low`.

On **CTU-13**:
* 0 of 147 normal hosts get an alert.
* Infected hosts are detected in 7 of 9 captures. All held-out botnet
  families are detected except NSIS.ay (P2P) and one Rbot DDoS capture.

The 2 h desktop recording gives 1 alert: some program reconnecting every 11 s
with 20% jitter.

**Hardening:**
* **Fuzzing:** the parsers that see attacker-controlled bytes (DNS, packet
  headers, netlink) are fuzzed in the test suite with 3.6M mutated inputs.
  That found and fixed one bug: IPv4 headers with IHL < 5 were accepted.
* **Code reviews:** two independent reviews found 25 issues and all are
  fixed. Among them:
  * a local user could crash the daemon by truncating a file mid-scan
    (now read instead of mmapped)
  * idle connections were double-counted after 15 min
  * XMPP was lost if Prosody started after ratel
  * netlink replies weren't matched to their requests
  * unbounded memory under a SYN flood
  * the notifier could block the main loop
  * clock steps stopped detection
  * suppressions didn't match across PIDs
* **Real packets:** `unshare -rn python3 train/net/sandbox_test.py` checks
  that exfiltration, DNS tunnel, beacon, reverse shell, ICMP tunnel, port scan,
  the file scan and the XMPP path all fire on real traffic, and that the
  benign traffic doesn't.
* **Real Alpine:** `train/net/alpine_test.sh` runs the static binary inside an
  Alpine 3.24 minirootfs, without root. All 17 package binaries verify against
  apk's database. Two tampered files are reported `MODIFIED`/`HIGH`. The
  allowlist works, and `watch` starts, captures, writes status and stops
  cleanly.

Limits:
* **Root required:** the monitor needs root (capture, destroy events,
  container namespaces, attribution).
* **Very short connections:** a connection that opens and closes before the
  kernel can be asked about it gets exact bytes but only `uid:N`
  attribution. Most connections are attributed at SYN time.
* **Encrypted DNS:** DNS over HTTPS or TLS is invisible as DNS. It's just HTTPS
  flows to a resolver.
* **UDP volume is sampled:** small UDP exfiltration and UDP-only C2 are weak
  spots.
* **One-off uploads:** the remaining false alarms are uploads by user tools
  (scp, git, curl) to hosts never seen before. They are indistinguishable from
  exfiltration by traffic alone. Use `ratel ack <id> --fp` or `ignore =`.
* **No real exfiltration data:** there's no public labelled dataset for
  exfiltration, so those families are synthetic.

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
Model: 200 trees per capability, depth 3, chosen by `train/sweep_static.py`.

| capability  | recall, unseen technique families | recall, known techniques | FPR synthetic negatives | flag rate, flatpak holdout | flag rate, Alpine holdout |
|-------------|-----:|-----:|-----:|-----:|-----:|
| anti_debug  | 0.64 | 0.69 | 2.2% | 0.6% | 1.8% |
| anti_vm     | 0.47 | 0.82 | 0.0% | 0.8% | 1.2% |
| obfuscation | 0.27 | 0.45 | 1.8% | 1.4% | 0.6% |
| packed      | 0.55 | 1.00 | 0.4% | 0.2% | 0.4% |
| crypto      | 0.69 | 0.78 | 1.4% | 5.9%* | 8.8%* |
| network     | 0.96 | 1.00 | 1.7% | 7.9%* | 14.6%* |

\* real binaries really do crypto and networking; those rates are mostly true positives.

Legitimate software from projects held out of training, `suspicious`/`high`
verdict rate, previous build → this one (no package trust; these are downloaded
files):

| held-out set | files | susp+high | not-excused detections that dropped |
|---|---:|---|---|
| debuggers (lldb, rizin, ltrace) | 57 | 0% → 0% | anti_debug 18% → 0% |
| hypervisors (VirtualBox, Firecracker) | 66 | 16.7% → 4.5% | anti_vm 45% → 23% |
| container runtimes (podman, crun) | 12 | 33% → 17% | anti_vm 50% → 0% |
| VM guest tools (eval only, really detect VMs) | 80 | 7.5% → 3.7% | anti_vm 59% → 50% |
| Alpine holdout | 513 | 1.8% → 0.4% | |
| flatpak holdout | 5,278 | 0.2% → 0.0% | |

On this machine's /usr (13.6k files), `high`/`suspicious` went from 7/40 to 2/22
without package trust: libc and musl libc stay `high` because they implement
ptrace and memfd. With package trust, nothing is above `low`, because every one of
those files is verified against pacman.

Footprint (static musl build, scanning /usr/bin + /usr/lib, 13.6k files):
4 MB binary (with `watch` and both model sets), ~30 MiB heap regardless of thread count (files are mmapped; RSS
including mapped file pages is 130 MiB with `-j1`), 108 s single-threaded, 28 s
with 4 threads, ~30 ms for one small file. Runs on baseline x86-64 (no AVX
required; memchr/aho-corasick pick SIMD at runtime).

### How far can training go on this hardware?

Both trainers measure a learning curve: validation quality vs. how much training
data the model gets. Each also runs a hyperparameter sweep (successive halving,
scored on the validation families only), so "train more" is a measured
question, not a guess. Everything runs on the CPU (16 cores). The GPU isn't
needed: one network-model fit on 2M rows takes 40–100 s.

* **Static (binary) model** (`train/sweep_static.py`, 36 configurations):
  * The learning curve is flat: mean validation F1 is 0.57 / 0.56 / 0.59 at
    25 / 50 / 100% of the corpus. More synthetic binaries of the same kind
    won't help.
  * Recall on unseen families is limited by how many *different* techniques
    exist, not how many samples.
  * Tuning bought +0.02 (0.577 → 0.595 mean recall on unseen families).
* **Network flow model** (`train/net/sweep.py`, 36 configurations):

  | training traces | validation F1 (default params) |
  |---|---|
  | 10% | 0.820 |
  | 25% | 0.867 |
  | 50% | 0.888 |
  | 100% (2,000 traces) | 0.907 |

  * Still rising, so the corpus was doubled to 4,000 traces.
  * Capacity mattered more than data: 800 trees of depth 4 reach **0.953**
    on the same data.
  * With 4,000 traces and the extra attack families and hard negatives, the
    final model scores **0.986** validation F1 (recall 0.97).
* **DNS model:** saturated. Validation F1 is 0.999 at every data size and
  every configuration. Real DNS tunnels are loud, and the remaining risk is
  quiet DNS beacons (see limits).



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
  (`watch` covers containers).

## Server deployment (not done)

`cargo build --release --target x86_64-unknown-linux-musl` gives a static binary
that runs on Alpine (baseline x86-64, no AVX). On Alpine it verifies files
against `/lib/apk/db/installed`. To install the monitor:

```sh
install -m755 ratel /usr/local/bin/ratel
install -m755 contrib/ratel-watch.initd /etc/init.d/ratel-watch
install -Dm644 contrib/watch.conf /etc/ratel/watch.conf
install -m644 contrib/ratel.logrotate /etc/logrotate.d/ratel
rc-update add ratel-watch default && rc-service ratel-watch start
```

It opens no ports, so the firewall needs no changes. It learns for 24 h before
novelty alerts start. Nothing has been deployed.
