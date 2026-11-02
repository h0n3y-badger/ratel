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
* **ClamAV signatures** (from freshclam's `/var/lib/clamav`) for plain
  "known malware" detection of any file type, plus **quarantine** and
  **process containment** (`ratel quarantine`, `ratel contain`, automatic in
  `ratel watch` for signature matches).

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


### Web dashboard: `ratel web`

A small dashboard over what `ratel watch` writes, so you don't need SSH. It
has four views:
* **Overview:** health, learning state, alert counts and a 48 h chart, open
  incidents, top uploaders.
* **Live:** the busiest flows per process right now, processes and DNS.
* **Alerts.**
* **Incidents:** the full `ratel explain` view, with **Reviewed** /
  **False alarm** buttons.

It's built into the same binary, so there's nothing extra to install on Alpine.

```sh
ratel web --init-token                       # once, as root: prints the access token, stores only its hash
rc-update add ratel-web default && rc-service ratel-web start   # contrib/ratel-web.initd
# then https://homelab.<tailnet>.ts.net:8448 through stunnel (contrib/stunnel-ratel-web.conf)
```

Security, because this sits next to a root daemon:

* **Independent review:** an adversarial review found 11 issues, all fixed and
  covered by tests:
  * a pre-auth log flood (91 MB/s)
  * slowloris
  * an admin lockout behind stunnel
  * localhost port squatting to steal the token
  * over-broad false-alarm suppressions
  * suppressions planted while the daemon was down
  * Landlock missing UDP and UNIX-socket rights
  * log injection via bare LF
  * group permissions
  * bidi spoofing
* **Least privilege:** `ratel web` never runs as root. It drops to `ratel-web`
  with no supplementary groups, sets no-new-privileges, and disables core
  dumps and ptrace attach. A **Landlock** sandbox then limits it to
  *read-only* access to `/var/lib/ratel`, `/var/log/ratel` and `/run/ratel`,
  plus write access to the feedback inbox `/var/lib/ratel/feedback.d/`.
  * On kernels with Landlock ABI ≥ 4 it can't open outbound TCP connections or
    bind other ports. With ABI ≥ 6 it can't reach abstract UNIX sockets or
    signal other processes. With ABI ≥ 9 / 10 it can't connect to UNIX socket
    files or send UDP.
  * At startup it proves the sandbox works: reading `/etc/passwd`, writing
    outside the inbox, outbound TCP and UDP must all fail. It refuses to start
    without Landlock unless given `--allow-unsandboxed`.
  * The daemon writes its files with umask 027 for the `ratel` group, so
    nobody else can read them.
* **Network exposure:** in production it listens on a **UNIX socket** in
  `/run/ratel-web` (owner ratel-web, group stunnel). Unlike a localhost port,
  no local user can squat it while the dashboard is down and receive the
  token. stunnel terminates TLS with the Tailscale certificate, so it's
  reachable on the tailnet only, and passes the real client address with the
  PROXY protocol. Cookies are `Secure` with the `__Host-` prefix, plus HSTS. A
  TCP listener defaults to 127.0.0.1 and needs `--allow-remote` for anything
  else.
* **Authentication:**
  * a 256-bit access token, stored only as a SHA-256 hash
  * login attempts are serialized with a 0.5 s delay on failure; there's no
    lockout an attacker could trigger against you, and brute force is
    impossible anyway
  * 256-bit random session ids in HttpOnly, SameSite=Strict cookies, idle
    expiry 12 h, absolute expiry 7 days
* **Every POST** needs a per-session CSRF token *and* an `Origin` matching the
  `Host`. The `Host` must be in an allowlist, which defeats DNS rebinding.
* **HTTP handling:**
  * strict CSP (`default-src 'none'`, scripts and styles only from itself)
  * frame-deny, nosniff, no-referrer, COOP/CORP, `no-store`
  * 8 KB header and body limits
  * an absolute 10 s deadline per request and 20 s per response (no
    slowloris)
  * 32 connections at most, no chunked bodies, no bare CR/LF, no duplicate
    Host/Origin/Cookie headers
  * incident ids checked against `YYYYMMDD-HHMMSS-kind` before any file access
* **The frontend** builds all DOM with `textContent` / `createElement`: alert
  text, DNS names and command lines are attacker-controlled and never parsed
  as HTML. Bidi overrides and invisible characters are shown as `\u{…}`
  escapes, so a process name can't disguise itself. It loads no external
  resources.
* **Audit:** every login (successful or failed), every rejected request and
  every acknowledgement is logged to `/var/log/ratel/web.log`, sanitized and
  rate-limited so the log can't be used to fill the disk.
* **Tamper visibility:** the root daemon announces every new suppression as an
  alert. It checks against a root-only ledger, so this includes suppressions
  planted while it was down. Broad ones are always listed in full.
  * Wildcards for unidentified processes are rejected, and the feedback inbox
    is capped (32 files, 1 MB each).
  * A compromised dashboard can at most mark specific things as false alarms,
    and that's visible on XMPP immediately.
* **Tests:**
  * `python3 train/web_test.py <state> <alerts.jsonl>` runs 57 checks: sandbox,
    auth, no-lockout, CSRF, Origin, Host, smuggling, slowloris, log flooding,
    path traversal, suppression scope, UNIX socket + PROXY, every route,
    headers.
  * The real-traffic sandbox test checks that planted suppressions are
    announced and catch-all wildcards rejected.

### Resisting injected or forged results

ratel runs as root and reads input from unprivileged sources: other users'
processes, containers, network peers, and the dashboard. None of these should be
able to plant a result, hide one, or launder an attacker's traffic as normal.

* **Text:** every attacker-chosen string (file names, command lines, DNS names,
  process names) is escaped before it reaches a terminal, a log line or an XMPP
  message. This covers control characters, ANSI sequences, bidi overrides,
  zero-width/tag/variation characters and filler characters. Entity names also
  escape `\`, so two different programs can never end up with the same name
  (and so share one baseline).
* **Files ratel believes:** the config, saved state, allowlists and
  `feedback.jsonl` are read with `trusted_read`:
  * symlinks are not followed;
  * the *opened* file must be owned by root (or ratel's own user) and not be
    group- or world-writable;
  * every directory above it, both as written and as resolved, must be
    trusted.

  An untrusted state file is ignored and raises a high health alert, and an
  untrusted config is refused. The dashboard's inbox (`feedback.d`) is
  untrusted by design: reads are capped, FIFOs and symlinks are refused, every
  suppression is announced, and catch-all wildcards are rejected. Package
  databases and the scan path are checked the same way. Scans open files with
  `O_NOFOLLOW`/`O_NONBLOCK` and never follow symlinks while walking.
* **Kernel data:** netlink replies are accepted only from the kernel
  (`nl_pid` 0) and matched by sequence number. Exact socket lookups check that
  the kernel returned the socket that was asked about.
* **DNS names:** a name is attached to an address only when:
  * the answer matches a query that was really sent (id, name, port and server;
    single use, within 10 s); and
  * that query went to a trusted resolver: one in `/etc/resolv.conf`, a large
    public resolver, a `resolver =` entry, or the host's own resolver daemon
    asking upstream (checked by process, not by name).

  A forged answer is dropped and counted. Bursts raise a "possible DNS
  spoofing" health alert. A program asking its own DNS server gets no names, so
  that server can't make the attacker's address look like github.com. The
  sandbox test checks both cases, plus a control run where trusting the rogue
  server does let the forged name through. Floods can't evict pending queries
  from the trusted resolver, and evictions never count as spoofing.
* **Who did it:**
  * The uid comes from the owner of `/proc/<pid>`, and every non-root user gets
    their own baselines (`(uid N)`).
  * Interpreters are named with the full script path. Containers, and
    processes in a private mount namespace, get their own prefix.
  * For programs started through the dynamic loader (`ld-musl prog`), the
    program is taken from `/proc/pid/maps` (ELF objects that request an
    interpreter) and read through `map_files`. A rewritten argv can't rename
    it or redirect its scan.
  * UDP ports are attributed to host sockets before any other network
    namespace's sockets, so nobody can claim port 53 with `unshare -rn`.
  * Executable scans are keyed on the file's identity (device, inode, ctime,
    size), so a binary swapped in at the same path is scanned again.
* **Poisoning the baseline:**
  * A high alert freezes that process's learning for an hour: no
    destinations, no upload volume. Any rise in its "largest normal upload"
    over the previous hour is undone. Medium alerts only un-learn their own
    destination, if it was learned in the last hour. A full freeze on medium
    alerts let one false alarm cascade into more (4× the learning-day false
    alarms).
  * When the entity table is full, processes that appeared after learning are
    evicted first.
  * Past the per-process alert cap, alerts are still logged and filed, and
    XMPP reports a count. High alerts bypass the daily XMPP cap.
* **Self-integrity:** the binary's SHA-256 is kept in the state. A change raises
  a health alert.
* **`ignore-dest` takes IP addresses only.** A domain could share a CDN address
  with any other site.

### How the network models are trained

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
* **Root can do anything:** none of the tampering defences above stop root.
  An attacker with root can stop or replace ratel. The binary hash check and
  XMPP silence (no digest, no heartbeat) are the only tells.
* **Slow baseline inflation:** a process can raise its own "normal" upload
  size through hours that don't alert. Capping that growth (4× per day) was
  tried and dropped. It made busy servers' ordinary growth look abnormal, for
  four times the false alarms.
* **LAN and tailnet uploads:** volume rules apply to public destinations only.
  Treating private and overlay destinations the same way (at 10× the
  thresholds) flagged ordinary backups to a NAS, at 1.2 false alarms a day, and
  caught nothing extra in the evaluation.
* **Packets ratel doesn't parse:** IPv6 extension headers and IPv4 fragments
  aren't parsed. DNS carried in them isn't seen, and their UDP volume is only
  counted, not attributed.
* **UDP attribution is by port:** a sampled UDP packet is attributed to the
  owner of its local port. Host sockets win over other namespaces, but two
  containers using the same port can be confused.
* **DNS from a non-standard resolver:** answers from a resolver that's neither
  configured nor a big public one carry no names, until it's added with
  `resolver =`.

## Known-malware signatures, quarantine and containment

### ClamAV signatures

When `/var/lib/clamav` exists (kept current by freshclam), `ratel scan` and
`ratel watch` match **every file**, not only ELF/PE, against ClamAV's databases.
ratel reads them with its own matcher in Rust: no libclamav, no clamd.

* **Coverage:**
  * whole-file MD5/SHA1/SHA256 hashes, including `*` sizes;
  * PE section hashes;
  * extended (`.ndb`) and logical (`.ldb`) body signatures, with the full hex
    syntax, every offset form, the `::i ::w ::a ::f` modifiers and counted
    expressions;
  * target types, functionality levels, `.fp`/`.sfp` allowlists and `.ign2`;
  * clamscan's text typing (ported from `textdet.c`) and text normalization
    (from `textnorm.c`).

  PUA signatures are off unless `--pua` is given.
* **Not supported** (2,917 of ~600k general signatures skipped):
  * PCRE, byte-compare, macro and fuzzy-image subsignatures;
  * bytecode signatures and icon groups;
  * container-only signatures, because ratel doesn't unpack archives, documents
    or installers;
  * ClamAV's full HTML and JavaScript normalizers (an approximation is used).
* **Parity with clamscan:** `train/clamav_parity.py` builds a test file for
  each of 1,500 randomly sampled real signatures. Of the 1,461 files it
  generated, clamscan confirms 1,460. On all 1,460 of those, ratel reports
  **exactly the same set of names as `clamscan --allmatch`**. That covers every
  target type and offset form, counts, modifiers and text normalization.
  * Hash, wildcard-size, section-hash, `.fp`/`.sfp` and `.ign2` cases all
    match too.
  * On `/usr/bin`, `/usr/lib/python3.14` and `/usr/share/doc`, neither scanner
    reports anything.
* **Cost:**
  * The general part loads in about 1.2 s and uses **41 MB**.
  * The Windows part is most of the database: 2.7M section hashes and
    ~1.4M patterns. It loads (about 5 s, ~350 MB peak) only when a PE file is
    scanned. `ratel watch` releases it after 10 idle minutes.
  * Matching uses a 4-byte anchor index with a byte prefilter, a backtracking
    bytecode matcher with per-try and per-pattern step budgets, and a memo for
    `*` gaps. With signatures on, `/usr/bin` (2.3 GB) scans in 24 s instead of
    10 s.
  * Hash signatures are held as 64-bit prefixes. On a hit, the name comes from
    the database files, which also re-checks the full hash.
* **Trust:**
  * The databases must be owned by root or the `clamav` user and must not be
    group- or world-writable. Otherwise they are refused, with a health alert.
  * A `.cvd`'s MD5 header is verified. ClamAV's own RSA and PKCS#7 signatures
    are not; freshclam checks those when it downloads.
  * Whoever can write the database decides what gets quarantined. The response
    limits below cap the damage.

### Quarantine (`ratel quarantine`)

Files go into `/var/lib/ratel/quarantine/<id>/`, root-only.

* **Storage:** each item is a scrambled copy (XOR keystream, not
  encryption) plus `meta.json`. Other scanners don't re-detect it and it can't
  be run by accident.
* **Moving a file:**
  * The file is opened once without following links, hashed through that
    handle, and must still have the content that was scanned.
  * It is removed with `unlinkat` on the parent directory, only if the name
    still points to the same inode. A file or symlink swapped in meanwhile is
    left alone, and the error says so.
  * Hard links are reported, since other links keep the content.
* **Restoring:** `ratel quarantine restore ID` writes the file back with its
  mode, owner and mtime. It never overwrites, and never follows a symlink,
  even with `--force`.
  * The target directory is opened one component at a time without following
    links. It must be the same directory (device and inode) the file came
    from, owned by root or the file's owner.
  * That blocks a quarantined user file being restored, by root, into a
    directory swapped in by a symlink, such as `/etc/profile.d`.
  * `--to` restores elsewhere.
* **`/dev/shm` and `/dev/mqueue`:** both are covered; the rest of `/dev`,
  `/proc` and `/sys` never are.
* **Commands:** `list`, `show`, `add PATH`, `restore ID [--to PATH]` and
  `delete ID`. `ratel scan --quarantine` moves signature matches from a manual
  scan.

### Containment (`ratel contain`)

`ratel contain` freezes a process tree.

* **Method:** it uses the cgroup v2 freezer. A `ratel-contain/<id>` cgroup is
  frozen first, then the process and every descendant are moved in, repeating
  until no new children appear.
* **Fallback:** without a writable cgroup2 it uses SIGSTOP. That is weaker,
  because a same-uid process can send SIGCONT.
* **Undo:** `release ID` puts every process back in its original cgroup and
  thaws it. `kill ID` ends the tree.
* **Safety:**
  * PID reuse is caught by checking each process's start time. ratel watch
    passes the start time seen at detection, so a pid freed and reused by an
    innocent process isn't frozen.
  * It never freezes init, ratel or its ancestors, or kernel threads.
  * It never freezes sshd, tailscaled, OpenRC, dockerd, containerd or prosody,
    plus anything in `contain-never`, so a false positive can't lock the admin
    out. Interpreters are protected only for their service user
    (`/usr/bin/lua5.4@prosody`), so malware can't escape a freeze by running
    as `lua5.4`.

### What `ratel watch` does on its own

| Detection | Default response |
|---|---|
| A file in a `scan-path` matches a signature | freeze processes running it, then quarantine it |
| A running networked program's executable matches a signature | freeze its process tree, then quarantine the executable |
| High behaviour alerts (exfil, beacon, reverse shell...) | nothing (`contain = high` to freeze) |
| Capability scanner "high" | alert only |

* **No automatic moves for package files:** a file that belongs to a package
  (even a modified one) or is allowlisted is never moved automatically. A
  trojaned `/usr/bin/sshd` is reported for reinstalling.
* **No automatic moves without a package database:** if the package database
  can't be trusted, nothing under `/usr`, `/bin`, `/sbin`, `/lib`, `/etc`,
  `/boot` or `/opt` is moved.
* **Responses act on what was scanned**, never on a path looked up again:
  * processes are found by the scanned file's device and inode;
  * the file is quarantined at the location the kernel reported for the open
    file;
  * the package-origin lookup uses that same location.

  A directory swapped for a symlink to `/bin` right after the read can't turn
  "quarantine /tmp/u/busybox" into "freeze every busybox".
* **Every action lands in the alert's evidence**, with the undo command (the
  XMPP message too).
* **Not fully checked is never clean:** a file can hold many near-matches
  meant to use up a signature's attempt budget before the real match. A file
  where a matching budget ran out is reported as `INCONCLUSIVE`
  (`clamav:not-fully-checked`, a medium alert in ratel watch), not as clean.
  * Only anchor hits inside a signature's offset window count towards the
    budget (50,000 per signature and file).
  * PE section hashing stops at 96 sections and 4 name look-ups per file.
* **Status:** `ratel status` and the dashboard's status show the vault and
  containment counts.
* **Off switches:** `quarantine = off`, `contain = off`.
* **Tests:** the sandbox test runs this end to end without root, using a test
  signature database. The EICAR file in a scanned folder is quarantined. A
  copy of Python made "known malware" by its hash beacons to the test C2
  address; it is frozen and its executable quarantined.
  * A first version of that test used a byte-identical copy and so flagged the
    interpreter running the test itself. ratel refused to freeze it, because it
    was its own parent. That is how the system-directory rule above was found.

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

For the signature part, install freshclam so `/var/lib/clamav` stays current
(Alpine: the `freshclam` package, run as its service or from cron).
ratel picks up updated databases within 15 minutes. clamd is not needed.
