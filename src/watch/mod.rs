//! `ratel watch`: network behaviour monitoring (data exfiltration, C2
//! beaconing, DNS / ICMP tunnels, DGA, scanning, reverse shells, fileless
//! networked processes) with XMPP alerts through the notify socket.
//!
//! Live:   ratel watch                       (root for the full view)
//! Record: ratel watch --record ev.jsonl     (events for training / debugging)
//! Replay: ratel watch --replay ev.jsonl [--emit rows.jsonl]

pub mod capture;
pub mod cli;
pub mod incidents;
pub mod diag;
pub mod dns;
pub mod engine;
pub mod events;
pub mod notify;
pub mod procs;
pub mod respond;

use engine::{Alert, Config, Engine, State};
use events::Event;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const USAGE: &str = "ratel watch — network behaviour monitor

usage: ratel watch [opts]
  --config FILE        key = value lines, same names as the options (default /etc/ratel/watch.conf)
  --state DIR          learned baselines (default /var/lib/ratel; replay: none)
  --log FILE           append alerts as JSON lines (default /var/log/ratel/alerts.jsonl when root)
  --interval SECS      socket dump interval (default 2)
  --learn-hours H      hours of learning before novelty rules apply (default 24)
  --cooldown H         hours before the same alert repeats (default 6)
  --notify-min SEV     lowest severity sent over XMPP: low|medium|high (default medium)
  --no-notify          never use the notify socket
  --no-capture         no packet capture (no DNS / SYN / ICMP / UDP visibility)
  --no-scan-exes       don't statically scan executables that start networking
  --ignore ENTITY      never alert for this entity (repeatable; trailing * = prefix)
  --ignore-dest IP     never alert for this address (repeatable; addresses only: a name
                       could share a CDN address with any other site)
  --scan-path DIR      also scan DIR statically every --scan-every hours (repeatable);
                       alerts once per file version on `high` and on modified package files
  --scan-every H       hours between static scans (default 6)
  --digest-hour H      send a daily XMPP digest at this local hour (default 9; off to disable)
  --status FILE        health/status file (default /run/ratel/status.json; see `ratel status`)
  --duration SECS      stop after SECS (default: run forever)
  --json               print alerts as JSON lines
  --record FILE        also write every event (JSON lines)
  --anonymize          with --record: replace IPs and names by stable pseudonyms
  --replay FILE        run the engine on recorded events instead of the live system
  --emit FILE          with --replay: write feature rows (training)
  --emit-all           with --emit: don't thin benign rows
  --loopback           include the loopback interface (testing in a network namespace)
  --resolver IP        also trust DNS answers from this server (repeatable; /etc/resolv.conf
                       servers and the big public resolvers are trusted already)
  --clamav-db DIR      ClamAV databases for the path scans and networked executables
                       (default /var/lib/clamav if present, kept current by freshclam)
  --no-clamav          don't use ClamAV signatures
  --quarantine MODE    off | signatures (files matching a ClamAV signature) | suspicious
                       (default: also executables in /tmp, /var/tmp, /dev/shm with 2+ of
                       anti-debug/anti-VM/obfuscation/packing at >= 0.85, and temp-dir
                       programs frozen for high alerts). Into <state>/quarantine; never
                       package-owned or allowlisted files. The dashboard can change it.
  --contain MODE       off | signatures (default: freeze processes running a matching or
                       obviously bad file) | high (also the processes behind high
                       network/process alerts). The dashboard can change it.
  --contain-never EXE  never freeze processes of this executable (repeatable; sshd,
                       tailscaled, init, dockerd, prosody... are protected already)
";

#[derive(Default)]
struct WOpts {
    state: Option<String>,
    log: Option<String>,
    interval: f64,
    learn_hours: f64,
    cooldown_h: f64,
    notify_min: String,
    no_notify: bool,
    no_capture: bool,
    no_scan: bool,
    ignore: Vec<String>,
    ignore_dest: Vec<String>,
    duration: f64,
    json: bool,
    record: Option<String>,
    anonymize: bool,
    replay: Option<String>,
    emit: Option<String>,
    emit_all: bool,
    loopback: bool,
    scan_paths: Vec<String>,
    resolvers: Vec<IpAddr>,
    clamav_db: Option<String>,
    no_clamav: bool,
    quarantine: String,
    contain: String,
    contain_never: Vec<String>,
    scan_every: f64,
    digest_hour: i32,
    status: Option<String>,
    emit_thin: u64,
    net_model: Option<String>,
}

fn parse(args: &[String]) -> Result<WOpts, String> {
    let mut o = WOpts { interval: 2.0, learn_hours: 24.0, cooldown_h: 6.0, notify_min: "medium".into(), scan_every: 6.0, digest_hour: 9, ..Default::default() };
    // config file first, command line overrides
    let cfg_path = args.windows(2).find(|w| w[0] == "--config").map(|w| w[1].clone());
    let mut all: Vec<String> = vec![];
    let cfg = cfg_path.clone().unwrap_or_else(|| "/etc/ratel/watch.conf".into());
    // the config decides what is ignored: refuse one that others could have edited
    let read = if std::path::Path::new(&cfg).exists() {
        match crate::safety::trusted_read_string(std::path::Path::new(&cfg), 1 << 20) {
            Ok(s) => Ok(s),
            Err(e) => return Err(format!("refusing config: {e} (fix: chown root, chmod go-w, no symlink)")),
        }
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    };
    match read {
        Ok(s) => {
            for line in s.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                let (k, v) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())).unwrap_or((line, ""));
                all.push(format!("--{k}"));
                if !v.is_empty() && !matches!(v, "true" | "yes") {
                    all.push(v.to_string());
                }
            }
        }
        Err(e) if cfg_path.is_some() => return Err(format!("{cfg}: {e}")),
        Err(_) => {}
    }
    all.extend(args.iter().cloned());
    let mut i = 0;
    let val = |i: &mut usize| -> Result<String, String> {
        *i += 1;
        all.get(*i).cloned().ok_or_else(|| format!("{} needs a value", all[*i - 1]))
    };
    let num = |s: String| -> Result<f64, String> { s.parse().map_err(|_| format!("bad number {s}")) };
    while i < all.len() {
        match all[i].as_str() {
            "--config" => {
                val(&mut i)?;
            }
            "--state" => o.state = Some(val(&mut i)?),
            "--log" => o.log = Some(val(&mut i)?),
            "--interval" => o.interval = num(val(&mut i)?)?.max(0.5),
            "--learn-hours" => o.learn_hours = num(val(&mut i)?)?,
            "--cooldown" => o.cooldown_h = num(val(&mut i)?)?,
            "--notify-min" => o.notify_min = val(&mut i)?,
            "--no-notify" => o.no_notify = true,
            "--no-capture" => o.no_capture = true,
            "--no-scan-exes" => o.no_scan = true,
            "--ignore" => o.ignore.push(val(&mut i)?),
            "--ignore-dest" => {
                let v = val(&mut i)?;
                let ip: IpAddr = v.parse().map_err(|_| format!("--ignore-dest takes an IP address, not {v:?}"))?;
                o.ignore_dest.push(ip.to_string());
            }
            "--duration" => o.duration = num(val(&mut i)?)?,
            "--json" => o.json = true,
            "--record" => o.record = Some(val(&mut i)?),
            "--anonymize" => o.anonymize = true,
            "--replay" => o.replay = Some(val(&mut i)?),
            "--emit" => o.emit = Some(val(&mut i)?),
            "--emit-all" => o.emit_all = true,
            "--net-model" => o.net_model = Some(val(&mut i)?),
            "--emit-thin" => o.emit_thin = num(val(&mut i)?)?.max(1.0) as u64,
            "--loopback" => o.loopback = true,
            "--digest-hour" => {
                let v = val(&mut i)?;
                o.digest_hour = if v == "off" { -1 } else { v.parse().map_err(|_| format!("bad --digest-hour {v}"))? };
            }
            "--status" => o.status = Some(val(&mut i)?),
            "--scan-path" => o.scan_paths.push(val(&mut i)?),
            "--clamav-db" => o.clamav_db = Some(val(&mut i)?),
            "--no-clamav" => o.no_clamav = true,
            "--quarantine" => o.quarantine = val(&mut i)?,
            "--contain" => o.contain = val(&mut i)?,
            "--contain-never" => o.contain_never.push(val(&mut i)?),
            "--resolver" => {
                let v = val(&mut i)?;
                o.resolvers.push(v.parse().map_err(|_| format!("bad resolver address {v}"))?);
            }
            "--scan-every" => o.scan_every = num(val(&mut i)?)?.max(0.05),
            "-h" | "--help" => return Err(String::new()),
            s => return Err(format!("unknown watch option {s}")),
        }
        i += 1;
    }
    Ok(o)
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Learned state is only loaded from a directory and file nobody else can write: forged
/// state could plant baselines, known destinations or cooldowns that hide an attack.
fn load_state_checked(dir: &Option<String>) -> (State, Option<String>) {
    let Some(d) = dir else { return (State::default(), None) };
    let dp = std::path::Path::new(d);
    let f = dp.join("net-state.json");
    if !f.exists() {
        return (State::default(), None);
    }
    let b = match crate::safety::trusted_read(&f, 512 << 20) {
        Ok(b) => b,
        Err(e) => return (State::default(), Some(format!("saved state ignored, starting fresh: {e}"))),
    };
    match serde_json::from_slice(&b).ok() {
        Some(s) => (s, None),
        None => (State::default(), Some("saved state unreadable, starting fresh".into())),
    }
}

fn load_state(dir: &Option<String>) -> State {
    load_state_checked(dir).0
}

fn save_state(dir: &Option<String>, st: &mut State) {
    let Some(d) = dir else { return };
    st.saved_t = now();
    let _ = std::fs::create_dir_all(d);
    let tmp = format!("{d}/net-state.json.tmp");
    if let Ok(b) = serde_json::to_vec(st) {
        use std::os::unix::fs::OpenOptionsExt;
        // learned baselines: root only (the dashboard group doesn't need them)
        let w = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)
            .and_then(|mut f| f.write_all(&b));
        if w.is_ok() {
            let _ = std::fs::rename(&tmp, format!("{d}/net-state.json"));
        }
    }
}

struct Out {
    json: bool,
    log: Option<std::fs::File>,
    notifier: notify::Notifier,
}

impl Out {
    fn alert(&mut self, a: &Alert) {
        let j = serde_json::to_string(a).unwrap_or_default();
        if self.json {
            println!("{j}");
        } else {
            println!("{:<6} {}  {}", a.severity.to_uppercase(), fmt_t(a.t), crate::safety::safe(&a.title));
            for e in &a.evidence {
                println!("         - {}", crate::safety::safe(e));
            }
        }
        if let Some(f) = self.log.as_mut() {
            let _ = writeln!(f, "{j}");
        }
        self.notifier.push(a);
    }
}

fn fmt_t(t: f64) -> String {
    let s = t as i64;
    format!("{:02}:{:02}:{:02}Z", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

struct Sink {
    rec: Option<std::io::BufWriter<std::fs::File>>,
    recorder: incidents::Recorder,
    store: Option<incidents::Store>,
    events: u64,
}

/// Medium+ alerts get context and an incident; everything is logged / notified.
fn handle_alert(mut a: Alert, eng: &Engine, sink: &mut Sink, out: &mut Out, health: &mut incidents::Health) {
    if notify::sev_rank(a.severity) >= 2 && a.kind != "health" {
        a.context = incidents::alert_context(&a, eng);
        if let Some(s) = sink.store.as_mut() {
            a.incident = s.on_alert(&a, &sink.recorder).0;
        }
    }
    health.note_alert(&a);
    out.alert(&a);
}

fn health_alert(kind_note: &str, severity: &'static str, title: &str, evidence: Vec<String>) -> Alert {
    Alert { t: now(), severity, kind: "health", entity: "ratel".into(), pid: std::process::id(), dest: kind_note.into(), score: 0.0,
        title: title.into(), evidence, incident: String::new(), context: serde_json::Value::Null, capped: false }
}

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn run(args: &[String]) {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("ratel: {e}");
            }
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    let net_json = match &o.net_model {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("ratel: {p}: {e}");
            std::process::exit(2)
        }),
        None => crate::model::EMBEDDED_NET.to_string(),
    };
    let model = crate::model::NetModel::load(&net_json,
        &[("flow", engine::FLOW_FEATURES), ("dns", engine::DNS_FEATURES)]).unwrap_or_else(|e| {
            eprintln!("ratel: {e}");
            std::process::exit(2)
        });
    let cfg = Config { suppress: Default::default(), learn_hours: o.learn_hours, cooldown: o.cooldown_h * 3600.0, ignore: o.ignore.clone(), ignore_dest: o.ignore_dest.clone() };
    if let Some(path) = &o.replay {
        replay(path, &o, cfg, model);
        return;
    }
    live(&o, cfg, model);
}

fn replay(path: &str, o: &WOpts, cfg: Config, model: crate::model::NetModel) {
    let st = load_state(&o.state);
    let mut eng = Engine::new(cfg, st, if model.units.is_empty() { None } else { Some(model) });
    if let Some(e) = &o.emit {
        let f = std::fs::File::create(e).unwrap_or_else(|err| {
            eprintln!("ratel: {e}: {err}");
            std::process::exit(2)
        });
        eng.emit = Some(Box::new(std::io::BufWriter::new(f)));
        eng.emit_all = o.emit_all;
        if o.emit_thin > 0 {
            eng.emit_thin = o.emit_thin;
        }
    }
    let mut out = Out { json: o.json, log: None, notifier: notify::Notifier::new(false, "high") };
    let rd: Box<dyn BufRead> = if path == "-" { Box::new(std::io::stdin().lock()) } else {
        Box::new(std::io::BufReader::new(std::fs::File::open(path).unwrap_or_else(|e| {
            eprintln!("ratel: {path}: {e}");
            std::process::exit(2)
        })))
    };
    let mut n = 0u64;
    for line in rd.lines() {
        let Ok(line) = line else { break };
        match serde_json::from_str::<Event>(&line) {
            Ok(ev) => {
                eng.feed(&ev);
                n += 1;
            }
            Err(e) => eprintln!("ratel: bad event ({e}): {}", line.chars().take(120).collect::<String>()),
        }
        for a in eng.drain_alerts() {
            out.alert(&a);
        }
    }
    let end = eng.t + 120.0;
    eng.tick(end);
    for a in eng.drain_alerts() {
        out.alert(&a);
    }
    if let Some(mut w) = eng.emit.take() {
        let _ = w.flush();
    }
    save_state(&o.state, &mut eng.st);
    eprintln!("ratel watch: replayed {n} events");
}

// ------------------------------------------------------------------ live

/// Stable pseudonyms for recordings: keyed hash, class-preserving (public stays
/// public, private stays private) so the engine sees the same structure.
struct Anon {
    key: u64,
}
impl Anon {
    fn h(&self, s: &[u8]) -> u64 {
        let mut x = self.key ^ 0x9e37_79b9_7f4a_7c15;
        for &b in s {
            x = (x ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
        x ^ (x >> 29)
    }
    fn ip(&self, ip: &IpAddr) -> IpAddr {
        use engine::{dest_class, DestClass};
        let h = self.h(ip.to_string().as_bytes());
        // keep the /24 structure: hash the prefix and the host part separately
        let (pre, host) = match ip {
            IpAddr::V4(v) => {
                let o = v.octets();
                (self.h(&o[..3]), o[3])
            }
            IpAddr::V6(v) => (self.h(&v.octets()[..6]), (h & 0xff) as u8),
        };
        let b = pre.to_be_bytes();
        match dest_class(ip) {
            DestClass::Public => IpAddr::V4(std::net::Ipv4Addr::new(45 + b[0] % 50, b[1], b[2], host)),
            DestClass::Private => IpAddr::V4(std::net::Ipv4Addr::new(10, b[1], b[2], host)),
            DestClass::Overlay => IpAddr::V4(std::net::Ipv4Addr::new(100, 64 + b[0] % 64, b[2], host)),
            DestClass::Local => *ip,
        }
    }
    fn name(&self, n: &str) -> String {
        n.split('.').map(|l| {
            let h = format!("{:016x}{:016x}", self.h(l.as_bytes()), self.h(&[l.as_bytes(), b"#"].concat()));
            h.chars().take(l.len().clamp(1, 32)).collect::<String>()
        }).collect::<Vec<_>>().join(".")
    }
    fn ent(&self, e: &str) -> String {
        format!("ent-{:08x}", self.h(e.as_bytes()) as u32)
    }
    fn event(&self, ev: &Event) -> Event {
        let mut ev = ev.clone();
        match &mut ev {
            Event::Tcp { ent, rip, .. } | Event::Udp { ent, rip, .. } => {
                *ent = self.ent(ent);
                *rip = self.ip(rip);
            }
            Event::Syn { ent, rip, .. } => {
                *ent = ent.as_ref().map(|e| self.ent(e));
                *rip = self.ip(rip);
            }
            Event::Dns { ent, name, answers, .. } => {
                *ent = ent.as_ref().map(|e| self.ent(e));
                *name = self.name(name);
                *answers = answers.iter().map(|a| self.ip(a)).collect();
            }
            Event::Icmp { rip, .. } => *rip = self.ip(rip),
            Event::Proc { ent, detail, .. } | Event::Exe { ent, detail, .. } => {
                *ent = self.ent(ent);
                detail.clear();
            }
            Event::Listen { ent, .. } => *ent = self.ent(ent),
            Event::Caps { .. } | Event::Label { .. } => {}
        }
        ev
    }
}

struct Ns {
    dump: diag::Diag,
    destroy: Option<diag::Diag>,
}

/// Nameservers from /etc/resolv.conf, and whether one of them is local (then the local
/// resolver daemon's own upstream queries are trusted too).
/// Public resolvers whose answers we believe even when a program asks them directly
/// (containers commonly do). A program querying any *other* server gets no names: its own
/// DNS server could otherwise claim that the attacker's address is github.com.
const PUBLIC_RESOLVERS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9", "2620:119:35::35", "2620:119:53::53",
];

fn resolv_conf(extra: &[IpAddr]) -> (HashSet<IpAddr>, bool) {
    let mut s: HashSet<IpAddr> = extra.iter().copied().collect();
    s.extend(PUBLIC_RESOLVERS.iter().filter_map(|a| a.parse::<IpAddr>().ok()));
    if let Ok(t) = std::fs::read_to_string("/etc/resolv.conf") {
        for l in t.lines() {
            let mut it = l.split_whitespace();
            if it.next() == Some("nameserver") {
                if let Some(ip) = it.next().and_then(|a| a.split('%').next()?.parse::<IpAddr>().ok()) {
                    s.insert(ip);
                }
            }
        }
    }
    let local = s.iter().any(|ip| ip.is_loopback());
    (s, local)
}

/// Dashboard request ids already executed (root-only, never trusted from elsewhere).
fn control_ledger(d: &std::path::Path) -> Result<HashSet<String>, String> {
    let p = d.join("control.ledger");
    if !p.exists() {
        return Ok(HashSet::new());
    }
    let t = crate::safety::trusted_read_string(&p, 8 << 20)?;
    Ok(t.lines().map(str::to_string).collect())
}

fn append_ledger(d: &std::path::Path, rq: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(d.join("control.ledger")) {
        let _ = writeln!(f, "{rq}");
    }
}

/// <state>/response.json for the dashboard (the vault itself is root-only).
fn write_response(d: &std::path::Path, response: &respond::Response, results: &std::collections::VecDeque<serde_json::Value>) {
    let v = response.snapshot(&results.iter().cloned().collect::<Vec<_>>());
    let (p, tmp) = (d.join("response.json"), d.join("response.json.tmp"));
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

/// Quarantine the executable of a (frozen) process if it runs from a temp directory.
fn quarantine_running_temp(response: &respond::Response, pid: u32, why: &str) -> Option<String> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if !respond::in_temp(&exe) {
        return None;
    }
    let (d, seen) = crate::read_any_seen(std::path::Path::new(&format!("/proc/{pid}/exe")), 128 << 20, true)?;
    use sha2::Digest;
    let sha = crate::trust::hex(&sha2::Sha256::digest(&d[..]));
    use std::os::unix::fs::MetadataExt;
    let same = std::fs::symlink_metadata(&exe).is_ok_and(|m| m.dev() == seen.dev && m.ino() == seen.ino);
    Some(if same { response.quarantine(&exe, &sha, &None, "behaviour", vec![format!("frozen for: {why}")]) }
        else { "not quarantined: the executable isn't reachable at its path from here".into() })
}

fn netns_list() -> HashMap<u64, u32> {
    // network namespace inode -> one pid inside it
    let mut out = HashMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            if let Ok(l) = std::fs::read_link(format!("/proc/{pid}/ns/net")) {
                if let Some(n) = l.to_string_lossy().strip_prefix("net:[").and_then(|x| x.strip_suffix(']')).and_then(|x| x.parse().ok()) {
                    out.entry(n).or_insert(pid);
                }
            }
        }
    }
    out
}

fn own_netns() -> u64 {
    std::fs::read_link("/proc/self/ns/net").ok()
        .and_then(|l| l.to_string_lossy().strip_prefix("net:[").and_then(|x| x.strip_suffix(']')).and_then(|x| x.parse().ok()))
        .unwrap_or(0)
}

fn local_addrs() -> HashSet<IpAddr> {
    let mut s = HashSet::new();
    // SAFETY: getifaddrs/freeifaddrs pair; we only read the returned list.
    unsafe {
        let mut ifa: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifa) == 0 {
            let mut p = ifa;
            while !p.is_null() {
                let a = (*p).ifa_addr;
                if !a.is_null() {
                    match (*a).sa_family as i32 {
                        libc::AF_INET => {
                            let sin = &*(a as *const libc::sockaddr_in);
                            s.insert(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                        }
                        libc::AF_INET6 => {
                            let sin = &*(a as *const libc::sockaddr_in6);
                            s.insert(IpAddr::V6(std::net::Ipv6Addr::from(sin.sin6_addr.s6_addr)));
                        }
                        _ => {}
                    }
                }
                p = (*p).ifa_next;
            }
            libc::freeifaddrs(ifa);
        }
    }
    s
}

fn live(o: &WOpts, cfg: Config, model: crate::model::NetModel) {
    // SAFETY: installing a signal handler that only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let root = unsafe { libc::geteuid() } == 0;
    // files we create are group-readable (for the `ratel web` group), never world-readable
    unsafe { libc::umask(0o027) };
    let state_dir = o.state.clone().or_else(|| root.then(|| "/var/lib/ratel".to_string()));
    let log_path = o.log.clone().or_else(|| root.then(|| "/var/log/ratel/alerts.jsonl".to_string()));
    let log = log_path.as_ref().and_then(|p| {
        if let Some(d) = std::path::Path::new(p).parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::OpenOptions::new().create(true).append(true).open(p).ok()
    });
    let sock_ok = std::path::Path::new(&std::env::var("NOTIFY_SOCKET").unwrap_or_else(|_| "/run/prosody/notify.sock".into())).exists();
    let mut out = Out { json: o.json, log, notifier: notify::Notifier::new(!o.no_notify && (root || sock_ok), &o.notify_min) };
    let response = std::sync::Arc::new(respond::Response::new(&o.quarantine, &o.contain, &o.contain_never, &state_dir)
        .unwrap_or_else(|e| {
            eprintln!("ratel: {e}");
            std::process::exit(2)
        }));
    // ClamAV signatures, shared by the scan threads; swapped when freshclam updates them
    type ClamSlot = std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::clamav::Db>>>>;
    let clam: ClamSlot = Default::default();
    let mut clam_problem = None;
    if !o.no_clamav {
        let dir = o.clamav_db.clone().unwrap_or_else(|| crate::clamav::DEFAULT_DIR.into());
        if o.clamav_db.is_some() || std::path::Path::new(&dir).is_dir() {
            match crate::clamav::Db::load(std::path::Path::new(&dir), false) {
                Ok(db) => *clam.lock().unwrap() = Some(std::sync::Arc::new(db)),
                Err(e) => clam_problem = Some(e),
            }
        }
    }
    let clam_now = |c: &ClamSlot| c.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut clam_check = Instant::now();
    let (loaded, state_problem) = load_state_checked(&state_dir);
    let mut eng = Engine::new(cfg, loaded, if model.units.is_empty() { None } else { Some(model) });
    let mut rec = o.record.as_ref().map(|p| std::io::BufWriter::new(std::fs::File::create(p).unwrap_or_else(|e| {
        eprintln!("ratel: {p}: {e}");
        std::process::exit(2)
    })));
    let anon = Anon { key: (now() * 1e6) as u64 ^ std::process::id() as u64 };

    let mut cap = if o.no_capture { None } else {
        match capture::Capture::new() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("ratel watch: packet capture unavailable ({e}); no DNS/SYN/ICMP/UDP visibility{}", if root { "" } else { " (needs root)" });
                None
            }
        }
    };
    if !root {
        eprintln!("ratel watch: not root: only your own processes are attributed, no destroy events, no XMPP");
    }
    let me = own_netns();
    let mut nss: HashMap<u64, Ns> = HashMap::new();
    let mut ns_refresh = Instant::now() - Duration::from_secs(3600);
    let mut procs = procs::Procs::default();
    let mut procs_at = Instant::now() - Duration::from_secs(3600);
    let mut cookie_ent: HashMap<u64, (String, u32)> = HashMap::new();
    // cookie -> (sent, recv, last emitted): unchanged connections are re-sent every 5 min
    let mut last_counts: HashMap<u64, (u64, u64, Instant)> = HashMap::new();
    // socket inodes no process holds (kernel-owned): don't rescan /proc for them every second
    let mut unattributable: HashMap<u64, Instant> = HashMap::new();
    let mut rescan_gap = Duration::from_secs(1);
    // UDP port -> owner; the host's own sockets take precedence over other network
    // namespaces (anyone can `unshare -rn` and bind :53 in a namespace of their own)
    let mut udp_port: HashMap<u16, String> = HashMap::new();
    let mut udp_pid: HashMap<u16, u32> = HashMap::new();
    let mut listening: HashSet<(u64, u16)> = HashSet::new();
    let mut listen_ents: HashSet<String> = HashSet::new();
    let mut flagged: HashSet<(u32, &'static str)> = HashSet::new();
    let mut local = local_addrs();
    let mut last_dump = Instant::now() - Duration::from_secs(3600);
    let mut last_udp = Instant::now() - Duration::from_secs(3600);
    let mut last_save = Instant::now();
    let mut last_flags = Instant::now() - Duration::from_secs(3600);
    let started = Instant::now();
    let mut syn_seen = false;
    // sockets present in the first dump: their counters are history
    let mut initial: Option<HashSet<u64>> = None;
    // static scans of newly networked executables, off the main loop
    // (entity, file to read, path for package provenance)
    // (entity, pid, its start time, file to read, path for package provenance)
    let (scan_tx, scan_rx) = std::sync::mpsc::channel::<(String, u32, Option<u64>, std::path::PathBuf, std::path::PathBuf)>();
    let (res_tx, res_rx) = std::sync::mpsc::channel::<(String, f32, String)>();
    let (file_tx, file_rx) = std::sync::mpsc::channel::<Alert>();
    let mut scanned: HashSet<String> = HashSet::new();
    if !o.no_scan {
        let (clam, response, alert_tx) = (clam.clone(), response.clone(), file_tx.clone());
        std::thread::spawn(move || {
            let m = crate::model::Model::load(crate::model::EMBEDDED).ok();
            let kind = crate::trust::detect_pkg_kind();
            // act once per (process, content): quarantining unlinks the file, which changes
            // its ctime and so brings it back here as "new"
            let mut acted: HashSet<(u32, [u8; 32])> = HashSet::new();
            for (ent, pid, start, p, exe) in scan_rx {
                let Some(d) = crate::read_candidate_heap(&p, 128 << 20) else { continue };
                let Some(m) = m.as_ref() else { continue };
                let mut r = crate::report::assess(&crate::features::analyze(&d), m);
                let h = crate::trust::hash(&d, kind);
                {
                    let wanted: HashSet<std::path::PathBuf> = [exe.clone()].into_iter().collect();
                    if let Ok(t) = crate::trust::Trust::load(kind, &crate::trust::default_allowlists().into_iter().map(|f| (f, false)).collect::<Vec<_>>(), &wanted) {
                        crate::report::apply_origin(&mut r, t.origin(&exe, &h), true);
                    }
                }
                let sigs = clam.lock().unwrap_or_else(|e| e.into_inner()).clone().map(|db| db.scan(&d)).unwrap_or_default();
                crate::report::apply_signatures(&mut r, sigs);
                // known malware (signature), or an "obviously bad" executable running from a
                // temp directory (strict static rule): freeze it, then quarantine the file
                let sig_hit = !r.signatures.is_empty() && r.verdict == "malware";
                let susp = if sig_hit || !response.suspicious_on() || !respond::in_temp(&exe) { None } else { respond::suspicious(&r) };
                if (sig_hit || susp.is_some()) && acted.insert((pid, h.sha256)) {
                    let sha = crate::trust::hex(&h.sha256);
                    let (what, mut ev, detector, reason): (String, Vec<String>, &str, Vec<String>) = match &susp {
                        None => (format!("ClamAV: {}", crate::safety::safe(&r.signatures.join(", "))),
                            r.signatures.iter().map(|s| format!("ClamAV signature {}", crate::safety::safe(s))).collect(),
                            "clamav", r.signatures.iter().map(|n| format!("clamav:{n}")).collect()),
                        Some(why) => (why.clone(), vec![format!("{why} (strict rule, temp directory)"),
                            format!("capability scan: {} {:.2}", r.verdict, r.risk)], "static", vec![why.clone()]),
                    };
                    if response.contain_sig() {
                        ev.push(response.contain(pid, start, &format!("runs malware ({what})")));
                    }
                    use std::os::unix::fs::MetadataExt;
                    let same = std::fs::metadata(&p).ok().zip(std::fs::symlink_metadata(&exe).ok())
                        .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino());
                    ev.push(if same { response.quarantine(&exe, &sha, &r.origin, detector, reason) }
                        else { "not quarantined: the file isn't reachable at its path from here (deleted, or another mount namespace)".into() });
                    ev.push(format!("sha256 {sha}"));
                    let _ = alert_tx.send(Alert {
                        t: now(), severity: "high", kind: "process", entity: ent.clone(), pid, dest: String::new(), score: 1.0,
                        title: format!("running malware: {} ({what})", ent),
                        evidence: ev, incident: String::new(), context: serde_json::Value::Null, capped: false,
                    });
                }
                let det: Vec<&str> = r.caps.iter().filter(|c| c.conf >= 0.5 && c.excused_by.is_none()).map(|c| c.cap).collect();
                let risk = if r.verdict == "allowed" { 0.0 } else { r.risk as f32 };
                let _ = res_tx.send((ent, risk, format!("{} {:.2} [{}]", r.verdict, r.risk, det.join(" "))));
            }
        });
    }

    // periodic static scans (one low-priority thread, one file at a time)
    if !o.scan_paths.is_empty() {
        let paths: Vec<std::path::PathBuf> = o.scan_paths.iter().map(std::path::PathBuf::from).collect();
        let every = Duration::from_secs_f64(o.scan_every * 3600.0);
        let (clam, response) = (clam.clone(), response.clone());
        std::thread::spawn(move || {
            // SAFETY: lowers the priority of this thread only (Linux: per-thread nice).
            unsafe { libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 15) };
            let Ok(m) = crate::model::Model::load(crate::model::EMBEDDED) else { return };
            loop {
                let db = clam.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let cfg = crate::ScanCfg { heap: true, jobs: 1, max: 64 << 20, allow: vec![], integrity: true, pkg_trust: true, clam: db };
                let _ = crate::scan_files(&paths, &cfg, &m, |p, r, seen| {
                    let sha = seen.sha256.clone();
                    let modified = matches!(r.origin, Some(crate::trust::Origin::Modified { .. }));
                    if !r.signatures.is_empty() && r.verdict == "malware" {
                        let sha = sha.unwrap_or_default();
                        let mut ev: Vec<String> = r.signatures.iter().map(|s| format!("ClamAV signature {}", crate::safety::safe(s))).collect();
                        if let Some(o) = &r.origin {
                            ev.push(format!("origin: {}", serde_json::to_string(o).unwrap_or_default()));
                        }
                        // act on the file that was read (its inode, its real path), never on
                        // whatever the path names by now
                        if response.contain_sig() && seen.ino != 0 {
                            for pid in respond::Response::running(seen.dev, seen.ino) {
                                ev.push(response.contain(pid, crate::contain::start_time(pid), &format!("runs malware ({})", r.signatures.join(", "))));
                            }
                        }
                        ev.push(match &seen.path {
                            Some(real) => response.quarantine(real, &sha, &r.origin, "clamav", r.signatures.iter().map(|n| format!("clamav:{n}")).collect()),
                            None => "not quarantined: the file's real location is unknown".into(),
                        });
                        ev.push(format!("sha256 {sha}"));
                        let _ = file_tx.send(Alert {
                            t: now(), severity: "high", kind: "file", entity: crate::safety::safe_path(p), pid: 0, dest: String::new(), score: 1.0,
                            title: format!("malware (ClamAV: {}): {}", crate::safety::safe(&r.signatures.join(", ")), crate::safety::safe_path(p)),
                            evidence: ev, incident: String::new(), context: serde_json::Value::Null, capped: false,
                        });
                        return;
                    }
                    // "obviously bad" executable in a temp directory (strict static rule)
                    if let (true, Some(real), Some(why)) = (response.suspicious_on(), &seen.path, respond::suspicious(r)) {
                        if respond::in_temp(real) {
                            let sha = sha.clone().unwrap_or_default();
                            let mut ev = vec![format!("{why} (strict rule, temp directory)"), format!("capability scan: {} {:.2}", r.verdict, r.risk)];
                            ev.extend(r.findings.iter().filter(|f| f.strength >= 2).take(3).map(|f| format!("{} {}: {}", f.cap, f.rule, crate::safety::safe(&f.evidence))));
                            if response.contain_sig() && seen.ino != 0 {
                                for pid in respond::Response::running(seen.dev, seen.ino) {
                                    ev.push(response.contain(pid, crate::contain::start_time(pid), &format!("runs a suspicious binary ({why})")));
                                }
                            }
                            ev.push(response.quarantine(real, &sha, &r.origin, "static", vec![why.clone()]));
                            ev.push(format!("sha256 {sha}"));
                            let _ = file_tx.send(Alert {
                                t: now(), severity: "high", kind: "file", entity: crate::safety::safe_path(p), pid: 0, dest: String::new(), score: r.risk,
                                title: format!("obviously malicious binary ({why}): {}", crate::safety::safe_path(p)),
                                evidence: ev, incident: String::new(), context: serde_json::Value::Null, capped: false,
                            });
                            return;
                        }
                    }
                    if r.sig_limited && r.signatures.is_empty() {
                        // crafted to exhaust the matcher before a real signature, or just huge
                        let _ = file_tx.send(Alert {
                            t: now(), severity: "medium", kind: "file", entity: crate::safety::safe_path(p), pid: 0, dest: String::new(), score: 0.5,
                            title: format!("file could not be fully checked against ClamAV signatures: {}", crate::safety::safe_path(p)),
                            evidence: vec!["a matching budget ran out (many near-matches, or too many PE sections)".into(),
                                format!("sha256 {}", sha.clone().unwrap_or_default())],
                            incident: String::new(), context: serde_json::Value::Null, capped: false,
                        });
                    }
                    if r.verdict != "high" && !modified {
                        return;
                    }
                    let det: Vec<&str> = r.caps.iter().filter(|c| c.conf >= 0.5 && c.excused_by.is_none()).map(|c| c.cap).collect();
                    let mut ev: Vec<String> = r.findings.iter().filter(|f| f.strength >= 2).take(4).map(|f| format!("{} {}: {}", f.cap, f.rule, f.evidence)).collect();
                    ev.push(format!("sha256 {}", sha.unwrap_or_default()));
                    let _ = file_tx.send(Alert {
                        t: now(), severity: if modified || r.risk >= 0.85 { "high" } else { "medium" }, kind: "file",
                        entity: crate::safety::safe_path(p), pid: 0, dest: String::new(), score: r.risk,
                        title: if modified { format!("package file modified after install: {}", crate::safety::safe_path(p)) }
                            else { format!("suspicious binary ({:.2}: {}): {}", r.risk, det.join(", "), crate::safety::safe_path(p)) },
                        evidence: ev, incident: String::new(), context: serde_json::Value::Null, capped: false,
                    });
                });
                std::thread::sleep(every);
            }
        });
    }

    // ---- after-detection machinery: incidents, flight recorder, health, feedback
    let mut sink = Sink { rec: rec.take(), recorder: incidents::Recorder::new(), events: 0,
        store: state_dir.as_ref().and_then(|d| incidents::Store::new(std::path::Path::new(d))) };
    let mut health = incidents::Health { started: now(), ..Default::default() };
    let status_path = o.status.clone().map(std::path::PathBuf::from).or_else(|| {
        if root && std::fs::create_dir_all("/run/ratel").is_ok() { Some("/run/ratel/status.json".into()) }
        else { state_dir.as_ref().map(|d| std::path::Path::new(d).join("status.json")) }
    });
    let feedback = state_dir.as_ref().map(std::path::PathBuf::from);
    let mut feedback_mtime = None;
    // dashboard control requests (feedback.d/control.req) and their results
    let mut ctl_stamp: Option<(u64, Option<std::time::SystemTime>)> = None;
    let mut last_ctl = Instant::now();
    let mut ctl_results: std::collections::VecDeque<serde_json::Value> = Default::default();
    let mut ctl_warned = false;
    let mut last_status = Instant::now() - Duration::from_secs(3600);
    let mut last_drop_check = Instant::now();
    let mut last_health: HashMap<&'static str, f64> = HashMap::new();
    if let Some(problem) = &clam_problem {
        // e.g. databases writable by someone other than root/clamav: refuse them, loudly
        let a = health_alert("clamav", "medium", "ClamAV signatures not loaded", vec![crate::safety::safe(problem)]);
        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
    }
    if let Some(problem) = &state_problem {
        let a = health_alert("state", "high", "ratel state was not trusted (possible tampering)", vec![problem.clone()]);
        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
    }
    if eng.st.running && state_dir.is_some() {
        let a = health_alert("unclean", "medium", "ratel watch was not stopped cleanly (crash, kill or power loss)",
            vec![format!("last state save {}", incidents::local_time(eng.st.saved_t))]);
        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
    }
    // self-integrity: notice when the ratel binary itself changes between runs
    let me_sha = std::fs::read("/proc/self/exe").ok().map(|b| {
        use sha2::Digest;
        crate::trust::hex(&sha2::Sha256::digest(&b))
    }).unwrap_or_default();
    if !me_sha.is_empty() && !eng.st.exe_sha256.is_empty() && eng.st.exe_sha256 != me_sha {
        let a = health_alert("binary", "medium", "the ratel binary changed since its last run (upgrade, or tampering?)",
            vec![format!("was sha256 {}", eng.st.exe_sha256), format!("now sha256 {me_sha}")]);
        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
    }
    eng.st.exe_sha256 = me_sha.clone();
    eng.st.running = true;
    save_state(&state_dir, &mut eng.st);

    let emit = |eng: &mut Engine, ev: Event, sink: &mut Sink| {
        if let Some(w) = sink.rec.as_mut() {
            let e = if o.anonymize { anon.event(&ev) } else { ev.clone() };
            let _ = writeln!(w, "{}", serde_json::to_string(&e).unwrap_or_default());
        }
        sink.recorder.push(&ev);
        if let Some(s) = sink.store.as_mut() {
            s.on_event(&ev);
        }
        sink.events += 1;
        eng.feed(&ev);
    };
    emit(&mut eng, Event::Caps { t: now(), dns: cap.is_some(), syn: cap.is_some(), udp: cap.is_some() }, &mut sink);
    eprintln!("ratel watch: running (capture {}, state {}, notify {})", if cap.is_some() { "on" } else { "off" },
        state_dir.as_deref().unwrap_or("none"), if out.notifier.enabled { "on" } else { "off" });

    let mut pkts = vec![];
    let mut destroyed = vec![];
    let mut dnsq = dns::QueryTracker::default();
    let mut resolvers = resolv_conf(&o.resolvers);
    let mut resolv_at = Instant::now();
    let mut dns_unsolicited_seen = 0u64;
    while !STOP.load(Ordering::Relaxed) {
        if o.duration > 0.0 && started.elapsed().as_secs_f64() >= o.duration {
            break;
        }
        if resolv_at.elapsed() >= Duration::from_secs(60) {
            resolv_at = Instant::now();
            resolvers = resolv_conf(&o.resolvers);
        }
        // ---- network namespaces (containers)
        if ns_refresh.elapsed() >= Duration::from_secs(30) {
            ns_refresh = Instant::now();
            local = local_addrs();
            let list = netns_list();
            nss.retain(|k, _| list.contains_key(k) || *k == me);
            for (ns, pid) in list {
                if nss.contains_key(&ns) {
                    continue;
                }
                let made = if ns == me {
                    diag::Diag::new().map(|d| (d, diag::Diag::destroy_listener().ok()))
                } else if root {
                    diag::in_netns(&format!("/proc/{pid}/ns/net"), || Ok((diag::Diag::new()?, diag::Diag::destroy_listener().ok())))
                } else {
                    continue;
                };
                if let Ok((dump, destroy)) = made {
                    nss.insert(ns, Ns { dump, destroy });
                }
            }
        }
        // ---- wait for packets / destroy events (or 250 ms)
        let mut pfds: Vec<libc::pollfd> = vec![];
        if let Some(c) = &cap {
            pfds.push(libc::pollfd { fd: c.raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        for n in nss.values() {
            if let Some(d) = &n.destroy {
                pfds.push(libc::pollfd { fd: d.raw_fd(), events: libc::POLLIN, revents: 0 });
            }
        }
        // SAFETY: poll on a valid array of pollfds.
        unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 250) };
        let t = now();

        // ---- packets
        if let Some(c) = cap.as_mut() {
            pkts.clear();
            c.read(&mut pkts, o.loopback);
            let mut lookups = 0;
            let mut dns_lookups = 0;
            for p in pkts.drain(..) {
                let ev = match p {
                    capture::Pkt::Syn { src, dst, sport, dport } => {
                        if local.contains(&dst) && !o.loopback {
                            continue; // inbound connection attempt
                        }
                        syn_seen = true;
                        // Attribute right away: very short connections are gone by the next dump.
                        let mut ent = None;
                        lookups += 1;
                        if let Some(n) = nss.get_mut(&me).filter(|_| lookups <= 64) {
                            if let Some(e) = n.dump.lookup((src, sport), (dst, dport)) {
                                if procs.get(e.inode).is_none() && procs_at.elapsed() >= Duration::from_millis(500) {
                                    procs = procs::Procs::scan();
                                    procs_at = Instant::now();
                                }
                                if let Some(p) = procs.get(e.inode) {
                                    cookie_ent.insert(e.cookie, (p.ent.clone(), p.pid));
                                    ent = Some(p.ent.clone());
                                }
                            }
                        }
                        Event::Syn { t, ent, sport, rip: dst, rport: dport }
                    }
                    capture::Pkt::Dns { src, dst, sport, dport, msg } => {
                        let mut msg = msg;
                        if msg.resp {
                            match dnsq.answer(t, msg.id, &msg.name, dport, src) {
                                None => continue, // unsolicited / forged answer: never believed
                                Some(false) => msg.answers.clear(), // answered, but not by a trusted resolver
                                Some(true) => {}
                            }
                        } else {
                            // trusted: to a configured resolver, or from the local resolver daemon
                            let mut trusted = resolvers.0.contains(&dst);
                            if !trusted && resolvers.1 && dns_lookups < 256 {
                                dns_lookups += 1;
                                // the host's resolver daemon (owner of :53 in our namespace)
                                // asking upstream: same process, by pid
                                if let (Some(rpid), Some(n)) = (udp_pid.get(&53), nss.get_mut(&me)) {
                                    let e = n.dump.lookup_proto(libc::IPPROTO_UDP as u8, (src, sport), (dst, dport));
                                    trusted = e.is_some_and(|e| match procs.get(e.inode) {
                                        Some(p) => p.pid == *rpid,
                                        None => procs::holds_socket(*rpid, e.inode), // opened since the last scan
                                    });
                                }
                            }
                            dnsq.query(t, msg.id, &msg.name, sport, dst, trusted);
                        }
                        let ent = if msg.resp { udp_port.get(&dport).cloned() }
                            else if local.contains(&src) || o.loopback { udp_port.get(&sport).cloned() } else { None };
                        Event::Dns { t, ent, name: msg.name, qtype: msg.qtype, resp: msg.resp, rcode: msg.rcode, answers: msg.answers }
                    }
                    capture::Pkt::Udp { src, dst, sport, dport, len, inbound } => {
                        let (lport, rip, rport) = if inbound { (dport, src, sport) } else { (sport, dst, dport) };
                        let ent = udp_port.get(&lport).cloned().unwrap_or_else(|| "unattributed-udp".into());
                        Event::Udp { t, ent, rip, rport, len, scale: capture::UDP_SAMPLE, inbound }
                    }
                    capture::Pkt::Icmp { dst, len } => Event::Icmp { t, rip: dst, len },
                };
                emit(&mut eng, ev, &mut sink);
            }
        }
        // ---- closed sockets: final counters
        for (ns, n) in nss.iter_mut() {
            if let Some(d) = n.destroy.as_mut() {
                destroyed.clear();
                d.drain(&mut destroyed);
                for e in destroyed.drain(..) {
                    if e.remote.1 == 0 || e.state == diag::TCP_LISTEN {
                        continue;
                    }
                    let (ent, pid) = cookie_ent.remove(&e.cookie).unwrap_or_else(|| (format!("uid:{}", e.uid), 0));
                    last_counts.remove(&e.cookie);
                    let inbound = listening.contains(&(*ns, e.local.1));
                    let pre = initial.as_ref().is_some_and(|i| i.contains(&e.cookie));
                    emit(&mut eng, Event::Tcp { t, id: e.cookie, ent, pid, lport: e.local.1, rip: e.remote.0, rport: e.remote.1,
                        sent: e.sent, recv: e.recv, inbound, closed: true, pre }, &mut sink);
                }
            }
        }
        // ---- periodic socket dumps (sooner after a SYN, to attribute new connections)
        let due = last_dump.elapsed().as_secs_f64() >= o.interval || (syn_seen && last_dump.elapsed() >= Duration::from_millis(300));
        if due {
            last_dump = Instant::now();
            syn_seen = false;
            let mut entries: Vec<(u64, diag::Entry)> = vec![];
            for (ns, n) in nss.iter_mut() {
                let mut v = vec![];
                let _ = n.dump.dump(libc::AF_INET as u8, libc::IPPROTO_TCP as u8, &mut v);
                let _ = n.dump.dump(libc::AF_INET6 as u8, libc::IPPROTO_TCP as u8, &mut v);
                entries.extend(v.into_iter().map(|e| (*ns, e)));
            }
            listening = entries.iter().filter(|(_, e)| e.state == diag::TCP_LISTEN).map(|(ns, e)| (*ns, e.local.1)).collect();
            if initial.is_none() {
                initial = Some(entries.iter().map(|(_, e)| e.cookie).collect());
            }
            let unknown = entries.iter().any(|(_, e)| e.inode != 0 && !cookie_ent.contains_key(&e.cookie) && procs.get(e.inode).is_none()
                && unattributable.get(&e.inode).is_none_or(|first| first.elapsed() < Duration::from_secs(30)));
            if (unknown && procs_at.elapsed() >= rescan_gap) || procs_at.elapsed() >= Duration::from_secs(15) {
                let missing: Vec<u64> = entries.iter().filter(|(_, e)| e.inode != 0 && procs.get(e.inode).is_none()).map(|(_, e)| e.inode).collect();
                procs = procs::Procs::scan();
                procs_at = Instant::now();
                if unattributable.len() > 20_000 {
                    unattributable.clear();
                }
                let found = missing.iter().any(|i| procs.get(*i).is_some());
                for (_, e) in &entries {
                    if e.inode != 0 && procs.get(e.inode).is_none() {
                        // still unattributed after 30 s = kernel-owned (NFS, CIFS) or a race we lost
                        unattributable.entry(e.inode).or_insert_with(Instant::now);
                    } else {
                        unattributable.remove(&e.inode);
                    }
                }
                // a stream of sockets that never resolve (short-lived on purpose) must not
                // keep ratel rescanning /proc every second: back off while rescans find nothing
                rescan_gap = if found || !unknown { Duration::from_secs(1) } else { (rescan_gap * 2).min(Duration::from_secs(8)) };
            }
            let mut seen = HashSet::new();
            for (ens, e) in &entries {
                let p = procs.get(e.inode);
                if e.state == diag::TCP_LISTEN {
                    if let Some(p) = p {
                        if listen_ents.insert(p.ent.clone()) {
                            emit(&mut eng, Event::Listen { t, ent: p.ent.clone() }, &mut sink);
                        }
                    }
                    continue;
                }
                if e.remote.1 == 0 {
                    continue;
                }
                seen.insert(e.cookie);
                let (ent, pid) = match (cookie_ent.get(&e.cookie), p) {
                    (Some(x), _) => x.clone(),
                    (None, Some(p)) => (p.ent.clone(), p.pid),
                    (None, None) => (format!("uid:{}", e.uid), 0),
                };
                if !cookie_ent.contains_key(&e.cookie) && pid != 0 {
                    cookie_ent.insert(e.cookie, (ent.clone(), pid));
                }
                if pid != 0 && !o.no_scan && engine::dest_class(&e.remote.0) != engine::DestClass::Local {
                    // the real program (not the loader that started it), keyed by the file's
                    // identity so a binary swapped in at the same path is scanned again
                    let mut targets: Vec<(std::path::PathBuf, std::path::PathBuf)> = procs.list.iter().find(|x| x.pid == pid)
                        .map(|x| x.mapped.iter().map(|(f, p)| (f.clone(), p.into())).collect()).unwrap_or_default();
                    if targets.is_empty() {
                        let f: std::path::PathBuf = format!("/proc/{pid}/exe").into();
                        let p = std::fs::read_link(&f).unwrap_or_else(|_| f.clone());
                        targets.push((f, p));
                    }
                    use std::os::unix::fs::MetadataExt;
                    for (read, origin_path) in targets {
                        // the file's identity (ctime changes on any write, and can't be set back)
                        let Ok(md) = std::fs::metadata(&read) else { continue };
                        let key = format!("{}:{}:{}.{}:{}", md.dev(), md.ino(), md.ctime(), md.ctime_nsec(), md.size());
                        if scanned.len() > 20_000 {
                            scanned.clear();
                        }
                        if scanned.insert(key) {
                            let _ = scan_tx.send((ent.clone(), pid, crate::contain::start_time(pid), read, origin_path));
                        }
                    }
                }
                if let Some((s0, r0, at)) = last_counts.get(&e.cookie) {
                    if (*s0, *r0) == (e.sent, e.recv) && at.elapsed() < Duration::from_secs(300) {
                        continue; // unchanged: no event (heartbeat every 5 min keeps it alive in the engine)
                    }
                }
                last_counts.insert(e.cookie, (e.sent, e.recv, Instant::now()));
                let inbound = listening.contains(&(*ens, e.local.1));
                let pre = initial.as_ref().is_some_and(|i| i.contains(&e.cookie));
                emit(&mut eng, Event::Tcp { t, id: e.cookie, ent, pid, lport: e.local.1, rip: e.remote.0, rport: e.remote.1,
                    sent: e.sent, recv: e.recv, inbound, closed: false, pre }, &mut sink);
            }
            // sockets gone without a destroy event (non-root): treat as closed
            cookie_ent.retain(|c, _| seen.contains(c));
            last_counts.retain(|c, _| seen.contains(c));
            // ---- process red flags (every 15 s, on the fresh process table)
            if last_flags.elapsed() >= Duration::from_secs(15) && procs_at.elapsed() < Duration::from_secs(20) {
                last_flags = Instant::now();
                let ext: HashSet<u64> = entries.iter().filter(|(_, e)| e.state == 1 && engine::dest_class(&e.remote.0) != engine::DestClass::Local).map(|(_, e)| e.inode).collect();
                let socks_of: HashSet<u64> = entries.iter().map(|(_, e)| e.inode).collect();
                for p in &procs.list {
                    if !p.socks.iter().any(|i| socks_of.contains(i)) {
                        continue;
                    }
                    for (rule, sev, detail) in procs::flags(p, &ext) {
                        if flagged.insert((p.pid, rule)) {
                            emit(&mut eng, Event::Proc { t, ent: p.ent.clone(), pid: p.pid, rule: rule.into(), sev, detail }, &mut sink);
                        }
                    }
                }
                flagged.retain(|(pid, _)| std::path::Path::new(&format!("/proc/{pid}")).exists());
            }
        }
        if last_udp.elapsed() >= Duration::from_secs(10) {
            last_udp = Instant::now();
            udp_port.clear();
            udp_pid.clear();
            let mut order: Vec<u64> = nss.keys().copied().collect();
            order.sort_by_key(|k| (*k != me, *k));
            for k in order {
                let Some(n) = nss.get_mut(&k) else { continue };
                let mut v = vec![];
                let _ = n.dump.dump(libc::AF_INET as u8, libc::IPPROTO_UDP as u8, &mut v);
                let _ = n.dump.dump(libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8, &mut v);
                for e in v {
                    if let Some(p) = procs.get(e.inode) {
                        udp_port.entry(e.local.1).or_insert_with(|| p.ent.clone());
                        if k == me {
                            udp_pid.entry(e.local.1).or_insert(p.pid);
                        }
                    }
                }
            }
        }
        while let Ok((ent, risk, detail)) = res_rx.try_recv() {
            emit(&mut eng, Event::Exe { t, ent, risk, detail }, &mut sink);
        }
        eng.tick(t);
        for mut a in eng.drain_alerts() {
            // `contain = high`: freeze the process behind a high behaviour alert
            if response.contain_high() && a.severity == "high" && a.pid != 0 && matches!(a.kind, "process" | "exfil" | "beacon") {
                // the alert's pid may be minutes old: only if it is still that program
                let line = match procs.list.iter().find(|x| x.pid == a.pid) {
                    Some(x) if x.ent == a.entity => response.contain(a.pid, crate::contain::start_time(a.pid), &a.title),
                    _ => format!("process not frozen: pid {} is no longer {}", a.pid, a.entity),
                };
                let frozen = line.starts_with("process tree frozen");
                a.evidence.push(line);
                // behaviour-confirmed: a frozen process running from a temp directory
                if frozen && response.suspicious_on() {
                    if let Some(l) = quarantine_running_temp(&response, a.pid, &a.title) {
                        a.evidence.push(l);
                    }
                }
            }
            handle_alert(a, &eng, &mut sink, &mut out, &mut health);
        }
        while let Ok(a) = file_rx.try_recv() {
            let sha = a.evidence.last().cloned().unwrap_or_default();
            if eng.st.file_alerted.get(&a.entity) != Some(&sha) {
                eng.st.file_alerted.insert(a.entity.clone(), sha);
                handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                if let Some(d) = &feedback {
                    write_response(d, &response, &ctl_results);
                }
            }
        }
        // ---- dashboard control requests (every 2 s): executed once each, announced
        if let (Some(d), true) = (&feedback, last_ctl.elapsed() >= Duration::from_secs(2)) {
            last_ctl = Instant::now();
            let req = d.join("feedback.d").join("control.req");
            let st = std::fs::metadata(&req).ok().map(|m| (m.len(), m.modified().ok()));
            if st.is_some() && st != ctl_stamp {
                ctl_stamp = st;
                match control_ledger(d) {
                    Err(e) => {
                        if !ctl_warned {
                            ctl_warned = true;
                            let a = health_alert("control", "high", "dashboard requests ignored: the request ledger is not trusted", vec![e]);
                            handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                        }
                    }
                    Ok(mut ledger) => {
                        let body = crate::safety::bounded_read(&req, 1 << 20).unwrap_or_default();
                        let mut n = 0;
                        for l in String::from_utf8_lossy(&body).lines() {
                            let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
                            let Some(rq) = v["req"].as_str().filter(|r| r.len() == 32 && r.bytes().all(|b| b.is_ascii_hexdigit())) else { continue };
                            if ledger.contains(rq) {
                                continue;
                            }
                            n += 1;
                            if n > 20 {
                                break; // the rest next round
                            }
                            // into the ledger before acting: a crash can't make it run twice
                            ledger.insert(rq.to_string());
                            append_ledger(d, rq);
                            let (ok, msg, sev) = respond::execute(&response, &v);
                            ctl_results.push_front(serde_json::json!({"req": rq, "t": now(), "ok": ok, "message": msg,
                                "action": crate::safety::safe(v["action"].as_str().unwrap_or(""))}));
                            ctl_results.truncate(50);
                            if ok {
                                let a = health_alert("dashboard", sev, &format!("dashboard: {msg}"),
                                    vec![format!("requested from {} via ratel web", crate::safety::safe(v["ip"].as_str().unwrap_or("?")))]);
                                handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                            }
                        }
                        if n > 20 {
                            ctl_stamp = None; // look again next round
                        }
                        write_response(d, &response, &ctl_results);
                    }
                }
            }
        }
        out.notifier.flush(false);
        // ---- health, status, feedback, digest (every 30 s)
        if last_status.elapsed() >= Duration::from_secs(30) {
            if let Some(d) = &feedback {
                write_response(d, &response, &ctl_results);
            }
            if let Some(db) = clam_now(&clam) {
                // the Windows signatures are big: keep them only while PE files keep coming
                db.release_idle_pe(Duration::from_secs(600));
                if clam_check.elapsed() >= Duration::from_secs(900) {
                    clam_check = Instant::now();
                    if db.changed() {
                        let slot = clam.clone();
                        std::thread::spawn(move || match db.reload() {
                            Ok(n) => *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::sync::Arc::new(n)),
                            Err(e) => eprintln!("ratel: ClamAV reload failed, keeping the loaded signatures: {e}"),
                        });
                    }
                }
            }
            last_status = Instant::now();
            if let Some(c) = &cap {
                let (pk, dr) = incidents::packet_stats(c.raw_fd());
                health.cap_packets += pk;
                health.cap_drops += dr;
                health.win_packets += pk;
                health.win_drops += dr;
            }
            health.events = sink.events;
            health.netns = nss.len();
            health.notify_failures = out.notifier.failures();
            if last_drop_check.elapsed() >= Duration::from_secs(600) {
                last_drop_check = Instant::now();
                // a burst of DNS answers nobody asked for = someone trying to spoof names
                let forged = dnsq.unsolicited - dns_unsolicited_seen;
                dns_unsolicited_seen = dnsq.unsolicited;
                if forged >= 20 && t - last_health.get("dnsspoof").copied().unwrap_or(0.0) > 21_600.0 {
                    last_health.insert("dnsspoof", t);
                    let a = health_alert("dnsspoof", "medium", "possible DNS spoofing: answers to queries this host never sent",
                        vec![format!("{forged} unsolicited DNS answers in 10 minutes were ignored (names from them are not trusted)")]);
                    handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                }
                let (p, d) = (health.win_packets, health.win_drops);
                // tp_packets already includes the drops
                if d >= 100 && d * 100 >= p.max(1) && t - last_health.get("drops").copied().unwrap_or(0.0) > 21_600.0 {
                    last_health.insert("drops", t);
                    let a = health_alert("drops", "medium", "packet capture is dropping packets (monitor overloaded?)",
                        vec![format!("{d} of {p} filtered packets dropped in 10 minutes; DNS/SYN visibility is incomplete")]);
                    handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                }
                health.win_packets = 0;
                health.win_drops = 0;
            }
            if let Some(d) = &feedback {
                let m = Some(incidents::feedback_stamp(d));
                if m != feedback_mtime {
                    feedback_mtime = m;
                    let (new, skipped) = incidents::load_suppressions_checked(d);
                    // Every suppression is announced once, against a root-only ledger: a
                    // compromised dashboard (or anyone with write access to the inbox) can't
                    // silently mute the monitor, not even while the daemon is restarting.
                    let mut ledger = incidents::announced(d);
                    let fresh: Vec<&(String, String, String)> = new.iter().filter(|x| !ledger.contains(*x)).collect();
                    if !fresh.is_empty() {
                        // wildcard / broad ones first and never cut; then the rest up to 20
                        let broad = |x: &&(String, String, String)| x.1 == "*" || x.2 == "*";
                        let mut lines: Vec<String> = fresh.iter().filter(|x| broad(x)).map(|(e, dst, k)| format!("BROAD: {k} alerts for {e} -> {dst}")).collect();
                        let mut rest: Vec<String> = fresh.iter().filter(|x| !broad(x)).map(|(e, dst, k)| format!("{k} alerts for {e} -> {dst}")).collect();
                        rest.sort();
                        let n_rest = rest.len();
                        rest.truncate(20);
                        lines.extend(rest);
                        if n_rest > 20 {
                            lines.push(format!("… and {} more (see feedback files)", n_rest - 20));
                        }
                        let a = health_alert("suppression", "medium", &format!("{} alert suppression(s) added (false-alarm feedback)", fresh.len()), lines);
                        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                        ledger.extend(new.iter().cloned());
                        incidents::save_announced(d, &ledger);
                    }
                    if !skipped.is_empty() && t - last_health.get("feedback").copied().unwrap_or(0.0) > 21_600.0 {
                        last_health.insert("feedback", t);
                        let a = health_alert("feedback", "medium", "feedback inbox: files or entries ignored", skipped.into_iter().take(10).collect());
                        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
                    }
                    eng.cfg.suppress = new;
                }
            }
            if o.digest_hour >= 0 && incidents::local_hour(t) == o.digest_hour && t - eng.st.last_digest > 20.0 * 3600.0
                && started.elapsed() > Duration::from_secs(60) {
                eng.st.last_digest = t;
                if let Some(sx) = sink.store.as_ref() {
                    sx.prune(incidents::RETENTION_DAYS);
                }
                let (sub, body) = incidents::digest(&health, &eng, t);
                out.notifier.send_now(&sub, &body);
            }
            if let Some(sx) = sink.store.as_mut() {
                sx.expire(t);
            }
            if let Some(sp) = &status_path {
                // live view for `ratel web`, next to the status file
                let lp = sp.with_file_name("live.json");
                let tmp = lp.with_extension("tmp");
                if std::fs::write(&tmp, eng.live_snapshot().to_string()).is_ok() {
                    let _ = std::fs::rename(&tmp, &lp);
                }
                let open = sink.store.as_ref().map_or(0, |s| s.open_count());
                let (quarantined, contained) = response.counts();
                incidents::write_status(sp, &health, &eng, serde_json::json!({"open_incidents": open, "suppressions": eng.cfg.suppress.len(),
                    "capture": cap.is_some(), "root": root, "exe_sha256": me_sha, "dns_unsolicited": dnsq.unsolicited,
                    "clamav": clam_now(&clam).map(|d| d.version.clone()), "quarantined": quarantined, "contained": contained,
                    "response": {"quarantine": response.modes().0, "contain": response.modes().1}}));
            }
        }
        if last_save.elapsed() >= Duration::from_secs(600) {
            last_save = Instant::now();
            save_state(&state_dir, &mut eng.st);
            if let Some(w) = sink.rec.as_mut() {
                let _ = w.flush();
            }
        }
    }
    out.notifier.flush(true);
    out.notifier.shutdown(Duration::from_secs(8));
    if let Some(sp) = &status_path {
        health.stopped = true;
        health.events = sink.events;
        incidents::write_status(sp, &health, &eng, serde_json::json!({"capture": cap.is_some(), "root": root}));
    }
    eng.st.running = false;
    save_state(&state_dir, &mut eng.st);
    if let Some(mut w) = sink.rec.take() {
        let _ = w.flush();
    }
    eprintln!("ratel watch: stopped");
}

#[cfg(test)]
mod tests {
    #[test]
    fn diag_dump_sees_own_connection() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (_s, _) = l.accept().unwrap();
        c.write_all(&[7u8; 5000]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut d = super::diag::Diag::new().unwrap();
        let mut v = vec![];
        d.dump(libc::AF_INET as u8, libc::IPPROTO_TCP as u8, &mut v).unwrap();
        let mine = v.iter().find(|e| e.remote.1 == port && e.state == 1).expect("own socket in dump");
        assert!(mine.sent >= 5000 && mine.inode != 0 && mine.cookie != 0, "{mine:?}");
    }
}
