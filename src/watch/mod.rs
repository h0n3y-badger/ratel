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
  --ignore-dest DEST   never alert for this IP or domain (repeatable)
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
    match std::fs::read_to_string(&cfg) {
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
            "--ignore-dest" => o.ignore_dest.push(val(&mut i)?),
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

fn load_state(dir: &Option<String>) -> State {
    dir.as_ref().and_then(|d| std::fs::read(format!("{d}/net-state.json")).ok())
        .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_state(dir: &Option<String>, st: &mut State) {
    let Some(d) = dir else { return };
    st.saved_t = now();
    let _ = std::fs::create_dir_all(d);
    let tmp = format!("{d}/net-state.json.tmp");
    if let Ok(b) = serde_json::to_vec(st) {
        if std::fs::write(&tmp, b).is_ok() {
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
            println!("{:<6} {}  {}", a.severity.to_uppercase(), fmt_t(a.t), a.title);
            for e in &a.evidence {
                println!("         - {e}");
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
        title: title.into(), evidence, incident: String::new(), context: serde_json::Value::Null }
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
    let mut eng = Engine::new(cfg, load_state(&state_dir), if model.units.is_empty() { None } else { Some(model) });
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
    let mut udp_port: HashMap<u16, String> = HashMap::new();
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
    let (scan_tx, scan_rx) = std::sync::mpsc::channel::<(String, u32)>();
    let (res_tx, res_rx) = std::sync::mpsc::channel::<(String, f32, String)>();
    let mut scanned: HashSet<String> = HashSet::new();
    if !o.no_scan {
        std::thread::spawn(move || {
            let m = crate::model::Model::load(crate::model::EMBEDDED).ok();
            let kind = crate::trust::detect_pkg_kind();
            for (ent, pid) in scan_rx {
                let p = format!("/proc/{pid}/exe");
                let Some(d) = crate::read_candidate_heap(std::path::Path::new(&p), 128 << 20) else { continue };
                let Some(m) = m.as_ref() else { continue };
                let mut r = crate::report::assess(&crate::features::analyze(&d), m);
                if let Ok(exe) = std::fs::read_link(&p) {
                    let h = crate::trust::hash(&d, kind);
                    let wanted: HashSet<std::path::PathBuf> = [exe.clone()].into_iter().collect();
                    if let Ok(t) = crate::trust::Trust::load(kind, &crate::trust::default_allowlists().into_iter().map(|f| (f, false)).collect::<Vec<_>>(), &wanted) {
                        crate::report::apply_origin(&mut r, t.origin(&exe, &h), true);
                    }
                }
                let det: Vec<&str> = r.caps.iter().filter(|c| c.conf >= 0.5 && c.excused_by.is_none()).map(|c| c.cap).collect();
                let risk = if r.verdict == "allowed" { 0.0 } else { r.risk as f32 };
                let _ = res_tx.send((ent, risk, format!("{} {:.2} [{}]", r.verdict, r.risk, det.join(" "))));
            }
        });
    }

    // periodic static scans (one low-priority thread, one file at a time)
    let (file_tx, file_rx) = std::sync::mpsc::channel::<Alert>();
    if !o.scan_paths.is_empty() {
        let paths: Vec<std::path::PathBuf> = o.scan_paths.iter().map(std::path::PathBuf::from).collect();
        let every = Duration::from_secs_f64(o.scan_every * 3600.0);
        std::thread::spawn(move || {
            // SAFETY: lowers the priority of this thread only (Linux: per-thread nice).
            unsafe { libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 15) };
            let Ok(m) = crate::model::Model::load(crate::model::EMBEDDED) else { return };
            let cfg = crate::ScanCfg { heap: true, jobs: 1, max: 64 << 20, allow: vec![], integrity: true, pkg_trust: true };
            loop {
                let _ = crate::scan_files(&paths, &cfg, &m, |p, r, sha| {
                    let modified = matches!(r.origin, Some(crate::trust::Origin::Modified { .. }));
                    if r.verdict != "high" && !modified {
                        return;
                    }
                    let det: Vec<&str> = r.caps.iter().filter(|c| c.conf >= 0.5 && c.excused_by.is_none()).map(|c| c.cap).collect();
                    let mut ev: Vec<String> = r.findings.iter().filter(|f| f.strength >= 2).take(4).map(|f| format!("{} {}: {}", f.cap, f.rule, f.evidence)).collect();
                    ev.push(format!("sha256 {}", sha.unwrap_or_default()));
                    let _ = file_tx.send(Alert {
                        t: now(), severity: if modified || r.risk >= 0.85 { "high" } else { "medium" }, kind: "file",
                        entity: p.display().to_string(), pid: 0, dest: String::new(), score: r.risk,
                        title: if modified { format!("package file modified after install: {}", p.display()) }
                            else { format!("suspicious binary ({:.2}: {}): {}", r.risk, det.join(", "), p.display()) },
                        evidence: ev, incident: String::new(), context: serde_json::Value::Null,
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
    let feedback = state_dir.as_ref().map(|d| std::path::Path::new(d).join("feedback.jsonl"));
    let mut feedback_mtime = None;
    let mut last_status = Instant::now() - Duration::from_secs(3600);
    let mut last_drop_check = Instant::now();
    let mut last_health: HashMap<&'static str, f64> = HashMap::new();
    if eng.st.running && state_dir.is_some() {
        let a = health_alert("unclean", "medium", "ratel watch was not stopped cleanly (crash, kill or power loss)",
            vec![format!("last state save {}", incidents::local_time(eng.st.saved_t))]);
        handle_alert(a, &eng, &mut sink, &mut out, &mut health);
    }
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
    while !STOP.load(Ordering::Relaxed) {
        if o.duration > 0.0 && started.elapsed().as_secs_f64() >= o.duration {
            break;
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
                    capture::Pkt::Dns { src, sport, dport, msg } => {
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
            if (unknown && procs_at.elapsed() >= Duration::from_secs(1)) || procs_at.elapsed() >= Duration::from_secs(15) {
                procs = procs::Procs::scan();
                procs_at = Instant::now();
                if unattributable.len() > 20_000 {
                    unattributable.clear();
                }
                for (_, e) in &entries {
                    if e.inode != 0 && procs.get(e.inode).is_none() {
                        // still unattributed after 30 s = kernel-owned (NFS, CIFS) or a race we lost
                        unattributable.entry(e.inode).or_insert_with(Instant::now);
                    } else {
                        unattributable.remove(&e.inode);
                    }
                }
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
                if pid != 0 && !o.no_scan && engine::dest_class(&e.remote.0) == engine::DestClass::Public && !scanned.contains(&ent) {
                    scanned.insert(ent.clone());
                    let _ = scan_tx.send((ent.clone(), pid));
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
            for n in nss.values_mut() {
                let mut v = vec![];
                let _ = n.dump.dump(libc::AF_INET as u8, libc::IPPROTO_UDP as u8, &mut v);
                let _ = n.dump.dump(libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8, &mut v);
                for e in v {
                    if let Some(p) = procs.get(e.inode) {
                        udp_port.insert(e.local.1, p.ent.clone());
                    }
                }
            }
        }
        while let Ok((ent, risk, detail)) = res_rx.try_recv() {
            emit(&mut eng, Event::Exe { t, ent, risk, detail }, &mut sink);
        }
        eng.tick(t);
        for a in eng.drain_alerts() {
            handle_alert(a, &eng, &mut sink, &mut out, &mut health);
        }
        while let Ok(a) = file_rx.try_recv() {
            let sha = a.evidence.last().cloned().unwrap_or_default();
            if eng.st.file_alerted.get(&a.entity) != Some(&sha) {
                eng.st.file_alerted.insert(a.entity.clone(), sha);
                handle_alert(a, &eng, &mut sink, &mut out, &mut health);
            }
        }
        out.notifier.flush(false);
        // ---- health, status, feedback, digest (every 30 s)
        if last_status.elapsed() >= Duration::from_secs(30) {
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
            if let Some(f) = &feedback {
                let m = std::fs::metadata(f).and_then(|m| m.modified()).ok();
                if m != feedback_mtime {
                    feedback_mtime = m;
                    eng.cfg.suppress = incidents::load_suppressions(f.parent().unwrap());
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
                let open = sink.store.as_ref().map_or(0, |s| s.open_count());
                incidents::write_status(sp, &health, &eng, serde_json::json!({"open_incidents": open, "suppressions": eng.cfg.suppress.len(),
                    "capture": cap.is_some(), "root": root}));
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
