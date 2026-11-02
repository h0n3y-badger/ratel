//! What happens after an alert.
//!
//! * Incidents: alerts about the same entity within an hour share an incident
//!   ID. Each incident is a JSON-lines file in <state>/incidents/<id>.jsonl:
//!   its alerts, the context captured when it opened, the entity's events from
//!   the flight recorder (the minutes *before* the alert), and follow-up events
//!   for two hours after (what it did next).
//! * Context: process tree, user, command line, working directory, executable
//!   hash and package ownership, what the destination resolved from.
//! * Flight recorder: a bounded ring buffer of recent events.
//! * Feedback: `ratel ack <id> --fp` lines in <state>/feedback.jsonl become
//!   suppressions, and the incident's events can be replayed as training negatives.

use super::engine::{Alert, Engine};
use super::events::Event;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const RECORDER_SPAN: f64 = 900.0;
const RECORDER_MAX: usize = 30_000;
const FOLLOW: f64 = 2.0 * 3600.0;
const MERGE: f64 = 3600.0;
const MAX_FILE: u64 = 20 << 20;
const MAX_OPEN: usize = 32;
pub const RETENTION_DAYS: u64 = 90;

pub struct Recorder {
    buf: VecDeque<Event>,
}

impl Recorder {
    pub fn new() -> Recorder {
        Recorder { buf: VecDeque::new() }
    }
    pub fn push(&mut self, ev: &Event) {
        if matches!(ev, Event::Caps { .. } | Event::Label { .. }) {
            return;
        }
        let t = ev.t();
        self.buf.push_back(ev.clone());
        while self.buf.len() > RECORDER_MAX || self.buf.front().is_some_and(|e| e.t() < t - RECORDER_SPAN) {
            self.buf.pop_front();
        }
    }
}

fn ev_ent(ev: &Event) -> Option<&str> {
    match ev {
        Event::Tcp { ent, .. } | Event::Udp { ent, .. } | Event::Proc { ent, .. } | Event::Listen { ent, .. } | Event::Exe { ent, .. } => Some(ent),
        Event::Syn { ent, .. } | Event::Dns { ent, .. } => ent.as_deref(),
        _ => None,
    }
}

fn ev_ip(ev: &Event) -> Option<IpAddr> {
    match ev {
        Event::Tcp { rip, .. } | Event::Udp { rip, .. } | Event::Syn { rip, .. } | Event::Icmp { rip, .. } => Some(*rip),
        _ => None,
    }
}

fn related(ev: &Event, ents: &HashSet<String>, ips: &HashSet<IpAddr>, domains: &HashSet<String>) -> bool {
    ev_ent(ev).is_some_and(|e| ents.contains(e)) || ev_ip(ev).is_some_and(|i| ips.contains(&i))
        || matches!(ev, Event::Dns { name, answers, .. } if domains.iter().any(|d| name == d || name.ends_with(&format!(".{d}")))
            || answers.iter().any(|a| ips.contains(a)))
}

struct Open {
    id: String,
    last_t: f64,
    until: f64,
    file: std::fs::File,
    bytes: u64,
    ents: HashSet<String>,
    ips: HashSet<IpAddr>,
    domains: HashSet<String>,
}

pub struct Store {
    dir: PathBuf,
    open: Vec<Open>,
}

#[allow(deprecated)] // libc::time_t: 64-bit on x86-64 musl and glibc alike
pub fn local_time(t: f64) -> String {
    // SAFETY: localtime_r writes into the tm we own.
    unsafe {
        let tt = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

#[allow(deprecated)]
pub fn local_hour(t: f64) -> i32 {
    // SAFETY: as above.
    unsafe {
        let tt = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        tm.tm_hour
    }
}

fn dest_ip(a: &Alert) -> Option<IpAddr> {
    a.dest.split(' ').next().and_then(|d| d.parse().ok())
}

impl Store {
    pub fn new(state_dir: &Path) -> Option<Store> {
        let dir = state_dir.join("incidents");
        std::fs::create_dir_all(&dir).ok()?;
        let s = Store { dir, open: vec![] };
        s.prune(RETENTION_DAYS);
        Some(s)
    }

    /// Delete incident records older than `days`.
    pub fn prune(&self, days: u64) {
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                if e.metadata().and_then(|m| m.modified()).is_ok_and(|m| m < cutoff) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    /// Files the alert under an incident (new or ongoing); returns (id, is_new).
    pub fn on_alert(&mut self, a: &Alert, rec: &Recorder) -> (String, bool) {
        let key_ent = a.entity.clone();
        let ip = dest_ip(a);
        let domain = (a.kind == "dns").then(|| a.dest.clone());
        let pos = self.open.iter().position(|o| a.t - o.last_t < MERGE
            && (o.ents.contains(&key_ent) && !matches!(key_ent.as_str(), "?" | "unattributed" | "unattributed-udp")
                || ip.is_some_and(|i| o.ips.contains(&i)) || domain.as_ref().is_some_and(|d| o.domains.contains(d))));
        if let Some(i) = pos {
            let o = &mut self.open[i];
            o.last_t = a.t;
            o.until = o.until.max(a.t + FOLLOW);
            o.ents.insert(key_ent);
            if let Some(i) = ip {
                o.ips.insert(i);
            }
            if let Some(d) = domain {
                o.domains.insert(d);
            }
            let line = serde_json::json!({"type": "alert", "alert": a});
            let _ = writeln!(o.file, "{line}");
            return (o.id.clone(), false);
        }
        let mut id = format!("{}-{}", local_time(a.t).replace(['-', ':'], "").replace(' ', "-"), a.kind);
        let mut n = 1;
        while self.dir.join(format!("{id}.jsonl")).exists() {
            n += 1;
            id = format!("{}-{}{n}", local_time(a.t).replace(['-', ':'], "").replace(' ', "-"), a.kind);
        }
        let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join(format!("{id}.jsonl"))) else {
            return (String::new(), true);
        };
        let mut ents = HashSet::new();
        ents.insert(key_ent);
        let ips: HashSet<IpAddr> = ip.into_iter().collect();
        let domains: HashSet<String> = domain.into_iter().collect();
        let _ = writeln!(file, "{}", serde_json::json!({"type": "incident", "id": id, "t": a.t, "time": local_time(a.t), "title": a.title}));
        let _ = writeln!(file, "{}", serde_json::json!({"type": "alert", "alert": a}));
        let mut bytes = 0u64;
        for ev in rec.buf.iter().filter(|e| related(e, &ents, &ips, &domains)) {
            let l = serde_json::json!({"type": "before", "ev": ev}).to_string();
            bytes += l.len() as u64 + 1;
            let _ = writeln!(file, "{l}");
        }
        if self.open.len() >= MAX_OPEN {
            self.open.remove(0);
        }
        self.open.push(Open { id: id.clone(), last_t: a.t, until: a.t + FOLLOW, file, bytes, ents, ips, domains });
        (id, true)
    }

    /// Follow-up: append events of entities / hosts under an open incident.
    pub fn on_event(&mut self, ev: &Event) {
        if self.open.is_empty() {
            return;
        }
        for o in self.open.iter_mut() {
            if o.bytes < MAX_FILE && related(ev, &o.ents, &o.ips, &o.domains) {
                let l = serde_json::json!({"type": "after", "ev": ev}).to_string();
                o.bytes += l.len() as u64 + 1;
                let _ = writeln!(o.file, "{l}");
            }
        }
    }

    pub fn expire(&mut self, now: f64) {
        self.open.retain(|o| now < o.until);
    }

    pub fn open_count(&self) -> usize {
        self.open.len()
    }
}

// ------------------------------------------------------------------ context

fn user_name(uid: u32) -> Option<String> {
    let pw = std::fs::read_to_string("/etc/passwd").ok()?;
    pw.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        f.next();
        (f.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces/parentheses: split after the last ')'
    let close = s.rfind(')')?;
    let comm = s[s.find('(')? + 1..close].to_string();
    let mut v = vec![s[..s.find('(')?].trim().to_string(), comm];
    v.extend(s[close + 2..].split(' ').map(str::to_string));
    Some(v)
}

fn boot_time() -> f64 {
    std::fs::read_to_string("/proc/stat").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("btime ")).and_then(|l| l[6..].trim().parse().ok()))
        .unwrap_or(0.0)
}

/// sha256 and package origin of an executable, hashed once (streaming, size-capped)
/// and cached per (path, size, mtime): alert bursts don't re-read big binaries.
fn exe_identity(proc_exe: &str, exe: &str) -> (Option<String>, Option<serde_json::Value>) {
    use sha2::Digest;
    use std::io::Read;
    use std::sync::{Mutex, OnceLock};
    type Key = (String, u64, i64);
    static CACHE: OnceLock<Mutex<HashMap<Key, (Option<String>, Option<serde_json::Value>)>>> = OnceLock::new();
    let Ok(f) = std::fs::File::open(proc_exe) else { return (None, None) };
    let Ok(md) = f.metadata() else { return (None, None) };
    let mtime = md.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64);
    let key = (exe.to_string(), md.len(), mtime);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return v.clone();
    }
    if md.len() > 256 << 20 {
        return (None, None);
    }
    let kind = crate::trust::detect_pkg_kind();
    let mut h256 = sha2::Sha256::new();
    let mut h1 = sha1::Sha1::new();
    let mut r = std::io::BufReader::new(f);
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                h256.update(&buf[..n]);
                if kind == crate::trust::PkgKind::Apk {
                    h1.update(&buf[..n]);
                }
            }
            Err(_) => return (None, None),
        }
    }
    let hashes = crate::trust::Hashes { sha256: h256.finalize().into(), sha1: (kind == crate::trust::PkgKind::Apk).then(|| h1.finalize().into()) };
    let path = PathBuf::from(exe.trim_end_matches(" (deleted)"));
    let wanted: HashSet<PathBuf> = [path.clone()].into_iter().collect();
    let origin = crate::trust::Trust::load(kind, &crate::trust::default_allowlists().into_iter().map(|f| (f, false)).collect::<Vec<_>>(), &wanted)
        .ok().and_then(|t| serde_json::to_value(t.origin(&path, &hashes)).ok());
    let v = (Some(crate::trust::hex(&hashes.sha256)), origin);
    let mut c = cache.lock().unwrap();
    if c.len() > 512 {
        c.clear();
    }
    c.insert(key, v.clone());
    v
}

/// Snapshot of a process and its ancestry (best effort: it may have exited).
pub fn process_context(pid: u32) -> serde_json::Value {
    if pid == 0 {
        return serde_json::Value::Null;
    }
    let base = format!("/proc/{pid}");
    if !Path::new(&base).exists() {
        return serde_json::json!({"pid": pid, "gone": true});
    }
    let rd = |f: &str| std::fs::read_link(format!("{base}/{f}")).map(|p| p.to_string_lossy().into_owned()).ok();
    let cmd = |p: u32| std::fs::read(format!("/proc/{p}/cmdline")).ok().map(|b| {
        b.split(|&c| c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>().join(" ")
    });
    let status = std::fs::read_to_string(format!("{base}/status")).unwrap_or_default();
    let uid: u32 = status.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()).unwrap_or(u32::MAX);
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let st = stat_fields(pid);
    let started = st.as_ref().and_then(|v| v.get(21)?.parse::<f64>().ok()).map(|j| local_time(boot_time() + j / tck));
    // ancestry
    let mut tree = vec![];
    let mut p = st.as_ref().and_then(|v| v.get(3)?.parse::<u32>().ok()).unwrap_or(0);
    for _ in 0..8 {
        if p <= 1 {
            break;
        }
        let Some(v) = stat_fields(p) else { break };
        tree.push(format!("{p} {}", cmd(p).filter(|c| !c.is_empty()).unwrap_or_else(|| format!("[{}]", v[1])).chars().take(120).collect::<String>()));
        p = v.get(3).and_then(|x| x.parse().ok()).unwrap_or(0);
    }
    let exe = rd("exe");
    let (sha, pkg) = exe.as_ref().map(|e| exe_identity(&format!("{base}/exe"), e)).unwrap_or((None, None));
    let s = |o: Option<String>| o.map(|x| crate::safety::safe(&x));
    let tree: Vec<String> = tree.iter().map(|t| crate::safety::safe(t)).collect();
    serde_json::json!({
        "pid": pid, "user": user_name(uid).unwrap_or_else(|| uid.to_string()), "uid": uid,
        "exe": s(exe), "sha256": sha, "origin": pkg, "cmdline": s(cmd(pid)), "cwd": s(rd("cwd")), "started": started,
        "container": super::procs::container_of(pid), "parents": tree,
        "open_fds": std::fs::read_dir(format!("{base}/fd")).map(|d| d.count()).ok(),
    })
}

/// Full context for an alert: process, the entity's learned profile, the destination.
pub fn alert_context(a: &Alert, eng: &Engine) -> serde_json::Value {
    let mut c = serde_json::Map::new();
    let p = process_context(a.pid);
    if !p.is_null() {
        c.insert("process".into(), p);
    }
    if let Some(e) = eng.ent_summary(&a.entity) {
        c.insert("profile".into(), e);
    }
    if let Some(ip) = dest_ip(a) {
        let (fe, fg) = eng.dest_first_seen(&a.entity, &ip);
        c.insert("destination".into(), serde_json::json!({
            "ip": ip, "dns_name": eng.name_of(&ip), "class": format!("{:?}", super::engine::dest_class(&ip)),
            "first_seen_by_entity": fe.map(local_time), "first_seen_here": fg.map(local_time),
        }));
    }
    serde_json::Value::Object(c)
}

// ------------------------------------------------------------------ feedback

/// Suppressions from `ratel ack --fp`: (entity, dest or "*", kind or "*").
/// Entities that stand for "some process we couldn't identify": silencing them with a
/// wildcard destination would mute whole alert classes host-wide.
pub fn catch_all_entity(e: &str) -> bool {
    matches!(e, "unattributed" | "unattributed-udp" | "?" | "" | "ratel") || e.starts_with("uid:") || e.starts_with("host:")
}

/// The suppressions a false-alarm ack of these alerts may create: (entity, dest|*, kind).
/// Catch-all entities only ever get a concrete destination; alerts without one can't be silenced.
pub fn suppressions_for(alerts: &[serde_json::Value], any_dest: bool) -> Vec<[String; 3]> {
    let mut out: Vec<[String; 3]> = vec![];
    for a in alerts {
        let ent = a["entity"].as_str().unwrap_or("").to_string();
        let kind = a["kind"].as_str().unwrap_or("").to_string();
        let dest = a["dest"].as_str().unwrap_or("").split(' ').next().unwrap_or("").to_string();
        if ent.is_empty() || kind.is_empty() || kind == "health" {
            continue;
        }
        let d = if catch_all_entity(&ent) || kind == "process" || kind == "file" {
            // process / file alerts carry a rule or path in dest; catch-alls need a concrete dest
            if dest.is_empty() || (catch_all_entity(&ent) && dest.parse::<IpAddr>().is_err() && kind != "dns") {
                continue;
            }
            dest
        } else if any_dest || dest.is_empty() {
            "*".to_string()
        } else {
            dest
        };
        let k = [ent, d, kind];
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

/// Feedback files: feedback.jsonl (`ratel ack`) and feedback.d/*.jsonl (`ratel web`).
pub fn feedback_files(state_dir: &Path) -> Vec<PathBuf> {
    let mut v = vec![state_dir.join("feedback.jsonl")];
    if let Ok(rd) = std::fs::read_dir(state_dir.join("feedback.d")) {
        let mut d: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "jsonl")).collect();
        d.sort();
        v.extend(d);
    }
    v
}

/// Changes whenever any feedback file changes (cheap to poll).
pub fn feedback_stamp(state_dir: &Path) -> Vec<(PathBuf, Option<std::time::SystemTime>, u64)> {
    feedback_files(state_dir).into_iter().map(|p| {
        let m = std::fs::metadata(&p).ok();
        let (mt, len) = (m.as_ref().and_then(|m| m.modified().ok()), m.map_or(0, |m| m.len()));
        (p, mt, len)
    }).collect()
}

const FEEDBACK_MAX_FILES: usize = 32;
const FEEDBACK_MAX_BYTES: u64 = 1 << 20;

/// Suppressions from all feedback files, plus the files that were skipped (too big /
/// too many: the inbox is writable by the less-privileged dashboard).
pub fn load_suppressions_checked(state_dir: &Path) -> (HashSet<(String, String, String)>, Vec<String>) {
    let mut s = HashSet::new();
    let mut skipped = vec![];
    for (n, f) in feedback_files(state_dir).into_iter().enumerate() {
    let size = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
    // feedback.jsonl (written by root's `ratel ack`) must be root-only; feedback.d is the
    // dashboard's inbox and is treated as untrusted input anyway (scoped, announced)
    let root_file = f.parent() == Some(state_dir);
    if n >= FEEDBACK_MAX_FILES || size > FEEDBACK_MAX_BYTES {
        if size > 0 || n >= FEEDBACK_MAX_FILES {
            skipped.push(format!("{} ({} bytes)", f.display(), size));
        }
        continue;
    }
    let t = if root_file {
        match crate::safety::trusted_read_string(&f, FEEDBACK_MAX_BYTES) {
            Ok(t) => t,
            Err(e) => {
                if f.exists() {
                    skipped.push(format!("ignored {}: {e}", f.display()));
                }
                continue;
            }
        }
    } else {
        // the dashboard's inbox: untrusted, but never a FIFO/symlink/endless file
        match crate::safety::bounded_read(&f, FEEDBACK_MAX_BYTES).map(String::from_utf8) {
            Ok(Ok(t)) => t,
            Ok(Err(_)) => continue,
            Err(e) => {
                if f.exists() {
                    skipped.push(format!("ignored {}: {e}", f.display()));
                }
                continue;
            }
        }
    };
    {
        for l in t.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
            if v["fp"].as_bool() != Some(true) {
                continue;
            }
            for k in v["suppress"].as_array().into_iter().flatten() {
                if let (Some(e), Some(d), Some(kind)) = (k[0].as_str(), k[1].as_str(), k[2].as_str()) {
                    // defence in depth: never a wildcard for an unidentified process
                    if catch_all_entity(e) && (d == "*" || d.is_empty()) {
                        skipped.push(format!("rejected suppression ({kind}, {e}, {d}) from {}", f.display()));
                        continue;
                    }
                    s.insert((e.to_string(), d.to_string(), kind.to_string()));
                }
            }
        }
    }
    }
    (s, skipped)
}

/// Suppressions already announced (root-only file next to the state); anything not in it
/// is announced, even when it appeared while the daemon was down.
pub fn announced(state_dir: &Path) -> HashSet<(String, String, String)> {
    std::fs::read(state_dir.join("suppressions.announced")).ok()
        .and_then(|b| serde_json::from_slice::<Vec<(String, String, String)>>(&b).ok())
        .map(|v| v.into_iter().collect()).unwrap_or_default()
}

pub fn save_announced(state_dir: &Path, s: &HashSet<(String, String, String)>) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut v: Vec<&(String, String, String)> = s.iter().collect();
    v.sort();
    let tmp = state_dir.join("suppressions.announced.tmp");
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp) {
        if f.write_all(serde_json::to_string(&v).unwrap_or_default().as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, state_dir.join("suppressions.announced"));
        }
    }
}

// ------------------------------------------------------------------ health

#[derive(Default)]
pub struct Health {
    pub started: f64,
    pub events: u64,
    pub cap_packets: u64,
    pub cap_drops: u64,
    pub win_packets: u64,
    pub win_drops: u64,
    pub alerts: HashMap<&'static str, u64>,
    pub last_alert: Option<(f64, String)>,
    pub notify_failures: u64,
    pub netns: usize,
    pub stopped: bool,
    pub recent: VecDeque<(f64, &'static str, &'static str, String)>,
}

impl Health {
    pub fn note_alert(&mut self, a: &Alert) {
        *self.alerts.entry(a.severity).or_default() += 1;
        self.last_alert = Some((a.t, a.title.clone()));
        self.recent.push_back((a.t, a.severity, a.kind, a.title.clone()));
        while self.recent.len() > 2000 || self.recent.front().is_some_and(|x| x.0 < a.t - 86_400.0) {
            self.recent.pop_front();
        }
    }
}

/// PACKET_STATISTICS: packets seen / dropped by the kernel since the last call.
pub fn packet_stats(fd: i32) -> (u64, u64) {
    #[repr(C)]
    struct TpStats {
        packets: u32,
        drops: u32,
    }
    let mut st = TpStats { packets: 0, drops: 0 };
    let mut len = std::mem::size_of::<TpStats>() as libc::socklen_t;
    // SAFETY: getsockopt into a correctly sized struct (SOL_PACKET = 263, PACKET_STATISTICS = 6).
    let r = unsafe { libc::getsockopt(fd, 263, 6, &mut st as *mut _ as *mut libc::c_void, &mut len) };
    if r == 0 { (st.packets as u64, st.drops as u64) } else { (0, 0) }
}

pub fn write_status(path: &Path, h: &Health, eng: &Engine, extra: serde_json::Value) {
    let v = serde_json::json!({
        "pid": std::process::id(), "version": env!("CARGO_PKG_VERSION"), "updated": super::now(), "started": h.started,
        "uptime_s": (super::now() - h.started).round(), "events": h.events, "engine": eng.stats(),
        "capture": {"packets": h.cap_packets, "dropped": h.cap_drops}, "netns": h.netns,
        "alerts": h.alerts, "last_alert": h.last_alert.as_ref().map(|(t, s)| serde_json::json!({"time": local_time(*t), "title": s})),
        "notify_failures": h.notify_failures, "stopped": h.stopped, "extra": extra,
    });
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Daily digest: what happened, who uploaded most, what's new, is the monitor healthy.
pub fn digest(h: &Health, eng: &Engine, now: f64) -> (String, String) {
    let day: Vec<_> = h.recent.iter().filter(|x| x.0 >= now - 86_400.0).collect();
    let by = |sev: &str| day.iter().filter(|x| x.1 == sev).count();
    let mut body = format!("Last 24 h: {} high, {} medium, {} low alerts\n", by("high"), by("medium"), by("low"));
    for x in day.iter().filter(|x| x.1 != "low").take(8) {
        body += &format!("  {} {} {}\n", local_time(x.0), x.1.to_uppercase(), x.3);
    }
    body += "Top uploaders (24 h):\n";
    for (e, b) in eng.top_uploaders(24, 5) {
        body += &format!("  {} {}\n", super::engine::human(b as f64), e);
    }
    let new = eng.new_entities_since(now - 86_400.0);
    if !new.is_empty() {
        body += &format!("New on the network (24 h): {}\n", new.iter().take(8).cloned().collect::<Vec<_>>().join(", "));
    }
    let st = eng.stats();
    body += &format!("Monitor: up {:.1} h, {} events, capture drops {}, {}\n", (now - h.started) / 3600.0, h.events, h.cap_drops,
        if st["learning"].as_bool() == Some(true) { "still learning" } else { "baselines active" });
    let subject = format!("daily digest: {} high / {} medium", by("high"), by("medium"));
    (subject, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(t: f64, ent: &str, dest: &str, kind: &'static str) -> Alert {
        Alert { t, severity: "high", kind, entity: ent.into(), pid: 0, dest: dest.into(), score: 0.9, title: "x".into(),
            evidence: vec![], incident: String::new(), context: serde_json::Value::Null, capped: false }
    }

    #[test]
    fn incidents_group_by_entity_and_host() {
        let dir = std::env::temp_dir().join(format!("ratel-inc-test-{}", std::process::id()));
        let mut s = Store::new(&dir).unwrap();
        let mut rec = Recorder::new();
        let ev = Event::Tcp { t: 1000.0, id: 1, ent: "/usr/bin/x".into(), pid: 1, lport: 1, rip: "203.0.113.9".parse().unwrap(), rport: 443,
            sent: 10, recv: 0, inbound: false, closed: false, pre: false };
        rec.push(&ev);
        let (a, new_a) = s.on_alert(&alert(1010.0, "/usr/bin/x", "203.0.113.9", "exfil"), &rec);
        let (b, new_b) = s.on_alert(&alert(1500.0, "/usr/bin/x", "198.51.100.1", "beacon"), &rec);
        let (c, new_c) = s.on_alert(&alert(1600.0, "/usr/bin/y", "203.0.113.9", "beacon"), &rec);
        let (d, new_d) = s.on_alert(&alert(9000.0, "/usr/bin/x", "203.0.113.9", "exfil"), &rec);
        assert!(new_a && !new_b && !new_c && new_d);
        assert!(a == b && b == c && d != a);
        s.on_event(&ev);
        let body = std::fs::read_to_string(dir.join("incidents").join(format!("{a}.jsonl"))).unwrap();
        assert!(body.contains("\"before\"") && body.contains("\"after\"") && body.matches("\"alert\"").count() >= 3);
        let _ = std::fs::remove_dir_all(dir);
    }
}
