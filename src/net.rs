//! Network view built from /proc: which process owns which socket, plus
//! heuristics that matter on a server: fileless / deleted / temp-dir binaries
//! holding sockets, masquerading kernel threads, raw/packet sockets, scanning,
//! and (with --watch) periodic reconnects that look like C2 beaconing.
//!
//! Needs root to see other users' processes; without it the view is partial.

use crate::Opts;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Sock {
    proto: &'static str,
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
    state: u8,
    inode: u64,
}

fn state_name(proto: &str, s: u8) -> &'static str {
    if proto.starts_with("udp") {
        return if s == 1 { "connected" } else { "open" };
    }
    match s {
        1 => "ESTAB", 2 => "SYN_SENT", 3 => "SYN_RECV", 4 => "FIN_WAIT1", 5 => "FIN_WAIT2", 6 => "TIME_WAIT",
        7 => "CLOSE", 8 => "CLOSE_WAIT", 9 => "LAST_ACK", 10 => "LISTEN", 11 => "CLOSING", _ => "?",
    }
}

fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.swap_bytes())),
        32 => {
            let mut b = [0u8; 16];
            for w in 0..4 {
                let v = u32::from_str_radix(&a[w * 8..w * 8 + 8], 16).ok()?.swap_bytes();
                b[w * 4..w * 4 + 4].copy_from_slice(&v.to_be_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some((ip, port))
}

fn read_sockets() -> Vec<Sock> {
    let mut out = vec![];
    for (file, proto) in [("tcp", "tcp"), ("tcp6", "tcp6"), ("udp", "udp"), ("udp6", "udp6"), ("raw", "raw"), ("raw6", "raw6")] {
        let Ok(s) = std::fs::read_to_string(format!("/proc/net/{file}")) else { continue };
        for line in s.lines().skip(1) {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() < 10 {
                continue;
            }
            let (Some(l), Some(r)) = (parse_addr(c[1]), parse_addr(c[2])) else { continue };
            let state = u8::from_str_radix(c[3], 16).unwrap_or(0);
            let inode = c[9].parse().unwrap_or(0);
            if inode == 0 {
                continue; // TIME_WAIT etc. no longer owned by anyone
            }
            out.push(Sock { proto, local: l, remote: r, state, inode });
        }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/net/packet") {
        for line in s.lines().skip(1) {
            let c: Vec<&str> = line.split_whitespace().collect();
            if let Some(inode) = c.get(8).and_then(|x| x.parse().ok()) {
                let z = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                out.push(Sock { proto: "packet", local: z, remote: z, state: 0, inode });
            }
        }
    }
    out
}

#[derive(Clone, Debug)]
struct Proc {
    pid: u32,
    uid: u32,
    comm: String,
    cmdline: String,
    exe: String,
    inodes: HashSet<u64>,
}

fn read_procs() -> (Vec<Proc>, usize) {
    let mut out = vec![];
    let mut denied = 0;
    let Ok(rd) = std::fs::read_dir("/proc") else { return (out, 0) };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let base = format!("/proc/{pid}");
        let Ok(fds) = std::fs::read_dir(format!("{base}/fd")) else {
            denied += 1;
            continue;
        };
        let mut inodes = HashSet::new();
        for fd in fds.flatten() {
            if let Ok(t) = std::fs::read_link(fd.path()) {
                let t = t.to_string_lossy();
                if let Some(n) = t.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                    if let Ok(n) = n.parse() {
                        inodes.insert(n);
                    }
                }
            }
        }
        if inodes.is_empty() {
            continue;
        }
        let comm = std::fs::read_to_string(format!("{base}/comm")).unwrap_or_default().trim().to_string();
        let cmdline = std::fs::read(format!("{base}/cmdline")).unwrap_or_default()
            .split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).to_string())
            .collect::<Vec<_>>().join(" ");
        let exe = std::fs::read_link(format!("{base}/exe")).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        let uid = std::fs::read_to_string(format!("{base}/status")).ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
            .unwrap_or(u32::MAX);
        out.push(Proc { pid, uid, comm, cmdline, exe, inodes });
    }
    (out, denied)
}

#[derive(serde::Serialize, Clone)]
struct Flag {
    severity: &'static str,
    rule: &'static str,
    detail: String,
}

fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_unspecified(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unspecified(),
    }
}

const ODD_PORTS: &[u16] = &[4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669, 5555, 2222, 9001, 9030, 9050, 1080, 3389, 5900, 23];

fn proc_flags(p: &Proc, socks: &[&Sock]) -> Vec<Flag> {
    let mut f = vec![];
    let exe = p.exe.as_str();
    if exe.starts_with("/memfd:") {
        f.push(Flag { severity: "high", rule: "fileless_exe", detail: format!("running from {exe} (memfd, no file on disk)") });
    } else if exe.ends_with(" (deleted)") {
        f.push(Flag { severity: "medium", rule: "deleted_exe", detail: format!("binary deleted after start: {exe} (also happens after package upgrades)") });
    }
    let path = exe.trim_end_matches(" (deleted)");
    if ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"].iter().any(|d| path.starts_with(d)) || path.contains("/.") {
        f.push(Flag { severity: "high", rule: "exe_in_temp_or_hidden", detail: format!("binary lives in a temp/hidden path: {path}") });
    }
    if p.cmdline.starts_with('[') && !exe.is_empty() {
        f.push(Flag { severity: "high", rule: "fake_kernel_thread", detail: format!("named like a kernel thread ({}) but has an executable {exe}", p.cmdline) });
    }
    if let Some(base) = path.rsplit('/').next() {
        let c = &p.comm;
        if !base.is_empty() && !c.is_empty() && !base.starts_with(c.as_str()) && !c.starts_with(&base[..base.len().min(15)])
            && !exe.starts_with("/memfd:") && !base.contains("python") && !base.contains("java") && !base.contains("node")
            && !base.contains("perl") && !base.contains("busybox") && !base.contains("ld-") && !base.contains("bash") && !base.contains("sh")
        {
            f.push(Flag { severity: "low", rule: "comm_mismatch", detail: format!("process name {c:?} differs from binary {base:?}") });
        }
    }
    let raw: Vec<&&Sock> = socks.iter().filter(|s| s.proto.starts_with("raw") || s.proto == "packet").collect();
    if !raw.is_empty() {
        f.push(Flag { severity: "medium", rule: "raw_socket", detail: format!("{} raw/packet socket(s) (sniffing or crafted packets)", raw.len()) });
    }
    let syn = socks.iter().filter(|s| s.proto.starts_with("tcp") && s.state == 2).count();
    let dests: HashSet<IpAddr> = socks.iter().filter(|s| s.proto.starts_with("tcp") && matches!(s.state, 1 | 2)).map(|s| s.remote.0).collect();
    if syn >= 20 {
        f.push(Flag { severity: "medium", rule: "many_syn_sent", detail: format!("{syn} half-open outbound connections (scanning?)") });
    }
    let odd: Vec<String> = socks.iter().filter(|s| s.state == 1 && !is_local(&s.remote.0) && ODD_PORTS.contains(&s.remote.1))
        .map(|s| format!("{}:{}", s.remote.0, s.remote.1)).collect();
    if !odd.is_empty() {
        f.push(Flag { severity: "low", rule: "odd_remote_port", detail: format!("connected to commonly-abused ports: {}", odd.join(", ")) });
    }
    if p.uid == 0 && dests.len() >= 50 {
        f.push(Flag { severity: "low", rule: "root_fanout", detail: format!("root process talking to {} distinct hosts", dests.len()) });
    }
    f
}

fn sev_rank(s: &str) -> u8 {
    match s { "high" => 3, "medium" => 2, "low" => 1, _ => 0 }
}

/// Beacon detection over sampled connection appearances.
struct Beacons {
    first_seen: HashMap<u64, ()>,
    /// (pid, comm, remote) -> appearance times (secs since start)
    events: HashMap<(u32, String, IpAddr, u16), Vec<f64>>,
}

impl Beacons {
    fn observe(&mut self, t: f64, socks: &[Sock], owner: &HashMap<u64, (u32, String)>) {
        for s in socks {
            if !s.proto.starts_with("tcp") || is_local(&s.remote.0) || s.remote.1 == 0 || s.state == 10 {
                continue;
            }
            if self.first_seen.insert(s.inode, ()).is_some() {
                continue;
            }
            let (pid, comm) = owner.get(&s.inode).cloned().unwrap_or((0, "?".into()));
            self.events.entry((pid, comm, s.remote.0, s.remote.1)).or_default().push(t);
        }
    }

    fn report(&self) -> Vec<(String, f64, f64, usize)> {
        let mut out = vec![];
        for ((pid, comm, ip, port), ts) in &self.events {
            // The first appearance may be a connection that already existed.
            let ts: Vec<f64> = ts.iter().skip(1).cloned().collect();
            if ts.len() < 4 {
                continue;
            }
            let gaps: Vec<f64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
            let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
            let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
            let cv = var.sqrt() / mean.max(1e-9);
            if mean >= 2.0 && cv < 0.25 {
                out.push((format!("pid {pid} ({comm}) -> {ip}:{port}"), mean, cv, ts.len()));
            }
        }
        out.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());
        out
    }
}

pub fn run(o: &Opts) {
    let mut beacons = Beacons { first_seen: HashMap::new(), events: HashMap::new() };
    let start = Instant::now();
    let mut socks;
    let mut procs;
    let mut denied;
    loop {
        socks = read_sockets();
        (procs, denied) = read_procs();
        if o.watch == 0 {
            break;
        }
        let owner: HashMap<u64, (u32, String)> = procs.iter()
            .flat_map(|p| p.inodes.iter().map(move |i| (*i, (p.pid, p.comm.clone())))).collect();
        beacons.observe(start.elapsed().as_secs_f64(), &socks, &owner);
        if start.elapsed() >= Duration::from_secs(o.watch) {
            break;
        }
        std::thread::sleep(Duration::from_millis(o.interval_ms));
    }

    let by_inode: HashMap<u64, &Sock> = socks.iter().map(|s| (s.inode, s)).collect();
    let mut owned: HashSet<u64> = HashSet::new();
    let model = if o.scan_exes { Some(crate::load_model(o)) } else { None };
    let mut exe_cache: HashMap<String, Option<(f64, &'static str, Vec<String>)>> = HashMap::new();
    let mut rows: Vec<(u8, serde_json::Value, String)> = vec![];
    for p in &procs {
        let mine: Vec<&Sock> = p.inodes.iter().filter_map(|i| by_inode.get(i).copied()).collect();
        if mine.is_empty() {
            continue;
        }
        owned.extend(mine.iter().map(|s| s.inode));
        let mut flags = proc_flags(p, &mine);
        let mut scan = None;
        if let Some(m) = &model {
            let key = p.exe.clone();
            let r = exe_cache.entry(key).or_insert_with(|| {
                // Read through /proc so deleted and memfd binaries are still reachable.
                crate::read_candidate(std::path::Path::new(&format!("/proc/{}/exe", p.pid)), o.max_size << 20).map(|d| {
                    let a = crate::report::assess(&crate::features::analyze(&d), m);
                    let det = a.caps.iter().filter(|c| c.conf >= 0.5).map(|c| c.cap.to_string()).collect();
                    (a.risk, a.verdict, det)
                })
            });
            if let Some((risk, verdict, det)) = r.clone() {
                if risk >= 0.5 {
                    flags.push(Flag { severity: if risk >= 0.75 { "high" } else { "medium" }, rule: "static_scan",
                        detail: format!("binary scores {verdict} ({risk:.2}): {}", det.join(", ")) });
                }
                scan = Some(serde_json::json!({"risk": risk, "verdict": verdict, "detected": det}));
            }
        }
        let worst = flags.iter().map(|f| sev_rank(f.severity)).max().unwrap_or(0);
        let listen: Vec<String> = mine.iter().filter(|s| s.state == 10 || (s.proto.starts_with("udp") && s.remote.1 == 0))
            .map(|s| format!("{}/{}:{}", s.proto, s.local.0, s.local.1)).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let mut remotes: BTreeMap<String, usize> = BTreeMap::new();
        for s in mine.iter().filter(|s| s.remote.1 != 0 && s.state != 10) {
            *remotes.entry(format!("{}:{} {}", s.remote.0, s.remote.1, state_name(s.proto, s.state))).or_default() += 1;
        }
        let exposed = listen.iter().any(|l| l.contains("/0.0.0.0:") || l.contains("/:::"));
        let json = serde_json::json!({
            "pid": p.pid, "uid": p.uid, "comm": p.comm, "exe": p.exe, "cmdline": p.cmdline,
            "listening": listen, "remotes": remotes, "flags": flags, "scan": scan,
        });
        let mut text = format!("{:>7} {:<16} uid={:<5} {}\n", p.pid, p.comm, p.uid, p.exe);
        if !listen.is_empty() {
            text += &format!("        listen{}: {}\n", if exposed { " (all interfaces)" } else { "" }, listen.join(" "));
        }
        let nrem = remotes.len();
        for (r, n) in remotes.iter().take(8) {
            text += &format!("        -> {r}{}\n", if *n > 1 { format!(" x{n}") } else { String::new() });
        }
        if nrem > 8 {
            text += &format!("        ... {} more remote endpoints\n", nrem - 8);
        }
        for f in &flags {
            text += &format!("        [{}] {}: {}\n", f.severity, f.rule, f.detail);
        }
        rows.push((worst, json, text));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    let orphans = socks.iter().filter(|s| !owned.contains(&s.inode) && s.state != 6).count();
    let beacon_hits = beacons.report();

    if o.json {
        let v = serde_json::json!({
            "processes": rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>(),
            "unattributed_sockets": orphans,
            "unreadable_processes": denied,
            "beacons": beacon_hits.iter().map(|(k, m, cv, n)| serde_json::json!({"flow": k, "period_s": m, "jitter_cv": cv, "events": n})).collect::<Vec<_>>(),
        });
        println!("{v}");
        return;
    }
    for r in &rows {
        print!("{}", r.2);
    }
    if o.watch > 0 {
        println!("\nbeaconing ({}s watch, {}ms samples):", o.watch, o.interval_ms);
        if beacon_hits.is_empty() {
            println!("    none (needs >=5 reconnects to one endpoint with <25% jitter)");
        }
        for (k, m, cv, n) in &beacon_hits {
            println!("    {k}: every {m:.1}s, jitter {:.0}%, {n} reconnects", cv * 100.0);
        }
    }
    let flagged = rows.iter().filter(|r| r.0 >= 2).count();
    eprintln!("ratel net: {} processes with sockets, {flagged} flagged medium+, {orphans} sockets not attributable{}",
        rows.len(), if denied > 0 { format!(", {denied} processes unreadable (run as root for the full view)") } else { String::new() });
}
