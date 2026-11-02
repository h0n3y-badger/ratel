//! The network detection engine. Pure and deterministic: it only reacts to
//! events (with their own timestamps), so a recorded or synthetic trace gives
//! exactly the alerts / training rows the live daemon would.
//!
//! Units it scores, once per simulated minute:
//! * flow: (entity, remote host) over the last 10 / 60 minutes: volume and
//!   direction, novelty against the entity's learned baseline, periodicity.
//! * dns:  (entity, base domain) over the last 10 minutes: tunnelling and
//!   exfiltration through query names.
//! Plus direct rules for ICMP tunnels, scanning and process red flags.

use super::dns::{entropy, split_base};
use super::events::Event;
use crate::model::NetModel;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

pub const FLOW_FEATURES: &[&str] = &[
    "out10_log", "in10_log", "out60_log", "in60_log", "ratio10", "ratio60", "conns10", "conns60_log", "active_min10",
    "active_min60", "udp_frac", "dest_public", "dest_private", "dest_overlay", "port_web", "port_dns", "port_ssh",
    "port_mail", "port_odd", "port_high", "port_new_ent", "inbound", "dest_age_log", "dest_new_ent", "dest_new_global",
    "dest_named", "dns_visible", "ent_age_log", "ent_server", "ent_outbound_frac", "ent_out_p95_log", "out60_vs_p95",
    "ent_out_share60", "ent_ndest60_log", "ent_ndest_p95_log", "history_log", "hour_activity", "beacon_n",
    "beacon_cv", "beacon_period_log", "out_per_conn_log", "long_lived", "ent_flag", "ent_static_risk",
    "pair_total_out_log", "pair_ratio_total", "pair_age_log", "ent_unnamed_frac", "ent_newdest_p95_log",
    "ent_max_pair_out_log", "out60_vs_max_pair",
];

pub const DNS_FEATURES: &[&str] = &[
    "q10_log", "uniq10_log", "uniq_ratio", "sub_len_mean", "sub_len_max", "label_len_max", "sub_entropy_mean",
    "digit_ratio", "hexlike_ratio", "depth_mean", "frac_txt", "frac_null", "frac_cname", "frac_mx", "frac_ptr",
    "frac_a", "frac_any_other", "nx_frac", "qbytes10_log", "domain_new_global", "domain_age_log", "history_log",
    "peak_per_min_log", "base_len", "base_entropy", "src_known",
];

const MIN: f64 = 60.0;
/// Calibrated model confidence needed to alert with no rule evidence at all.
const MODEL_ONLY_MIN: f64 = 0.97;
const HOUR: f64 = 3600.0;
const MAX_PAIRS: usize = 40_000;
const MAX_ENTS: usize = 4_000;
const MAX_ENT_DESTS: usize = 4_096;
const MAX_GLOBAL: usize = 200_000;
const MAX_NAMES: usize = 50_000;

fn log2p(x: f64) -> f32 {
    (1.0 + x.max(0.0)).log2() as f32
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DestClass {
    Public,
    Private,
    Overlay,
    Local,
}

pub fn dest_class(ip: &IpAddr) -> DestClass {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_loopback() || v.is_unspecified() {
                DestClass::Local
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                DestClass::Overlay // CGNAT range: Tailscale
            } else if v.is_private() || v.is_link_local() || v.is_broadcast() || v.is_multicast() {
                DestClass::Private
            } else {
                DestClass::Public
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() || v.is_unspecified() {
                DestClass::Local
            } else if s[0] & 0xfe00 == 0x0200 || (s[0] == 0xfd7a && s[1] == 0x115c) {
                DestClass::Overlay // Yggdrasil 200::/7, Tailscale fd7a:115c::/32
            } else if s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfe80 || s[0] & 0xff00 == 0xff00 {
                DestClass::Private
            } else if let Some(v4) = v.to_ipv4_mapped() {
                dest_class(&IpAddr::V4(v4))
            } else {
                DestClass::Public
            }
        }
    }
}

/// /24 (IPv4) or /48 (IPv6) prefix key: "same network" for novelty.
fn prefix(ip: &IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v) => (4u64 << 56) | (u32::from(*v) >> 8) as u64,
        IpAddr::V6(v) => {
            let b = v.octets();
            (6u64 << 56) | u64::from_be_bytes([0, 0, b[0], b[1], b[2], b[3], b[4], b[5]])
        }
    }
}

const ODD_PORTS: &[u16] = &[4444, 4445, 1337, 31337, 6666, 6667, 6697, 5555, 1080, 3389, 5900, 23, 8888, 9999, 12345, 54321];

fn port_kind(p: u16) -> (bool, bool, bool, bool, bool, bool) {
    let web = matches!(p, 80 | 443 | 8080 | 8443);
    let dns = matches!(p, 53 | 853);
    let ssh = p == 22;
    let mail = matches!(p, 25 | 465 | 587 | 993 | 995 | 143 | 110);
    let odd = ODD_PORTS.contains(&p);
    let high = p >= 1024 && !web && !odd;
    (web, dns, ssh, mail, odd, high)
}

pub fn human(b: f64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let mut x = b;
    let mut i = 0;
    while x >= 1000.0 && i < u.len() - 1 {
        x /= 1000.0;
        i += 1;
    }
    if i == 0 { format!("{x:.0} {}", u[i]) } else { format!("{x:.1} {}", u[i]) }
}

// ---------------------------------------------------------------- persisted state

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Ent {
    pub name: String,
    pub first_t: f64,
    pub last_t: f64,
    /// Completed hours: (hour index, bytes out, distinct destinations, outbound conns made).
    hours: VecDeque<(i64, u64, u32, u32)>,
    /// How many observed days the entity was active in each hour of day.
    hod: Vec<u16>,
    pub server: bool,
    /// Destination prefixes ever contacted -> first seen.
    dests: HashMap<u64, f64>,
    ports: Vec<u16>,
    pub flag: u8,
    pub flag_detail: String,
    pub static_risk: f32,
    pub static_detail: String,
    syn_max_min: u32,
    #[serde(default)]
    pub last_pid: u32,
    /// New public destinations that had / hadn't been returned by DNS.
    #[serde(default)]
    named_new: u32,
    #[serde(default)]
    unnamed_new: u32,
    /// Largest hourly volume ever sent to a single destination.
    #[serde(default)]
    max_pair_out: u64,
    #[serde(default)]
    newdest_hours: VecDeque<u32>,
    #[serde(default)]
    cur_newdests: u32,
    // current hour accumulators
    cur_hour: i64,
    cur_out: u64,
    cur_dests: Vec<u64>,
    cur_outconns: u32,
}

impl Ent {
    fn new(name: &str, t: f64) -> Ent {
        Ent { name: name.to_string(), first_t: t, last_t: t, hod: vec![0; 24], cur_hour: (t / HOUR) as i64, ..Default::default() }
    }

    fn roll(&mut self, t: f64) {
        let h = (t / HOUR) as i64;
        if h <= self.cur_hour {
            return;
        }
        if self.cur_out > 0 || !self.cur_dests.is_empty() {
            self.hours.push_back((self.cur_hour, self.cur_out, self.cur_dests.len() as u32, self.cur_outconns));
            if self.hours.len() > 168 {
                self.hours.pop_front();
            }
            if self.hod.len() != 24 {
                self.hod = vec![0; 24];
            }
            let hod = (self.cur_hour.rem_euclid(24)) as usize;
            self.hod[hod] = self.hod[hod].saturating_add(1);
        }
        if self.cur_out > 0 || !self.cur_dests.is_empty() {
            self.newdest_hours.push_back(self.cur_newdests);
            if self.newdest_hours.len() > 168 {
                self.newdest_hours.pop_front();
            }
        }
        self.cur_newdests = 0;
        self.cur_hour = h;
        self.cur_out = 0;
        self.cur_dests.clear();
        self.cur_outconns = 0;
    }

    fn p95(&self, f: impl Fn(&(i64, u64, u32, u32)) -> f64) -> Option<f64> {
        if self.hours.len() < 6 {
            return None;
        }
        let mut v: Vec<f64> = self.hours.iter().map(f).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Some(v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)])
    }

    fn unnamed_frac(&self) -> f32 {
        let n = self.named_new + self.unnamed_new;
        if n < 10 { -1.0 } else { self.unnamed_new as f32 / n as f32 }
    }

    fn newdest_p95(&self) -> Option<f64> {
        if self.newdest_hours.len() < 6 {
            return None;
        }
        let mut v: Vec<u32> = self.newdest_hours.iter().copied().collect();
        v.sort();
        Some(v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)] as f64)
    }

    fn outbound_frac(&self) -> f32 {
        if self.hours.is_empty() {
            return 0.0;
        }
        self.hours.iter().filter(|h| h.3 > 0).count() as f32 / self.hours.len() as f32
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    pub start_t: f64,
    pub ents: Vec<Ent>,
    dests_global: HashMap<u64, f64>,
    domains_global: HashMap<String, f64>,
    cooldown: HashMap<String, (f64, u8)>,
    /// Files already alerted on by periodic static scans: path -> sha256.
    #[serde(default)]
    pub file_alerted: HashMap<String, String>,
}

// ---------------------------------------------------------------- volatile state

struct Conn {
    ent: usize,
    rip: IpAddr,
    sent: u64,
    recv: u64,
    first_t: f64,
    last_t: f64,
}

#[derive(Default)]
struct Pair {
    /// (minute, out, in, starts, udp_out)
    mins: VecDeque<(i64, u64, u64, u32, u64)>,
    starts: VecDeque<f64>,
    ports: Vec<u16>,
    first_t: f64,
    last_t: f64,
    total_out: u64,
    total_in: u64,
    inbound: u32,
    outbound: u32,
    long_lived: bool,
}

#[derive(Default)]
struct DnsAgg {
    /// (t, subdomain, qtype)
    q: VecDeque<(f64, String, u16)>,
    nx: VecDeque<f64>,
    last_t: f64,
}

#[derive(Default)]
struct IcmpAgg {
    p: VecDeque<(f64, u32)>,
}

#[derive(Default)]
struct SynAgg {
    minute: i64,
    per_host: HashMap<IpAddr, u32>,
    hosts: HashSet<IpAddr>,
    ports: HashMap<IpAddr, HashSet<u16>>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Alert {
    pub t: f64,
    /// "high" | "medium" | "low"
    pub severity: &'static str,
    pub kind: &'static str,
    pub entity: String,
    pub pid: u32,
    pub dest: String,
    pub score: f64,
    pub title: String,
    pub evidence: Vec<String>,
}

pub struct Finding {
    pub rule: &'static str,
    pub strength: u8,
    pub text: String,
}

fn rule_conf(fs: &[Finding]) -> f64 {
    let s3 = fs.iter().filter(|f| f.strength >= 3).count();
    let s2 = fs.iter().filter(|f| f.strength == 2).count();
    let s1 = fs.iter().filter(|f| f.strength == 1).count();
    if s3 > 0 {
        0.9
    } else if s2 >= 2 || (s2 == 1 && s1 >= 2) {
        0.75
    } else if s2 == 1 {
        0.7
    } else if s1 >= 3 {
        0.5
    } else if s1 > 0 {
        0.3
    } else {
        0.0
    }
}

fn calibrate(p: f64, thr: f64) -> f64 {
    let thr = thr.clamp(0.01, 0.99);
    if p < thr { 0.5 * p / thr } else { 0.5 + 0.5 * (p - thr) / (1.0 - thr) }
}

pub struct Config {
    /// Hours before novelty / baseline rules are trusted.
    pub learn_hours: f64,
    /// Seconds before the same alert key may fire again (unless it gets worse).
    pub cooldown: f64,
    /// Entities never alerted on (exact names, or prefixes ending in '*').
    pub ignore: Vec<String>,
    /// Destinations (IPs, base domains) never alerted on.
    pub ignore_dest: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config { learn_hours: 24.0, cooldown: 6.0 * HOUR, ignore: vec![], ignore_dest: vec![] }
    }
}

pub struct Engine {
    pub cfg: Config,
    pub st: State,
    ent_idx: HashMap<String, usize>,
    pub t: f64,
    session_t0: f64,
    next_eval: f64,
    caps: (bool, bool, bool),
    conns: HashMap<u64, Conn>,
    syn_pending: HashMap<(u16, IpAddr, u16), f64>,
    pairs: HashMap<(usize, IpAddr), Pair>,
    names: HashMap<IpAddr, String>,
    dns: HashMap<(String, String), DnsAgg>,
    dga: HashMap<String, VecDeque<(f64, String)>>,
    icmp: HashMap<IpAddr, IcmpAgg>,
    syn: HashMap<String, SynAgg>,
    model: Option<NetModel>,
    pub alerts: Vec<Alert>,
    // training
    labels: HashMap<(String, String), Vec<(f64, f64, String)>>,
    pub emit: Option<Box<dyn std::io::Write>>,
    pub emit_all: bool,
}

impl Engine {
    pub fn new(cfg: Config, st: State, model: Option<NetModel>) -> Engine {
        let ent_idx = st.ents.iter().enumerate().map(|(i, e)| (e.name.clone(), i)).collect();
        Engine {
            cfg, st, ent_idx, t: 0.0, session_t0: f64::NAN, next_eval: 0.0, caps: (false, false, false),
            conns: HashMap::new(), syn_pending: HashMap::new(), pairs: HashMap::new(), names: HashMap::new(),
            dns: HashMap::new(), dga: HashMap::new(), icmp: HashMap::new(), syn: HashMap::new(), model,
            alerts: vec![], labels: HashMap::new(), emit: None, emit_all: false,
        }
    }

    fn ent(&mut self, name: &str, t: f64) -> usize {
        if let Some(&i) = self.ent_idx.get(name) {
            return i;
        }
        if self.st.ents.len() >= MAX_ENTS {
            // reuse the slot of the longest-idle entity
            let (i, _) = self.st.ents.iter().enumerate().min_by(|a, b| a.1.last_t.partial_cmp(&b.1.last_t).unwrap()).unwrap();
            self.ent_idx.remove(&self.st.ents[i].name);
            self.pairs.retain(|k, _| k.0 != i);
            self.conns.retain(|_, c| c.ent != i);
            self.st.ents[i] = Ent::new(name, t);
            self.ent_idx.insert(name.to_string(), i);
            return i;
        }
        self.st.ents.push(Ent::new(name, t));
        self.ent_idx.insert(name.to_string(), self.st.ents.len() - 1);
        self.st.ents.len() - 1
    }

    pub fn history_hours(&self) -> f64 {
        ((self.t - self.st.start_t) / HOUR).max(0.0)
    }

    /// Feed one event. Events must come in (roughly) time order.
    pub fn feed(&mut self, ev: &Event) {
        if let Event::Label { ent, dest, t0, t1, kind } = ev {
            self.labels.entry((ent.clone(), dest.clone())).or_default().push((*t0, *t1, kind.clone()));
            return;
        }
        let t = ev.t();
        if self.session_t0.is_nan() {
            self.session_t0 = t;
            if self.st.start_t == 0.0 {
                self.st.start_t = t;
            }
            self.next_eval = (t / MIN).floor() * MIN + MIN;
        }
        // Evaluate every minute boundary we pass.
        while t >= self.next_eval {
            self.t = self.next_eval;
            self.evaluate();
            self.next_eval += MIN;
        }
        self.t = self.t.max(t);
        match ev {
            Event::Caps { dns, syn, udp, .. } => self.caps = (*dns, *syn, *udp),
            Event::Tcp { id, ent, pid, lport, rip, rport, sent, recv, inbound, closed, pre, .. } => {
                if dest_class(rip) == DestClass::Local {
                    return;
                }
                let ei = self.ent(ent, t);
                if *pid != 0 {
                    self.st.ents[ei].last_pid = *pid;
                }
                let baseline = !self.conns.contains_key(id) && *pre;
                if !self.conns.contains_key(id) {
                    let start = self.syn_pending.remove(&(*lport, *rip, *rport)).unwrap_or(t);
                    self.conns.insert(*id, Conn {
                        ent: ei, rip: *rip, sent: if baseline { *sent } else { 0 },
                        recv: if baseline { *recv } else { 0 }, first_t: start, last_t: t,
                    });
                    if !baseline {
                        self.conn_start(ei, *rip, *rport, start, *inbound);
                    }
                }
                let c = self.conns.get_mut(id).unwrap();
                let (dout, din) = (sent.saturating_sub(c.sent), recv.saturating_sub(c.recv));
                c.sent = c.sent.max(*sent);
                c.recv = c.recv.max(*recv);
                c.last_t = t;
                let long = t - c.first_t > 600.0;
                let (cent, crip) = (c.ent, c.rip);
                if *closed {
                    self.conns.remove(id);
                }
                self.account(cent, crip, t, dout, din, 0, long);
            }
            Event::Syn { sport, rip, rport, ent, .. } => {
                if dest_class(rip) == DestClass::Local {
                    return;
                }
                self.syn_pending.insert((*sport, *rip, *rport), t);
                let key = ent.clone().unwrap_or_else(|| "unattributed".into());
                let m = (t / MIN) as i64;
                let a = self.syn.entry(key).or_default();
                if a.minute != m {
                    *a = SynAgg { minute: m, ..Default::default() };
                }
                if a.hosts.len() < 4096 {
                    a.hosts.insert(*rip);
                }
                if a.per_host.len() < 4096 || a.per_host.contains_key(rip) {
                    *a.per_host.entry(*rip).or_default() += 1;
                }
                let ps = a.ports.entry(*rip).or_default();
                if ps.len() < 4096 {
                    ps.insert(*rport);
                }
            }
            Event::Udp { ent, rip, rport, len, scale, .. } => {
                if dest_class(rip) == DestClass::Local {
                    return;
                }
                let ei = self.ent(ent, t);
                let bytes = *len as u64 * (*scale).max(1) as u64;
                let p = self.pairs.entry((ei, *rip)).or_default();
                if !p.ports.contains(rport) && p.ports.len() < 16 {
                    p.ports.push(*rport);
                }
                self.account(ei, *rip, t, bytes, 0, bytes, false);
            }
            Event::Dns { ent, name, qtype, resp, rcode, answers, .. } => self.dns_event(ent.as_deref(), name, *qtype, *resp, *rcode, answers, t),
            Event::Icmp { rip, len, .. } => {
                if dest_class(rip) != DestClass::Local {
                    let a = self.icmp.entry(*rip).or_default();
                    a.p.push_back((t, *len));
                    while a.p.len() > 4096 || a.p.front().is_some_and(|x| x.0 < t - 600.0) {
                        a.p.pop_front();
                    }
                }
            }
            Event::Proc { ent, pid, rule, sev, detail, .. } => {
                let ei = self.ent(ent, t);
                let e = &mut self.st.ents[ei];
                e.last_pid = *pid;
                if *sev > e.flag {
                    e.flag = *sev;
                    e.flag_detail = format!("{rule}: {detail}");
                }
                if *sev >= 2 {
                    let fs = vec![Finding { rule: "process", strength: *sev, text: format!("{rule}: {detail}") }];
                    self.raise("process", ent.clone(), *pid, String::new(), 0.0, fs, format!("suspicious networked process: {rule}"));
                }
            }
            Event::Listen { ent, .. } => {
                let ei = self.ent(ent, t);
                self.st.ents[ei].server = true;
            }
            Event::Exe { ent, risk, detail, .. } => {
                let ei = self.ent(ent, t);
                let e = &mut self.st.ents[ei];
                e.static_risk = *risk;
                e.static_detail = detail.clone();
            }
            Event::Label { .. } => {}
        }
    }

    fn conn_start(&mut self, ei: usize, rip: IpAddr, rport: u16, t: f64, inbound: bool) {
        let pk = prefix(&rip);
        let e = &mut self.st.ents[ei];
        e.roll(t);
        if !inbound {
            e.cur_outconns += 1;
            if !e.ports.contains(&rport) && e.ports.len() < 256 {
                e.ports.push(rport);
            }
        }
        let p = self.pairs.entry((ei, rip)).or_default();
        if p.first_t == 0.0 {
            p.first_t = t;
        }
        if !inbound {
            p.starts.push_back(t);
            if p.starts.len() > 64 {
                p.starts.pop_front();
            }
        }
        if inbound { p.inbound += 1 } else { p.outbound += 1 }
        if !p.ports.contains(&rport) && p.ports.len() < 16 {
            p.ports.push(rport);
        }
        let m = (t / MIN) as i64;
        match p.mins.back_mut() {
            Some(b) if b.0 == m => b.3 += 1,
            _ => p.mins.push_back((m, 0, 0, 1, 0)),
        }
        let _ = pk;
    }

    #[allow(clippy::too_many_arguments)]
    fn account(&mut self, ei: usize, rip: IpAddr, t: f64, dout: u64, din: u64, udp: u64, long: bool) {
        let pk = prefix(&rip);
        {
            let e = &mut self.st.ents[ei];
            e.roll(t);
            e.last_t = t;
            e.cur_out += dout;
            if !e.cur_dests.contains(&pk) && e.cur_dests.len() < 4096 {
                e.cur_dests.push(pk);
            }
        }
        let p = self.pairs.entry((ei, rip)).or_default();
        if p.first_t == 0.0 {
            p.first_t = t;
        }
        p.last_t = t;
        p.total_out += dout;
        p.total_in += din;
        p.long_lived |= long;
        let m = (t / MIN) as i64;
        match p.mins.back_mut() {
            Some(b) if b.0 == m => {
                b.1 += dout;
                b.2 += din;
                b.4 += udp;
            }
            _ => p.mins.push_back((m, dout, din, 0, udp)),
        }
        while p.mins.front().is_some_and(|b| b.0 <= m - 60) {
            p.mins.pop_front();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dns_event(&mut self, ent: Option<&str>, name: &str, qtype: u16, resp: bool, rcode: u8, answers: &[IpAddr], t: f64) {
        let (base, sub) = split_base(name);
        if base.is_empty() || name.ends_with(".local") || !name.contains('.') {
            return;
        }
        let src = ent.unwrap_or("?").to_string();
        if resp {
            for a in answers {
                if self.names.len() >= MAX_NAMES {
                    self.names.clear(); // crude but bounded; repopulates within minutes
                }
                self.names.insert(*a, name.to_string());
            }
            if rcode == 3 {
                let a = self.dns.entry((src.clone(), base.to_string())).or_default();
                a.nx.push_back(t);
                let d = self.dga.entry(src).or_default();
                d.push_back((t, base.to_string()));
                while d.len() > 2048 || d.front().is_some_and(|x| x.0 < t - 600.0) {
                    d.pop_front();
                }
            }
            return;
        }
        let g = &mut self.st.domains_global;
        if !g.contains_key(base) {
            if g.len() >= MAX_GLOBAL {
                g.clear();
            }
            g.insert(base.to_string(), t);
        }
        let a = self.dns.entry((src, base.to_string())).or_default();
        a.q.push_back((t, sub.to_string(), qtype));
        a.last_t = t;
        while a.q.len() > 4096 || a.q.front().is_some_and(|x| x.0 < t - 600.0) {
            a.q.pop_front();
        }
        while a.nx.front().is_some_and(|x| *x < t - 600.0) {
            a.nx.pop_front();
        }
    }

    fn ignored(&self, ent: &str, dest: &str) -> bool {
        self.cfg.ignore.iter().any(|i| if let Some(p) = i.strip_suffix('*') { ent.starts_with(p) } else { i == ent })
            || self.cfg.ignore_dest.iter().any(|d| d == dest || dest.ends_with(&format!(".{d}")))
    }

    fn raise(&mut self, kind: &'static str, entity: String, pid: u32, dest: String, score: f64, fs: Vec<Finding>, title: String) {
        if self.ignored(&entity, &dest) {
            return;
        }
        let mut conf = score.max(rule_conf(&fs));
        // "high" needs strong rule evidence; the model can raise weak evidence to medium;
        // the model alone (no rule evidence) only ever logs a "low".
        if fs.iter().all(|f| f.strength == 0) {
            conf = conf.min(0.6);
        } else if fs.iter().all(|f| f.strength <= 1) {
            conf = conf.min(0.84);
        }
        let sev_n: u8 = if conf >= 0.85 { 3 } else if conf >= 0.65 { 2 } else { 1 };
        let key = format!("{kind}|{entity}|{dest}");
        if let Some((last, s)) = self.st.cooldown.get(&key) {
            if self.t - last < self.cfg.cooldown && sev_n <= *s {
                return;
            }
        }
        self.st.cooldown.insert(key, (self.t, sev_n));
        let severity = match sev_n { 3 => "high", 2 => "medium", _ => "low" };
        self.alerts.push(Alert {
            t: self.t, severity, kind, entity, pid, dest, score: (conf * 1000.0).round() / 1000.0, title,
            evidence: fs.into_iter().map(|f| f.text).collect(),
        });
    }

    fn label_for(&self, ent: &str, dest: &str, t0: f64, t1: f64) -> Option<String> {
        self.labels.get(&(ent.to_string(), dest.to_string()))?.iter().find(|l| l.0 <= t1 && l.1 >= t0).map(|l| l.2.clone())
    }

    fn emit_row(&mut self, unit: &str, ent: &str, dest: &str, x: &[f32], fs: &[Finding], force: bool) {
        let rules = fs.iter().map(|f| f.strength).max().unwrap_or(0);
        let rc = rule_conf(fs);
        if self.emit.is_none() {
            return;
        }
        let y = self.label_for(ent, dest, self.t - 600.0, self.t);
        // Benign rows are thinned (one minute in five per unit) to keep datasets small.
        let h = ent.bytes().chain(dest.bytes()).fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64));
        if y.is_none() && !force && !self.emit_all && ((self.t / MIN) as u64 + h) % 5 != 0 {
            return;
        }
        let row = serde_json::json!({"u": unit, "t": self.t, "ent": ent, "dest": dest, "x": x, "r": rules, "rc": rc, "y": y});
        if let Some(w) = self.emit.as_mut() {
            let _ = writeln!(w, "{row}");
        }
    }

    // ------------------------------------------------------------ evaluation

    fn evaluate(&mut self) {
        let now = self.t;
        let learning = self.history_hours() < self.cfg.learn_hours;
        let now_m = (now / MIN) as i64;
        // stale connections (destroy notification missed)
        self.conns.retain(|_, c| now - c.last_t < 900.0);
        self.syn_pending.retain(|_, t| now - *t < 60.0);
        for e in self.st.ents.iter_mut() {
            e.roll(now);
        }

        // ---- flows
        let keys: Vec<(usize, IpAddr)> = self.pairs.iter().filter(|(_, p)| now - p.last_t.max(p.starts.back().copied().unwrap_or(0.0)) < 600.0).map(|(k, _)| *k).collect();
        // per-entity totals over the last hour (share of traffic, distinct destinations)
        let mut ent_out60: HashMap<usize, (u64, u32)> = HashMap::new();
        for ((ei, _), p) in &self.pairs {
            let o: u64 = p.mins.iter().filter(|b| b.0 > now_m - 60).map(|b| b.1).sum();
            if p.mins.iter().any(|b| b.0 > now_m - 60) {
                let x = ent_out60.entry(*ei).or_default();
                x.0 += o;
                x.1 += 1;
            }
        }
        // SMTP fan-out per entity (spam bots), excluding entities that sent mail while learning
        let mut smtp: HashMap<usize, u32> = HashMap::new();
        for ((ei, ip), p) in &self.pairs {
            if dest_class(ip) == DestClass::Public && p.outbound > 0 && p.ports.iter().any(|x| matches!(x, 25 | 465 | 587))
                && p.starts.back().is_some_and(|s| now - s < 600.0) {
                *smtp.entry(*ei).or_default() += 1;
            }
        }
        for (ei, n) in smtp {
            let e = &self.st.ents[ei];
            let mailer = e.server && e.ports.contains(&25) && e.first_t <= self.st.start_t + self.cfg.learn_hours * HOUR;
            if n >= 15 && !mailer {
                let fs = vec![Finding { rule: "smtp_fanout", strength: 2, text: format!("connected to {n} different mail servers in 10 minutes") }];
                let (name, pid) = (e.name.clone(), e.last_pid);
                self.raise("spam", name.clone(), pid, String::new(), 0.0, fs, format!("possible spam bot: {name}"));
            }
        }
        let mut pair_max: Vec<(usize, u64)> = vec![];
        for k in keys {
            let (x, fs, dest_txt) = self.flow_features(k, now_m, &ent_out60, learning);
            pair_max.push((k.0, self.pairs[&k].mins.iter().filter(|b| b.0 > now_m - 60).map(|b| b.1).sum()));
            let ent = self.st.ents[k.0].name.clone();
            self.emit_row("flow", &ent, &k.1.to_string(), &x, &fs, false);
            let score = self.model.as_ref().and_then(|m| m.unit("flow")).map(|u| calibrate(u.predict(&x), u.threshold));
            self.decide("flow", ent, k.0, dest_txt, score, fs);
        }

        for (ei, o) in pair_max {
            let e = &mut self.st.ents[ei];
            e.max_pair_out = e.max_pair_out.max(o);
        }
        // ---- dns
        let dkeys: Vec<(String, String)> = self.dns.iter().filter(|(_, a)| now - a.last_t < 600.0 && !a.q.is_empty()).map(|(k, _)| k.clone()).collect();
        for k in dkeys {
            let (x, fs) = self.dns_features(&k);
            self.emit_row("dns", &k.0, &k.1, &x, &fs, false);
            let score = self.model.as_ref().and_then(|m| m.unit("dns")).map(|u| calibrate(u.predict(&x), u.threshold));
            let ent = k.0.clone();
            self.decide("dns", ent, usize::MAX, k.1.clone(), score, fs);
        }
        self.dga_rules();
        self.icmp_rules();
        self.scan_rules(now_m, learning);

        // ---- prune
        self.pairs.retain(|_, p| now - p.last_t.max(p.starts.back().copied().unwrap_or(0.0)) < 4.0 * HOUR);
        if self.pairs.len() > MAX_PAIRS {
            let mut v: Vec<((usize, IpAddr), f64)> = self.pairs.iter().map(|(k, p)| (*k, p.last_t)).collect();
            v.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            for (k, _) in v.into_iter().take(self.pairs.len() - MAX_PAIRS) {
                self.pairs.remove(&k);
            }
        }
        self.dns.retain(|_, a| now - a.last_t < 900.0);
        self.icmp.retain(|_, a| a.p.back().is_some_and(|x| now - x.0 < 600.0));
        self.syn.retain(|_, a| now_m - a.minute < 2);
        let cd = self.cfg.cooldown;
        self.st.cooldown.retain(|_, (t, _)| now - *t < cd * 2.0);
        // Novelty bookkeeping happens after scoring, so "new" means new this minute.
        self.commit_dests(now);
    }

    /// Record destinations seen in the last minute as known (entity and global).
    fn commit_dests(&mut self, now: f64) {
        let now_m = (now / MIN) as i64;
        let mut fresh = vec![];
        for ((ei, ip), p) in &self.pairs {
            if p.mins.back().is_some_and(|b| b.0 >= now_m - 1) {
                fresh.push((*ei, prefix(ip), p.first_t, dest_class(ip) == DestClass::Public, self.names.contains_key(ip)));
            }
        }
        for (ei, pk, t0, public, named) in fresh {
            let e = &mut self.st.ents[ei];
            if !e.dests.contains_key(&pk) {
                e.cur_newdests += 1;
                if public {
                    if named { e.named_new += 1 } else { e.unnamed_new += 1 }
                }
                if e.dests.len() >= MAX_ENT_DESTS {
                    let oldest = *e.dests.iter().min_by(|a, b| a.1.partial_cmp(b.1).unwrap()).unwrap().0;
                    e.dests.remove(&oldest);
                }
                e.dests.insert(pk, t0);
            }
            let g = &mut self.st.dests_global;
            if !g.contains_key(&pk) {
                if g.len() >= MAX_GLOBAL {
                    g.clear();
                }
                g.insert(pk, t0);
            }
        }
    }

    fn decide(&mut self, unit: &'static str, ent: String, ei: usize, dest: String, score: Option<f64>, fs: Vec<Finding>) {
        let m = score.unwrap_or(0.0);
        // Same gate as the static scanner: a model score without any rule finding
        // only counts when very confident, so every alert carries a reason.
        let m = if fs.is_empty() && (m < MODEL_ONLY_MIN || self.history_hours() < self.cfg.learn_hours) { m.min(0.49) } else { m };
        let conf = m.max(rule_conf(&fs));
        if conf < 0.5 {
            return;
        }
        let (title, kind) = match unit {
            "flow" => {
                let strong = fs.iter().any(|f| f.rule.contains("upload") || f.rule.contains("drip"));
                let beacon = fs.iter().any(|f| f.rule == "beaconing");
                let flood = fs.iter().any(|f| f.rule == "flood");
                if flood {
                    (format!("possible flood / DoS from {ent} -> {dest}"), "flood")
                } else if strong {
                    (format!("possible data exfiltration: {ent} -> {dest}"), "exfil")
                } else if beacon {
                    (format!("possible C2 beaconing: {ent} -> {dest}"), "beacon")
                } else {
                    (format!("unusual network flow: {ent} -> {dest}"), "flow")
                }
            }
            _ => (format!("possible DNS tunnel / exfiltration via {dest} (from {ent})"), "dns"),
        };
        let pid = if ei == usize::MAX { 0 } else { self.st.ents[ei].last_pid };
        let mut fs = fs;
        if let Some(s) = score {
            fs.push(Finding { rule: "model", strength: 0, text: format!("model score {:.2}{}", s, if fs.is_empty() { " (no rule evidence)" } else { "" }) });
        }
        self.raise(kind, ent, pid, dest, m, fs, title);
    }

    fn flow_features(&self, k: (usize, IpAddr), now_m: i64, ent_out60: &HashMap<usize, (u64, u32)>, learning: bool) -> (Vec<f32>, Vec<Finding>, String) {
        let (ei, ip) = k;
        let p = &self.pairs[&k];
        let e = &self.st.ents[ei];
        let sum = |w: i64, f: &dyn Fn(&(i64, u64, u64, u32, u64)) -> u64| -> u64 { p.mins.iter().filter(|b| b.0 > now_m - w).map(f).sum() };
        let (o10, i10, o60, i60) = (sum(10, &|b| b.1), sum(10, &|b| b.2), sum(60, &|b| b.1), sum(60, &|b| b.2));
        let (c10, c60) = (sum(10, &|b| b.3 as u64), sum(60, &|b| b.3 as u64));
        let udp60 = sum(60, &|b| b.4);
        let act10 = p.mins.iter().filter(|b| b.0 > now_m - 10 && (b.1 + b.2 + b.3 as u64) > 0).count();
        let act60 = p.mins.iter().filter(|b| b.0 > now_m - 60 && (b.1 + b.2 + b.3 as u64) > 0).count();
        let cls = dest_class(&ip);
        let port = p.ports.first().copied().unwrap_or(0);
        let (web, dnsp, ssh, mail, odd, high) = port_kind(port);
        let pk = prefix(&ip);
        let dest_first = e.dests.get(&pk).copied();
        let dest_age_h = dest_first.map_or(0.0, |f| (self.t - f) / HOUR);
        let dest_new_ent = dest_first.is_none_or(|f| self.t - f < HOUR);
        let dest_new_global = self.st.dests_global.get(&pk).is_none_or(|f| self.t - f < HOUR);
        let name = self.names.get(&ip);
        let named = name.is_some();
        let ent_age_h = (self.t - e.first_t) / HOUR;
        let p95 = e.p95(|h| h.1 as f64);
        let ndest_p95 = e.p95(|h| h.2 as f64);
        let (eo60, end60) = ent_out60.get(&ei).copied().unwrap_or((0, 0));
        let hod = ((self.t / HOUR) as i64).rem_euclid(24) as usize;
        let days = (e.hours.len() as f64 / 24.0).max(1.0);
        let hour_act = if e.hod.len() == 24 { (e.hod[hod] as f64 / days).min(1.0) } else { 0.0 };
        // beacon statistics over connection starts
        let starts: Vec<f64> = p.starts.iter().copied().filter(|s| self.t - s < 6.0 * HOUR).collect();
        let (bn, bcv, bper) = beacon_stats(&starts);
        let inbound = p.inbound > p.outbound;
        let x: Vec<f32> = vec![
            log2p(o10 as f64), log2p(i10 as f64), log2p(o60 as f64), log2p(i60 as f64),
            (log2p(o10 as f64) - log2p(i10 as f64)), (log2p(o60 as f64) - log2p(i60 as f64)),
            c10 as f32, log2p(c60 as f64), act10 as f32, act60 as f32,
            if o60 > 0 { udp60 as f32 / o60 as f32 } else { 0.0 },
            (cls == DestClass::Public) as u8 as f32, (cls == DestClass::Private) as u8 as f32, (cls == DestClass::Overlay) as u8 as f32,
            web as u8 as f32, dnsp as u8 as f32, ssh as u8 as f32, mail as u8 as f32, odd as u8 as f32, high as u8 as f32,
            (!e.ports.contains(&port) || e.ports.len() <= 1) as u8 as f32, inbound as u8 as f32,
            log2p(dest_age_h), dest_new_ent as u8 as f32, dest_new_global as u8 as f32,
            named as u8 as f32, self.caps.0 as u8 as f32, log2p(ent_age_h), e.server as u8 as f32, e.outbound_frac(),
            p95.map_or(-1.0, log2p), p95.map_or(0.0, |b| log2p(o60 as f64) - log2p(b)),
            if eo60 > 0 { o60 as f32 / eo60 as f32 } else { 0.0 }, log2p(end60 as f64), ndest_p95.map_or(-1.0, log2p),
            log2p(self.history_hours()), hour_act as f32, bn as f32, bcv as f32, log2p(bper),
            log2p(if c60 > 0 { o60 as f64 / c60 as f64 } else { o60 as f64 }), p.long_lived as u8 as f32,
            e.flag as f32, e.static_risk, log2p(p.total_out as f64),
            (log2p(p.total_out as f64) - log2p(p.total_in as f64)), log2p((self.t - p.first_t) / HOUR),
            e.unnamed_frac(), e.newdest_p95().map_or(-1.0, log2p), log2p(e.max_pair_out as f64),
            log2p(o60 as f64) - log2p(e.max_pair_out as f64),
        ];
        debug_assert_eq!(x.len(), FLOW_FEATURES.len());

        // ---- rules (evidence)
        let mut fs = vec![];
        let dest_txt = match name {
            Some(n) => format!("{ip} ({n})"),
            None => ip.to_string(),
        };
        let mature = !learning && e.hours.len() >= 24;
        let ratio60 = (o60 as f64 + 1.0) / (i60 as f64 + 1.0);
        let external = cls == DestClass::Public;
        // Entities that normally talk to unresolved, ever-new peers (p2p routers, torrent
        // clients) make "new destination" and "no DNS name" meaningless.
        let p2pish = e.unnamed_frac() >= 0.5 || e.newdest_p95().is_some_and(|n| n >= 20.0);
        let beyond_history = e.max_pair_out == 0 || o60 as f64 >= 3.0 * e.max_pair_out as f64;
        if external && !inbound && o60 >= 50_000_000 && ratio60 >= 4.0 && (dest_new_ent && !learning || !named && self.caps.0) {
            let s = if p2pish && !beyond_history { 1 } else if o60 >= 500_000_000 { 3 } else { 2 };
            fs.push(Finding { rule: "large_upload_new_dest", strength: s,
                text: format!("sent {} (received {}) in the last hour to a {} destination", human(o60 as f64), human(i60 as f64),
                    if dest_new_ent { "new" } else { "never-resolved" }) });
        }
        if external && inbound && o60 >= 200_000_000 && ratio60 >= 4.0 && dest_new_ent && !learning && beyond_history {
            fs.push(Finding { rule: "large_upload_new_dest", strength: if e.max_pair_out > 0 { 2 } else { 1 },
                text: format!("served {} in the last hour to a new client {} (largest per-client hour before: {})", human(o60 as f64),
                    ip, human(e.max_pair_out as f64)) });
        }
        if let (true, Some(b), true) = (mature, p95, external) {
            if eo60 >= 20_000_000 && eo60 as f64 >= 10.0 * b.max(1e6) && o60 * 2 >= eo60 {
                fs.push(Finding { rule: "upload_above_baseline", strength: 2,
                    text: format!("{} sent {} in the last hour; its usual peak hour is {}", e.name, human(eo60 as f64), human(b)) });
            }
        }
        if external && self.caps.0 && !named && o60 >= 5_000_000 && ratio60 >= 4.0 && !inbound && !p2pish && !learning {
            fs.push(Finding { rule: "direct_ip_upload", strength: if odd || high { 2 } else { 1 },
                text: format!("{} uploaded to an address no DNS lookup returned (port {port})", human(o60 as f64)) });
        }
        if bn >= 10 && bcv < 0.2 && bper >= 5.0 && cls != DestClass::Local {
            // Pollers (update checks, monitoring) beacon too: a named host that is long known,
            // or seen while still learning, is weak evidence; a bare IP or new host is not.
            // Legitimate pollers beacon too. Strong evidence only for a bare IP that no DNS
            // lookup returned (visible DNS), and not for hosts learned as normal.
            let learned = dest_first.is_some_and(|f| f <= self.st.start_t + self.cfg.learn_hours * HOUR);
            let bare = self.caps.0 && !named && external;
            let strong = bare && !learned && dest_age_h < 24.0 && !p2pish;
            fs.push(Finding { rule: "beaconing", strength: if strong { 2 } else { 1 },
                text: format!("{bn} connections every {:.0}s (jitter {:.0}%){}", bper, bcv * 100.0,
                    if bare { " to an address no DNS lookup returned" } else { "" }) });
        }
        // Weak evidence: lets the model speak (it can't alert on its own unless very sure).
        if external && !inbound && o60 >= 2_000_000 && ratio60 >= 8.0 && (dest_new_ent || !named && self.caps.0)
            && !fs.iter().any(|f| f.rule == "large_upload_new_dest") {
            fs.push(Finding { rule: "upload_heavy_new_dest", strength: 1,
                text: format!("upload-heavy: {} out vs {} in over the last hour to a new destination", human(o60 as f64), human(i60 as f64)) });
        }
        if external && inbound && o60 >= 50_000_000 && ratio60 >= 8.0 && dest_new_ent && !fs.iter().any(|f| f.rule == "large_upload_new_dest") {
            fs.push(Finding { rule: "inbound_pull_new_client", strength: 1,
                text: format!("a new client pulled {} in the last hour", human(o60 as f64)) });
        }
        let age_h = (self.t - p.first_t) / HOUR;
        if external && !learning && age_h <= 12.0 && dest_age_h <= 12.0 && p.total_out >= 300_000
            && p.total_out as f64 >= 10.0 * (p.total_in as f64).max(1.0) && p.outbound >= 5 {
            fs.push(Finding { rule: "slow_drip", strength: 1,
                text: format!("{} out vs {} in over {} connections in {:.1}h to a new destination", human(p.total_out as f64),
                    human(p.total_in as f64), p.outbound, age_h) });
        }
        if e.server && !inbound && external && mature && e.outbound_frac() == 0.0 && c10 > 0 {
            fs.push(Finding { rule: "server_new_outbound", strength: 2,
                text: format!("{} is a server that had never opened outbound connections before", e.name) });
        }
        // minute buckets: the current one has just started, so "last minute" = the previous bucket
        // A single TCP upload is congestion-controlled and not a flood; floods are
        // connection storms or one-way UDP volume.
        let (u1, i1, c1) = (sum(2, &|b| b.4), sum(2, &|b| b.2), sum(2, &|b| b.3 as u64));
        if external && !inbound && ((u1 >= 30_000_000 && i1 * 50 < u1) || c1 >= 300) {
            fs.push(Finding { rule: "flood", strength: 2, text: if c1 >= 300 { format!("{c1} connections to one host in the last minute (DoS?)") }
                else { format!("{} of UDP to one host in the last minute, almost nothing back (DoS?)", human(u1 as f64)) } });
        }
        if odd && !inbound && external && c60 > 0 {
            fs.push(Finding { rule: "odd_port", strength: 1, text: format!("outbound to port {port}, common for shells/RATs") });
        }
        if e.flag >= 2 && external {
            // The process alert already fired; here it only supports other evidence.
            fs.push(Finding { rule: "process_flag", strength: 1, text: e.flag_detail.clone() });
        }
        if e.static_risk >= 0.75 && external {
            fs.push(Finding { rule: "static_scan", strength: 2, text: format!("binary scores high statically: {}", e.static_detail) });
        }
        (x, fs, dest_txt)
    }

    fn dns_features(&self, k: &(String, String)) -> (Vec<f32>, Vec<Finding>) {
        let a = &self.dns[k];
        let base = k.1.as_str();
        let n = a.q.len().max(1) as f64;
        let uniq: HashSet<&str> = a.q.iter().map(|q| q.1.as_str()).collect();
        let subs: Vec<&str> = a.q.iter().map(|q| q.1.as_str()).filter(|s| !s.is_empty()).collect();
        let ns = subs.len().max(1) as f64;
        let sub_len_mean = subs.iter().map(|s| s.len()).sum::<usize>() as f64 / ns;
        let sub_len_max = subs.iter().map(|s| s.len()).max().unwrap_or(0);
        let label_max = subs.iter().flat_map(|s| s.split('.')).map(|l| l.len()).max().unwrap_or(0);
        let ent_mean = subs.iter().map(|s| entropy(&s.replace('.', "")) as f64).sum::<f64>() / ns;
        let chars: usize = subs.iter().map(|s| s.len()).sum::<usize>().max(1);
        let digits = subs.iter().flat_map(|s| s.bytes()).filter(|b| b.is_ascii_digit()).count();
        let hexlike = subs.iter().filter(|s| s.len() >= 8 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.')).count();
        let depth = subs.iter().map(|s| s.matches('.').count() + 1).sum::<usize>() as f64 / ns;
        let frac = |f: &dyn Fn(u16) -> bool| a.q.iter().filter(|q| f(q.2)).count() as f32 / n as f32;
        let qbytes: usize = a.q.iter().map(|q| q.1.len()).sum();
        let mut per_min: BTreeMap<i64, u32> = BTreeMap::new();
        for q in &a.q {
            *per_min.entry((q.0 / MIN) as i64).or_default() += 1;
        }
        let peak = per_min.values().max().copied().unwrap_or(0);
        let first = self.st.domains_global.get(base).copied().unwrap_or(self.t);
        let x: Vec<f32> = vec![
            log2p(n), log2p(uniq.len() as f64), (uniq.len() as f64 / n) as f32, sub_len_mean as f32, sub_len_max as f32,
            label_max as f32, ent_mean as f32, digits as f32 / chars as f32, hexlike as f32 / ns as f32, depth as f32,
            frac(&|t| t == 16), frac(&|t| t == 10), frac(&|t| t == 5), frac(&|t| t == 15), frac(&|t| t == 12),
            frac(&|t| t == 1 || t == 28), frac(&|t| !matches!(t, 1 | 28 | 5 | 10 | 12 | 15 | 16 | 65)),
            (a.nx.len() as f64 / n).min(1.0) as f32, log2p(qbytes as f64), ((self.t - first) < HOUR) as u8 as f32,
            log2p((self.t - first) / HOUR), log2p(self.history_hours()), log2p(peak as f64), base.len() as f32,
            entropy(base.split('.').next().unwrap_or("")), (k.0 != "?") as u8 as f32,
        ];
        debug_assert_eq!(x.len(), DNS_FEATURES.len());
        let mut fs = vec![];
        let ptr = base.ends_with(".arpa");
        if !ptr && uniq.len() >= 20 && sub_len_mean >= 20.0 && ent_mean >= 3.3 {
            fs.push(Finding { rule: "dns_tunnel", strength: 3, text: format!("{} distinct long random subdomains of {base} in 10 min (avg {:.0} chars, entropy {:.1})",
                uniq.len(), sub_len_mean, ent_mean) });
        } else if !ptr && qbytes >= 4000 && uniq.len() as f64 >= 0.8 * n && sub_len_mean >= 12.0 {
            fs.push(Finding { rule: "dns_exfil_volume", strength: 2, text: format!("{} encoded in {} unique query names under {base}", human(qbytes as f64), uniq.len()) });
        }
        let txtnull = frac(&|t| t == 16 || t == 10);
        if !ptr && n >= 20.0 && txtnull >= 0.5 && uniq.len() >= 10 {
            fs.push(Finding { rule: "dns_txt_channel", strength: 2, text: format!("{:.0}% of {} queries to {base} are TXT/NULL with changing names", txtnull * 100.0, n) });
        }
        (x, fs)
    }

    fn dga_rules(&mut self) {
        let mut hits = vec![];
        for (src, d) in &self.dga {
            let bases: HashSet<&str> = d.iter().map(|x| x.1.as_str()).collect();
            if bases.len() >= 25 {
                let ent: f32 = bases.iter().map(|b| entropy(b.split('.').next().unwrap_or(""))).sum::<f32>() / bases.len() as f32;
                if ent >= 3.0 {
                    let mut ex: Vec<&str> = bases.iter().copied().collect();
                    ex.sort();
                    ex.truncate(4);
                    hits.push((src.clone(), bases.len(), ent, ex.join(", ")));
                }
            }
        }
        for (src, n, ent, ex) in hits {
            let fs = vec![Finding { rule: "dga_nxdomain", strength: 2, text: format!("{n} different random-looking domains failed to resolve in 10 min (entropy {ent:.1}), e.g. {ex}") }];
            self.raise("dga", src.clone(), 0, String::new(), 0.0, fs, format!("possible domain-generation algorithm (from {src})"));
        }
    }

    fn icmp_rules(&mut self) {
        let mut hits = vec![];
        for (ip, a) in &self.icmp {
            let n = a.p.len();
            let bytes: u64 = a.p.iter().map(|x| x.1 as u64).sum();
            if n >= 30 && bytes as f64 / n as f64 >= 128.0 && dest_class(ip) != DestClass::Local {
                hits.push((*ip, n, bytes));
            }
        }
        for (ip, n, bytes) in hits {
            let fs = vec![Finding { rule: "icmp_tunnel", strength: if bytes >= 1_000_000 { 3 } else { 2 },
                text: format!("{n} echo requests carrying {} (avg {} per packet; ping sends 56)", human(bytes as f64), bytes / n as u64) }];
            self.raise("icmp", "unattributed".into(), 0, ip.to_string(), 0.0, fs, format!("possible ICMP tunnel to {ip}"));
        }
    }

    fn scan_rules(&mut self, now_m: i64, learning: bool) {
        let mut hits = vec![];
        for (src, a) in &self.syn {
            if a.minute != now_m - 1 {
                continue; // only complete minutes
            }
            let base = self.ent_idx.get(src).map_or(0, |&i| self.st.ents[i].syn_max_min);
            let hosts = a.hosts.len() as u32;
            let maxports = a.ports.values().map(|p| p.len()).max().unwrap_or(0) as u32;
            if hosts >= 64 && (learning || hosts >= 4 * base.max(16)) {
                hits.push((src.clone(), "scan_hosts", format!("SYNs to {hosts} different hosts in one minute (usual max {base})")));
            }
            if let Some((ip, n)) = a.per_host.iter().max_by_key(|x| *x.1) {
                if *n >= 1000 {
                    hits.push((src.clone(), "syn_flood", format!("{n} SYNs to {ip} in one minute")));
                }
            }
            if maxports >= 64 {
                hits.push((src.clone(), "scan_ports", format!("SYNs to {maxports} different ports on one host in one minute")));
            }
            if let Some(&i) = self.ent_idx.get(src) {
                let e = &mut self.st.ents[i];
                e.syn_max_min = e.syn_max_min.max(hosts.min(base.max(1) * 2 + 8)); // grow slowly
            }
        }
        for (src, rule, text) in hits {
            let fs = vec![Finding { rule, strength: 2, text }];
            if rule == "syn_flood" {
                self.raise("flood", src.clone(), 0, String::new(), 0.0, fs, format!("possible SYN flood / DoS from {src}"));
            } else {
                self.raise("scan", src.clone(), 0, String::new(), 0.0, fs, format!("network scanning from {src}"));
            }
        }
    }

    /// Advance time with no events (live mode: called every second).
    pub fn tick(&mut self, t: f64) {
        if self.session_t0.is_nan() {
            return;
        }
        while t >= self.next_eval {
            self.t = self.next_eval;
            self.evaluate();
            self.next_eval += MIN;
        }
        self.t = self.t.max(t);
    }

    pub fn drain_alerts(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.alerts)
    }
}

/// (count, coefficient of variation, mean period) of gaps between connection
/// starts, ignoring the largest 10% of gaps (missed / skipped beacons).
fn beacon_stats(starts: &[f64]) -> (usize, f64, f64) {
    if starts.len() < 4 {
        return (starts.len(), 1.0, 0.0);
    }
    let mut gaps: Vec<f64> = starts.windows(2).map(|w| w[1] - w[0]).filter(|g| *g > 0.5).collect();
    if gaps.len() < 3 {
        return (starts.len(), 1.0, 0.0);
    }
    gaps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let keep = ((gaps.len() as f64) * 0.9).ceil() as usize;
    let g = &gaps[..keep.max(3).min(gaps.len())];
    let mean = g.iter().sum::<f64>() / g.len() as f64;
    let sd = (g.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / g.len() as f64).sqrt();
    (starts.len(), sd / mean.max(1e-9), mean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tcp(t: f64, id: u64, ent: &str, ip: [u8; 4], port: u16, sent: u64, recv: u64, closed: bool) -> Event {
        Event::Tcp { t, id, ent: ent.into(), pid: 1, lport: 40000 + id as u16, rip: IpAddr::V4(Ipv4Addr::from(ip)), rport: port,
            sent, recv, inbound: false, closed, pre: false }
    }

    #[test]
    fn bulk_upload_to_new_host_alerts_after_learning() {
        let mut e = Engine::new(Config { learn_hours: 1.0, ..Default::default() }, State::default(), None);
        e.feed(&Event::Caps { t: 0.0, dns: true, syn: true, udp: true });
        // two hours of small benign traffic to a known, named host
        let mut id = 1;
        for m in 0..120 {
            let t = m as f64 * 60.0 + 1.0;
            e.feed(&Event::Dns { t, ent: None, name: "api.example.com".into(), qtype: 1, resp: true, rcode: 0,
                answers: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))] });
            e.feed(&tcp(t + 1.0, id, "/usr/bin/app", [93, 184, 216, 34], 443, 2_000, 30_000, true));
            id += 1;
        }
        let pre = e.drain_alerts();
        assert!(pre.is_empty(), "{pre:?}");
        // then 300 MB to a never-seen, never-resolved address
        for s in 0..30 {
            let t = 7300.0 + s as f64 * 10.0;
            e.feed(&tcp(t, 999, "/usr/bin/app", [203, 0, 113, 9], 8443, (s + 1) * 10_000_000, 50_000, false));
        }
        e.tick(7300.0 + 400.0);
        let a = e.drain_alerts();
        assert!(a.iter().any(|a| a.kind == "exfil" && a.dest.starts_with("203.0.113.9")), "{a:?}");
    }

    #[test]
    fn dns_tunnel_rule() {
        let mut e = Engine::new(Config::default(), State::default(), None);
        for i in 0..60 {
            let sub = format!("{:032x}.{:08x}", (i as u128).wrapping_mul(0x9e3779b97f4a7c15f39cc0605cedc835), i * 7919);
            e.feed(&Event::Dns { t: 10.0 + i as f64, ent: None, name: format!("{sub}.t.evil-example.net"), qtype: 16, resp: false, rcode: 0, answers: vec![] });
        }
        e.tick(200.0);
        let a = e.drain_alerts();
        assert!(a.iter().any(|a| a.kind == "dns" && a.dest == "evil-example.net"), "{a:?}");
    }

    #[test]
    fn beacon_stats_periodic() {
        let s: Vec<f64> = (0..12).map(|i| i as f64 * 30.0 + if i % 2 == 0 { 0.5 } else { -0.5 }).collect();
        let (n, cv, per) = beacon_stats(&s);
        assert_eq!(n, 12);
        assert!(cv < 0.1 && (per - 30.0).abs() < 2.0);
    }
}
