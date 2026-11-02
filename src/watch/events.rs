//! Events: everything the engine knows about the network comes in as one of
//! these. The live collector produces them, `--record` writes them as JSON
//! lines, and `--replay` (and training) feeds them back through the exact same
//! engine. Time `t` is Unix seconds.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "e", rename_all = "snake_case")]
pub enum Event {
    /// Cumulative byte counters of one TCP socket (periodic dump), or its final
    /// counters (`closed`, from the kernel's socket-destroy notification).
    Tcp {
        t: f64,
        /// Kernel socket cookie: unique per socket.
        id: u64,
        ent: String,
        #[serde(default)]
        pid: u32,
        lport: u16,
        rip: IpAddr,
        rport: u16,
        sent: u64,
        recv: u64,
        /// Accepted on one of our listening ports (someone connected to us).
        #[serde(default)]
        inbound: bool,
        #[serde(default)]
        closed: bool,
        /// Existed before monitoring started: the counters are history, not new traffic.
        #[serde(default)]
        pre: bool,
    },
    /// Outbound TCP SYN seen on the wire: exact start of every connection attempt.
    Syn {
        t: f64,
        #[serde(default)]
        ent: Option<String>,
        sport: u16,
        rip: IpAddr,
        rport: u16,
    },
    /// DNS query (or response, with the addresses it resolved to).
    Dns {
        t: f64,
        #[serde(default)]
        ent: Option<String>,
        name: String,
        qtype: u16,
        #[serde(default)]
        resp: bool,
        #[serde(default)]
        rcode: u8,
        #[serde(default)]
        answers: Vec<IpAddr>,
    },
    /// Sampled UDP packet (outbound, or `inbound` from the remote); it stands for `scale` packets.
    Udp {
        t: f64,
        ent: String,
        rip: IpAddr,
        rport: u16,
        len: u32,
        scale: u32,
        #[serde(default)]
        inbound: bool,
    },
    /// Outbound ICMP echo request (payload length).
    Icmp { t: f64, rip: IpAddr, len: u32 },
    /// Process-level red flag (reverse shell, fileless executable, ...); sev 1..3.
    Proc { t: f64, ent: String, pid: u32, rule: String, sev: u8, detail: String },
    /// The entity has listening sockets: it's a server.
    Listen { t: f64, ent: String },
    /// Static scan of the entity's executable.
    Exe { t: f64, ent: String, risk: f32, detail: String },
    /// What the collector can see (DNS / SYN / UDP capture need root).
    Caps { t: f64, dns: bool, syn: bool, udp: bool },
    /// Training annotation, ignored by detection: activity of `ent` toward `dest`
    /// (an IP, or a DNS base domain) during [t0, t1] is `kind`.
    Label { ent: String, dest: String, t0: f64, t1: f64, kind: String },
}

impl Event {
    pub fn t(&self) -> f64 {
        match self {
            Event::Tcp { t, .. } | Event::Syn { t, .. } | Event::Dns { t, .. } | Event::Udp { t, .. }
            | Event::Icmp { t, .. } | Event::Proc { t, .. } | Event::Listen { t, .. } | Event::Exe { t, .. }
            | Event::Caps { t, .. } => *t,
            Event::Label { t0, .. } => *t0,
        }
    }
}
