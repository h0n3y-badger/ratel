//! Lightweight packet capture: one AF_PACKET socket with a classic BPF filter
//! that runs in the kernel, so only a trickle reaches userspace:
//!   * DNS (UDP port 53, either direction), up to 1500 bytes: query names and answers
//!   * TCP SYN without ACK, headers only: every connection attempt, exactly timed
//!   * ICMP / ICMPv6 echo requests, headers only: tunnels
//!   * 1 in 16 other UDP packets, headers only: UDP volume estimates (QUIC, custom)
//! Needs CAP_NET_RAW (root). Sees all interfaces of the host's network
//! namespace, which includes traffic forwarded from containers.

use super::dns::{self, DnsMsg};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const UDP_SAMPLE: u32 = 16;

pub enum Pkt {
    Syn { src: IpAddr, dst: IpAddr, sport: u16, dport: u16 },
    Dns { src: IpAddr, dst: IpAddr, sport: u16, dport: u16, msg: DnsMsg },
    /// `inbound`: arrived from `src`; otherwise sent to `dst`.
    Udp { src: IpAddr, dst: IpAddr, sport: u16, dport: u16, len: u32, inbound: bool },
    Icmp { dst: IpAddr, len: u32 },
}

// ---- a tiny classic-BPF assembler with labels
#[derive(Clone, Copy)]
enum J {
    Next,
    L(&'static str),
}
struct Ins {
    label: Option<&'static str>,
    code: u16,
    jt: J,
    jf: J,
    k: u32,
}
fn ins(code: u16, k: u32) -> Ins {
    Ins { label: None, code, jt: J::Next, jf: J::Next, k }
}
fn jmp(code: u16, k: u32, jt: J, jf: J) -> Ins {
    Ins { label: None, code, jt, jf, k }
}
fn at(label: &'static str, mut i: Ins) -> Ins {
    i.label = Some(label);
    i
}

const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LD_B_IND: u16 = 0x50;
const LDX_MSH: u16 = 0xb1;
const AND_K: u16 = 0x54;
const JEQ: u16 = 0x15;
const JSET: u16 = 0x45;
const RET: u16 = 0x06;
const AD_PROTOCOL: u32 = 0xffff_f000;
const AD_RANDOM: u32 = 0xffff_f000 + 56;

pub fn filter() -> Vec<libc::sock_filter> {
    use J::*;
    let p = vec![
        ins(LD_W_ABS, AD_PROTOCOL),
        jmp(JEQ, 0x0800, L("v4"), Next),
        jmp(JEQ, 0x86dd, L("v6"), L("drop")),
        // ---- IPv4
        at("v4", ins(LD_B_ABS, 9)),
        jmp(JEQ, 6, L("t4"), Next),
        jmp(JEQ, 17, L("u4"), Next),
        jmp(JEQ, 1, L("i4"), L("drop")),
        at("t4", ins(LD_H_ABS, 6)),
        jmp(JSET, 0x1fff, L("drop"), Next),
        ins(LDX_MSH, 0),
        ins(LD_B_IND, 13),
        ins(AND_K, 0x12),
        jmp(JEQ, 0x02, L("hdr"), L("drop")),
        at("u4", ins(LD_H_ABS, 6)),
        jmp(JSET, 0x1fff, L("drop"), Next),
        ins(LDX_MSH, 0),
        ins(LD_H_IND, 0),
        jmp(JEQ, 53, L("dns"), Next),
        ins(LD_H_IND, 2),
        jmp(JEQ, 53, L("dns"), L("samp")),
        at("i4", ins(LDX_MSH, 0)),
        ins(LD_B_IND, 0),
        jmp(JEQ, 8, L("hdr"), L("drop")),
        // ---- IPv6 (no extension headers)
        at("v6", ins(LD_B_ABS, 6)),
        jmp(JEQ, 6, L("t6"), Next),
        jmp(JEQ, 17, L("u6"), Next),
        jmp(JEQ, 58, L("i6"), L("drop")),
        at("t6", ins(LD_B_ABS, 53)),
        ins(AND_K, 0x12),
        jmp(JEQ, 0x02, L("hdr"), L("drop")),
        at("u6", ins(LD_H_ABS, 40)),
        jmp(JEQ, 53, L("dns"), Next),
        ins(LD_H_ABS, 42),
        jmp(JEQ, 53, L("dns"), L("samp")),
        at("i6", ins(LD_B_ABS, 40)),
        jmp(JEQ, 128, L("hdr"), L("drop")),
        // ---- sampling and returns
        at("samp", ins(LD_W_ABS, AD_RANDOM)),
        ins(AND_K, UDP_SAMPLE - 1),
        jmp(JEQ, 0, L("hdr"), L("drop")),
        at("dns", ins(RET, 1500)),
        at("hdr", ins(RET, 96)),
        at("drop", ins(RET, 0)),
    ];
    let pos = |l: &str| p.iter().position(|i| i.label == Some(l)).unwrap_or_else(|| panic!("bpf label {l}"));
    p.iter().enumerate().map(|(i, x)| {
        let rel = |j: J| -> u8 {
            match j {
                J::Next => 0,
                J::L(l) => {
                    let d = pos(l) as isize - i as isize - 1;
                    assert!((0..256).contains(&d), "bpf jump out of range");
                    d as u8
                }
            }
        };
        libc::sock_filter { code: x.code, jt: rel(x.jt), jf: rel(x.jf), k: x.k }
    }).collect()
}

pub struct Capture {
    fd: OwnedFd,
    lo: i32,
    buf: Vec<u8>,
}

impl Capture {
    pub fn new() -> io::Result<Capture> {
        // SAFETY: socket/setsockopt/fcntl on our own fd with correctly sized arguments.
        unsafe {
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, (libc::ETH_P_ALL as u16).to_be() as i32);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let mut f = filter();
            let prog = libc::sock_fprog { len: f.len() as u16, filter: f.as_mut_ptr() };
            if libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void, std::mem::size_of::<libc::sock_fprog>() as u32) < 0 {
                return Err(io::Error::last_os_error());
            }
            let sz: libc::c_int = 2 << 20;
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &sz as *const _ as *const libc::c_void, 4);
            let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
            let lo = libc::if_nametoindex(c"lo".as_ptr()) as i32;
            let mut c = Capture { fd, lo, buf: vec![0; 2048] };
            // Packets queued before the filter was attached are unfiltered: discard them.
            let mut junk = vec![];
            c.read(&mut junk, true);
            Ok(c)
        }
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Reads everything queued. `loopback`: also look at the lo interface (testing).
    pub fn read(&mut self, out: &mut Vec<Pkt>, loopback: bool) {
        for _ in 0..10_000 {
            // SAFETY: recvfrom into our buffer; sockaddr_ll is plain data.
            let (n, sll) = unsafe {
                let mut sll: libc::sockaddr_ll = std::mem::zeroed();
                let mut sl = std::mem::size_of::<libc::sockaddr_ll>() as u32;
                let n = libc::recvfrom(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0,
                    &mut sll as *mut _ as *mut libc::sockaddr, &mut sl);
                (n, sll)
            };
            if n <= 0 {
                return;
            }
            let outgoing = sll.sll_pkttype == libc::PACKET_OUTGOING as u8;
            let on_lo = sll.sll_ifindex == self.lo;
            if on_lo && (!loopback || !outgoing) {
                continue; // loopback packets appear twice; and are ignored outside tests
            }
            if let Some(mut p) = parse(&self.buf[..n as usize]) {
                let host = sll.sll_pkttype == libc::PACKET_HOST as u8;
                if let Pkt::Udp { inbound, .. } = &mut p {
                    *inbound = !outgoing && host && !on_lo;
                }
                let keep = match &p {
                    // inbound UDP samples balance the outbound ones (VPN / QUIC aren't floods)
                    Pkt::Udp { inbound: true, .. } => true,
                    // DNS answers arrive; everything else we look at leaves this host.
                    Pkt::Dns { msg, .. } if msg.resp => on_lo || sll.sll_pkttype == libc::PACKET_HOST as u8,
                    _ => outgoing,
                };
                if keep {
                    out.push(p);
                }
            }
        }
    }
}

fn parse(b: &[u8]) -> Option<Pkt> {
    let v = b.first()? >> 4;
    let (src, dst, proto, l4, total): (IpAddr, IpAddr, u8, usize, usize) = match v {
        4 => {
            if b.len() < 20 {
                return None;
            }
            let ihl = (b[0] & 0xf) as usize * 4;
            if ihl < 20 {
                return None; // IHL < 5: ports would be read from inside the IP header
            }
            (IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])), IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
                b[9], ihl, u16::from_be_bytes([b[2], b[3]]) as usize)
        }
        6 => {
            if b.len() < 40 {
                return None;
            }
            let s: [u8; 16] = b[8..24].try_into().ok()?;
            let d: [u8; 16] = b[24..40].try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)), b[6], 40, 40 + u16::from_be_bytes([b[4], b[5]]) as usize)
        }
        _ => return None,
    };
    let h = b.get(l4..)?;
    match proto {
        6 => {
            let (sport, dport) = (u16::from_be_bytes([*h.first()?, *h.get(1)?]), u16::from_be_bytes([*h.get(2)?, *h.get(3)?]));
            Some(Pkt::Syn { src, dst, sport, dport })
        }
        17 => {
            let sport = u16::from_be_bytes([*h.first()?, *h.get(1)?]);
            let dport = u16::from_be_bytes([*h.get(2)?, *h.get(3)?]);
            if sport == 53 || dport == 53 {
                let msg = dns::parse(h.get(8..)?)?;
                Some(Pkt::Dns { src, dst, sport, dport, msg })
            } else {
                Some(Pkt::Udp { src, dst, sport, dport, len: total.saturating_sub(l4) as u32, inbound: false })
            }
        }
        1 | 58 => Some(Pkt::Icmp { dst, len: total.saturating_sub(l4 + 8) as u32 }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::dns::fuzz::{mutate, Rng};
    use super::*;
    use std::time::Instant;

    #[test]
    fn filter_assembles_and_ends_with_returns() {
        let f = super::filter();
        assert!(f.len() < 64);
        assert_eq!(f.last().unwrap().code, super::RET);
        assert_eq!(f.last().unwrap().k, 0);
    }

    fn dns_query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[1, b'a', 2, b'b', b'c', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        q
    }

    fn dns_answer() -> Vec<u8> {
        let mut r = dns_query();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        r
    }

    fn v4(proto: u8, l4: &[u8], opts: usize) -> Vec<u8> {
        let ihl = 20 + opts;
        let mut p = vec![0x40 | (ihl / 4) as u8, 0];
        p.extend_from_slice(&((ihl + l4.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1]);
        p.extend(std::iter::repeat(1).take(opts)); // NOP options
        p.extend_from_slice(l4);
        p
    }

    fn v6(proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(l4.len() as u16).to_be_bytes());
        p.extend_from_slice(&[proto, 64]);
        p.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(l4);
        p
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = sport.to_be_bytes().to_vec();
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    fn seeds() -> Vec<Vec<u8>> {
        let syn = [0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0];
        let icmp = [8, 0, 0, 0, 0, 1, 0, 1, 1, 2, 3, 4];
        let icmp6 = [128, 0, 0, 0, 0, 1, 0, 1];
        vec![
            v4(6, &syn, 0),
            v4(6, &syn, 12),
            v4(17, &udp(40000, 53, &dns_query()), 0),
            v4(17, &udp(53, 40000, &dns_answer()), 4),
            v4(17, &udp(40000, 443, &[0xc3; 40]), 0),
            v4(1, &icmp, 0),
            v6(6, &syn),
            v6(17, &udp(53, 40000, &dns_answer())),
            v6(17, &udp(40000, 443, &[0x40; 24])),
            v6(58, &icmp6),
        ]
    }

    /// Header-aware mutations: version / IHL nibble, total & payload length,
    /// protocol, ports (towards and away from 53).
    fn ip_specific(r: &mut Rng, p: &mut Vec<u8>) {
        if p.is_empty() {
            return;
        }
        match r.below(5) {
            0 => p[0] = ([0x40, 0x60, 0x00, 0xF0][r.below(4)] & 0xF0) | (r.next() as u8 & 0x0F),
            1 if p.len() >= 6 => {
                let at = if p[0] >> 4 == 6 { 4 } else { 2 };
                let v = r.interesting(p.len()) as u16;
                p[at..at + 2].copy_from_slice(&v.to_be_bytes());
            }
            2 if p.len() >= 10 => {
                let at = if p[0] >> 4 == 6 { 6 } else { 9 };
                p[at] = [1, 6, 17, 58, 0, 255][r.below(6)];
            }
            3 if p.len() >= 4 => {
                let l4 = if p[0] >> 4 == 6 { 40 } else { (p[0] & 0xF) as usize * 4 };
                if p.len() >= l4 + 4 {
                    let at = l4 + 2 * r.below(2);
                    let v: u16 = if r.chance(2) { 53 } else { r.next() as u16 };
                    p[at..at + 2].copy_from_slice(&v.to_be_bytes());
                }
            }
            _ => p.truncate(r.below(p.len() + 1)),
        }
    }

    fn check(b: &[u8], p: &Pkt) {
        if b[0] >> 4 == 4 {
            assert!((b[0] & 0xF) >= 5, "IPv4 with IHL < 5 accepted");
        }
        match p {
            Pkt::Dns { msg, .. } => {
                assert!(msg.name.len() <= 300);
                assert!(msg.answers.len() <= 32);
            }
            Pkt::Udp { len, .. } | Pkt::Icmp { len, .. } => assert!(*len <= 65535 + 40),
            Pkt::Syn { .. } => {}
        }
    }

    #[test]
    fn fuzz_capture_parse() {
        let t = Instant::now();
        let mut r = Rng(0x0123_4567_89AB_CDEF);
        let seeds = seeds();
        for s in &seeds {
            check(s, &parse(s).expect("seed parses"));
        }
        let (mut ok, mut iters) = (0u64, 0u64);
        // fully random buffers, most with a v4 or v6 version nibble
        for _ in 0..500_000 {
            let mut b = r.bytes(200);
            if !b.is_empty() && !r.chance(4) {
                b[0] = if r.chance(2) { 0x40 } else { 0x60 } | (b[0] & 0x0F);
            }
            if let Some(p) = parse(&b) {
                check(&b, &p);
                ok += 1;
            }
            iters += 1;
        }
        // stacked mutations of valid packets
        for _ in 0..300_000 {
            let mut b = seeds[r.below(seeds.len())].clone();
            for _ in 0..1 + r.below(4) {
                if r.chance(2) {
                    mutate(&mut r, &mut b, true);
                } else {
                    ip_specific(&mut r, &mut b);
                }
                if let Some(p) = parse(&b) {
                    check(&b, &p);
                    ok += 1;
                }
                iters += 1;
            }
        }
        eprintln!("fuzz_capture_parse: {iters} iterations, {ok} parsed, {:?}", t.elapsed());
        assert!(ok > 10_000);
    }
}
