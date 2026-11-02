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
    Dns { src: IpAddr, sport: u16, msg: DnsMsg },
    Udp { dst: IpAddr, sport: u16, dport: u16, len: u32 },
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
            if let Some(p) = parse(&self.buf[..n as usize]) {
                let keep = match &p {
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
                Some(Pkt::Dns { src, sport, msg })
            } else {
                Some(Pkt::Udp { dst, sport, dport, len: total.saturating_sub(l4) as u32 })
            }
        }
        1 | 58 => Some(Pkt::Icmp { dst, len: total.saturating_sub(l4 + 8) as u32 }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn filter_assembles_and_ends_with_returns() {
        let f = super::filter();
        assert!(f.len() < 64);
        assert_eq!(f.last().unwrap().code, super::RET);
        assert_eq!(f.last().unwrap().k, 0);
    }
}
