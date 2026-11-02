//! NETLINK_SOCK_DIAG: the same kernel interface `ss -ti` uses. Gives every
//! TCP socket with its byte counters (tcp_info: bytes_acked / bytes_received),
//! UDP sockets (for port -> process attribution), and, subscribed to the
//! destroy groups, the final counters of every TCP socket the moment it closes,
//! so even sub-second connections are accounted for.
//!
//! Each socket lives in one network namespace; `in_netns` creates sockets inside
//! another namespace (a container's) from a short-lived thread.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const INET_DIAG_INFO: u16 = 2;
pub const TCP_LISTEN: u8 = 10;

#[derive(Clone, Debug)]
pub struct Entry {
    pub state: u8,
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    pub uid: u32,
    pub inode: u64,
    pub cookie: u64,
    pub sent: u64,
    pub recv: u64,
}

pub struct Diag {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

fn nl_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the fd is owned immediately.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl Diag {
    pub fn new() -> io::Result<Diag> {
        Ok(Diag { fd: nl_socket()?, seq: 1, buf: vec![0; 1 << 16] })
    }

    /// A socket subscribed to TCP (v4+v6) destroy notifications. Needs CAP_NET_ADMIN.
    pub fn destroy_listener() -> io::Result<Diag> {
        let fd = nl_socket()?;
        // SAFETY: sockaddr_nl is plain data; bind with the correct size.
        unsafe {
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            // SKNLGRP_INET_TCP_DESTROY = 1, SKNLGRP_INET6_TCP_DESTROY = 3  ->  bits 0 and 2
            sa.nl_groups = (1 << 0) | (1 << 2);
            if libc::bind(fd.as_raw_fd(), &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) < 0 {
                return Err(io::Error::last_os_error());
            }
            let sz: libc::c_int = 4 << 20;
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &sz as *const _ as *const libc::c_void, 4);
            let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        Ok(Diag { fd, seq: 1, buf: vec![0; 1 << 16] })
    }

    /// Dump all sockets of one family/protocol (TCP gets byte counters).
    pub fn dump(&mut self, family: u8, proto: u8, out: &mut Vec<Entry>) -> io::Result<()> {
        self.seq = self.seq.wrapping_add(1);
        let mut req = [0u8; 16 + 56];
        req[0..4].copy_from_slice(&((16 + 56) as u32).to_ne_bytes());
        req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        req[16] = family;
        req[17] = proto;
        req[18] = if proto == libc::IPPROTO_TCP as u8 { 1 << (INET_DIAG_INFO - 1) } else { 0 };
        req[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // all states
        // SAFETY: sending a fully initialised buffer on our own socket.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), req.as_ptr() as *const libc::c_void, req.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            // SAFETY: receiving into our own buffer of the given length.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if parse_msgs(&self.buf[..n as usize], out, Some(self.seq)) {
                return Ok(());
            }
        }
    }

    /// Exact lookup of one TCP socket by its 4-tuple (as seen from this host).
    pub fn lookup(&mut self, local: (IpAddr, u16), remote: (IpAddr, u16)) -> Option<Entry> {
        let family = match (local.0, remote.0) {
            (IpAddr::V4(_), IpAddr::V4(_)) => libc::AF_INET as u8,
            (IpAddr::V6(_), IpAddr::V6(_)) => libc::AF_INET6 as u8,
            _ => return None,
        };
        self.seq = self.seq.wrapping_add(1);
        let mut req = [0u8; 16 + 56];
        req[0..4].copy_from_slice(&((16 + 56) as u32).to_ne_bytes());
        req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        req[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        req[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        req[16] = family;
        req[17] = libc::IPPROTO_TCP as u8;
        req[18] = 1 << (INET_DIAG_INFO - 1);
        req[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        let id = &mut req[24..72];
        id[0..2].copy_from_slice(&local.1.to_be_bytes());
        id[2..4].copy_from_slice(&remote.1.to_be_bytes());
        let put = |b: &mut [u8], ip: IpAddr| match ip {
            IpAddr::V4(v) => b[..4].copy_from_slice(&v.octets()),
            IpAddr::V6(v) => b[..16].copy_from_slice(&v.octets()),
        };
        put(&mut id[4..20], local.0);
        put(&mut id[20..36], remote.0);
        id[40..48].copy_from_slice(&[0xff; 8]); // INET_DIAG_NOCOOKIE
        // SAFETY: as in dump().
        unsafe {
            if libc::send(self.fd.as_raw_fd(), req.as_ptr() as *const libc::c_void, req.len(), 0) < 0 {
                return None;
            }
            // replies to earlier requests (a dump cut short) are skipped by sequence number
            for _ in 0..8 {
                let n = libc::recv(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0);
                if n <= 0 {
                    return None;
                }
                let mut v = vec![];
                let done = parse_msgs(&self.buf[..n as usize], &mut v, Some(self.seq));
                if let Some(e) = v.pop() {
                    return Some(e);
                }
                if done {
                    return None;
                }
            }
            None
        }
    }

    /// Drain pending destroy notifications (non-blocking).
    pub fn drain(&mut self, out: &mut Vec<Entry>) {
        loop {
            // SAFETY: as above.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0) };
            if n <= 0 {
                return; // EAGAIN, or ENOBUFS after an overflow: events lost, keep going
            }
            parse_msgs(&self.buf[..n as usize], out, None);
        }
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

fn addr(family: u8, b: &[u8]) -> IpAddr {
    if family == libc::AF_INET as u8 {
        IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    } else {
        let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
        v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
    }
}

fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}

/// Parses a buffer of netlink messages; returns true at NLMSG_DONE / error. With `seq`,
/// messages answering other requests are ignored.
fn parse_msgs(mut b: &[u8], out: &mut Vec<Entry>, seq: Option<u32>) -> bool {
    while b.len() >= 16 {
        let len = u32at(b, 0) as usize;
        let ty = u16::from_ne_bytes([b[4], b[5]]);
        if len < 16 || len > b.len() {
            return true;
        }
        let mine = seq.is_none_or(|s| u32at(b, 8) == s);
        if mine && (ty == NLMSG_DONE || ty == NLMSG_ERROR) {
            return true;
        }
        if mine && ty == SOCK_DIAG_BY_FAMILY {
            let m = &b[16..len];
            if m.len() >= 72 {
                let family = m[0];
                let state = m[1];
                let sport = u16::from_be_bytes([m[4], m[5]]);
                let dport = u16::from_be_bytes([m[6], m[7]]);
                let src = addr(family, &m[8..24]);
                let dst = addr(family, &m[24..40]);
                let cookie = u32at(m, 44) as u64 | ((u32at(m, 48) as u64) << 32);
                let uid = u32at(m, 64);
                let inode = u32at(m, 68) as u64;
                let (mut sent, mut recv) = (0, 0);
                // attributes
                let mut a = &m[72..];
                while a.len() >= 4 {
                    let alen = u16::from_ne_bytes([a[0], a[1]]) as usize;
                    let aty = u16::from_ne_bytes([a[2], a[3]]) & 0x3fff;
                    if alen < 4 || alen > a.len() {
                        break;
                    }
                    if aty == INET_DIAG_INFO && alen >= 4 + 136 {
                        let ti = &a[4..alen];
                        sent = u64at(ti, 120); // tcpi_bytes_acked
                        recv = u64at(ti, 128); // tcpi_bytes_received
                    }
                    let step = (alen + 3) & !3;
                    if step >= a.len() {
                        break;
                    }
                    a = &a[step..];
                }
                out.push(Entry { state, local: (src, sport), remote: (dst, dport), uid, inode, cookie, sent, recv });
            }
        }
        let step = (len + 3) & !3;
        if step >= b.len() {
            break;
        }
        b = &b[step..];
    }
    false
}

/// Runs `f` on a thread that has joined the network namespace at `ns_path`
/// (e.g. /proc/<pid>/ns/net). Sockets created there stay in that namespace.
pub fn in_netns<T: Send + 'static>(ns_path: &str, f: impl FnOnce() -> io::Result<T> + Send + 'static) -> io::Result<T> {
    let file = std::fs::File::open(ns_path)?;
    std::thread::spawn(move || {
        // SAFETY: setns on this thread only (network namespace is per-thread).
        if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        f()
    }).join().map_err(|_| io::Error::other("netns thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::super::dns::fuzz::{mutate, Rng};
    use super::*;
    use std::time::Instant;

    /// One SOCK_DIAG_BY_FAMILY message (nlmsghdr + inet_diag_msg + rtattrs).
    fn diag_msg(family: u8, sport: u16, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = vec![0u8; 72];
        m[0] = family;
        m[1] = 1; // ESTABLISHED
        m[4..6].copy_from_slice(&sport.to_be_bytes());
        m[6..8].copy_from_slice(&443u16.to_be_bytes());
        if family == libc::AF_INET as u8 {
            m[8..12].copy_from_slice(&[10, 0, 0, 2]);
            m[24..28].copy_from_slice(&[1, 1, 1, 1]);
        } else {
            m[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            m[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 9, 9, 9, 9]);
        }
        m[44..48].copy_from_slice(&7u32.to_ne_bytes());
        m[64..68].copy_from_slice(&1000u32.to_ne_bytes());
        m[68..72].copy_from_slice(&12345u32.to_ne_bytes());
        for (ty, data) in attrs {
            let alen = 4 + data.len();
            m.extend_from_slice(&(alen as u16).to_ne_bytes());
            m.extend_from_slice(&ty.to_ne_bytes());
            m.extend_from_slice(data);
            m.resize((m.len() + 3) & !3, 0);
        }
        let mut h = ((16 + m.len()) as u32).to_ne_bytes().to_vec();
        h.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        h.extend_from_slice(&[0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        h.extend_from_slice(&m);
        h
    }

    fn tcp_info(acked: u64, received: u64) -> Vec<u8> {
        let mut ti = vec![0u8; 232];
        ti[120..128].copy_from_slice(&acked.to_ne_bytes());
        ti[128..136].copy_from_slice(&received.to_ne_bytes());
        ti
    }

    fn done() -> Vec<u8> {
        let mut d = 20u32.to_ne_bytes().to_vec();
        d.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        d.extend_from_slice(&[0; 14]);
        d
    }

    fn seeds() -> Vec<Vec<u8>> {
        let v4 = diag_msg(libc::AF_INET as u8, 50000, &[(1, vec![0; 20]), (INET_DIAG_INFO, tcp_info(100, 200))]);
        let v6 = diag_msg(libc::AF_INET6 as u8, 50001, &[(INET_DIAG_INFO, tcp_info(5, 6)), (6, vec![1, 2, 3])]);
        let udp = diag_msg(libc::AF_INET as u8, 5353, &[]);
        let mut multi = [v4.clone(), v6.clone(), udp.clone()].concat();
        multi.extend_from_slice(&done());
        vec![v4, v6, udp, multi]
    }

    /// Netlink-aware mutations: nlmsg_len, nlmsg_type, rta_len / rta_type
    /// of attributes, and the family byte.
    fn nl_specific(r: &mut Rng, b: &mut [u8]) {
        if b.len() < 16 {
            return;
        }
        // offsets of message starts (following nlmsg_len as the parser would)
        let mut starts = vec![];
        let mut o = 0;
        while o + 16 <= b.len() && starts.len() < 8 {
            starts.push(o);
            let l = u32::from_ne_bytes(b[o..o + 4].try_into().unwrap()) as usize;
            if l < 16 {
                break;
            }
            o += (l + 3) & !3;
        }
        let s = starts[r.below(starts.len())];
        match r.below(5) {
            0 => {
                let v = r.interesting(b.len() - s);
                b[s..s + 4].copy_from_slice(&v.to_ne_bytes());
            }
            1 => {
                let v = [NLMSG_DONE, NLMSG_ERROR, SOCK_DIAG_BY_FAMILY, 0, 0xffff][r.below(5)];
                b[s + 4..s + 6].copy_from_slice(&v.to_ne_bytes());
            }
            2 if b.len() > s + 16 => b[s + 16] = [libc::AF_INET as u8, libc::AF_INET6 as u8, 0, 0xff][r.below(4)],
            _ if b.len() >= s + 16 + 72 + 4 => {
                // an attribute header somewhere past inet_diag_msg
                let a = s + 16 + 72 + r.below(b.len() - (s + 16 + 72 + 3));
                let a = a & !3;
                if a + 4 <= b.len() && a >= s + 16 + 72 {
                    let len = [0u16, 3, 4, 139, 140, 141, 0xffff, r.next() as u16][r.below(8)];
                    b[a..a + 2].copy_from_slice(&len.to_ne_bytes());
                    if r.chance(2) {
                        b[a + 2..a + 4].copy_from_slice(&(INET_DIAG_INFO | 0x8000).to_ne_bytes());
                    }
                }
            }
            _ => {}
        }
    }

    fn run(b: &[u8]) -> usize {
        let mut out = vec![];
        parse_msgs(b, &mut out, None);
        // every entry needs a 16-byte header and a 72-byte inet_diag_msg
        assert!(out.len() <= b.len() / 88, "{} entries from {} bytes", out.len(), b.len());
        out.len()
    }

    #[test]
    fn parse_seed_messages() {
        let s = seeds();
        let mut out = vec![];
        assert!(parse_msgs(&s[3], &mut out, None));
        assert_eq!(out.len(), 3);
        assert_eq!((out[0].sent, out[0].recv, out[0].uid, out[0].inode, out[0].cookie), (100, 200, 1000, 12345, 7));
        assert_eq!(out[0].local, (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 50000));
        assert_eq!((out[1].sent, out[1].recv), (5, 6));
        assert_eq!(out[1].remote.0, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!((out[2].sent, out[2].recv), (0, 0));
    }

    #[test]
    fn fuzz_parse_msgs() {
        let t = Instant::now();
        let mut r = Rng(0xA5A5_5A5A_1234_8765);
        let seeds = seeds();
        let (mut entries, mut iters) = (0usize, 0u64);
        // fully random buffers; some get a sane nlmsg_len/type up front
        for _ in 0..400_000 {
            let mut b = r.bytes(1200);
            if b.len() >= 16 && r.chance(2) {
                let l = 16 + r.below(b.len() - 15);
                b[0..4].copy_from_slice(&(l as u32).to_ne_bytes());
                b[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            }
            entries += run(&b);
            iters += 1;
        }
        // stacked mutations of valid dumps
        for _ in 0..300_000 {
            let mut b = seeds[r.below(seeds.len())].clone();
            for _ in 0..1 + r.below(4) {
                if r.chance(2) {
                    mutate(&mut r, &mut b, false);
                } else {
                    nl_specific(&mut r, &mut b);
                }
                entries += run(&b);
                iters += 1;
            }
        }
        // many tiny messages back to back: the loop must keep advancing
        let mut many = vec![];
        for i in 0..4000u32 {
            let mut h = 16u32.to_ne_bytes().to_vec();
            h.extend_from_slice(&((i % 7) as u16 + 4).to_ne_bytes());
            h.extend_from_slice(&[0; 10]);
            many.extend_from_slice(&h);
        }
        assert!(!parse_msgs(&many, &mut vec![], None));
        eprintln!("fuzz_parse_msgs: {iters} iterations, {entries} entries, {:?}", t.elapsed());
        assert!(entries > 10_000);
    }
}
