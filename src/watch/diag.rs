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
            if parse_msgs(&self.buf[..n as usize], out) {
                return Ok(());
            }
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
            parse_msgs(&self.buf[..n as usize], out);
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

/// Parses a buffer of netlink messages; returns true at NLMSG_DONE / error.
fn parse_msgs(mut b: &[u8], out: &mut Vec<Entry>) -> bool {
    while b.len() >= 16 {
        let len = u32at(b, 0) as usize;
        let ty = u16::from_ne_bytes([b[4], b[5]]);
        if len < 16 || len > b.len() {
            return true;
        }
        if ty == NLMSG_DONE || ty == NLMSG_ERROR {
            return true;
        }
        if ty == SOCK_DIAG_BY_FAMILY {
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
