//! DNS helpers: wire-format parsing (queries and A/AAAA answers), base-domain
//! extraction and the per-name statistics used to spot tunnelling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct DnsMsg {
    pub resp: bool,
    pub rcode: u8,
    pub name: String,
    pub qtype: u16,
    pub answers: Vec<IpAddr>,
}

/// Reads a (possibly compressed) name starting at `off`; returns it and the
/// offset just past it in the original position.
fn read_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(off + 1)? as usize;
            if end.is_none() {
                end = Some(off + 2);
            }
            jumps += 1;
            if jumps > 16 || ptr >= msg.len() {
                return None;
            }
            off = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(off + 1..off + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        for &b in label {
            let c = b.to_ascii_lowercase();
            out.push(if c.is_ascii_graphic() { c as char } else { '?' });
        }
        off += 1 + len;
        if out.len() > 300 {
            return None;
        }
    }
    Some((out, end.unwrap_or(off)))
}

pub fn parse(msg: &[u8]) -> Option<DnsMsg> {
    if msg.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if qd != 1 || flags & 0x7800 != 0 {
        return None; // only standard queries with one question
    }
    let (name, mut off) = read_name(msg, 12)?;
    let qtype = u16::from_be_bytes([*msg.get(off)?, *msg.get(off + 1)?]);
    off += 4;
    let resp = flags & 0x8000 != 0;
    let mut answers = vec![];
    if resp {
        for _ in 0..an.min(32) {
            let Some((_, o)) = read_name(msg, off) else { break };
            let Some(h) = msg.get(o..o + 10) else { break };
            let (ty, rdlen) = (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[8], h[9]]) as usize);
            let Some(rd) = msg.get(o + 10..o + 10 + rdlen) else { break };
            match (ty, rdlen) {
                (1, 4) => answers.push(IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]))),
                (28, 16) => answers.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rd).unwrap()))),
                _ => {}
            }
            off = o + 10 + rdlen;
        }
    }
    Some(DnsMsg { resp, rcode: (flags & 0xF) as u8, name, qtype, answers })
}

/// Second-level suffixes and dynamic-DNS / hosting zones where the registrable
/// domain is one label deeper (a tiny stand-in for the Public Suffix List).
const MULTI: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "co.nz",
    "com.br", "com.cn", "com.tr", "co.in", "co.za", "com.mx", "co.kr", "com.tw", "com.sg", "com.hk", "com.ar", "com.ua",
    "github.io", "gitlab.io", "herokuapp.com", "duckdns.org", "ddns.net", "no-ip.org", "no-ip.com", "hopto.org",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
    "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "appspot.com", "firebaseapp.com", "web.app",
    "s3.amazonaws.com", "compute.amazonaws.com", "trycloudflare.com", "onrender.com", "glitch.me", "repl.co",
    "in-addr.arpa", "ip6.arpa", "dyndns.org", "serveo.net", "loca.lt", "pythonanywhere.com",
];

/// Registrable ("base") domain and the subdomain part in front of it.
pub fn split_base(name: &str) -> (&str, &str) {
    let name = name.trim_end_matches('.');
    let dots: Vec<usize> = name.match_indices('.').map(|(i, _)| i).collect();
    let take = |n: usize| -> (&str, &str) {
        // base = last n labels
        if dots.len() < n {
            return (name, "");
        }
        let cut = dots[dots.len() - n];
        (&name[cut + 1..], &name[..cut])
    };
    let zone = MULTI.iter().filter(|m| name.len() > m.len() && name.ends_with(*m)
        && name.as_bytes()[name.len() - m.len() - 1] == b'.').max_by_key(|m| m.len());
    match zone {
        Some(m) => take(m.matches('.').count() + 2),
        None => take(2),
    }
}

pub fn entropy(s: &str) -> f32 {
    let b = s.as_bytes();
    if b.is_empty() {
        return 0.0;
    }
    let mut h = [0u32; 256];
    for &c in b {
        h[c as usize] += 1;
    }
    let n = b.len() as f32;
    h.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f32 / n;
        -p * p.log2()
    }).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_domains() {
        assert_eq!(split_base("a.b.example.com"), ("example.com", "a.b"));
        assert_eq!(split_base("www.bbc.co.uk"), ("bbc.co.uk", "www"));
        assert_eq!(split_base("x1y2.foo.duckdns.org"), ("foo.duckdns.org", "x1y2"));
        assert_eq!(split_base("abc.mybucket.blob.core.windows.net"), ("mybucket.blob.core.windows.net", "abc"));
        assert_eq!(split_base("example.com"), ("example.com", ""));
        assert_eq!(split_base("4.3.2.1.in-addr.arpa"), ("1.in-addr.arpa", "4.3.2"));
    }

    #[test]
    fn parse_query_and_answer() {
        // query for a.bc.com A, id 0x1234
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[1, b'a', 2, b'b', b'c', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        let m = parse(&q).unwrap();
        assert_eq!((m.name.as_str(), m.qtype, m.resp), ("a.bc.com", 1, false));
        // response with one compressed A answer
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let m = parse(&r).unwrap();
        assert!(m.resp);
        assert_eq!(m.answers, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }
}
