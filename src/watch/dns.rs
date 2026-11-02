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

/// Deterministic, std-only fuzzing helpers shared by the parser tests in
/// dns.rs, capture.rs and diag.rs.
#[cfg(test)]
pub(super) mod fuzz {
    /// xorshift64: tiny, deterministic, good enough to drive mutations.
    pub struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        pub fn below(&mut self, n: usize) -> usize {
            if n == 0 { 0 } else { (self.next() % n as u64) as usize }
        }
        pub fn chance(&mut self, one_in: u64) -> bool {
            self.next() % one_in == 0
        }
        pub fn bytes(&mut self, max_len: usize) -> Vec<u8> {
            let n = self.below(max_len + 1);
            (0..n).map(|_| self.next() as u8).collect()
        }
        /// A "length-like" value: boundaries, small, near `around`, or random.
        pub fn interesting(&mut self, around: usize) -> u32 {
            match self.below(8) {
                0 => 0,
                1 => 1,
                2 => u32::MAX,
                3 => [0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x7fff, 0x8000, 0xffff][self.below(8)],
                4 => (around as u32).wrapping_add(self.below(9) as u32).wrapping_sub(4),
                5 => self.below(64) as u32,
                _ => self.next() as u32,
            }
        }
    }

    /// Generic mutations: bit flips, byte sets, truncation, extension,
    /// insert/delete, chunk duplication and length-field-like overwrites.
    /// `be` picks the byte order of overwritten 16/32-bit fields.
    pub fn mutate(r: &mut Rng, b: &mut Vec<u8>, be: bool) {
        for _ in 0..1 + r.below(4) {
            let n = b.len();
            match r.below(9) {
                0 if n > 0 => {
                    let i = r.below(n);
                    b[i] ^= 1 << r.below(8);
                }
                1 if n > 0 => {
                    let i = r.below(n);
                    b[i] = [0, 0xff, 0x7f, 0x80, 0xc0, 0x3f, 0x40, r.next() as u8][r.below(8)];
                }
                2 => b.truncate(r.below(n + 1)),
                3 => {
                    let extra = r.bytes(64);
                    b.extend_from_slice(&extra);
                }
                4 if n > 0 => {
                    let i = r.below(n);
                    let k = 1 + r.below(16.min(n - i));
                    b.drain(i..i + k);
                }
                5 => {
                    let i = r.below(n + 1);
                    let ins = r.bytes(16);
                    b.splice(i..i, ins);
                }
                6 if n >= 2 => {
                    let i = r.below(n - 1);
                    let v = r.interesting(n) as u16;
                    let v = if be { v.to_be_bytes() } else { v.to_ne_bytes() };
                    b[i..i + 2].copy_from_slice(&v);
                }
                7 if n >= 4 => {
                    let i = r.below(n - 3);
                    let v = r.interesting(n);
                    let v = if be { v.to_be_bytes() } else { v.to_ne_bytes() };
                    b[i..i + 4].copy_from_slice(&v);
                }
                8 if n > 0 && n < 4096 => {
                    let i = r.below(n);
                    let k = 1 + r.below(32.min(n - i));
                    let chunk = b[i..i + k].to_vec();
                    let at = r.below(n + 1);
                    b.splice(at..at, chunk);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fuzz::{mutate, Rng};
    use super::*;
    use std::time::Instant;

    /// Upper bound on a parsed name (read_name stops past 300 characters).
    const MAX_NAME: usize = 300;

    fn query(name: &[&str], qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    /// Valid seeds: queries, and responses with compressed / uncompressed
    /// A, AAAA and CNAME answers.
    fn seeds() -> Vec<Vec<u8>> {
        let mut v = vec![query(&["a", "bc", "com"], 1), query(&["www", "example", "co", "uk"], 28)];
        let long = "x".repeat(63);
        v.push(query(&[&long, &long, &long, "com"], 16));
        let mut r = query(&["a", "bc", "com"], 1);
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 3;
        // CNAME a.bc.com -> www.bc.com (compressed suffix), then A and AAAA
        r.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'w', b'w', b'w', 0xC0, 14]);
        let cname_at = (r.len() - 6) as u8;
        r.extend_from_slice(&[0xC0, cname_at, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        r.extend_from_slice(&[0xC0, cname_at, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        r.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.push(r);
        // uncompressed answer, NXDOMAIN
        let mut n = query(&["evil", "test"], 1);
        n[2] = 0x81;
        n[3] = 0x83;
        n[7] = 1;
        n.extend_from_slice(&[4, b'e', b'v', b'i', b'l', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 0, 0, 1]);
        v.push(n);
        v
    }

    /// DNS-aware mutations: compression pointers, section counts, flags, label types.
    fn dns_specific(r: &mut Rng, m: &mut Vec<u8>) {
        if m.len() < 12 {
            return;
        }
        match r.below(6) {
            // compression pointer to itself, to the header, or anywhere
            0 | 1 if m.len() > 13 => {
                let at = 12 + r.below(m.len() - 13);
                let target = match r.below(4) {
                    0 => at,
                    1 => 12,
                    2 => r.below(12),
                    _ => r.below(m.len() + 4),
                } as u16;
                m[at] = 0xC0 | ((target >> 8) as u8 & 0x3F);
                m[at + 1] = target as u8;
            }
            // two pointers chasing each other
            2 if m.len() > 16 => {
                let a = 12 + r.below(m.len() - 14);
                let b = 12 + r.below(m.len() - 14);
                m[a] = 0xC0;
                m[a + 1] = b as u8;
                m[b] = 0xC0;
                m[b + 1] = a as u8;
            }
            // huge or odd section counts (qd/an/ns/ar)
            3 => {
                let i = 4 + 2 * r.below(4);
                let v = [0u16, 1, 2, 32, 33, 0x7fff, 0xffff][r.below(7)];
                m[i..i + 2].copy_from_slice(&v.to_be_bytes());
            }
            // flags: response / opcode / rcode bits
            4 => {
                m[2] = r.next() as u8;
                m[3] = r.next() as u8;
            }
            // reserved 0x40/0x80 label types and over-long labels
            _ if m.len() > 12 => {
                let at = 12 + r.below(m.len() - 12);
                m[at] = [0x40, 0x80, 0xBF, 64, 63, 0xFF][r.below(6)];
            }
            _ => {}
        }
    }

    fn check(m: &DnsMsg) {
        assert!(m.name.len() <= MAX_NAME, "name too long: {}", m.name.len());
        assert!(m.name.bytes().all(|c| c.is_ascii_graphic() && !c.is_ascii_uppercase()), "odd name {:?}", m.name);
        assert!(m.answers.len() <= 32);
        assert!(m.rcode <= 0xF);
        let (base, sub) = split_base(&m.name);
        assert!(base.len() + sub.len() <= m.name.len());
        assert!(m.name.contains(base) && m.name.contains(sub));
        let e = entropy(&m.name);
        assert!(e.is_finite() && (0.0..=8.0).contains(&e), "entropy {e}");
    }

    #[test]
    fn fuzz_dns_pointer_loops_terminate() {
        // header with one question; name starts at 12
        let hdr = |resp: bool, an: u16| {
            let mut h = vec![0, 0, if resp { 0x81 } else { 0x01 }, 0x80, 0, 1];
            h.extend_from_slice(&an.to_be_bytes());
            h.extend_from_slice(&[0, 0, 0, 0]);
            h
        };
        let mut cases = vec![];
        // self-reference
        let mut m = hdr(false, 0);
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        cases.push(m);
        // two-hop loop
        let mut m = hdr(false, 0);
        m.extend_from_slice(&[0xC0, 14, 0xC0, 12, 0, 1, 0, 1]);
        cases.push(m);
        // label then pointer back to the label: a.a.a.a... until the cap
        let mut m = hdr(false, 0);
        m.extend_from_slice(&[1, b'a', 0xC0, 12, 0, 1, 0, 1]);
        cases.push(m);
        // 63-byte label looping: hits the length cap before the jump cap
        let mut m = hdr(false, 0);
        m.push(63);
        m.extend_from_slice(&[b'z'; 63]);
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        cases.push(m);
        // pointer just past the end, and into the header
        let mut m = hdr(false, 0);
        m.extend_from_slice(&[0xC0, 14]);
        cases.push(m);
        let mut m = hdr(false, 0);
        m.extend_from_slice(&[0xC0, 0, 0, 1, 0, 1]);
        cases.push(m);
        // valid question, 65535 answers that are all a self-looping pointer
        let mut m = hdr(true, 0xFFFF);
        m.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        let at = m.len() as u8;
        for _ in 0..200 {
            m.extend_from_slice(&[0xC0, at]);
        }
        cases.push(m);
        // 65535 answers with valid A records: capped at 32
        let mut m = hdr(true, 0xFFFF);
        m.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        for i in 0..100u8 {
            m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, i]);
        }
        cases.push(m);
        for (i, c) in cases.iter().enumerate() {
            let t = Instant::now();
            for _ in 0..1000 {
                if let Some(m) = parse(c) {
                    check(&m);
                }
            }
            assert!(t.elapsed().as_millis() < 2000, "case {i} too slow");
        }
        // the loops above yield either nothing or a bounded name
        assert!(parse(&cases[0]).is_none());
        assert!(parse(&cases[1]).is_none());
        assert!(parse(&cases[2]).map_or(true, |m| m.name.len() <= MAX_NAME));
        assert!(parse(&cases[3]).is_none());
        assert_eq!(parse(&cases[7]).unwrap().answers.len(), 32);
        // read_name directly: every start offset of every case terminates
        for c in &cases {
            for off in 0..c.len() + 2 {
                if let Some((n, end)) = read_name(c, off) {
                    assert!(n.len() <= MAX_NAME);
                    assert!(end <= c.len());
                }
            }
        }
    }

    #[test]
    fn fuzz_dns_parse() {
        let t = Instant::now();
        let mut r = Rng(0x9E37_79B9_7F4A_7C15);
        let seeds = seeds();
        for s in &seeds {
            check(&parse(s).expect("seed parses"));
        }
        let (mut ok, mut iters) = (0u64, 0u64);
        // fully random buffers, half of them with a plausible header
        for _ in 0..400_000 {
            let mut b = r.bytes(600);
            if b.len() >= 12 && r.chance(2) {
                b[2] &= 0x87;
                b[4] = 0;
                b[5] = 1;
            }
            if let Some(m) = parse(&b) {
                check(&m);
                ok += 1;
            }
            iters += 1;
        }
        // mutations of valid seeds (stacked: mutate a mutant a few times)
        for _ in 0..250_000 {
            let mut b = seeds[r.below(seeds.len())].clone();
            for _ in 0..1 + r.below(4) {
                if r.chance(2) {
                    mutate(&mut r, &mut b, true);
                } else {
                    dns_specific(&mut r, &mut b);
                }
                if let Some(m) = parse(&b) {
                    check(&m);
                    ok += 1;
                }
                iters += 1;
            }
        }
        // read_name at random offsets of random buffers full of pointers
        for _ in 0..200_000 {
            let mut b = r.bytes(300);
            for _ in 0..r.below(16) {
                if b.len() >= 2 {
                    let i = r.below(b.len() - 1);
                    b[i] |= 0xC0;
                }
            }
            if let Some((n, end)) = read_name(&b, r.below(b.len() + 2)) {
                assert!(n.len() <= MAX_NAME);
                assert!(end <= b.len());
            }
            iters += 1;
        }
        eprintln!("fuzz_dns_parse: {iters} iterations, {ok} parsed, {:?}", t.elapsed());
        assert!(ok > 1000, "mutations barely reach the parser body");
    }

    #[test]
    fn fuzz_split_base_entropy() {
        let mut r = Rng(0xDEAD_BEEF_CAFE_F00D);
        let alphabet: Vec<char> = "abc.-.xyz0129.é√日.".chars().collect();
        let zones = ["co.uk", "duckdns.org", "blob.core.windows.net", "in-addr.arpa", "com", "."];
        for _ in 0..300_000 {
            let mut s: String = (0..r.below(80)).map(|_| alphabet[r.below(alphabet.len())]).collect();
            if r.chance(2) {
                s.push_str(zones[r.below(zones.len())]);
            }
            let (base, sub) = split_base(&s);
            assert!(s.contains(base) && s.contains(sub));
            let e = entropy(&s);
            assert!(e.is_finite() && (0.0..=8.0).contains(&e));
        }
    }

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
