//! ClamAV signature databases (main/daily .cvd/.cld as kept up to date by freshclam,
//! or plain .hdb/.hsb/.ndb/.ldb/... files) for simple file-based detection.
//!
//! Supported: whole-file hashes (.hdb/.hsb, MD5/SHA1/SHA256, `*` sizes), PE section
//! hashes (.mdb/.msb, PE32 only as in ClamAV), extended body signatures (.ndb) and
//! logical signatures (.ldb) with the full hex syntax, offsets (n, n+maxshift, EOF-n,
//! EP±n, Sx+n, SEx, SL+n), subsignature modifiers (::i ::w ::a ::f), counted logical
//! expressions, target types, false-positive lists (.fp/.sfp) and ignore lists
//! (.ign/.ign2). PUA databases (*.?du) are skipped like clamscan does by default.
//! Not supported (those signatures are skipped and counted): PCRE, byte-compare,
//! macro and fuzzy-image subsignatures, bytecode (.cbc), icon groups, container-only
//! signatures, archive unpacking, and ClamAV's full HTML/script normalizers.
//!
//! Memory: hash signatures are kept as (size, 64-bit hash prefix) only; on a hit the
//! name is looked up in the database files, which also re-checks the full hash. Body
//! patterns live in one bytecode arena per target type, indexed by a 4-byte anchor
//! (2 bytes for the few without four fixed bytes in a row). The Windows (PE) part is
//! most of the database (2.7M section hashes, ~1.4M patterns); it is loaded the first
//! time a PE file is scanned and can be released again when idle.

mod ftype;
pub mod md5;
pub mod pattern;

use pattern::Tok;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use ftype::FType;

/// The functionality level of ClamAV 1.5 (cl_retflevel): signatures for newer
/// engines, or only for older ones, are skipped exactly as clamscan skips them.
pub const FLEVEL: u32 = 234;
pub const DEFAULT_DIR: &str = "/var/lib/clamav";
/// Offset windows up to this size are tried position by position; larger ones float.
const FIXED_MAX_SHIFT: u32 = 4096;
/// Matcher steps per verification, and per pattern per file in total: work, not a
/// count of anchor hits, so cheap frequent checks (2-byte x86 anchors) finish while
/// expensive ones stay bounded (~tens of ms per pattern on hostile input).
const MATCH_BUDGET: u32 = 200_000;
const PATTERN_STEPS: u64 = 20_000_000;
// Running out of either budget is reported (`limited`), never silently treated as clean.
/// PE sections hashed per file, and hash-name lookups per file (each re-reads the DB).
const MAX_PE_SECTIONS: usize = 96;
const MAX_HASH_LOOKUPS: usize = 4;

#[derive(Default)]
struct Names {
    buf: String,
    off: Vec<u32>,
    dedup: HashMap<String, u32>,
}

impl Names {
    fn add(&mut self, n: &str) -> u32 {
        if let Some(&i) = self.dedup.get(n) {
            return i;
        }
        let i = self.off.len() as u32;
        self.off.push(self.buf.len() as u32);
        self.buf.push_str(n);
        self.dedup.insert(n.to_string(), i);
        i
    }
    fn finish(&mut self) {
        self.dedup = HashMap::new();
        self.off.push(self.buf.len() as u32);
        self.off.shrink_to_fit();
        self.buf.shrink_to_fit();
    }
    fn get(&self, i: u32) -> &str {
        &self.buf[self.off[i as usize] as usize..self.off[i as usize + 1] as usize]
    }
}

/// (size, first 8 bytes of the hash), sorted; struct-of-arrays to stay at 12 bytes each.
#[derive(Default)]
struct HashIdx {
    tmp: Vec<(u32, u64)>,
    size: Vec<u32>,
    pre: Vec<u64>,
}

fn prefix(h: &[u8]) -> u64 {
    u64::from_le_bytes(h[..8].try_into().unwrap())
}

impl HashIdx {
    fn finish(&mut self) {
        let mut t = std::mem::take(&mut self.tmp);
        t.sort_unstable();
        t.dedup();
        self.size = t.iter().map(|e| e.0).collect();
        self.pre = t.iter().map(|e| e.1).collect();
    }
    fn has_size(&self, s: u32) -> bool {
        let i = self.size.partition_point(|&x| x < s);
        self.size.get(i) == Some(&s)
    }
    fn contains(&self, s: u32, h: &[u8]) -> bool {
        let p = prefix(h);
        let k = {
            let (mut lo, mut hi) = (0usize, self.size.len());
            while lo < hi {
                let m = (lo + hi) / 2;
                if (self.size[m], self.pre[m]) < (s, p) { lo = m + 1 } else { hi = m }
            }
            lo
        };
        k < self.size.len() && self.size[k] == s && self.pre[k] == p
    }
}

fn hash_kind(len: usize) -> Option<usize> {
    match len {
        16 => Some(0),
        20 => Some(1),
        32 => Some(2),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
enum Base {
    Abs,
    Eof,
    Ep,
    Sec(u16),
    Last,
}

#[derive(Clone, Copy, Debug)]
enum Off {
    Any,
    At(Base, i32, u32),
    InSec(u16),
}

fn parse_off(s: &str) -> Result<Off, String> {
    if s == "*" {
        return Ok(Off::Any);
    }
    let (s, shift) = match s.split_once(',') {
        Some((a, b)) => (a, b.parse::<u32>().map_err(|_| format!("bad maxshift {b}"))?),
        None => (s, 0),
    };
    let int = |x: &str| x.parse::<i32>().map_err(|_| format!("bad offset {x}"));
    let signed = |x: &str| -> Result<i32, String> {
        if let Some(n) = x.strip_prefix('+') { int(n) } else if let Some(n) = x.strip_prefix('-') { Ok(-int(n)?) } else if x.is_empty() { Ok(0) } else { Err(format!("bad offset {x}")) }
    };
    let sec = |x: &str| x.parse::<u16>().map_err(|_| format!("bad section {x}"));
    if let Some(r) = s.strip_prefix("EOF-") {
        return Ok(Off::At(Base::Eof, -int(r)?, shift));
    }
    if let Some(r) = s.strip_prefix("EP") {
        return Ok(Off::At(Base::Ep, signed(r)?, shift));
    }
    if let Some(r) = s.strip_prefix("SE") {
        return Ok(Off::InSec(sec(r)?));
    }
    if let Some(r) = s.strip_prefix("SL") {
        return Ok(Off::At(Base::Last, signed(r)?, shift));
    }
    if let Some(r) = s.strip_prefix('S') {
        let k = r.find(['+', '-']).unwrap_or(r.len());
        return Ok(Off::At(Base::Sec(sec(&r[..k])?), signed(&r[k..])?, shift));
    }
    if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
        return Ok(Off::At(Base::Abs, int(s)?, shift));
    }
    Err(format!("unsupported offset {s}"))
}

impl Off {
    /// Inclusive range of allowed start positions.
    fn range(&self, i: &ftype::Info) -> Option<(usize, usize)> {
        let (base, n, shift) = match *self {
            Off::Any => return Some((0, i.len)),
            Off::InSec(x) => {
                let &(o, l) = i.secs.get(x as usize)?;
                return (o < i.len && l > 0).then(|| (o, (o + l - 1).min(i.len)));
            }
            Off::At(b, n, s) => (b, n as i64, s),
        };
        let b: i64 = match base {
            Base::Abs => 0,
            Base::Eof => i.len as i64,
            Base::Ep => i.ep? as i64,
            Base::Sec(x) => i.secs.get(x as usize)?.0 as i64,
            Base::Last => i.secs.last()?.0 as i64,
        };
        let lo = b + n;
        if lo < 0 || lo as usize > i.len {
            return None;
        }
        Some((lo as usize, (lo as usize).saturating_add(shift as usize).min(i.len)))
    }
    fn fixed(&self) -> bool {
        matches!(self, Off::At(_, _, s) if *s <= FIXED_MAX_SHIFT)
    }
}

const F_NC: u8 = 1;
const F_FW: u8 = 2;
const F_WIDE: u8 = 4;
/// `sub` value of extended (.ndb) signatures: `owner` is then the name index.
const NDB: u8 = 255;

/// One compiled pattern: `pre` (reversed, before the anchor) then `post` (after it)
/// in the group's code arena. Fixed-offset patterns have no anchor: all in `post`.
struct Pat {
    /// arena layout: [anchor bytes (alen)] [pre] [post]
    code: u32,
    pre: u32,
    post: u32,
    /// where the indexed key starts inside the anchor
    ko: u8,
    off: Off,
    owner: u32,
    sub: u8,
    alen: u8,
    flags: u8,
}

/// Anchor index: sorted (key, pattern) with a bitmap prefilter.
#[derive(Default)]
struct QIdx {
    /// (key, pattern), sorted by key
    k4: Vec<(u32, u32)>,
    b4: Vec<u64>,
    s4: u32,
    /// open-addressing table: key -> (start, count) in k4; count 0 = empty slot
    t4: Vec<(u32, u32, u32)>,
    k2: Vec<(u16, u32)>,
    b2: Vec<u64>,
}

impl QIdx {
    fn finish(&mut self) {
        self.k4.sort_unstable();
        self.k4.shrink_to_fit();
        self.k2.sort_unstable();
        self.k2.shrink_to_fit();
        if !self.k4.is_empty() {
            let bits = (self.k4.len() * 64).next_power_of_two().clamp(1 << 12, 1 << 26);
            self.s4 = 32 - bits.trailing_zeros();
            self.b4 = vec![0; bits / 64];
            for &(k, _) in &self.k4 {
                let h = self.h4(k);
                self.b4[h >> 6] |= 1 << (h & 63);
            }
            let mut runs: Vec<(u32, u32, u32)> = vec![];
            for (i, &(k, _)) in self.k4.iter().enumerate() {
                match runs.last_mut() {
                    Some(r) if r.0 == k => r.2 += 1,
                    _ => runs.push((k, i as u32, 1)),
                }
            }
            let size = (runs.len() * 2).next_power_of_two();
            self.t4 = vec![(0, 0, 0); size];
            for r in runs {
                let mut j = (r.0.wrapping_mul(0x85EB_CA6B) as usize) & (size - 1);
                while self.t4[j].2 != 0 {
                    j = (j + 1) & (size - 1);
                }
                self.t4[j] = r;
            }
        }
        if !self.k2.is_empty() {
            self.b2 = vec![0; 1024];
            for &(k, _) in &self.k2 {
                self.b2[k as usize >> 6] |= 1 << (k & 63);
            }
        }
    }
    #[inline]
    fn h4(&self, k: u32) -> usize {
        (k.wrapping_mul(0x9E37_79B1) >> self.s4) as usize
    }
    #[inline]
    fn get4(&self, k: u32) -> &[(u32, u32)] {
        let b = self.h4(k);
        if self.b4[b >> 6] >> (b & 63) & 1 == 0 {
            return &[];
        }
        let m = self.t4.len() - 1;
        let mut j = (k.wrapping_mul(0x85EB_CA6B) as usize) & m;
        loop {
            let e = self.t4[j];
            if e.2 == 0 {
                return &[];
            }
            if e.0 == k {
                return &self.k4[e.1 as usize..(e.1 + e.2) as usize];
            }
            j = (j + 1) & m;
        }
    }
}

#[derive(Default)]
struct Group {
    code: Vec<u8>,
    pats: Vec<Pat>,
    fixed: Vec<u32>,
    /// [case-sensitive, case-insensitive]
    idx: [QIdx; 2],
}

/// How common a byte is in typical files (higher = worse anchor): padding, x86
/// prologue bytes, and the letters/space of text and identifiers.
fn commonness(b: u8) -> i32 {
    match b {
        0x00 => 8,
        0xff | 0x20 => 6,
        b'e' | b't' | b'a' | b'o' | b'i' | b'n' | b's' | b'r' | b'h' | b'l' => 5,
        0xcc | 0x90 | 0x8b | 0x89 | 0xe8 | 0x48 | 0x0f | 0x24 => 4,
        b'a'..=b'z' | b'_' | b'.' | b'/' | 0x0a | 0x0d | 0x01 => 3,
        b'A'..=b'Z' | b'0'..=b'9' => 2,
        _ => 1,
    }
}

/// Best anchor window of `w` exact bytes: rare and distinct bytes.
fn pick_anchor(t: &[Tok], w: usize) -> Option<usize> {
    let mut best: Option<(i32, usize)> = None;
    let mut i = 0;
    while i + w <= t.len() {
        if t[i..i + w].iter().all(|x| matches!(x, Tok::B(_, 0xff))) {
            let bytes: Vec<u8> = t[i..i + w].iter().map(|x| if let Tok::B(v, _) = x { *v } else { 0 }).collect();
            let mut seen = [false; 256];
            let distinct = bytes.iter().filter(|&&b| !std::mem::replace(&mut seen[b as usize], true)).count() as i32;
            let score = distinct * 3 - bytes.iter().map(|&b| commonness(b)).sum::<i32>();
            if best.is_none_or(|(s, _)| score > s) {
                best = Some((score, i));
            }
        }
        i += 1;
    }
    best.map(|(_, i)| i)
}

enum Expr {
    Sub(u8),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cnt(Box<Expr>, u8, u32, Option<u32>),
}

impl Expr {
    /// (true?, total match count, distinct subsignatures matched)
    fn eval(&self, c: &[u32]) -> (bool, u64, u32) {
        match self {
            Expr::Sub(i) => {
                let n = c.get(*i as usize).copied().unwrap_or(0);
                (n > 0, n as u64, (n > 0) as u32)
            }
            Expr::And(a, b) | Expr::Or(a, b) => {
                // a block counts only the parts that are true (as clamscan does)
                let (x, y) = (a.eval(c), b.eval(c));
                let ok = if matches!(self, Expr::And(..)) { x.0 && y.0 } else { x.0 || y.0 };
                let part = |v: (bool, u64, u32)| if v.0 { (v.1, v.2) } else { (0, 0) };
                let (px, py) = (part(x), part(y));
                (ok, px.0 + py.0, px.1 + py.1)
            }
            Expr::Cnt(e, op, x, y) => {
                let (_, n, u) = e.eval(c);
                // `=X,Y` needs exactly Y distinct subsignatures, `>`/`<` at least Y
                let ok = match op {
                    b'=' => n == *x as u64 && y.is_none_or(|y| u == y),
                    b'>' => n > *x as u64 && y.is_none_or(|y| u >= y),
                    _ => n < *x as u64 && y.is_none_or(|y| u >= y),
                };
                (ok, n, u)
            }
        }
    }
    fn max_sub(&self) -> u8 {
        match self {
            Expr::Sub(i) => *i,
            Expr::And(a, b) | Expr::Or(a, b) => a.max_sub().max(b.max_sub()),
            Expr::Cnt(e, ..) => e.max_sub(),
        }
    }
}

/// Logical expression, parsed the way clamscan evaluates unparenthesised mixes
/// (measured against it): at top level it splits at the *first* operator
/// (`0&1|2` = `0&(1|2)`), inside parentheses at the *last* (`(0|1&2)` = `(0|1)&2`).
/// Parenthesised groups may carry `=X[,Y]`, `>X[,Y]`, `<X[,Y]`.
fn parse_expr(s: &str) -> Result<Expr, String> {
    parse_level(s, false)
}

fn parse_level(s: &str, inner: bool) -> Result<Expr, String> {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut split = None;
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'&' | b'|' if depth == 0 => {
                split = Some(i);
                if !inner {
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(i) = split else { return parse_unit(s) };
    let (l, r) = if inner {
        (parse_level(&s[..i], true)?, parse_unit(&s[i + 1..])?)
    } else {
        (parse_unit(&s[..i])?, parse_level(&s[i + 1..], false)?)
    };
    let (l, r) = (Box::new(l), Box::new(r));
    Ok(if b[i] == b'&' { Expr::And(l, r) } else { Expr::Or(l, r) })
}

fn parse_unit(s: &str) -> Result<Expr, String> {
    let s = s.trim();
    let (e, rest) = if s.starts_with('(') {
        let mut depth = 0;
        let mut end = None;
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.ok_or("unbalanced parentheses")?;
        (parse_level(&s[1..end], true)?, &s[end + 1..])
    } else {
        let k = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let n: u8 = s[..k].parse().map_err(|_| format!("bad expression {s:?}"))?;
        (Expr::Sub(n), &s[k..])
    };
    if rest.is_empty() {
        return Ok(e);
    }
    let op = rest.as_bytes()[0];
    if !matches!(op, b'=' | b'>' | b'<') {
        return Err(format!("bad expression {s:?}"));
    }
    let (x, y) = match rest[1..].split_once(',') {
        Some((x, y)) => (x.parse().map_err(|_| "bad count")?, Some(y.parse().map_err(|_| "bad count")?)),
        None => (rest[1..].parse().map_err(|_| "bad count")?, None),
    };
    Ok(Expr::Cnt(Box::new(e), op, x, y))
}

struct Ldb {
    name: u32,
    expr: Expr,
    nsub: u8,
    fsize: Option<(u64, u64)>,
    ep: Option<(u64, u64)>,
    nsec: Option<(u64, u64)>,
}

#[derive(Default, Clone, Debug, serde::Serialize)]
pub struct Stats {
    pub hashes: u64,
    pub section_hashes: u64,
    pub body: u64,
    pub logical: u64,
    pub skipped: u64,
    pub skip_reasons: std::collections::BTreeMap<String, u64>,
}


fn skip(st: &mut Stats, why: &str) {
    st.skipped += 1;
    *st.skip_reasons.entry(why.to_string()).or_default() += 1;
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn flevel_ok(min: Option<&str>, max: Option<&str>) -> bool {
    let p = |s: Option<&str>| s.filter(|s| !s.is_empty()).and_then(|s| s.parse::<u32>().ok());
    p(min).is_none_or(|m| m <= FLEVEL) && p(max).is_none_or(|m| m >= FLEVEL)
}

fn range(s: &str) -> Option<(u64, u64)> {
    match s.split_once('-') {
        Some((a, b)) => Some((a.parse().ok()?, if b.is_empty() { u64::MAX } else { b.parse().ok()? })),
        None => s.parse().ok().map(|n| (n, n)),
    }
}


/// One load pass: the general part, or the PE part.
#[derive(Default)]
struct Part {
    names: Names,
    /// whole-file hashes by kind (MD5, SHA1, SHA256)
    whole: [HashIdx; 3],
    star: Vec<(Vec<u8>, u32)>,
    /// PE section hashes by kind
    sect: [HashIdx; 3],
    sect_star: Vec<(Vec<u8>, u32)>,
    groups: HashMap<u8, Group>,
    ldbs: Vec<Ldb>,
    stats: Stats,
}

impl Part {
    fn finish(&mut self) {
        self.names.finish();
        for h in self.whole.iter_mut().chain(self.sect.iter_mut()) {
            h.finish();
        }
        for g in self.groups.values_mut() {
            g.code.shrink_to_fit();
            g.pats.shrink_to_fit();
            for q in g.idx.iter_mut() {
                q.finish();
            }
        }
        self.ldbs.shrink_to_fit();
    }

    fn add_hash(&mut self, hash: &str, size: &str, name: &str, section: bool) -> Result<(), &'static str> {
        let h = unhex(hash).ok_or("bad hash")?;
        let kind = hash_kind(h.len()).ok_or("bad hash length")?;
        if size == "*" {
            let n = self.names.add(name);
            if section { self.sect_star.push((h, n)) } else { self.star.push((h, n)) }
            return Ok(());
        }
        let size: u32 = size.parse().map_err(|_| "bad size")?;
        let t = if section { &mut self.sect[kind] } else { &mut self.whole[kind] };
        t.tmp.push((size, prefix(&h)));
        Ok(())
    }

    /// Compile one body (sub)signature into patterns of group `target`.
    fn add_body(&mut self, target: u8, off: &str, hex: &str, mods: &str, owner: u32, sub: u8) -> Result<(), String> {
        let toks = pattern::parse_hex(hex)?;
        let off = parse_off(off)?;
        let (nc, wide, fw) = (mods.contains('i'), mods.contains('w'), mods.contains('f'));
        let ascii = mods.contains('a') || !wide;
        let mut variants: Vec<(Vec<Tok>, bool)> = vec![];
        if ascii {
            variants.push((toks.clone(), false));
        }
        if wide {
            variants.push((pattern::widen(&toks), true));
        }
        // check every variant before adding any
        let mut plans = vec![];
        for (mut t, w) in variants {
            if nc {
                pattern::lower(&mut t);
            }
            let a = if off.fixed() {
                None
            } else {
                let (k, n) = match pick_anchor(&t, 4) {
                    Some(i) => (i, 4),
                    None => (pick_anchor(&t, 2).ok_or("no static anchor of 2+ bytes")?, 2),
                };
                // widen the anchor to up to 8 exact bytes around the key: candidates are
                // rejected by a byte compare before any backtracking
                let exact = |j: usize| matches!(t.get(j), Some(Tok::B(_, 0xff)));
                let (mut a0, mut a1) = (k, k + n);
                while a1 - a0 < 8 && (exact(a1) || (a0 > 0 && exact(a0 - 1))) {
                    if exact(a1) {
                        a1 += 1;
                    } else {
                        a0 -= 1;
                    }
                }
                Some((a0, a1, k - a0, n))
            };
            plans.push((t, w, a));
        }
        let g = self.groups.entry(target).or_default();
        for (t, w, a) in plans {
            let flags = (nc as u8 * F_NC) | (fw as u8 * F_FW) | (w as u8 * F_WIDE);
            let id = g.pats.len() as u32;
            let code = g.code.len() as u32;
            let (pre, post, alen, ko) = match a {
                None => {
                    let c = pattern::encode(&t, false);
                    g.code.extend_from_slice(&c);
                    (0, c.len() as u32, 0, 0)
                }
                Some((a0, a1, ko, n)) => {
                    let anchor = pattern::anchor_bytes(&t, (a0, a1 - a0));
                    let pre = pattern::encode(&t[..a0], true);
                    let post = pattern::encode(&t[a1..], false);
                    g.code.extend_from_slice(&anchor);
                    g.code.extend_from_slice(&pre);
                    g.code.extend_from_slice(&post);
                    let key = &anchor[ko..ko + n];
                    let ix = &mut g.idx[nc as usize];
                    if n == 4 {
                        ix.k4.push((u32::from_le_bytes(key.try_into().unwrap()), id));
                    } else {
                        ix.k2.push((u16::from_le_bytes([key[0], key[1]]), id));
                    }
                    (pre.len() as u32, post.len() as u32, anchor.len() as u8, ko as u8)
                }
            };
            if a.is_none() {
                g.fixed.push(id);
            }
            g.pats.push(Pat { code, pre, post, ko, off, owner, sub, alen, flags });
        }
        Ok(())
    }

    fn add_ndb(&mut self, line: &str, pe: bool) {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            return skip(&mut self.stats, "malformed");
        }
        let Ok(target) = f[1].parse::<u8>() else { return skip(&mut self.stats, "malformed") };
        if (target == 1) != pe {
            return;
        }
        if !flevel_ok(f.get(4).copied(), f.get(5).copied()) {
            return skip(&mut self.stats, "functionality level");
        }
        if let Err(e) = pattern::parse_hex(f[3]).and(parse_off(f[2])) {
            return skip(&mut self.stats, &format!("ndb: {}", e.split([' ', ':']).take(3).collect::<Vec<_>>().join(" ")));
        }
        let n = self.names.add(f[0]);
        match self.add_body(target, f[2], f[3], "", n, NDB) {
            Ok(()) => self.stats.body += 1,
            Err(e) => skip(&mut self.stats, &format!("ndb: {}", e.split([' ', ':']).take(3).collect::<Vec<_>>().join(" "))),
        }
    }

    fn add_ldb(&mut self, line: &str, pe: bool) {
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 4 {
            return skip(&mut self.stats, "malformed");
        }
        let mut target = None;
        let (mut fsize, mut ep, mut nsec) = (None, None, None);
        for kv in f[1].split(',') {
            let (k, v) = kv.split_once(':').unwrap_or((kv, ""));
            match k {
                "Target" => target = v.parse::<u8>().ok(),
                "Engine" => {
                    let (a, b) = v.split_once('-').unwrap_or((v, ""));
                    if !flevel_ok(Some(a), Some(b)) {
                        return skip(&mut self.stats, "functionality level");
                    }
                }
                "FileSize" => fsize = range(v),
                "EntryPoint" => ep = range(v),
                "NumberOfSections" => nsec = range(v),
                "Container" if v == "CL_TYPE_ANY" => {}
                "Container" | "Intermediates" => return skip(&mut self.stats, "ldb: container"),
                "IconGroup1" | "IconGroup2" => return skip(&mut self.stats, "ldb: icon group"),
                "HandlerType" => return skip(&mut self.stats, "ldb: handler type"),
                _ => {}
            }
        }
        let Some(target) = target else { return skip(&mut self.stats, "malformed") };
        if (target == 1) != pe {
            return;
        }
        let subs = &f[3..];
        if subs.len() > 64 {
            return skip(&mut self.stats, "malformed");
        }
        for s in subs {
            if s.contains('/') {
                return skip(&mut self.stats, "ldb: pcre");
            }
            if s.contains('#') {
                return skip(&mut self.stats, "ldb: byte compare / fuzzy");
            }
            if s.starts_with('$') {
                return skip(&mut self.stats, "ldb: macro");
            }
        }
        let expr = match parse_expr(f[2]) {
            Ok(e) if (e.max_sub() as usize) < subs.len() => e,
            _ => return skip(&mut self.stats, "ldb: expression"),
        };
        // validate every subsignature first: a signature is all or nothing
        let mut parsed = vec![];
        for (k, s) in subs.iter().enumerate() {
            let (body, mods) = s.split_once("::").unwrap_or((s, ""));
            let (off, hex) = body.split_once(':').unwrap_or(("*", body));
            let Ok(t) = pattern::parse_hex(hex) else { return skip(&mut self.stats, "ldb: subsignature syntax") };
            let Ok(o) = parse_off(off) else { return skip(&mut self.stats, "ldb: subsignature syntax") };
            if !o.fixed() && pick_anchor(&t, 2).is_none() && pick_anchor(&pattern::widen(&t), 2).is_none() {
                return skip(&mut self.stats, "ldb: no anchor");
            }
            parsed.push((off, hex, mods, k as u8));
        }
        let lid = self.ldbs.len() as u32;
        let name = self.names.add(f[0]);
        for (off, hex, mods, k) in parsed {
            if self.add_body(target, off, hex, mods, lid, k).is_err() {
                // can't happen after the checks above; never leave a half signature
                for g in self.groups.values_mut() {
                    for q in g.idx.iter_mut() {
                        q.k4.retain(|&(_, id)| !(g.pats[id as usize].sub != NDB && g.pats[id as usize].owner == lid));
                        q.k2.retain(|&(_, id)| !(g.pats[id as usize].sub != NDB && g.pats[id as usize].owner == lid));
                    }
                    g.fixed.retain(|&id| !(g.pats[id as usize].sub != NDB && g.pats[id as usize].owner == lid));
                }
                return skip(&mut self.stats, "ldb: no anchor");
            }
        }
        self.ldbs.push(Ldb { name, expr, nsub: subs.len() as u8, fsize, ep, nsec });
        self.stats.logical += 1;
    }
}

/// Database files must not be writable by anyone but root, the clamav user (freshclam
/// runs as it) or us: whoever can edit signatures decides what gets quarantined.
fn trusted_db(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let clamav = clamav_uid();
    // SAFETY: trivial libc call.
    let me = unsafe { libc::geteuid() };
    let check = |q: &Path| -> Result<(), String> {
        let md = std::fs::metadata(q).map_err(|e| format!("{}: {e}", q.display()))?;
        if md.uid() != 0 && md.uid() != me && Some(md.uid()) != clamav {
            return Err(format!("{} is owned by uid {}, not root or clamav", q.display(), md.uid()));
        }
        if md.mode() & 0o022 != 0 && !(md.is_dir() && md.uid() == 0 && md.mode() & 0o1000 != 0) {
            return Err(format!("{} is group/world-writable", q.display()));
        }
        Ok(())
    };
    check(p)?;
    if let Some(d) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        check(d)?;
    }
    Ok(())
}

fn clamav_uid() -> Option<u32> {
    let pw = std::fs::read_to_string("/etc/passwd").ok()?;
    pw.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&"clamav")).then(|| f.get(2)?.parse().ok()).flatten()
    })
}

const BASE_EXT: &[&str] = &["hdb", "hsb", "mdb", "msb", "ndb", "ldb", "fp", "sfp", "ign", "ign2"];
const PUA_EXT: &[&str] = &["hdu", "hsu", "mdu", "msu", "ndu", "ldu"];

/// Which source files to read: .cvd/.cld containers (newest of each name) and plain
/// signature files.
fn sources(dir: &Path, pua: bool) -> Result<Vec<PathBuf>, String> {
    let mut by_base: HashMap<String, (PathBuf, u64)> = HashMap::new();
    let mut plain = vec![];
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in rd.flatten() {
        let p = e.path();
        let Some(ext) = p.extension().and_then(|x| x.to_str()) else { continue };
        let stem = p.file_stem().and_then(|x| x.to_str()).unwrap_or("").to_string();
        if !e.file_type().is_ok_and(|t| t.is_file() || t.is_symlink()) {
            continue;
        }
        match ext {
            "cvd" | "cld" => {
                let ver = cvd_header(&p).ok().and_then(|h| h.get(2).and_then(|v| v.parse().ok())).unwrap_or(0);
                if by_base.get(&stem).is_none_or(|(_, v)| ver > *v) {
                    by_base.insert(stem, (p, ver));
                }
            }
            x if BASE_EXT.contains(&x) || (pua && PUA_EXT.contains(&x)) => plain.push(p),
            _ => {}
        }
    }
    let mut v: Vec<PathBuf> = by_base.into_values().map(|(p, _)| p).collect();
    v.extend(plain);
    v.sort();
    for p in &v {
        trusted_db(p)?;
    }
    if v.is_empty() {
        return Err(format!("no ClamAV databases in {}", dir.display()));
    }
    Ok(v)
}

fn cvd_header(p: &Path) -> Result<Vec<String>, String> {
    let mut h = [0u8; 512];
    std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut h)).map_err(|e| format!("{}: {e}", p.display()))?;
    let s = String::from_utf8_lossy(&h).trim_end().to_string();
    if !s.starts_with("ClamAV-VDB:") {
        return Err(format!("{}: not a ClamAV database", p.display()));
    }
    Ok(s.split(':').map(str::to_string).collect())
}

/// CVD integrity: the header's MD5 over the compressed body (CLD files, which
/// freshclam patches in place, carry none).
fn verify_cvd(p: &Path) -> Result<(), String> {
    let h = cvd_header(p)?;
    let want = h.get(5).cloned().unwrap_or_default();
    if want.len() != 32 {
        return Ok(());
    }
    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 1 << 20];
    f.read_exact(&mut buf[..512]).map_err(|e| e.to_string())?;
    let mut m = md5::Md5::default();
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        m.update(&buf[..n]);
    }
    let got: String = m.finish().iter().map(|b| format!("{b:02x}")).collect();
    if got != want {
        return Err(format!("{}: MD5 mismatch (corrupt or tampered)", p.display()));
    }
    Ok(())
}

/// Calls `f(member name, reader)` for each signature file in a source.
fn each_member(p: &Path, f: &mut dyn FnMut(&str, &mut dyn BufRead)) -> Result<(), String> {
    let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
    let file = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if ext != "cvd" && ext != "cld" {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        f(name, &mut std::io::BufReader::new(file));
        return Ok(());
    }
    let mut r = std::io::BufReader::with_capacity(1 << 16, file);
    let mut hdr = [0u8; 512];
    r.read_exact(&mut hdr).map_err(|e| e.to_string())?;
    let gz = r.fill_buf().map_err(|e| e.to_string())?.starts_with(&[0x1f, 0x8b]);
    let mut body: Box<dyn Read> = if gz { Box::new(flate2::read::GzDecoder::new(r)) } else { Box::new(r) };
    loop {
        let mut th = [0u8; 512];
        if body.read_exact(&mut th).is_err() || th.iter().all(|&b| b == 0) {
            break;
        }
        let name = String::from_utf8_lossy(&th[..100]).trim_end_matches('\0').to_string();
        let size_s = String::from_utf8_lossy(&th[124..136]).trim_matches(|c: char| c == '\0' || c == ' ').to_string();
        let size = u64::from_str_radix(&size_s, 8).map_err(|_| format!("{}: bad tar member {name}", p.display()))?;
        let mut member = std::io::BufReader::new((&mut body).take(size));
        f(&name, &mut member);
        // drain whatever the callback didn't read, then the padding
        std::io::copy(&mut member, &mut std::io::sink()).map_err(|e| e.to_string())?;
        let pad = (512 - size % 512) % 512;
        std::io::copy(&mut (&mut body).take(pad), &mut std::io::sink()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn lines(r: &mut dyn BufRead, mut f: impl FnMut(&str)) {
    let mut buf = vec![];
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let l = String::from_utf8_lossy(&buf);
                let l = l.trim_end_matches(['\n', '\r']);
                if !l.is_empty() && !l.starts_with('#') {
                    f(l);
                }
            }
        }
    }
}


struct Hits {
    names: Vec<u32>,
    done: HashSet<u32>,
    seen: HashSet<(u32, usize)>,
    /// matcher steps spent per pattern in this file
    tries: HashMap<u32, u64>,
    counts: HashMap<u32, Vec<u32>>,
    memo: HashMap<u32, pattern::Memo>,
    /// a budget ran out: the file was not fully checked
    limited: bool,
}

impl Hits {
    fn new() -> Hits {
        Hits { names: vec![], done: HashSet::new(), seen: HashSet::new(), tries: HashMap::new(), counts: HashMap::new(), memo: HashMap::new(), limited: false }
    }
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

impl Part {
    fn pat_name(&self, p: &Pat) -> String {
        if p.sub == NDB { self.names.get(p.owner).to_string() } else { format!("{} sub{}", self.names.get(self.ldbs[p.owner as usize].name), p.sub) }
    }

    fn record(&self, p: &Pat, pid: u32, start: usize, h: &mut Hits) {
        if p.sub == NDB {
            if h.done.insert(pid) {
                h.names.push(p.owner);
            }
        } else if h.seen.insert((pid, start)) {
            let c = h.counts.entry(p.owner).or_insert_with(|| vec![0; self.ldbs[p.owner as usize].nsub as usize]);
            c[p.sub as usize] = c[p.sub as usize].saturating_add(1).min(10_000);
        }
    }

    /// Verify pattern `pid` around an anchor found at `pos`.
    fn try_anchor(&self, g: &Group, pid: u32, pos: usize, d: &[u8], inf: &ftype::Info, h: &mut Hits) {
        let p = &g.pats[pid as usize];
        if p.sub == NDB && h.done.contains(&pid) {
            return;
        }
        // the whole anchor, not just the indexed key
        let Some(pos) = pos.checked_sub(p.ko as usize) else { return };
        let alen = p.alen as usize;
        let anchor = &g.code[p.code as usize..p.code as usize + alen];
        let Some(here) = d.get(pos..pos + alen) else { return };
        if !(if p.flags & F_NC != 0 { here.eq_ignore_ascii_case(anchor) } else { here == anchor }) {
            return;
        }
        let Some((lo, hi)) = p.off.range(inf) else { return };
        // the match starts at or before the anchor: an anchor before the window can't
        // match, and with nothing before the anchor it must be inside the window
        if pos < lo || (p.pre == 0 && pos > hi) {
            return;
        }
        let spent = h.tries.get(&pid).copied().unwrap_or(0);
        if spent >= PATTERN_STEPS {
            if !h.limited && std::env::var_os("RATEL_CLAM_DEBUG").is_some() { eprintln!("LIMIT steps pid {pid} {}", self.pat_name(p)); }
            h.limited = true;
            return;
        }
        let budget = MATCH_BUDGET.min((PATTERN_STEPS - spent) as u32);
        let (fw, wide) = (p.flags & F_FW != 0, p.flags & F_WIDE != 0);
        let c0 = p.code as usize + alen;
        let pre = &g.code[c0..c0 + p.pre as usize];
        let post = &g.code[c0 + p.pre as usize..c0 + (p.pre + p.post) as usize];
        let mut start = None;
        let used: u32;
        let ok = {
            let memo = h.memo.entry(pid).or_default();
            let mut m = pattern::M { d, nc: p.flags & F_NC != 0, budget, memo: Some(memo) };
            let r = m.fwd(post, 0, pos + alen, &mut |e| !fw || e >= d.len() || !word(d[e]))
                && m.bwd(pre, 0, pos, &mut |s| {
                    let ok = s >= lo && s <= hi && (!fw || s == 0 || !word(d[s - if wide && s >= 2 { 2 } else { 1 }]));
                    if ok {
                        start = Some(s);
                    }
                    ok
                });
            if m.budget == 0 {
                if std::env::var_os("RATEL_CLAM_DEBUG").is_some() { eprintln!("LIMIT budget(anchor) pid {pid} pos {pos} {}", self.pat_name(p)); }
                h.limited = true;
            }
            used = budget - m.budget;
            r
        };
        *h.tries.entry(pid).or_default() += used as u64 + 1;
        if ok {
            self.record(p, pid, start.unwrap_or(pos), h);
        }
    }

    fn scan_group(&self, target: u8, d: &[u8], inf: &ftype::Info, h: &mut Hits) {
        let Some(g) = self.groups.get(&target) else { return };
        for &pid in &g.fixed {
            let p = &g.pats[pid as usize];
            let Some((lo, hi)) = p.off.range(inf) else { continue };
            let fw = p.flags & F_FW != 0;
            let code = &g.code[p.code as usize..(p.code + p.post) as usize];
            for s in lo..=hi {
                if p.sub == NDB && h.done.contains(&pid) {
                    break;
                }
                if fw && s > 0 && word(d[s - 1]) {
                    continue;
                }
                // a pattern tried at a handful of positions may backtrack more; all of it
                // comes out of the same per-pattern budget
                let spent = h.tries.get(&pid).copied().unwrap_or(0);
                if spent >= PATTERN_STEPS {
                    h.limited = true;
                    break;
                }
                let per = if hi - lo < 16 { MATCH_BUDGET * 10 } else { MATCH_BUDGET };
                let budget = per.min((PATTERN_STEPS - spent) as u32);
                let (ok, used) = {
                    let memo = h.memo.entry(pid).or_default();
                    let mut m = pattern::M { d, nc: p.flags & F_NC != 0, budget, memo: Some(memo) };
                    let r = m.fwd(code, 0, s, &mut |e| !fw || e >= d.len() || !word(d[e]));
                    if m.budget == 0 {
                        if std::env::var_os("RATEL_CLAM_DEBUG").is_some() { eprintln!("LIMIT budget(fixed) pid {pid} {}", self.pat_name(p)); }
                        h.limited = true;
                    }
                    (r, budget - m.budget)
                };
                *h.tries.entry(pid).or_default() += used as u64 + 1;
                if ok {
                    self.record(p, pid, s, h);
                }
            }
        }
        // one pass, rolling 4-byte keys (raw and lower-cased)
        let (cs, ci) = (&g.idx[0], &g.idx[1]);
        let (use_cs, use_ci) = (!cs.k4.is_empty(), !ci.k4.is_empty());
        if (use_cs || use_ci) && d.len() >= 4 {
            let (mut kr, mut kl) = (0u32, 0u32);
            for (i, &b) in d.iter().enumerate() {
                kr = (kr >> 8) | ((b as u32) << 24);
                kl = (kl >> 8) | ((b.to_ascii_lowercase() as u32) << 24);
                if i < 3 {
                    continue;
                }
                let pos = i - 3;
                if use_cs {
                    for &(_, pid) in cs.get4(kr) {
                        self.try_anchor(g, pid, pos, d, inf, h);
                    }
                }
                if use_ci {
                    for &(_, pid) in ci.get4(kl) {
                        self.try_anchor(g, pid, pos, d, inf, h);
                    }
                }
            }
        }
        for (ci, q) in g.idx.iter().enumerate() {
            let nc = ci == 1;
            let low = |b: u8| if nc { b.to_ascii_lowercase() } else { b };
            if !q.k2.is_empty() && d.len() >= 2 {
                for pos in 0..=d.len() - 2 {
                    let k = u16::from_le_bytes([low(d[pos]), low(d[pos + 1])]);
                    if q.b2[k as usize >> 6] >> (k & 63) & 1 == 0 {
                        continue;
                    }
                    let i = q.k2.partition_point(|e| e.0 < k);
                    for &(kk, pid) in &q.k2[i..] {
                        if kk != k {
                            break;
                        }
                        self.try_anchor(g, pid, pos, d, inf, h);
                    }
                }
            }
        }
    }

    fn eval_ldbs(&self, h: &Hits, inf: &ftype::Info, out: &mut Vec<String>) {
        for (l, c) in &h.counts {
            let s = &self.ldbs[*l as usize];
            let inr = |r: Option<(u64, u64)>, v: Option<u64>| r.is_none_or(|(a, b)| v.is_some_and(|v| v >= a && v <= b));
            if !inr(s.fsize, Some(inf.len as u64)) || !inr(s.ep, inf.ep.map(|e| e as u64)) || !inr(s.nsec, Some(inf.secs.len() as u64)) {
                continue;
            }
            if s.expr.eval(c).0 {
                out.push(self.names.get(s.name).to_string());
            }
        }
    }
}

pub struct Db {
    gen: Part,
    /// file-type magic (daily.ftm, fixed-offset entries): (offset, bytes, text-like type)
    ftm: Vec<(usize, Vec<u8>, bool)>,
    fp: [HashIdx; 3],
    fp_any: HashSet<Vec<u8>>,
    ign: HashSet<String>,
    pe: Mutex<Option<(Arc<Part>, Instant)>>,
    sources: Vec<PathBuf>,
    pua: bool,
    pub version: String,
    dir: PathBuf,
    stamp: Vec<(PathBuf, Option<std::time::SystemTime>)>,
}

fn stamp(dir: &Path) -> Vec<(PathBuf, Option<std::time::SystemTime>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten()
        .map(|e| (e.path(), e.metadata().and_then(|m| m.modified()).ok())).collect();
    v.sort();
    v
}

fn ext_of(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or("")
}

impl Db {
    /// Load the general (non-PE) part of every database in `dir`.
    pub fn load(dir: &Path, pua: bool) -> Result<Db, String> {
        let srcs = sources(dir, pua)?;
        for s in &srcs {
            if s.extension().is_some_and(|e| e == "cvd") {
                verify_cvd(s)?;
            }
        }
        let mut gen = Part::default();
        let mut fp: [HashIdx; 3] = Default::default();
        let mut fp_any = HashSet::new();
        let mut ign = HashSet::new();
        let mut ftm = vec![];
        let mut versions = vec![];
        for s in &srcs {
            if let Ok(h) = cvd_header(s) {
                versions.push(format!("{} {}", s.file_name().and_then(|n| n.to_str()).unwrap_or(""), h.get(2).map_or("", |v| v.as_str())));
            }
            each_member(s, &mut |name, r| {
                let ext = ext_of(name);
                let pua_ok = pua && PUA_EXT.contains(&ext);
                match ext {
                    "hdb" | "hsb" => lines(r, |l| gen.add_hash_line(l)),
                    "hdu" | "hsu" if pua_ok => lines(r, |l| gen.add_hash_line(l)),
                    "fp" | "sfp" => lines(r, |l| {
                        let f: Vec<&str> = l.split(':').collect();
                        let Some(h) = f.first().and_then(|h| unhex(h)) else { return };
                        let Some(kind) = hash_kind(h.len()) else { return };
                        match f.get(1).and_then(|s| s.parse::<u32>().ok()) {
                            Some(size) => fp[kind].tmp.push((size, prefix(&h))),
                            None => {
                                fp_any.insert(h);
                            }
                        }
                    }),
                    "ftm" => lines(r, |l| {
                        let f: Vec<&str> = l.split(':').collect();
                        if f.len() >= 6 && f[0] == "0" && f[4] == "CL_TYPE_ANY" && flevel_ok(f.get(6).copied(), f.get(7).copied()) {
                            if let (Ok(o), Some(m)) = (f[1].parse::<usize>(), unhex(f[2])) {
                                let texty = ["TEXT", "HTML", "MAIL", "SCRIPT"].iter().any(|t| f[5].contains(t));
                                ftm.push((o, m, texty));
                            }
                        }
                    }),
                    "ign" | "ign2" => lines(r, |l| {
                        let n = if ext == "ign" { l.rsplit(':').next().unwrap_or(l) } else { l.split(':').next().unwrap_or(l) };
                        ign.insert(n.to_string());
                    }),
                    "ndb" => lines(r, |l| gen.add_ndb(l, false)),
                    "ndu" if pua_ok => lines(r, |l| gen.add_ndb(l, false)),
                    "ldb" => lines(r, |l| gen.add_ldb(l, false)),
                    "ldu" if pua_ok => lines(r, |l| gen.add_ldb(l, false)),
                    _ => {}
                }
            })?;
        }
        gen.finish();
        for f in fp.iter_mut() {
            f.finish();
        }
        let version = if versions.is_empty() { format!("{} signature file(s) in {}", srcs.len(), dir.display()) } else { versions.join(", ") };
        Ok(Db { gen, ftm, fp, fp_any, ign, pe: Mutex::new(None), sources: srcs, pua, version,
            dir: dir.to_path_buf(), stamp: stamp(dir) })
    }

    /// The Windows part, loaded on first use and kept until `release_idle_pe`.
    fn pe_part(&self) -> Arc<Part> {
        let mut g = self.pe.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((p, t)) = g.as_mut() {
            *t = Instant::now();
            return p.clone();
        }
        let mut p = Part::default();
        for s in &self.sources {
            let r = each_member(s, &mut |name, r| {
                let ext = ext_of(name);
                let pua_ok = self.pua && PUA_EXT.contains(&ext);
                match ext {
                    "mdb" | "msb" => lines(r, |l| p.add_section_line(l)),
                    "mdu" | "msu" if pua_ok => lines(r, |l| p.add_section_line(l)),
                    "ndb" => lines(r, |l| p.add_ndb(l, true)),
                    "ndu" if pua_ok => lines(r, |l| p.add_ndb(l, true)),
                    "ldb" => lines(r, |l| p.add_ldb(l, true)),
                    "ldu" if pua_ok => lines(r, |l| p.add_ldb(l, true)),
                    _ => {}
                }
            });
            if let Err(e) = r {
                eprintln!("ratel: clamav PE signatures: {e}");
            }
        }
        p.finish();
        let p = Arc::new(p);
        *g = Some((p.clone(), Instant::now()));
        p
    }

    /// Whether clamscan would type this file as text and scan its normalized form:
    /// the first matching file-type magic decides, else `cli_texttype`.
    fn text_pass(&self, d: &[u8], ft: FType) -> bool {
        if matches!(ft, FType::Pe | FType::Elf | FType::MachO) {
            return false;
        }
        let head = &d[..d.len().min(1024)];
        if let Some((_, _, texty)) = self.ftm.iter().find(|(o, m, _)| head.get(*o..*o + m.len()) == Some(&m[..])) {
            return *texty;
        }
        if ftype::detect_magic_only(d) {
            return false;
        }
        ftype::texttype(d)
    }

    /// The database directory changed since loading (freshclam updated it).
    pub fn changed(&self) -> bool {
        stamp(&self.dir) != self.stamp
    }

    /// Load a fresh copy of the same databases.
    pub fn reload(&self) -> Result<Db, String> {
        Db::load(&self.dir, self.pua)
    }

    /// Load the Windows part now (so a later scan doesn't stall on it).
    pub fn preload_pe(&self) {
        self.pe_part();
    }

    /// Free the Windows part if no PE file was scanned for `idle`. Returns true if freed.
    pub fn release_idle_pe(&self, idle: Duration) -> bool {
        let mut g = self.pe.lock().unwrap_or_else(|e| e.into_inner());
        if g.as_ref().is_some_and(|(_, t)| t.elapsed() >= idle) {
            *g = None;
            return true;
        }
        false
    }

    pub fn stats(&self) -> (Stats, Option<Stats>) {
        let pe = self.pe.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|(p, _)| p.stats.clone());
        (self.gen.stats.clone(), pe)
    }

    /// Names of hash signatures with exactly this (size, full hash), read from the
    /// database files (only the 64-bit prefix is kept in memory).
    fn resolve_hash(&self, section: bool, size: u32, h: &[u8]) -> Vec<String> {
        let want: &[&str] = if section { &["mdb", "msb", "mdu", "msu"] } else { &["hdb", "hsb", "hdu", "hsu"] };
        let mut out = vec![];
        for s in &self.sources {
            let _ = each_member(s, &mut |name, r| {
                let ext = ext_of(name);
                if !want.contains(&ext) || (ext.ends_with('u') && !self.pua) {
                    return;
                }
                lines(r, |l| {
                    let f: Vec<&str> = l.split(':').collect();
                    if f.len() < 3 || !flevel_ok(f.get(3).copied(), f.get(4).copied()) {
                        return;
                    }
                    let (hs, ss) = if section { (f[1], f[0]) } else { (f[0], f[1]) };
                    if ss.parse::<u32>().ok() == Some(size) && unhex(hs).as_deref() == Some(h) {
                        out.push(f[2].to_string());
                    }
                });
            });
        }
        out
    }

    /// Names of the signatures `d` matches (empty when clean or allowlisted by .fp/.sfp).
    pub fn scan(&self, d: &[u8]) -> Vec<String> {
        self.scan_full(d).0
    }

    /// `scan`, plus whether a matching budget ran out (the file wasn't fully checked:
    /// crafted input can try to exhaust a pattern before its real occurrence).
    pub fn scan_full(&self, d: &[u8]) -> (Vec<String>, bool) {
        if d.len() <= 5 {
            return (vec![], false); // clamscan never scans files this small
        }
        let mut limited = false;
        let mut lookups = 0usize;
        let size = d.len() as u32;
        let hashes: [std::cell::OnceCell<Vec<u8>>; 3] = Default::default();
        let hash = |k: usize| -> &[u8] {
            hashes[k].get_or_init(|| match k {
                0 => md5::md5(d).to_vec(),
                1 => { use sha1::Digest; sha1::Sha1::digest(d).to_vec() }
                _ => { use sha2::Digest; sha2::Sha256::digest(d).to_vec() }
            })
        };
        // allowlisted by ClamAV's own false-positive lists
        if (0..3).any(|k| self.fp[k].has_size(size) && self.fp[k].contains(size, hash(k)))
            || (!self.fp_any.is_empty() && (0..3).any(|k| self.fp_any.contains(hash(k))))
        {
            return (vec![], false);
        }
        let mut out = vec![];
        let g = &self.gen;
        for k in 0..3 {
            if g.whole[k].has_size(size) && g.whole[k].contains(size, hash(k)) {
                lookups += 1;
                out.extend(self.resolve_hash(false, size, hash(k)));
            }
        }
        for (h, n) in &g.star {
            if hash_kind(h.len()).is_some_and(|k| hash(k) == &h[..]) {
                out.push(g.names.get(*n).to_string());
            }
        }

        let ft = ftype::detect(d);
        let inf = ftype::info(d, ft);
        let mut h = Hits::new();
        g.scan_group(0, d, &inf, &mut h);
        if let Some(t) = ft.raw_target().filter(|&t| t != 1) {
            g.scan_group(t, d, &inf, &mut h);
        }
        out.extend(h.names.iter().map(|&i| g.names.get(i).to_string()));
        g.eval_ldbs(&h, &inf, &mut out);
        limited |= h.limited;
        // text gets a second pass over the normalized buffer: target 0 and 7 (and 3 for
        // HTML), with its own logical-signature counts, as clamscan does
        if self.text_pass(d, ft) {
            let n = ftype::norm_text(d);
            let ni = ftype::Info { len: n.len(), ..Default::default() };
            let mut th = Hits::new();
            g.scan_group(0, &n, &ni, &mut th);
            g.scan_group(7, &n, &ni, &mut th);
            if ft == FType::Html {
                let hn = ftype::norm_html(d);
                let hi = ftype::Info { len: hn.len(), ..Default::default() };
                g.scan_group(3, &hn, &hi, &mut th);
            }
            out.extend(th.names.iter().map(|&i| g.names.get(i).to_string()));
            g.eval_ldbs(&th, &ni, &mut out);
            limited |= th.limited;
        }
        if ft == FType::Pe {
            let p = self.pe_part();
            if inf.pe32 {
                // crafted headers can list 65535 overlapping sections: bound the work
                let mut done: HashSet<(usize, usize)> = HashSet::new();
                if inf.secs.len() > MAX_PE_SECTIONS {
                    limited = true;
                }
                for &(o, l) in inf.secs.iter().take(MAX_PE_SECTIONS) {
                    if l == 0 || o.saturating_add(l) > d.len() || !done.insert((o, l)) {
                        continue;
                    }
                    let (sec, ls) = (&d[o..o + l], l as u32);
                    let star = |k: usize| p.sect_star.iter().any(|(h, _)| hash_kind(h.len()) == Some(k));
                    for k in 0..3 {
                        if p.sect[k].has_size(ls) || star(k) {
                            let hk: Vec<u8> = match k {
                                0 => md5::md5(sec).to_vec(),
                                1 => { use sha1::Digest; sha1::Sha1::digest(sec).to_vec() }
                                _ => { use sha2::Digest; sha2::Sha256::digest(sec).to_vec() }
                            };
                            if p.sect[k].contains(ls, &hk) {
                                if lookups < MAX_HASH_LOOKUPS {
                                    lookups += 1;
                                    out.extend(self.resolve_hash(true, ls, &hk));
                                } else {
                                    limited = true;
                                }
                            }
                            out.extend(p.sect_star.iter().filter(|(h, _)| h[..] == hk[..]).map(|(_, n)| p.names.get(*n).to_string()));
                        }
                    }
                }
            }
            let mut ph = Hits::new();
            p.scan_group(1, d, &inf, &mut ph);
            out.extend(ph.names.iter().map(|&i| p.names.get(i).to_string()));
            p.eval_ldbs(&ph, &inf, &mut out);
            limited |= ph.limited;
        }
        out.retain(|n| !self.ign.contains(n));
        out.sort();
        out.dedup();
        (out, limited)
    }
}

impl Part {
    fn add_hash_line(&mut self, l: &str) {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 3 || !flevel_ok(f.get(3).copied(), f.get(4).copied()) || (f[1] == "*" && f.get(3).is_none()) {
            return skip(&mut self.stats, "hash: malformed or level");
        }
        match self.add_hash(f[0], f[1], f[2], false) {
            Ok(()) => self.stats.hashes += 1,
            Err(e) => skip(&mut self.stats, e),
        }
    }

    fn add_section_line(&mut self, l: &str) {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 3 || !flevel_ok(f.get(3).copied(), f.get(4).copied()) {
            return skip(&mut self.stats, "section hash: malformed or level");
        }
        match self.add_hash(f[1], f[0], f[2], true) {
            Ok(()) => self.stats.section_hashes += 1,
            Err(e) => skip(&mut self.stats, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_with(files: &[(&str, &str)]) -> (Db, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("ratel-clamav-{}-{}", std::process::id(), files.len()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (n, c) in files {
            std::fs::write(d.join(n), c).unwrap();
            std::fs::set_permissions(d.join(n), std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        (Db::load(&d, false).unwrap(), d)
    }

    #[test]
    fn hashes_bodies_logical_and_lists() {
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let ndb = "Test.Body-1:0:*:6576696c{2-4}7061796c6f6164\nTest.Fixed-1:0:4:4142\nTest.Eof-1:0:EOF-2:7a7a\nTest.Elf-1:6:*:73656372657421\n";
        let ldb = "Test.Logic-1;Engine:51-255,Target:0;(0&1)|2>1;6f6e65;74776f::i;7468726565\nTest.Wide-1;Target:0;0;4142::w\nTest.Word-1;Target:0;0;6b6579::f\nTest.Count-1;Target:0;0=2;787878\n";
        let (db, dir) = db_with(&[
            ("t.hdb", "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n"),
            ("t.ndb", ndb),
            ("t.ldb", ldb),
            ("t.ign2", "Test.Ignored-1\n"),
        ]);
        assert_eq!(db.scan(eicar), vec!["Eicar-Test-Signature"]);
        assert_eq!(db.scan(b"...evil--payload..."), vec!["Test.Body-1"]);
        assert!(db.scan(b"...evil-----payload").is_empty(), "gap too long");
        assert_eq!(db.scan(b"....AB.."), vec!["Test.Fixed-1"]);
        assert_eq!(db.scan(b"hello zz"), vec!["Test.Eof-1"]);
        assert!(db.scan(b"zz hello").is_empty());
        assert_eq!(db.scan(b"one ... TWO"), vec!["Test.Logic-1"]);
        assert_eq!(db.scan(b"three, three"), vec!["Test.Logic-1"]);
        assert!(db.scan(b"three only once").is_empty());
        assert_eq!(db.scan(b"..A\0B\0.."), vec!["Test.Wide-1"]);
        assert_eq!(db.scan(b"a key here"), vec!["Test.Word-1"]);
        assert!(db.scan(b"a keyboard").is_empty(), "fullword");
        assert_eq!(db.scan(b"xxx xxx"), vec!["Test.Count-1"]);
        assert!(db.scan(b"xxx xxx xxx").is_empty(), "exactly two");
        assert!(db.scan(b"text secret!").is_empty(), "ELF-only signature on text");
        // an .fp entry allowlists the file entirely
        std::fs::write(dir.join("t.fp"), "44d88612fea8a8f36de82e1278abb02f:68:allow\n").unwrap();
        let db2 = Db::load(&dir, false).unwrap();
        assert!(db2.scan(eicar).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expressions() {
        let e = parse_expr("0|1&(2&3)").unwrap();
        assert!(e.eval(&[1, 0, 0, 0]).0);
        assert!(!e.eval(&[0, 1, 1, 0]).0);
        assert!(e.eval(&[0, 1, 1, 1]).0);
        let g = parse_expr("(0|1|2)>1,2").unwrap();
        assert!(!g.eval(&[5, 0, 0]).0, "needs 2 distinct");
        assert!(g.eval(&[1, 1, 0]).0);
        assert!(parse_expr("0&").is_err());
    }

    #[test]
    fn offsets() {
        let i = ftype::Info { len: 100, ep: Some(40), secs: vec![(10, 20), (60, 30)], pe32: true };
        assert_eq!(parse_off("EP+4,2").unwrap().range(&i), Some((44, 46)));
        assert_eq!(parse_off("EP-50").unwrap().range(&i), None);
        assert_eq!(parse_off("S1+2").unwrap().range(&i), Some((62, 62)));
        assert_eq!(parse_off("SE0").unwrap().range(&i), Some((10, 29)));
        assert_eq!(parse_off("SL+0").unwrap().range(&i), Some((60, 60)));
        assert_eq!(parse_off("EOF-10").unwrap().range(&i), Some((90, 90)));
        assert!(parse_off("VI").is_err());
    }
}
