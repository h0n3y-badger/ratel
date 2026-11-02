//! ClamAV body-signature patterns (the hex syntax of .ndb and .ldb subsignatures):
//! parsing into a compact bytecode, and backtracking matching around an anchor.
//!
//! Bytecode (one pattern is a few bytes per signature byte, not a token list: the
//! Windows signatures alone have ~900k subsignatures):
//!   RUN n b1..bn          n exact bytes
//!   MASK v m              one byte with (byte & m) == v  (nibble / ?? wildcards)
//!   GAP min:u32 max:u32   skip min..=max bytes (max = INF for `*`)
//!   ALT neg n {len (v m)*len}*n   alternatives; negated ones are all one length

pub const INF: u32 = u32::MAX;
const RUN: u8 = 1;
const MASK: u8 = 2;
const GAP: u8 = 3;
const ALT: u8 = 4;

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    B(u8, u8),
    Alt(Vec<Vec<(u8, u8)>>, bool),
    Gap(u32, u32),
}

fn nib(c: u8) -> Option<(u8, u8)> {
    match c {
        b'?' => Some((0, 0)),
        b'0'..=b'9' => Some((c - b'0', 0xf)),
        b'a'..=b'f' => Some((c - b'a' + 10, 0xf)),
        b'A'..=b'F' => Some((c - b'A' + 10, 0xf)),
        _ => None,
    }
}

fn byte_at(s: &[u8], i: usize) -> Option<(u8, u8)> {
    let (h, hm) = nib(*s.get(i)?)?;
    let (l, lm) = nib(*s.get(i + 1)?)?;
    Some(((h << 4) | l, (hm << 4) | lm))
}

fn num(s: &str) -> Result<u32, String> {
    s.parse::<u32>().map_err(|_| format!("bad number {s:?}"))
}

/// Parse a ClamAV hex signature. Unsupported syntax ((B)/(L)/(W) markers, `~`
/// negation from functionality level 240) is an error: the signature is skipped.
pub fn parse_hex(sig: &str) -> Result<Vec<Tok>, String> {
    let s = sig.as_bytes();
    let mut t = vec![];
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'*' => {
                t.push(Tok::Gap(0, INF));
                i += 1;
            }
            b'{' | b'[' => {
                let close = if s[i] == b'{' { b'}' } else { b']' };
                let end = s[i..].iter().position(|&c| c == close).ok_or("unterminated range")? + i;
                let body = std::str::from_utf8(&s[i + 1..end]).map_err(|_| "bad range")?;
                let (a, b) = match body.split_once('-') {
                    None => (num(body)?, num(body)?),
                    Some(("", b)) => (0, num(b)?),
                    Some((a, "")) => (num(a)?, INF),
                    Some((a, b)) => (num(a)?, num(b)?),
                };
                if b < a {
                    return Err("inverted range".into());
                }
                t.push(Tok::Gap(a, b));
                i = end + 1;
            }
            b'!' | b'(' => {
                let neg = s[i] == b'!';
                if neg {
                    i += 1;
                    if s.get(i) != Some(&b'(') {
                        return Err("! without (".into());
                    }
                }
                if matches!(s.get(i + 1..i + 3), Some(b"B)") | Some(b"L)") | Some(b"W)")) {
                    return Err("(B)/(L)/(W) markers not supported".into());
                }
                i += 1;
                let mut opts = vec![vec![]];
                loop {
                    match s.get(i) {
                        None => return Err("unterminated alternative".into()),
                        Some(b')') => {
                            i += 1;
                            break;
                        }
                        Some(b'|') => {
                            opts.push(vec![]);
                            i += 1;
                        }
                        Some(b'{') => {
                            let end = s[i..].iter().position(|&c| c == b'}').ok_or("unterminated range")? + i;
                            let n = num(std::str::from_utf8(&s[i + 1..end]).map_err(|_| "bad range")?)?;
                            if n >= 128 {
                                return Err("range in alternative too large".into());
                            }
                            opts.last_mut().unwrap().extend(std::iter::repeat_n((0u8, 0u8), n as usize));
                            i = end + 1;
                        }
                        Some(_) => {
                            let b = byte_at(s, i).ok_or_else(|| format!("bad byte in alternative at {i}"))?;
                            opts.last_mut().unwrap().push(b);
                            i += 2;
                        }
                    }
                }
                if opts.iter().any(|o| o.is_empty() || o.len() > 255) || opts.len() > 255 {
                    return Err("bad alternative".into());
                }
                if neg && opts.iter().any(|o| o.len() != opts[0].len()) {
                    return Err("negated alternatives must have one length".into());
                }
                t.push(Tok::Alt(opts, neg));
            }
            _ => {
                let b = byte_at(s, i).ok_or_else(|| format!("unsupported syntax at {i}: {:?}", s[i] as char))?;
                t.push(Tok::B(b.0, b.1));
                i += 2;
            }
        }
    }
    if t.is_empty() {
        return Err("empty".into());
    }
    Ok(t)
}

/// UTF-16LE form (`::w`): every byte followed by a NUL. Gaps are not widened.
pub fn widen(t: &[Tok]) -> Vec<Tok> {
    let mut o = vec![];
    for x in t {
        match x {
            Tok::B(v, m) => {
                o.push(Tok::B(*v, *m));
                o.push(Tok::B(0, 0xff));
            }
            Tok::Alt(opts, neg) => o.push(Tok::Alt(opts.iter().map(|op| op.iter().flat_map(|&b| [b, (0, 0xff)]).collect()).collect(), *neg)),
            Tok::Gap(a, b) => o.push(Tok::Gap(*a, *b)),
        }
    }
    o
}

/// `::i`: exact letters compared lower-case.
pub fn lower(t: &mut [Tok]) {
    for x in t.iter_mut() {
        match x {
            Tok::B(v, 0xff) => *v = v.to_ascii_lowercase(),
            Tok::Alt(opts, _) => {
                for op in opts {
                    for (v, m) in op.iter_mut() {
                        if *m == 0xff {
                            *v = v.to_ascii_lowercase();
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn encode(t: &[Tok], reverse: bool) -> Vec<u8> {
    let mut c = vec![];
    let toks: Vec<&Tok> = if reverse { t.iter().rev().collect() } else { t.iter().collect() };
    let mut i = 0;
    while i < toks.len() {
        match toks[i] {
            Tok::B(_, 0xff) => {
                let mut run = vec![];
                while let Some(Tok::B(v, 0xff)) = toks.get(i) {
                    if run.len() == 255 {
                        break;
                    }
                    run.push(*v);
                    i += 1;
                }
                c.push(RUN);
                c.push(run.len() as u8);
                c.extend(run);
                continue;
            }
            Tok::B(v, m) => c.extend([MASK, *v, *m]),
            Tok::Gap(a, b) => {
                c.push(GAP);
                c.extend(a.to_le_bytes());
                c.extend(b.to_le_bytes());
            }
            Tok::Alt(opts, neg) => {
                c.extend([ALT, *neg as u8, opts.len() as u8]);
                for o in opts {
                    c.push(o.len() as u8);
                    let it: Box<dyn Iterator<Item = &(u8, u8)>> = if reverse { Box::new(o.iter().rev()) } else { Box::new(o.iter()) };
                    for (v, m) in it {
                        c.extend([*v, *m]);
                    }
                }
            }
        }
        i += 1;
    }
    c
}

/// The best anchor: a window of up to 12 exact bytes inside the longest exact run,
/// with as many distinct byte values as possible. Returns (first token, token count).
#[cfg(test)]
pub fn anchor(t: &[Tok]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut i = 0;
    while i < t.len() {
        if matches!(t[i], Tok::B(_, 0xff)) {
            let s = i;
            while i < t.len() && matches!(t[i], Tok::B(_, 0xff)) {
                i += 1;
            }
            let len = i - s;
            if best.is_none_or(|(_, l)| len > l) {
                best = Some((s, len));
            }
        } else {
            i += 1;
        }
    }
    let (s, len) = best.filter(|&(_, l)| l >= 2)?;
    let w = len.min(12);
    let score = |k: usize| {
        let mut seen = [false; 256];
        let mut n = 0;
        for x in &t[k..k + w] {
            if let Tok::B(v, _) = x {
                if !seen[*v as usize] {
                    seen[*v as usize] = true;
                    n += 1;
                }
            }
        }
        n
    };
    let k = (s..=s + len - w).max_by_key(|&k| (score(k), std::cmp::Reverse(k)))?;
    Some((k, w))
}

pub fn anchor_bytes(t: &[Tok], a: (usize, usize)) -> Vec<u8> {
    t[a.0..a.0 + a.1].iter().map(|x| if let Tok::B(v, _) = x { *v } else { 0 }).collect()
}

/// Backtracking matcher over the bytecode with a step budget (patterns with several
/// `*` gaps could otherwise go quadratic on hostile input).
pub struct M<'a> {
    pub d: &'a [u8],
    pub nc: bool,
    pub budget: u32,
    /// Per-pattern memo for unbounded (`*`) gaps, keyed by (forward?, pc):
    /// [failed-at, succeeded-at]. What follows a `*` matches from position s iff it
    /// matches somewhere after s, so one result settles every later (forward) or
    /// earlier (backward) query: repeated anchor hits don't rescan the file.
    pub memo: Option<&'a mut Memo>,
}

pub type Memo = std::collections::HashMap<(bool, u32), [Option<usize>; 2]>;

impl M<'_> {
    fn memo_get(&self, fwd: bool, pc: usize, pos: usize) -> Option<bool> {
        let [fail, succ] = *self.memo.as_ref()?.get(&(fwd, pc as u32))?;
        if fwd {
            if fail.is_some_and(|f| pos >= f) {
                return Some(false);
            }
            if succ.is_some_and(|s| pos <= s) {
                return Some(true);
            }
        } else {
            if fail.is_some_and(|f| pos <= f) {
                return Some(false);
            }
            if succ.is_some_and(|s| pos >= s) {
                return Some(true);
            }
        }
        None
    }

    fn memo_put(&mut self, fwd: bool, pc: usize, pos: usize, ok: bool) {
        let Some(m) = self.memo.as_mut() else { return };
        let e = m.entry((fwd, pc as u32)).or_insert([None, None]);
        let (k, better): (usize, fn(usize, usize) -> usize) = match (fwd, ok) {
            (true, false) => (0, usize::min),
            (true, true) => (1, usize::max),
            (false, false) => (0, usize::max),
            (false, true) => (1, usize::min),
        };
        e[k] = Some(e[k].map_or(pos, |o| better(o, pos)));
    }
}

#[inline]
fn eq(d: u8, v: u8, m: u8, nc: bool) -> bool {
    let d = if nc && m == 0xff { d.to_ascii_lowercase() } else { d };
    d & m == v & m
}

fn u32at(c: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([c[i], c[i + 1], c[i + 2], c[i + 3]])
}

impl M<'_> {
    /// Match `c[pc..]` forwards from `pos`; `fin(end)` accepts or rejects a complete match.
    pub fn fwd(&mut self, c: &[u8], pc: usize, pos: usize, fin: &mut dyn FnMut(usize) -> bool) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        let d = self.d;
        if pc >= c.len() {
            return fin(pos);
        }
        match c[pc] {
            RUN => {
                let n = c[pc + 1] as usize;
                let run = &c[pc + 2..pc + 2 + n];
                if pos + n > d.len() {
                    return false;
                }
                let ok = if self.nc { d[pos..pos + n].iter().zip(run).all(|(a, b)| a.to_ascii_lowercase() == *b) } else { &d[pos..pos + n] == run };
                ok && self.fwd(c, pc + 2 + n, pos + n, fin)
            }
            MASK => pos < d.len() && eq(d[pos], c[pc + 1], c[pc + 2], self.nc) && self.fwd(c, pc + 3, pos + 1, fin),
            GAP => {
                let inf = u32at(c, pc + 5) == INF;
                if inf {
                    if let Some(r) = self.memo_get(true, pc, pos) {
                        return r;
                    }
                }
                let r = self.gap_fwd(c, pc, pos, fin);
                if inf && (r || self.budget > 0) {
                    self.memo_put(true, pc, pos, r);
                }
                r
            }
            ALT => {
                let (neg, n) = (c[pc + 1] != 0, c[pc + 2] as usize);
                let mut q = pc + 3;
                let mut opts = vec![];
                for _ in 0..n {
                    let l = c[q] as usize;
                    opts.push((q + 1, l));
                    q += 1 + 2 * l;
                }
                let nc = self.nc;
                let at = |o: usize, l: usize| pos + l <= d.len() && (0..l).all(|k| eq(d[pos + k], c[o + 2 * k], c[o + 2 * k + 1], nc));
                if neg {
                    let l = opts[0].1;
                    pos + l <= d.len() && !opts.iter().any(|&(o, l)| at(o, l)) && self.fwd(c, q, pos + l, fin)
                } else {
                    for (o, l) in opts {
                        if at(o, l) && self.fwd(c, q, pos + l, fin) {
                            return true;
                        }
                    }
                    false
                }
            }
            _ => false,
        }
    }

    fn gap_fwd(&mut self, c: &[u8], pc: usize, pos: usize, fin: &mut dyn FnMut(usize) -> bool) -> bool {
        let d = self.d;
        {
            {
                let (a, b) = (u32at(c, pc + 1) as usize, u32at(c, pc + 5));
                let next = pc + 9;
                let lo = pos.saturating_add(a);
                if lo > d.len() {
                    return false;
                }
                let hi = if b == INF { d.len() } else { pos.saturating_add(b as usize).min(d.len()) };
                // jump straight to occurrences of the next fixed run (substring search:
                // searching for its first byte alone burns the budget on common bytes)
                if next < c.len() && c[next] == RUN && !self.nc {
                    let run = &c[next + 2..next + 2 + c[next + 1] as usize];
                    let end = (hi + run.len()).min(d.len());
                    let mut s = lo;
                    while s <= hi && s < end {
                        match memchr::memmem::find(&d[s..end], run) {
                            Some(k) => {
                                if self.fwd(c, next, s + k, fin) {
                                    return true;
                                }
                                if self.budget == 0 {
                                    return false;
                                }
                                s += k + 1;
                            }
                            None => break,
                        }
                    }
                    return false;
                }
                for s in lo..=hi {
                    if self.fwd(c, next, s, fin) {
                        return true;
                    }
                    if self.budget == 0 {
                        return false;
                    }
                }
                false
            }
        }
    }

    /// Match reversed bytecode backwards, ending (exclusive) at `pos`; `fin(start)`.
    pub fn bwd(&mut self, c: &[u8], pc: usize, pos: usize, fin: &mut dyn FnMut(usize) -> bool) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        let d = self.d;
        if pc >= c.len() {
            return fin(pos);
        }
        match c[pc] {
            RUN => {
                let n = c[pc + 1] as usize;
                let run = &c[pc + 2..pc + 2 + n]; // reversed
                if pos < n {
                    return false;
                }
                let ok = (0..n).all(|k| {
                    let x = d[pos - 1 - k];
                    (if self.nc { x.to_ascii_lowercase() } else { x }) == run[k]
                });
                ok && self.bwd(c, pc + 2 + n, pos - n, fin)
            }
            MASK => pos > 0 && eq(d[pos - 1], c[pc + 1], c[pc + 2], self.nc) && self.bwd(c, pc + 3, pos - 1, fin),
            GAP => {
                let inf = u32at(c, pc + 5) == INF;
                if inf {
                    if let Some(r) = self.memo_get(false, pc, pos) {
                        return r;
                    }
                }
                let r = self.gap_bwd(c, pc, pos, fin);
                if inf && (r || self.budget > 0) {
                    self.memo_put(false, pc, pos, r);
                }
                r
            }
            ALT => {
                let (neg, n) = (c[pc + 1] != 0, c[pc + 2] as usize);
                let mut q = pc + 3;
                let mut opts = vec![];
                for _ in 0..n {
                    let l = c[q] as usize;
                    opts.push((q + 1, l));
                    q += 1 + 2 * l;
                }
                let nc = self.nc;
                let at = |o: usize, l: usize| pos >= l && (0..l).all(|k| eq(d[pos - 1 - k], c[o + 2 * k], c[o + 2 * k + 1], nc));
                if neg {
                    let l = opts[0].1;
                    pos >= l && !opts.iter().any(|&(o, l)| at(o, l)) && self.bwd(c, q, pos - l, fin)
                } else {
                    for (o, l) in opts {
                        if at(o, l) && self.bwd(c, q, pos - l, fin) {
                            return true;
                        }
                    }
                    false
                }
            }
            _ => false,
        }
    }

    fn gap_bwd(&mut self, c: &[u8], pc: usize, pos: usize, fin: &mut dyn FnMut(usize) -> bool) -> bool {
        let d = self.d;
        let (a, b) = (u32at(c, pc + 1) as usize, u32at(c, pc + 5));
        let next = pc + 9;
        if pos < a {
            return false;
        }
        let hi = pos - a;
        let lo = if b == INF { 0 } else { pos.saturating_sub(b as usize) };
        // jump straight to occurrences of the previous fixed run, which must end at a
        // candidate position s in lo..=hi (the run is stored reversed)
        if next < c.len() && c[next] == RUN && !self.nc && hi > 0 {
            let n = c[next + 1] as usize;
            let run: Vec<u8> = c[next + 2..next + 2 + n].iter().rev().copied().collect();
            let base = lo.saturating_sub(n);
            let mut e = hi;
            while e > base {
                match memchr::memmem::rfind(&d[base..e], &run) {
                    Some(j) => {
                        let at = base + j + n;
                        if at >= lo && self.bwd(c, next, at, fin) {
                            return true;
                        }
                        if self.budget == 0 {
                            return false;
                        }
                        e = base + j + n - 1;
                    }
                    None => break,
                }
            }
            return false;
        }
        for s in (lo..=hi).rev() {
            if self.bwd(c, next, s, fin) {
                return true;
            }
            if self.budget == 0 {
                return false;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(sig: &str, data: &[u8], nc: bool) -> Option<usize> {
        let mut t = parse_hex(sig).unwrap();
        if nc {
            lower(&mut t);
        }
        let code = encode(&t, false);
        for s in 0..=data.len() {
            let mut m = M { d: data, nc, budget: 100_000, memo: None };
            if m.fwd(&code, 0, s, &mut |_| true) {
                return Some(s);
            }
        }
        None
    }

    #[test]
    fn syntax() {
        assert_eq!(find("6162", b"xxab", false), Some(2));
        assert_eq!(find("61??63", b"..a.c", false), Some(2));
        assert_eq!(find("6?62", b"ob", false), Some(0));
        assert_eq!(find("61*7a", b"a---------z", false), Some(0));
        assert_eq!(find("61{2-3}64", b"a12d", false), Some(0));
        assert_eq!(find("61{2-3}64", b"a1d", false), None);
        assert_eq!(find("61{-1}64", b"ad", false), Some(0));
        assert_eq!(find("61[1-2]64", b"axxd", false), Some(0));
        assert_eq!(find("61(62|6363)64", b"accd", false), Some(0));
        assert_eq!(find("61!(62|63)64", b"abd acd azd", false), Some(8));
        assert_eq!(find("4142", b"zab", true), Some(1));
        assert!(parse_hex("41(B)42").is_err());
        assert!(parse_hex("~4142").is_err());
        assert_eq!(widen(&parse_hex("41").unwrap()), vec![Tok::B(0x41, 0xff), Tok::B(0, 0xff)]);
    }

    #[test]
    fn anchored_both_ways() {
        let t = parse_hex("61{1-2}626364*7a").unwrap();
        let a = anchor(&t).unwrap();
        assert_eq!(anchor_bytes(&t, a), b"bcd");
        let pre = encode(&t[..a.0], true);
        let post = encode(&t[a.0 + a.1..], false);
        let d = b"..a.bcd....z";
        let mut m = M { d, nc: false, budget: 1000, memo: None };
        let mut start = None;
        assert!(m.bwd(&pre, 0, 4, &mut |s| { start = Some(s); true }));
        assert_eq!(start, Some(2));
        assert!(m.fwd(&post, 0, 7, &mut |e| e == 12));
    }

    #[test]
    fn star_gaps_are_memoised() {
        // "ab*cd" anchored on "ab" thousands of times in a file with no "cd": one scan
        let t = parse_hex("6162*6364").unwrap();
        let post = encode(&t[2..], false);
        let d: Vec<u8> = b"ab".repeat(50_000);
        let mut memo = Memo::new();
        let mut steps = 0;
        for pos in (0..d.len()).step_by(2) {
            let mut m = M { d: &d, nc: false, budget: 1_000_000, memo: Some(&mut memo) };
            assert!(!m.fwd(&post, 0, pos + 2, &mut |_| true));
            steps += 1_000_000 - m.budget;
        }
        assert!(steps < 200_000, "{steps} steps");
        let d2 = [b"ab".repeat(10), b"cd".to_vec()].concat();
        let mut memo = Memo::new();
        for pos in (0..20).step_by(2) {
            let mut m = M { d: &d2, nc: false, budget: 1000, memo: Some(&mut memo) };
            assert!(m.fwd(&post, 0, pos + 2, &mut |_| true));
        }
    }

    #[test]
    fn hostile_input_is_bounded() {
        let code = encode(&parse_hex("61*61*61*61*61*62").unwrap(), false);
        let d = vec![b'a'; 100_000];
        let mut m = M { d: &d, nc: false, budget: 50_000, memo: None };
        assert!(!m.fwd(&code, 0, 0, &mut |_| true));
        assert_eq!(m.budget, 0);
    }
}
