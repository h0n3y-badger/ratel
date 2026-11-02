#!/usr/bin/env python3
"""ClamAV signature parity harness: ratel's ClamAV matcher vs the real clamscan.

For a seeded sample of real body (.ndb) and logical (.ldb) signatures this builds
one minimal file per signature that satisfies it (wildcards, gaps, alternatives,
modifiers, offsets, logical expressions with counts, FileSize/NumberOfSections),
wrapped in a PE / ELF / Mach-O container when the target type needs one. Hash
signatures cannot be satisfied by construction, so they (and the .fp/.sfp/.ign2
mechanics) are tested with a custom database built from hashes of generated files.

The files contain signature byte patterns only; they are not functional malware.

Steps:
  1. sample signatures (stratified by kind / target / offset class / features)
  2. generate files (gen/) and a custom hash DB test set (hash/ + hashdb/)
  3. validate with clamscan: a generated file only "counts" if clamscan reports
     the intended signature name for it (generator yield per category)
  4. compare ratel (`ratel scan --json --all --clamav-db DB ...`): recall on the
     clamscan-confirmed files, extra / missing names, benign-tree FP diff
  5. JSON summary (--out) + readable table + mismatch list with signature text

usage:
  clamav_parity.py --sigdb UNPACKED_CVD_DIR --work-base DIR [--n 1500] [--seed 1]
                   [--clamscan-only] [--ratel PATH] [--out FILE]
  clamav_parity.py --reuse WORKDIR [--ratel PATH] [--out FILE]   # ratel only, reuse
                                                                 # files + clamscan results
--sigdb is a directory holding the unpacked main/daily databases (any depth:
*.ndb / *.ldb / *.ign / *.ign2 are picked up; PUA *.ndu / *.ldu are not).

clamscan 1.5.4 semantics measured while building this (custom-DB probes):
  * text files get TWO passes: raw (target 0 roots) and normalized (targets 0 AND
    7), so a lowercase target-0 sig also matches "HELLO   World" in a text file and
    --allmatch reports it twice. Lsig counts are per pass, not summed.
  * normalization: A-Z -> a-z; runs of \\t \\n \\v \\f \\r and space -> one space
    (leading/trailing runs too); other bytes < 0x20 (incl. NUL) and all >= 0x80 are
    deleted; 0x7f and punctuation kept. Offsets (n, EOF-n) of target-7 sigs refer to
    the normalized buffer. Target-7 sigs with uppercase bytes, NUL/ctrl/high bytes,
    two spaces in a row or ::w can never match.
  * the normalized pass is gated on ClamAV's text-encoding detection: "ASCII text",
    UTF-8 and (heuristically) UTF-16 get it -- random binary is often classed
    UTF-16BE and does get it; "binary data" (e.g. text followed by a few NUL+ctrl
    bytes) does not. ELF/PE never get it.
  * files of <= 5 bytes are not scanned at all; ndb patterns need >= 3 static bytes
    (lsig subsigs >= 2), or the DB fails to load.
  * lsig expressions: top level splits at the FIRST operator (0&1|2 == 0&(1|2)),
    inside parentheses at the LAST one ((0|1&2) == ((0|1)&2)).
  * counts: overlapping matches count (ZZZZZZ holds ZZZZ 3 times). Block modifiers
    use the summed count of the TRUE parts only ((0&1)<2 is true if only 0 matched;
    (0&1&2)>2 needs all three present). '=X,Y' needs exactly Y distinct subsigs,
    '>X,Y' / '<X,Y' at least Y. '=0' / '<X' blocks fire with no match at all.
  * ::w doubles bytes and ?? (-> ??00) and alternatives, NOT gaps ({2-3} = raw
    bytes). ::f treats '_' as a boundary and is wide-aware for ::fw.
  * hash DBs: '*' size needs the ':73' flevel field; .fp/.sfp whitelist by whole-file
    hash, .ign2 drops a sig by name; custom (-d) DB names get '.UNOFFICIAL'.
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RATEL = os.path.join(ROOT, "target", "release", "ratel")
TARGETS = (0, 1, 6, 7, 9)
TARGET_NAMES = {0: "any", 1: "PE", 6: "ELF", 7: "text", 9: "Mach-O"}
# share of --n per (kind, target); capped by availability, leftovers redistributed
WEIGHTS = {("ndb", 0): 17, ("ndb", 1): 10, ("ndb", 6): 6, ("ndb", 7): 13, ("ndb", 9): 4,
           ("ldb", 0): 14, ("ldb", 1): 14, ("ldb", 6): 9, ("ldb", 7): 8, ("ldb", 9): 7}
MAX_OCC = 2500         # cap on placed subsig occurrences per file (counts like 1>1750 exist)
MIN_FILE = 32           # clamscan does not scan files of <= 5 bytes; stay well above


class Unsupported(Exception):
    pass


class Conflict(Exception):
    pass


# --------------------------------------------------------------------------- utils

def flevel():
    try:
        out = subprocess.run(["clamconf"], capture_output=True, text=True, timeout=60).stdout
        m = re.search(r"Engine flevel:\s*(\d+)", out)
        if m:
            return int(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    return 234   # ClamAV 1.5.x


def align(x, a):
    return (x + a - 1) // a * a


def strip_unofficial(name):
    return name[:-len(".UNOFFICIAL")] if name.endswith(".UNOFFICIAL") else name


# ----------------------------------------------------------------- offset parsing

OFF_RE = [
    (re.compile(r"^\*$"), lambda m: {"k": "any"}),
    (re.compile(r"^(\d+)(?:,(\d+))?$"), lambda m: {"k": "abs", "n": int(m.group(1)), "shift": int(m.group(2) or 0)}),
    (re.compile(r"^EOF-(\d+)(?:,(\d+))?$"), lambda m: {"k": "eof", "n": int(m.group(1)), "shift": int(m.group(2) or 0)}),
    (re.compile(r"^EP([+-])(\d+)(?:,(\d+))?$"),
     lambda m: {"k": "ep", "n": int(m.group(2)) * (1 if m.group(1) == "+" else -1), "shift": int(m.group(3) or 0)}),
    (re.compile(r"^S(\d+)\+(\d+)(?:,(\d+))?$"),
     lambda m: {"k": "sec", "sec": int(m.group(1)), "n": int(m.group(2)), "shift": int(m.group(3) or 0)}),
    (re.compile(r"^SL\+(\d+)(?:,(\d+))?$"), lambda m: {"k": "sl", "n": int(m.group(1)), "shift": int(m.group(2) or 0)}),
    (re.compile(r"^SE(\d+)$"), lambda m: {"k": "se", "sec": int(m.group(1))}),
]


def parse_offset(s):
    for rx, f in OFF_RE:
        m = rx.match(s)
        if m:
            return f(m)
    raise Unsupported("offset:" + re.sub(r"\d+", "N", s)[:20])


def offset_class(s):
    return re.sub(r"\d+", "N", s)


# ------------------------------------------------------------ hex pattern parsing

HEXB = re.compile(r"[0-9a-f?]{2}")


def parse_byte(s):
    hi, lo = s[0], s[1]
    v = m = 0
    if hi != "?":
        v |= int(hi, 16) << 4
        m |= 0xF0
    if lo != "?":
        v |= int(lo, 16)
        m |= 0x0F
    return (v, m)


def parse_alt_body(body):
    alts = []
    for a in body.split("|"):
        if not a or len(a) % 2 or not all(HEXB.fullmatch(a[i:i + 2]) for i in range(0, len(a), 2)):
            raise Unsupported("alt-syntax")
        alts.append([parse_byte(a[i:i + 2]) for i in range(0, len(a), 2)])
    return alts


def parse_hex(sig):
    """ClamAV hex body signature -> token list.
    ('b', v, mask) | ('gap', lo, hi|None) | ('alt', [[(v,m)..]..], negated) | ('mark', 'b'|'l'|'w')"""
    s = sig.lower()
    toks = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "{":
            j = s.index("}", i)
            body = s[i + 1:j]
            if re.fullmatch(r"\d+", body):
                toks.append(("gap", int(body), int(body)))
            elif re.fullmatch(r"-\d+", body):
                toks.append(("gap", 0, int(body[1:])))
            elif re.fullmatch(r"\d+-", body):
                toks.append(("gap", int(body[:-1]), None))
            elif re.fullmatch(r"\d+-\d+", body):
                a, b = body.split("-")
                toks.append(("gap", int(a), int(b)))
            else:
                raise Unsupported("gap-syntax")
            i = j + 1
        elif c == "[":
            j = s.index("]", i)
            a, b = s[i + 1:j].split("-")
            toks.append(("gap", int(a), int(b)))
            i = j + 1
        elif c == "*":
            toks.append(("gap", 0, None))
            i += 1
        elif s.startswith("!(", i):
            j = s.index(")", i)
            toks.append(("alt", parse_alt_body(s[i + 2:j]), True))
            i = j + 1
        elif c == "(":
            j = s.index(")", i)
            body = s[i + 1:j]
            if body in ("b", "l", "w"):
                toks.append(("mark", body))
            else:
                toks.append(("alt", parse_alt_body(body), False))
            i = j + 1
        elif HEXB.fullmatch(s[i:i + 2] or "x"):
            v, m = parse_byte(s[i:i + 2])
            toks.append(("b", v, m))
            i += 2
        else:
            raise Unsupported("hex-syntax")
    if not toks:
        raise Unsupported("empty")
    return toks


def parse_subsig(s):
    """'[offset:]hex[::mods]' -> dict; raises Unsupported for PCRE/byte-compare/macro/fuzzy."""
    if s.startswith("fuzzy_img"):
        raise Unsupported("fuzzy_img")
    if s.startswith("${"):
        raise Unsupported("macro")
    if re.match(r"^\d+\([<>=]", s) or re.match(r"^\d+\(", s):
        raise Unsupported("byte-compare")
    if "/" in s:
        raise Unsupported("pcre")
    mods = ""
    if "::" in s:
        s, mods = s.split("::", 1)
        if set(mods) - set("iwaf"):
            raise Unsupported("modifier:" + mods)
    off = "*"
    if ":" in s:
        off, s = s.split(":", 1)
    return {"off": parse_offset(off), "off_s": off, "toks": parse_hex(s), "mods": mods}


# ------------------------------------------------------------ logical expressions

def parse_expr(s, last=False):
    """Mirror of clamscan's lsig expression parser (measured, 1.5.4): at the top level
    of an expression it splits at the FIRST operator (0&1|2 == 0&(1|2)), but inside
    a parenthesised block at the LAST one ((0|1&2) == ((0|1)&2))."""
    s = s.strip()
    depth = 0
    ops = []
    for i, c in enumerate(s):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and c in "&|":
            ops.append(i)
    if ops:
        i = ops[-1] if last else ops[0]
        return (s[i], parse_expr(s[:i]), parse_expr(s[i + 1:]))
    m = re.fullmatch(r"\((.*)\)(?:([=<>])(\d+)(?:,(\d+))?)?", s, re.S)
    if m:
        inner = parse_expr(m.group(1), last=True)
        if m.group(2):
            return ("grp", inner, m.group(2), int(m.group(3)), None if m.group(4) is None else int(m.group(4)))
        return inner
    m = re.fullmatch(r"(\d+)(?:([=<>])(\d+)(?:,(\d+))?)?", s)
    if m:
        return ("leaf", int(m.group(1)), m.group(2), int(m.group(3)) if m.group(3) else None,
                None if m.group(4) is None else int(m.group(4)))
    raise Unsupported("expr-syntax")


def leaves(node):
    if node[0] == "leaf":
        return {node[1]}
    if node[0] == "grp":
        return leaves(node[1])
    return leaves(node[1]) | leaves(node[2])


def cmp_mod(op, x, y, total, distinct):
    # measured against clamscan 1.5.4: '=X,Y' needs exactly Y distinct subsigs,
    # '>X,Y' and '<X,Y' need at least Y distinct
    if op == "=":
        return total == x and (y is None or distinct == y)
    if op == ">":
        return total > x and (y is None or distinct >= y)
    return total < x and (y is None or distinct >= y)


def eval_node(node, cnt):
    """-> (value, match count, matched subsig ids). A false subexpression contributes
    count 0 to an enclosing block modifier: (0&1)<2 is true when only 0 matched."""
    t = node[0]
    if t == "leaf":
        c = cnt.get(node[1], 0)
        v = c > 0 if node[2] is None else cmp_mod(node[2], node[3], node[4], c, 1 if c else 0)
        return (v, c, {node[1]} if c else set()) if v else (False, 0, set())
    if t == "grp":
        _, ic, ids = eval_node(node[1], cnt)
        v = cmp_mod(node[2], node[3], node[4], ic, len(ids))
        return (True, ic, ids) if v else (False, 0, set())
    lv, lc, li = eval_node(node[1], cnt)
    rv, rc, ri = eval_node(node[2], cnt)
    v = (lv and rv) if t == "&" else (lv or rv)
    return (True, lc + rc, li | ri) if v else (False, 0, set())


def eval_expr(node, cnt):
    return eval_node(node, cnt)[0]


def _spread(rng, idx, total, distinct):
    idx = list(idx)
    distinct = max(0, min(distinct, len(idx), total))
    if total and not distinct:
        distinct = 1
    chosen = rng.sample(idx, distinct)
    out = {i: 1 for i in chosen}
    for _ in range(total - distinct):
        out[rng.choice(chosen)] += 1
    return out


def solve(node, rng):
    t = node[0]
    if t == "leaf":
        _, i, op, x, y = node
        if op is None:
            return {i: 1 if rng.random() < 0.85 else 2}
        if op == "=":
            return {i: x}
        if op == ">":
            return {i: x + 1 + (rng.random() < 0.2)}
        return {i: rng.randint(1, x - 1) if x > 1 else 0}
    if t == "grp" and rng.random() < 0.6:
        _, inner, op, x, y = node
        idx = sorted(leaves(inner))
        c = solve(inner, rng)
        want = x + 1 if op == ">" else x if op == "=" else rng.randint(0, max(0, x - 1))
        if op == "<" and not y:
            return {} if rng.random() < 0.3 else c if sum(c.values()) < x else {}
        for i in idx:
            if y and sum(1 for v in c.values() if v) < y and not c.get(i):
                c[i] = 1
        while sum(c.values()) < want:
            k = rng.choice([i for i in idx if c.get(i)] or idx)
            c[k] = c.get(k, 0) + 1
        return c
    if t == "grp":
        _, inner, op, x, y = node
        idx = leaves(inner)
        if op == "=":
            total = x
            d = y if y is not None else rng.randint(min(1, x), max(min(1, x), min(len(idx), x)))
        elif op == ">":
            total = x + 1
            d = max(y or 1, 1)
            total = max(total, d)
        else:
            total = rng.randint(max(y or 0, 1), x - 1) if x - 1 >= max(y or 0, 1) else 0
            d = max(y or 1, 1) if total else 0
        return _spread(rng, idx, total, d)
    a, b = solve(node[1], rng), solve(node[2], rng)
    if t == "|":
        r = rng.random()
        if r < 0.45:
            return a
        if r < 0.9:
            return b
    out = dict(a)
    for k, v in b.items():
        out[k] = max(out.get(k, 0), v)
    return out


def find_counts(expr, nsub, maxc, rng):
    """Satisfying count vector for an lsig expression (my model of clamscan's)."""
    for attempt in range(300):
        if attempt < 200:
            c = solve(expr, rng)
        else:
            c = {i: rng.choice((0, 0, 1, 1, 2, 3)) for i in range(nsub)}
        if any(v > maxc[i] for i, v in c.items() if i < nsub) or any(i >= nsub for i in c):
            continue
        if eval_expr(expr, c) and sum(c.values()) > 0:
            return c
    return None


# ------------------------------------------------------------------ instantiation

ALNUM = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
# bytes that survive clamscan's text normalization unchanged (target 7): printable
# ASCII except uppercase (lowercased) -- space is kept but runs collapse to one
T7_FIXED_OK = frozenset(set(range(0x20, 0x80)) - set(range(0x41, 0x5B)))
T7_FREE = bytes(sorted(T7_FIXED_OK - {0x20}))
T7_FILLER = b"abcdefghijklmnopqrstuvwxyz0123456789"
ANY = bytes(range(256))


def gap_len(rng, lo, hi):
    if hi is None:
        hi = lo + 8
    r = rng.random()
    if r < 0.3:
        return lo
    if r < 0.5:
        return hi
    return rng.randint(lo, min(hi, lo + 48))


def instantiate(toks, mods, rng, text):
    """-> (template [(v,mask)..], lead). mask 0 bytes are free (chosen at write time).
    `lead` = delimiter bytes before the real match start (::f)."""
    wide = "w" in mods and ("a" not in mods or rng.random() < 0.5)
    nocase = "i" in mods
    tm = []

    def put(v, m):
        if nocase and m == 0xFF and v in ALNUM and chr(v).isalpha():
            v = ord(chr(v).lower()) if text else (v ^ 0x20 if rng.random() < 0.5 else v)
        tm.append((v, m))
        if wide:
            tm.append((0, 0xFF))

    for t in toks:
        if t[0] == "b":
            put(t[1], t[2])
        elif t[0] == "gap":
            # gaps count raw bytes even under ::w (measured)
            tm.extend([(0, 0)] * gap_len(rng, t[1], t[2]))
        elif t[0] == "alt":
            if not t[2]:
                for v, m in rng.choice(t[1]):
                    put(v, m)
            else:
                n = len(t[1][0])
                if any(len(a) != n for a in t[1]):
                    raise Unsupported("neg-alt-len")
                pool = T7_FREE if text else ANY
                for _ in range(200):
                    cand = [rng.choice(pool) for _ in range(n)]
                    if not any(all((c & m) == (v & m) for c, (v, m) in zip(cand, a)) for a in t[1]):
                        break
                else:
                    raise Unsupported("neg-alt-unsat")
                for c in cand:
                    put(c, 0xFF)
        elif t[0] == "mark":
            put(0x0A if t[1] == "l" and not text else 0x20, 0xFF)
    lead = 0
    if "f" in mods:
        d = (0x20, 0xFF)
        if wide:
            tm = [d, (0, 0xFF)] + tm + [d, (0, 0xFF)]
            lead = 2
        else:
            tm = [d] + tm + [d]
            lead = 1
    if text:
        for (v, m), (v2, m2) in zip(tm, tm[1:] + [(0, 0)]):
            if m == 0xFF and v not in T7_FIXED_OK:
                raise Unsupported("t7-unnormalizable")
            if m == 0xFF and v == 0x20 and m2 == 0xFF and v2 == 0x20:
                raise Unsupported("t7-unnormalizable")
            if m not in (0, 0xFF) and not any((b & m) == (v & m) for b in T7_FREE):
                raise Unsupported("t7-unnormalizable")
    return tm, lead


def _cls(v, m, nocase):
    if m == 0:
        return b"."
    if m == 0xFF:
        if nocase and chr(v).isalpha() and v < 0x80:
            return b"[" + re.escape(bytes([v | 0x20])) + re.escape(bytes([v & ~0x20])) + b"]"
        return re.escape(bytes([v]))
    return b"[" + b"".join(re.escape(bytes([b])) for b in range(256) if (b & m) == (v & m)) + b"]"


def pattern_regex(toks, mods):
    """bytes regex approximating where a subsig can match (offsets ignored)."""
    def build(wide):
        z = b"\\x00" if wide else b""
        out = b""
        for t in toks:
            if t[0] == "b":
                out += _cls(t[1], t[2], "i" in mods) + z
            elif t[0] == "gap":
                out += b".{%d,%s}?" % (t[1], b"" if t[2] is None else b"%d" % t[2])
            elif t[0] == "alt":
                alts = b"|".join(b"".join(_cls(v, m, "i" in mods) + z for v, m in a) for a in t[1])
                if t[2]:
                    out += b"(?:(?!" + alts + b")" + b"." * (len(t[1][0]) * (2 if wide else 1)) + b")"
                else:
                    out += b"(?:" + alts + b")"
            else:
                out += b"."
        return out
    if "w" in mods and "a" in mods:
        body = b"(?:" + build(False) + b"|" + build(True) + b")"
    else:
        body = build("w" in mods)
    if "f" in mods:
        body = b"(?<![A-Za-z0-9])" + body + b"(?![A-Za-z0-9])"
    return re.compile(b"(?=" + body + b")", re.S)


# ------------------------------------------------------------------------- canvas

FREE, SOFT, HARD = 0, 1, 2


class Canvas:
    def __init__(self, rng, text):
        self.buf = bytearray()
        self.st = bytearray()
        self.rng = rng
        self.text = text

    def ensure(self, n):
        if n > len(self.buf):
            self.buf.extend(b"\0" * (n - len(self.buf)))
            self.st.extend(b"\0" * (n - len(self.st)))

    def preset(self, pos, data, state):
        self.ensure(pos + len(data))
        self.buf[pos:pos + len(data)] = data
        for i in range(pos, pos + len(data)):
            self.st[i] = state

    def can_write(self, pos, tm):
        if pos < 0:
            return False
        for i, (v, m) in enumerate(tm):
            p = pos + i
            if p < len(self.st) and self.st[p] == HARD and (self.buf[p] & m) != (v & m):
                return False
        return True

    def write(self, pos, tm):
        if not self.can_write(pos, tm):
            raise Conflict()
        self.ensure(pos + len(tm))
        pool = T7_FREE if self.text else ANY
        for i, (v, m) in enumerate(tm):
            p = pos + i
            if self.st[p] == HARD or (self.st[p] == SOFT and m != 0xFF and (self.buf[p] & m) == (v & m)):
                pass   # keep header/stub bytes where the signature allows them
            elif m == 0xFF:
                self.buf[p] = v
            else:
                if m == 0:
                    b = self.rng.choice(T7_FILLER if self.text else ANY)
                else:
                    cands = [b for b in pool if (b & m) == (v & m)]
                    b = self.rng.choice(cands)
                self.buf[p] = b
            self.st[p] = HARD

    def fill(self):
        filler = T7_FILLER if self.text else ANY
        for p in range(len(self.buf)):
            if self.st[p] == FREE:
                self.buf[p] = self.rng.choice(filler)


# ---------------------------------------------------------------------- containers

DOS_HDR = (bytes.fromhex("4d5a90000300000004000000ffff0000b8000000000000004000000000000000")
           + b"\0" * 28 + struct.pack("<I", 0x80)
           + bytes.fromhex("0e1fba0e00b409cd21b8014ccd21") + b"This program cannot be run in DOS mode.\r\r\n$")
DOS_HDR += b"\0" * (0x80 - len(DOS_HDR))
assert len(DOS_HDR) == 0x80, len(DOS_HDR)


def pe_header(nsec, raw_sizes, ep_sec, ep_off, rng, plain_names=False):
    FA, SA = 0x200, 0x1000
    hdr_end = 0x80 + 4 + 20 + 0xE0 + 40 * nsec
    hsize = align(hdr_end, FA)
    raws, vas = [], []
    r, va = hsize, 0x1000
    for z in raw_sizes:
        raws.append(r)
        vas.append(va)
        r += z
        va += align(z, SA)
    size_image = va
    ep_rva = vas[ep_sec] + ep_off
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x14C, nsec, rng.randrange(0x50000000, 0x68000000), 0, 0, 0xE0, 0x0102)
    opt = struct.pack("<HBB9I6H4I2H6I", 0x10B, 14, 0, raw_sizes[0], sum(raw_sizes[1:]), 0, ep_rva, vas[0],
                      vas[1] if nsec > 1 else vas[0], 0x400000, SA, FA, 6, 0, 0, 0, 6, 0, 0, size_image, hsize, 0,
                      2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + b"\0" * 128
    names = [b".text", b".rdata", b".data", b".rsrc", b".reloc"]
    sh = b""
    for k in range(nsec):
        nm = names[k] if k < len(names) and not plain_names else b".s%d" % k
        ch = 0x60000020 if k == 0 else 0xC0000040
        sh += struct.pack("<8sIIIIIIHHI", nm, raw_sizes[k], vas[k], raw_sizes[k], raws[k], 0, 0, 0, 0, ch)
    hdr = DOS_HDR + coff + opt + sh
    return hdr, hsize, raws, hdr_end


def elf_header(payload_off, payload_size, ep_off):
    base = 0x400000
    total = payload_off + payload_size
    eh = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 0x3E, 1,
                     base + payload_off + ep_off, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, total, total, 0x1000)
    return eh + ph


def macho_header(payload_off, payload_size):
    vm = 0x100000000
    total = payload_off + payload_size
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", vm + payload_off, payload_size,
                       payload_off, 4, 0, 0, 0x80000400, 0, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", 0x19, 72 + 80, b"__TEXT", vm, align(total, 0x1000), 0, total,
                      7, 5, 1, 0) + sect
    regs = [0] * 21
    regs[16] = vm + payload_off
    th = struct.pack("<IIII", 5, 16 + 168, 4, 42) + struct.pack("<21Q", *regs)
    cmds = seg + th
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 2, len(cmds), 0, 0) + cmds
    return hdr


TRUE_BIN = "/usr/bin/true"


# ------------------------------------------------------------------------ layout

def layout(target, occ, tdb, rng):
    """occ: [(template, lead, off_dict)]. Returns (bytes, info). Raises Conflict / Unsupported."""
    text = target == 7
    cv = Canvas(rng, text)
    fs_lo, fs_hi = tdb.get("FileSize", (0, 1 << 40))
    rel, absol, eof, flt = [], [], [], []
    for tm, lead, off in occ:
        k = off["k"]
        if k == "any":
            flt.append((tm, lead, off))
        elif k == "abs":
            absol.append((tm, lead, off))
        elif k == "eof":
            eof.append((tm, lead, off))
        else:
            if target != 1 and k in ("sec", "sl", "se"):
                raise Unsupported("section-offset-non-PE")
            if target not in (1, 6) and k == "ep":
                raise Unsupported("ep-offset-raw")
            rel.append((tm, lead, off))
    rng.shuffle(flt)
    info = {}

    def shift(off):
        return rng.randint(0, off.get("shift", 0))

    def float_seq(start):
        """positions for floating placements, sequential with filler gaps"""
        out, cur = [], start
        for tm, lead, off in flt:
            cur += rng.randint(1, 24)
            out.append((cur, tm))
            cur += len(tm)
        return out, cur

    writes = []   # (pos, template)
    if target in (0, 7):
        for tm, lead, off in absol:
            writes.append((off["n"] + shift(off) - lead, tm))
        start = max([p + len(t) for p, t in writes] + [rng.randint(0, 40)])
        fw, end = float_seq(start)
        writes += fw
        body_end = end + rng.randint(4, 40)
    elif target == 6:
        use_real = not rel and not absol and "FileSize" not in tdb and rng.random() < 0.5
        if use_real:
            with open(TRUE_BIN, "rb") as f:
                base = f.read()
            cv.preset(0, base, HARD)
            fw, end = float_seq(len(base))
            writes += fw
            body_end = end + rng.randint(4, 40)
            info["container"] = "elf:/usr/bin/true+append"
        else:
            P = 120
            # EP region: EP-n placements need room before the entry point
            back = max([-o["n"] + lead for _, lead, o in rel if o["n"] < 0] + [0])
            ep_off = back + rng.randint(0, 64)
            epw = []
            for tm, lead, off in rel:
                epw.append((P + ep_off + off["n"] + shift(off) - lead, tm))
            ep_end = max([p + len(t) for p, t in epw] + [P + ep_off + 16])
            fw, end = float_seq(ep_end)
            payload = end + rng.randint(4, 40) - P
            for tm, lead, off in absol:
                a = off["n"] + shift(off) - lead
                payload = max(payload, a + len(tm) - P)
            cv.preset(0, elf_header(P, payload, ep_off), HARD)
            cv.ensure(P + payload)
            writes += epw + fw
            for tm, lead, off in absol:
                writes.append((off["n"] + shift(off) - lead, tm))
            body_end = P + payload
            info["container"] = "elf:built"
            info["ep"] = P + ep_off
    elif target == 9:
        P = 0x200
        fw, end = float_seq(P)
        payload = end + rng.randint(4, 40) - P
        for tm, lead, off in absol:
            payload = max(payload, off["n"] + off.get("shift", 0) + len(tm) - P)
        hdr = macho_header(P, payload)
        cv.preset(0, hdr, HARD)
        cv.preset(len(hdr), b"\0" * (P - len(hdr)), SOFT)
        cv.ensure(P + payload)
        writes += fw
        for tm, lead, off in absol:
            writes.append((off["n"] + shift(off) - lead, tm))
        body_end = P + payload
        info["container"] = "macho:built"
    elif target == 1:
        need = 0
        for tm, lead, off in rel:
            if off["k"] in ("sec", "se"):
                need = max(need, off["sec"] + 1)
        ns_lo, ns_hi = tdb.get("NumberOfSections", (1, 96))
        nsec = max(need, ns_lo, 2 if ns_hi >= 2 else 1)
        if nsec > ns_hi:
            raise Unsupported("nsec")
        last = nsec - 1
        cursors = [0] * nsec
        secw = []   # (sec, off_in_sec, tm)

        def at_sec(k, n, tm):
            secw.append((k, n, tm))
            cursors[k] = max(cursors[k], n + len(tm))

        for tm, lead, off in rel:
            if off["k"] == "sec":
                at_sec(off["sec"], off["n"] + shift(off) - lead, tm)
            elif off["k"] == "sl":
                at_sec(last, off["n"] + shift(off) - lead, tm)
        for tm, lead, off in rel:
            if off["k"] == "se":
                at_sec(off["sec"], cursors[off["sec"]] + rng.randint(0, 16), tm)
        # entry point in section 0, after anything anchored to S0
        eps = [(tm, lead, off) for tm, lead, off in rel if off["k"] == "ep"]
        back = max([-o["n"] + lead for _, lead, o in eps if o["n"] < 0] + [0])
        ep_off = cursors[0] + back + rng.randint(0, 32)
        ep_off = max(ep_off, 0)
        for tm, lead, off in eps:
            if any(p < 0 for p in [ep_off + off["n"] - lead]):
                raise Conflict()
            at_sec(0, ep_off + off["n"] + shift(off) - lead, tm)
        cursors[0] = max(cursors[0], ep_off + 16)
        c = cursors[last]
        for tm, lead, off in flt:
            c += rng.randint(1, 24)
            secw.append((last, c, tm))
            c += len(tm)
        cursors[last] = c
        sizes = [align(max(cur + rng.randint(8, 64), 1), 0x200) for cur in cursors]
        hdr, hsize, raws, hdr_end = pe_header(nsec, sizes, 0, ep_off, rng, bool(tdb.get("_nostub")))
        cv.preset(0, hdr[:0x80] if not tdb.get("_nostub") else hdr[:0x40] + b"\0" * 0x40, SOFT)
        cv.preset(0, hdr[:2], HARD)
        cv.preset(0x3C, hdr[0x3C:0x40], HARD)
        cv.preset(0x80, hdr[0x80:hdr_end], HARD)
        cv.preset(hdr_end, b"\0" * (hsize - hdr_end), SOFT)
        cv.ensure(raws[-1] + sizes[-1])
        for k, n, tm in secw:
            writes.append((raws[k] + n, tm))
        for tm, lead, off in absol:
            writes.append((off["n"] + shift(off) - lead, tm))
        body_end = raws[-1] + sizes[-1]
        info["container"] = "pe:built"
        info["ep"] = raws[0] + ep_off
        info["nsec"] = nsec
    else:
        raise Unsupported("target")

    for pos, tm in writes:
        cv.write(pos, tm)
    body_end = max(body_end, len(cv.buf))
    # EOF-anchored placements live in a tail block appended after padding
    tail_len = max([o["n"] for _, _, o in eof] + [0])
    tailw = []
    for tm, lead, off in eof:
        s = rng.randint(0, max(0, min(off.get("shift", 0), off["n"] - len(tm) + lead)))
        p = tail_len - off["n"] + s - lead
        if p < 0 or p + len(tm) > tail_len:
            raise Unsupported("eof-too-short")
        tailw.append((p, tm))
    total = body_end + tail_len
    if text:
        total += 1   # gap so the tail never touches the body
    pad = max(0, fs_lo - total, MIN_FILE - total)
    tail_start = body_end + pad + (1 if text else 0)
    cv.ensure(tail_start + tail_len)
    for p, tm in tailw:
        cv.write(tail_start + p, tm)
    if len(cv.buf) < tail_start + tail_len:
        cv.ensure(tail_start + tail_len)
    cv.fill()
    data = bytes(cv.buf)
    if len(data) > fs_hi:
        raise Unsupported("filesize")
    if text and b"  " in data:
        raise Conflict()
    return data, info


def denormalize(data, rng):
    """raw text whose clamscan normalization is `data` (target 7)."""
    out = bytearray()
    drop = list(range(0x01, 0x09)) + list(range(0x0E, 0x20)) + [0x00] + list(range(0x80, 0x100))
    for i, b in enumerate(data):
        if i < 4:   # keep the start intact: an uppercased 'MZ'/'PK' would change the file type
            out.append(b)
            continue
        if rng.random() < 0.03:
            out.append(rng.choice(drop))
        if 0x61 <= b <= 0x7A and rng.random() < 0.25:
            out.append(b - 0x20)
        elif b == 0x20 and rng.random() < 0.6:
            out += bytes(rng.choice(b" \t\n\r\x0b\x0c") for _ in range(rng.randint(1, 3)))
        else:
            out.append(b)
    return bytes(out)


# ---------------------------------------------------------------- signature DB

def load_ignored(sigdb):
    names = set()
    for p in glob.glob(os.path.join(sigdb, "**", "*.ign*"), recursive=True):
        if not (p.endswith(".ign") or p.endswith(".ign2")):
            continue
        with open(p, encoding="latin-1") as f:
            for line in f:
                line = line.strip()
                if line:
                    names.add(line.split(":")[-1] if p.endswith(".ign") else line.split(":")[0])
    return names


def parse_tdb(s):
    out = {}
    for kv in s.split(","):
        if ":" not in kv:
            continue
        k, v = kv.split(":", 1)
        if k in ("Engine", "FileSize", "NumberOfSections", "EntryPoint"):
            a, _, b = v.partition("-")
            out[k] = (int(a), int(b) if b else int(a))
        elif k == "Target":
            out[k] = int(v)
        else:
            out[k] = v
    return out


def classify_ndb(line, fl, ign):
    p = line.split(":")
    if len(p) < 4:
        return None, "malformed"
    name, tgt = p[0], p[1]
    if name in ign:
        return None, "ignored(.ign2)"
    if not tgt.isdigit() or int(tgt) not in TARGETS:
        return None, "target-not-covered"
    if len(p) > 4 and p[4] and int(p[4]) > fl or len(p) > 5 and p[5] and int(p[5]) < fl:
        return None, "flevel"
    off = p[2]
    if "VI" in off:
        return None, "offset:VI"
    return {"kind": "ndb", "name": name, "target": int(tgt), "ocls": offset_class(off), "feat": ""}, None


def classify_ldb(line, fl, ign):
    p = line.split(";")
    if len(p) < 4:
        return None, "malformed"
    name = p[0]
    if name in ign:
        return None, "ignored(.ign2)"
    tdb = parse_tdb(p[1])
    t = tdb.get("Target")
    if t not in TARGETS:
        return None, "target-not-covered"
    lo, hi = tdb.get("Engine", (0, 255))
    if lo > fl or hi < fl:
        return None, "flevel"
    for k in ("Container", "Intermediates", "IconGroup1", "IconGroup2", "HandlerType", "EntryPoint"):
        if k in tdb:
            return None, "tdb:" + k
    ocls = "*"
    feats = set()
    for s in p[3:]:
        if s.startswith("fuzzy_img"):
            return None, "fuzzy_img"
        if s.startswith("${"):
            return None, "macro"
        if re.match(r"^\d+\(", s):
            return None, "byte-compare"
        if "/" in s:
            return None, "pcre"
        if "::" in s:
            feats.add("mod")
            s = s.split("::", 1)[0]
        m = re.match(r"^([^:]+):", s)
        if m:
            if m.group(1) == "VI":
                return None, "offset:VI"
            if ocls == "*":
                ocls = offset_class(m.group(1))
    if re.search(r"[=<>]", p[2]):
        feats.add("count")
    return {"kind": "ldb", "name": name, "target": t, "ocls": ocls, "feat": "+".join(sorted(feats))}, None


def load_db(sigdb, fl):
    ign = load_ignored(sigdb)
    sigs, skip = [], collections.Counter()
    seen = set()
    deep_first = lambda p: (-p.count(os.sep), p)   # prefer main/daily over aggregate copies
    files = sorted(glob.glob(os.path.join(sigdb, "**", "*.ndb"), recursive=True), key=deep_first) + \
        sorted(glob.glob(os.path.join(sigdb, "**", "*.ldb"), recursive=True), key=deep_first)
    for path in files:
        kind = path.rsplit(".", 1)[1]
        cls = classify_ndb if kind == "ndb" else classify_ldb
        with open(path, encoding="latin-1") as f:
            for ln, line in enumerate(f, 1):
                line = line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                if line in seen:
                    skip[(kind, "duplicate-line")] += 1
                    continue
                seen.add(line)
                try:
                    rec, why = cls(line, fl, ign)
                except (ValueError, IndexError):
                    rec, why = None, "malformed"
                if rec is None:
                    skip[(kind, why)] += 1
                    continue
                rec["src"] = "%s:%d" % (os.path.relpath(path, sigdb), ln)
                rec["line"] = line
                sigs.append(rec)
    return sigs, skip


def sample(sigs, n, rng, names=None):
    if names:
        want = set(names)
        return [s for s in sigs if s["name"] in want]
    bycat = collections.defaultdict(list)
    for s in sigs:
        bycat[(s["kind"], s["target"])].append(s)
    tot_w = sum(WEIGHTS.values())
    quota = {c: min(len(bycat[c]), round(n * w / tot_w)) for c, w in WEIGHTS.items()}
    left = n - sum(quota.values())
    while left > 0:
        grow = [c for c in WEIGHTS if quota[c] < len(bycat[c])]
        if not grow:
            break
        for c in grow:
            if left <= 0:
                break
            quota[c] += 1
            left -= 1
    out = []
    for c in sorted(WEIGHTS):
        pool = bycat[c]
        q = quota[c]
        strata = collections.defaultdict(list)
        for s in pool:
            strata[(s["ocls"], s["feat"])].append(s)
        keys = sorted(strata)
        for k in keys:
            rng.shuffle(strata[k])
        picked, seen = [], set()
        # half round-robin across strata (rare offset classes / features), half uniform
        i = 0
        while len(picked) < q // 2 and any(strata[k] for k in keys):
            k = keys[i % len(keys)]
            i += 1
            if strata[k]:
                s = strata[k].pop()
                picked.append(s)
                seen.add(id(s))
        rest = [s for s in pool if id(s) not in seen]
        picked += rng.sample(rest, min(q - len(picked), len(rest)))
        out += picked
    return out


# ------------------------------------------------------------------- generation

def build_for_sig(rec, rng):
    """-> (bytes, info). Raises Unsupported / Conflict."""
    target = rec["target"]
    text = target == 7
    if rec["kind"] == "ndb":
        p = rec["line"].split(":")
        sub = {"off": parse_offset(p[2]), "off_s": p[2], "toks": parse_hex(p[3]), "mods": ""}
        tm, lead = instantiate(sub["toks"], "", rng, text)
        return layout(target, [(tm, lead, sub["off"])], {}, rng)
    p = rec["line"].split(";")
    tdb = parse_tdb(p[1])
    subs = [parse_subsig(s) for s in p[3:]]
    expr = parse_expr(p[2])
    if max(leaves(expr)) >= len(subs):
        raise Unsupported("expr-index")
    maxc = [MAX_OCC if s["off"]["k"] in ("any", "se") else 1 + s["off"].get("shift", 0) for s in subs]
    counts = find_counts(expr, len(subs), maxc, rng)
    if counts is None:
        raise Unsupported("expr-unsat")
    if sum(counts.values()) > MAX_OCC:
        raise Unsupported("count-too-large")
    occ = []
    for i, c in sorted(counts.items()):
        for _ in range(c):
            tm, lead = instantiate(subs[i]["toks"], subs[i]["mods"], rng, text)
            occ.append((tm, lead, subs[i]["off"]))
    checkable = [i for i in sorted(leaves(expr)) if subs[i]["off"]["k"] in ("any", "abs", "eof")]
    for nostub in (False, True):
        data, info = layout(target, occ, dict(tdb, _nostub=nostub), random.Random(rng.random()))
        # subsigs can also match by accident (container headers, the PE DOS stub, one
        # subsig inside another): recount floating ones and re-check the expression;
        # retry without the DOS stub / section names, else give up on this signature
        seen = dict(counts)
        for i in checkable:
            off = subs[i]["off"]
            lo, hi = 0, len(data)
            if off["k"] == "abs":
                lo, hi = off["n"], off["n"] + off["shift"]
            elif off["k"] == "eof":
                lo = len(data) - off["n"]
                hi = lo + off["shift"]
            seen[i] = sum(1 for m in pattern_regex(subs[i]["toks"], subs[i]["mods"]).finditer(data)
                          if lo <= m.start() <= hi)
        if eval_expr(expr, seen):
            break
    else:
        raise Unsupported("accidental-subsig-matches")
    info["counts"] = {str(k): v for k, v in counts.items() if v}
    return data, info


def generate(samples, gen_dir, rng, meta_path):
    os.makedirs(gen_dir)
    metas = []
    for i, rec in enumerate(samples):
        m = {k: rec[k] for k in ("kind", "name", "target", "ocls", "feat", "src", "line")}
        m["cat"] = "%s/t%d" % (rec["kind"], rec["target"])
        last, data = None, None
        for attempt in range(6):
            try:
                data, info = build_for_sig(rec, random.Random(rng.random()))
                break
            except Conflict:
                last = "layout-conflict"
            except Unsupported as e:
                last = str(e)
                break
            except (ValueError, IndexError, KeyError) as e:
                last = "parse-error:" + type(e).__name__
                break
        if data is None:
            m["gen_fail"] = last
            metas.append(m)
            continue
        if rec["target"] == 7:
            lo, hi = parse_tdb(rec["line"].split(";")[1]).get("FileSize", (0, 1 << 40)) \
                if rec["kind"] == "ldb" else (0, 1 << 40)
            r = rng.random()
            if r < 0.25 and rec["ocls"] == "*":
                # clamscan also runs the normalized text pass over unrecognised binary
                # data: wrap the (floating-only) text in random binary junk
                junk = lambda: bytes([rng.randrange(0x90, 0xC0)]) + bytes(
                    rng.randrange(256) for _ in range(rng.randint(64, 512)))
                raw = junk() + data + junk()
                if lo <= len(raw) <= hi:
                    data = raw
                    info["t7_in_binary"] = True
            elif r < 0.75:
                raw = denormalize(data, rng)
                if lo <= len(raw) <= hi:
                    data = raw
                    info["denormalized"] = True
        fn = "%05d_%s_t%d" % (i, rec["kind"], rec["target"])
        with open(os.path.join(gen_dir, fn), "wb") as f:
            f.write(data)
        m["file"] = fn
        m["size"] = len(data)
        m.update(info)
        metas.append(m)
    with open(meta_path, "w") as f:
        for m in metas:
            f.write(json.dumps(m) + "\n")
    return metas


# ------------------------------------------------------------- hash / fp tests

def gen_hash_tests(hash_dir, db_dir, n, rng):
    """Custom DB exercising .hdb/.hsb (md5/sha1/sha256, wildcard size), .mdb/.msb
    (PE section hashes), .fp/.sfp whitelisting and .ign2. Returns expectations:
    {file: {"expect": [names], "test": kind}}."""
    os.makedirs(hash_dir)
    os.makedirs(db_dir)
    hdb, hsb, mdb, msb, ndb, fp, sfp, ign2 = [], [], [], [], [], [], [], []
    exp = {}

    def newfile(tag, data):
        fn = "%s_%04d" % (tag, len(exp))
        with open(os.path.join(hash_dir, fn), "wb") as f:
            f.write(data)
        return fn

    def rnd(lo=64, hi=40000):
        return bytes(rng.randrange(256) for _ in range(rng.randint(lo, hi)))

    kinds = ["md5", "sha1", "sha256", "md5-anysize", "sha256-anysize", "md5-wrongsize",
             "sha256-wrongsize", "mdb", "msb-sha256", "mdb-anysize", "fp-md5", "sfp-sha256", "ign2", "control"]
    for i in range(n):
        k = kinds[i % len(kinds)]
        nm = "Parity.Hash.%s-%d" % (k.replace("-", "_"), i)
        if k in ("mdb", "msb-sha256", "mdb-anysize"):
            sec = rnd(200, 6000)
            raw = align(len(sec), 0x200)
            secdata = sec + b"\0" * (raw - len(sec))
            hdr, hsize, raws, hdr_end = pe_header(2, [raw, 0x200], 0, 0, rng)
            data = bytearray(hdr + b"\0" * (hsize - len(hdr)) + secdata + rnd(0x200, 0x200))
            fn = newfile(k, bytes(data))
            if k == "mdb":
                mdb.append("%d:%s:%s" % (raw, hashlib.md5(secdata).hexdigest(), nm))
            elif k == "mdb-anysize":
                mdb.append("*:%s:%s:73" % (hashlib.md5(secdata).hexdigest(), nm))
            else:
                msb.append("%d:%s:%s" % (raw, hashlib.sha256(secdata).hexdigest(), nm))
            exp[fn] = {"expect": [nm], "test": k}
            continue
        data = rnd()
        fn = newfile(k, data)
        sz = len(data)
        if k == "md5":
            hdb.append("%s:%d:%s" % (hashlib.md5(data).hexdigest(), sz, nm))
        elif k == "sha1":
            hsb.append("%s:%d:%s" % (hashlib.sha1(data).hexdigest(), sz, nm))
        elif k == "sha256":
            hsb.append("%s:%d:%s" % (hashlib.sha256(data).hexdigest(), sz, nm))
        elif k == "md5-anysize":
            hdb.append("%s:*:%s:73" % (hashlib.md5(data).hexdigest(), nm))
        elif k == "sha256-anysize":
            hsb.append("%s:*:%s:73" % (hashlib.sha256(data).hexdigest(), nm))
        elif k == "md5-wrongsize":
            hdb.append("%s:%d:%s" % (hashlib.md5(data).hexdigest(), sz + 1, nm))
            exp[fn] = {"expect": [], "test": k}
            continue
        elif k == "sha256-wrongsize":
            hsb.append("%s:%d:%s" % (hashlib.sha256(data).hexdigest(), sz - 1, nm))
            exp[fn] = {"expect": [], "test": k}
            continue
        elif k in ("fp-md5", "sfp-sha256", "ign2"):
            # a body sig hits the file; .fp/.sfp whitelists it by hash, .ign2 drops the sig
            marker = bytes(rng.randrange(256) for _ in range(12))
            data = data[:sz // 2] + marker + data[sz // 2:]
            os.unlink(os.path.join(hash_dir, fn))
            fn = newfile(k, data)
            ndb.append("%s:0:*:%s" % (nm, marker.hex()))
            if k == "fp-md5":
                fp.append("%s:%d:%s" % (hashlib.md5(data).hexdigest(), len(data), "fp_" + nm))
            elif k == "sfp-sha256":
                sfp.append("%s:%d:%s" % (hashlib.sha256(data).hexdigest(), len(data), "fp_" + nm))
            else:
                ign2.append(nm)
            # a sibling with the same marker but different hash must still be detected
            sib = newfile(k + "-sibling", data + b"x")
            exp[sib] = {"expect": [nm] if k != "ign2" else [], "test": k + "-sibling"}
            exp[fn] = {"expect": [], "test": k}
            continue
        elif k == "control":
            exp[fn] = {"expect": [], "test": k}
            continue
        exp[fn] = {"expect": [nm], "test": k}
    for ext, rows in (("hdb", hdb), ("hsb", hsb), ("mdb", mdb), ("msb", msb), ("ndb", ndb),
                      ("fp", fp), ("sfp", sfp), ("ign2", ign2)):
        if rows:
            with open(os.path.join(db_dir, "parity." + ext), "w") as f:
                f.write("\n".join(rows) + "\n")
    return exp


# ------------------------------------------------------------------ scanners

def parse_clamscan(out):
    res = collections.defaultdict(list)
    for line in out.splitlines():
        if not line.endswith(" FOUND"):
            continue
        i = line.rfind(": ")
        if i < 0:
            continue
        res[os.path.realpath(line[:i])].append(strip_unofficial(line[i + 2:-6]))
    return res


def run_clamscan(db, paths, log):
    cmd = ["clamscan", "--allmatch", "--no-summary", "--infected", "-r", "-d", db] + paths
    t = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    log("clamscan -d %s (%d path(s)): %.0fs, exit %d" % (db, len(paths), time.time() - t, r.returncode))
    if r.returncode not in (0, 1):
        log("clamscan stderr: " + r.stderr[-2000:])
    return parse_clamscan(r.stdout)


def ratel_ready(ratel):
    try:
        for args in (["scan", "--help"], []):
            r = subprocess.run([ratel] + args, capture_output=True, text=True, timeout=60)
            if "--clamav-db" in r.stdout + r.stderr:
                return True
    except OSError:
        return False
    return False


def run_ratel(ratel, db, paths, extra, log):
    cmd = [ratel, "scan", "--json", "--all", "--clamav-db", db] + extra + paths
    t = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    log("ratel --clamav-db %s (%d path(s)): %.0fs, exit %d" % (db, len(paths), time.time() - t, r.returncode))
    if r.returncode not in (0, 1) or not r.stdout.strip():
        log("ratel stderr: " + r.stderr[-2000:])
    res = {}
    bad = 0
    for line in r.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(j, dict) or "path" not in j:
            continue
        sigs = j.get("signatures") or []
        names = [strip_unofficial(s if isinstance(s, str) else s.get("name", "")) for s in sigs]
        res.setdefault(os.path.realpath(j["path"]), []).extend(names)
    if bad:
        log("ratel: %d non-JSON output lines ignored" % bad)
    return res


# ------------------------------------------------------------------- reporting

def table(rows, header):
    w = [max(len(str(r[i])) for r in rows + [header]) for i in range(len(header))]
    fmt = "  ".join("{:<%d}" % x if i == 0 else "{:>%d}" % x for i, x in enumerate(w))
    lines = [fmt.format(*header), fmt.format(*["-" * x for x in w])]
    lines += [fmt.format(*r) for r in rows]
    return "\n".join(lines)


def pct(a, b):
    return "%.1f%%" % (100.0 * a / b) if b else "-"


def generator_yield(metas, clam, gen_dir):
    by = collections.defaultdict(collections.Counter)
    fails = collections.defaultdict(collections.Counter)
    unconfirmed = []
    for m in metas:
        keys = [m["cat"], "%s/%s" % (m["cat"], m["ocls"])]
        if m.get("feat"):
            keys.append("%s/feat:%s" % (m["cat"], m["feat"]))
        if m.get("denormalized"):
            keys.append("%s/denormalized" % m["cat"])
        if m.get("t7_in_binary"):
            keys.append("%s/in-binary-data" % m["cat"])
        for k in keys + ["ALL"]:
            by[k]["sampled"] += 1
        if "gen_fail" in m:
            for k in keys + ["ALL"]:
                fails[k][m["gen_fail"]] += 1
            continue
        names = clam.get(os.path.realpath(os.path.join(gen_dir, m["file"])), [])
        ok = m["name"] in names
        m["clam"] = sorted(set(names))
        m["confirmed"] = ok
        for k in keys + ["ALL"]:
            by[k]["generated"] += 1
            by[k]["confirmed"] += ok
        if not ok:
            unconfirmed.append(m)
    return by, fails, unconfirmed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sigdb", help="unpacked ClamAV DB dir (main/ daily/ ...)")
    ap.add_argument("--clamav-db", default="/var/lib/clamav", help="DB for clamscan -d (default %(default)s)")
    ap.add_argument("--ratel-db", help="DB dir passed to ratel --clamav-db (default: --clamav-db)")
    ap.add_argument("--n", type=int, default=1500)
    ap.add_argument("--n-hash", type=int, default=140, help="custom hash/fp DB test files")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--names", help="comma-separated signature names to generate (debugging)")
    ap.add_argument("--work-base", default=tempfile.gettempdir(), help="a fresh work dir is created inside")
    ap.add_argument("--reuse", help="existing work dir: skip generation + clamscan, run ratel only")
    ap.add_argument("--ratel", default=DEFAULT_RATEL)
    ap.add_argument("--ratel-extra", default="", help="extra args for ratel scan (space separated)")
    ap.add_argument("--clamscan-only", action="store_true")
    ap.add_argument("--fp-trees", default="/usr/bin,/usr/lib/python3*,/usr/share/doc")
    ap.add_argument("--no-fp", action="store_true", help="skip the benign-tree FP check")
    ap.add_argument("--out", help="JSON summary path (default: WORK/summary.json)")
    ap.add_argument("--show", type=int, default=25, help="mismatches printed per section")
    a = ap.parse_args()

    log_lines = []

    def log(s):
        log_lines.append(s)
        print(s, file=sys.stderr, flush=True)

    if a.reuse:
        work = os.path.abspath(a.reuse)
        with open(os.path.join(work, "state.json")) as f:
            st = json.load(f)
        metas = [json.loads(x) for x in open(os.path.join(work, "meta.jsonl"))]
        clam_gen = st["clam_gen"]
        clam_hash = st["clam_hash"]
        clam_fp = st["clam_fp"]
        hash_exp = st["hash_exp"]
        pop_skip = st["pop_skip"]
        fp_trees = st["fp_trees"]
        args_used = st["args"]
    else:
        if not a.sigdb:
            ap.error("--sigdb is required (unless --reuse)")
        for p in fp_check_paths(a):
            if os.path.realpath(p).startswith(os.path.realpath(os.path.expanduser("~"))):
                ap.error("benign trees must not be under $HOME: " + p)
        work = tempfile.mkdtemp(prefix="clamav-parity-", dir=a.work_base)
        log("work dir: " + work)
        fl = flevel()
        t = time.time()
        sigs, skip = load_db(a.sigdb, fl)
        log("loaded %d candidate sigs in %.0fs (flevel %d); skipped by kind/reason: %d"
            % (len(sigs), time.time() - t, fl, sum(skip.values())))
        rng = random.Random(a.seed)
        samples = sample(sigs, a.n, rng, a.names.split(",") if a.names else None)
        log("sampled %d" % len(samples))
        gen_dir = os.path.join(work, "gen")
        metas = generate(samples, gen_dir, rng, os.path.join(work, "meta.jsonl"))
        hash_dir, hashdb = os.path.join(work, "hash"), os.path.join(work, "hashdb")
        hash_exp = gen_hash_tests(hash_dir, hashdb, a.n_hash, rng)
        fp_trees = [] if a.no_fp else fp_check_paths(a)
        allc = run_clamscan(a.clamav_db, [gen_dir] + fp_trees, log)
        clam_gen = {k: v for k, v in allc.items() if k.startswith(os.path.realpath(gen_dir) + os.sep)}
        clam_fp = {k: v for k, v in allc.items() if k not in clam_gen}
        clam_hash = run_clamscan(hashdb, [hash_dir], log)
        pop_skip = {"%s:%s" % k: v for k, v in sorted(skip.items())}
        args_used = vars(a)
        with open(os.path.join(work, "state.json"), "w") as f:
            json.dump({"clam_gen": clam_gen, "clam_hash": clam_hash, "clam_fp": clam_fp, "hash_exp": hash_exp,
                       "pop_skip": pop_skip, "fp_trees": fp_trees, "args": args_used}, f)

    gen_dir = os.path.join(work, "gen")
    hash_dir, hashdb = os.path.join(work, "hash"), os.path.join(work, "hashdb")
    by, fails, unconfirmed = generator_yield(metas, clam_gen, gen_dir)

    summary = {"work": work, "args": args_used, "population_skips": pop_skip}
    # ---- generator yield
    cats = sorted(k for k in by if k != "ALL")
    rows = []
    for k in ["ALL"] + cats:
        c = by[k]
        f = fails.get(k, {})
        rows.append([k, c["sampled"], sum(f.values()), c["generated"], c["confirmed"],
                     pct(c["confirmed"], c["generated"]),
                     ", ".join("%s=%d" % kv for kv in sorted(f.items(), key=lambda kv: -kv[1])[:3])])
    print("\n== generator yield vs clamscan (confirmed = clamscan reports the intended name)")
    print(table(rows, ["category", "sampled", "skipped", "generated", "confirmed", "yield", "skip reasons"]))
    summary["generator"] = {k: dict(by[k], skipped=dict(fails.get(k, {}))) for k in ["ALL"] + cats}
    summary["unconfirmed"] = [{k: m.get(k) for k in ("file", "name", "cat", "ocls", "src", "line", "clam",
                                                     "counts", "container", "denormalized", "t7_in_binary")}
                              for m in unconfirmed]
    # ---- hash tests vs expectation
    hrows = collections.defaultdict(collections.Counter)
    hash_bad = []
    for fn, e in sorted(hash_exp.items()):
        got = sorted(set(clam_hash.get(os.path.realpath(os.path.join(hash_dir, fn)), [])))
        ok = got == sorted(e["expect"])
        hrows[e["test"]]["files"] += 1
        hrows[e["test"]]["as_expected"] += ok
        if not ok:
            hash_bad.append({"file": fn, "test": e["test"], "expect": e["expect"], "clam": got})
    print("\n== custom hash/fp DB tests: clamscan vs expectation")
    print(table([[k, v["files"], v["as_expected"]] for k, v in sorted(hrows.items())],
                ["test", "files", "clamscan-as-expected"]))
    summary["hash_tests"] = {k: dict(v) for k, v in hrows.items()}
    summary["hash_unexpected"] = hash_bad
    for h in hash_bad[:a.show]:
        print("  unexpected:", h)
    if fp_trees:
        nfp = sum(1 for v in clam_fp.values() if v)
        print("\n== benign trees %s: clamscan flagged %d file(s)" % (",".join(fp_trees), nfp))
        summary["clamscan_benign_hits"] = {k: sorted(set(v)) for k, v in clam_fp.items()}
        for k, v in list(clam_fp.items())[:a.show]:
            print("  %s: %s" % (k, ", ".join(sorted(set(v)))))

    # ---- ratel
    if not a.clamscan_only:
        if not ratel_ready(a.ratel):
            log("ratel at %s has no --clamav-db support yet: clamscan-only run" % a.ratel)
            a.clamscan_only = True
    if not a.clamscan_only:
        rdb = a.ratel_db or args_used.get("ratel_db") or args_used.get("clamav_db") or a.clamav_db
        extra = a.ratel_extra.split()
        rg = run_ratel(a.ratel, rdb, [gen_dir], extra, log)
        rh = run_ratel(a.ratel, hashdb, [hash_dir], extra, log)
        summary["ratel"] = compare(metas, gen_dir, clam_gen, rg, hash_exp, hash_dir, clam_hash, rh, a.show)
        if fp_trees:
            rf = run_ratel(a.ratel, rdb, fp_trees, extra, log)
            summary["ratel"]["benign"] = compare_fp(clam_fp, rf, a.show)

    # ---- unconfirmed generator outputs (for generator debugging)
    print("\n== generated but not confirmed by clamscan: %d (first %d)" % (len(unconfirmed), a.show))
    for m in unconfirmed[:a.show]:
        print("  %s [%s %s] %s  clam=%s\n      %s" % (m["file"], m["cat"], m["ocls"], m["name"], m.get("clam"),
                                                     m["line"][:300]))
    summary["log"] = log_lines
    out = a.out or os.path.join(work, "summary.json")
    with open(out, "w") as f:
        json.dump(summary, f, indent=1)
    print("\nsummary: " + out)


def fp_check_paths(a):
    if a.no_fp:
        return []
    out = []
    for pat in a.fp_trees.split(","):
        out += sorted(glob.glob(pat))
    return out


def compare(metas, gen_dir, clam, rat, hash_exp, hash_dir, clam_hash, rat_hash, show):
    by = collections.defaultdict(collections.Counter)
    extra_names = collections.Counter()
    missing_names = collections.Counter()
    mism = []
    for m in metas:
        if not m.get("confirmed"):
            continue
        p = os.path.realpath(os.path.join(gen_dir, m["file"]))
        cs, rs = set(clam.get(p, [])), set(rat.get(p, []))
        hit = m["name"] in rs
        keys = [m["cat"], "%s/%s" % (m["cat"], m["ocls"]), "ALL"]
        if m.get("feat"):
            keys.append("%s/feat:%s" % (m["cat"], m["feat"]))
        if m.get("denormalized"):
            keys.append("%s/denormalized" % m["cat"])
        if m.get("t7_in_binary"):
            keys.append("%s/in-binary-data" % m["cat"])
        for k in keys:
            by[k]["confirmed"] += 1
            by[k]["ratel_hit"] += hit
            by[k]["exact_set"] += cs == rs
        for n in rs - cs:
            extra_names[n] += 1
        for n in cs - rs:
            missing_names[n] += 1
        if not hit or cs != rs:
            mism.append({"file": m["file"], "kind": "missed-intended" if not hit else "set-differs",
                         "name": m["name"], "cat": m["cat"], "ocls": m["ocls"], "src": m["src"],
                         "line": m["line"], "clam": sorted(cs), "ratel": sorted(rs),
                         "extra": sorted(rs - cs), "missing": sorted(cs - rs),
                         "counts": m.get("counts"), "container": m.get("container"),
                         "denormalized": m.get("denormalized", False),
                         "t7_in_binary": m.get("t7_in_binary", False)})
    rows = [[k, v["confirmed"], v["ratel_hit"], pct(v["ratel_hit"], v["confirmed"]), v["exact_set"]]
            for k, v in sorted(by.items(), key=lambda kv: (kv[0] != "ALL", kv[0]))]
    print("\n== ratel recall on clamscan-confirmed files")
    print(table(rows, ["category", "confirmed", "ratel-hit", "recall", "same-name-set"]))
    # hash tests
    hb = collections.defaultdict(collections.Counter)
    hmism = []
    for fn, e in sorted(hash_exp.items()):
        p = os.path.realpath(os.path.join(hash_dir, fn))
        cs, rs = sorted(set(clam_hash.get(p, []))), sorted(set(rat_hash.get(p, [])))
        hb[e["test"]]["files"] += 1
        hb[e["test"]]["same_as_clamscan"] += cs == rs
        if cs != rs:
            hmism.append({"file": fn, "test": e["test"], "clam": cs, "ratel": rs})
    print("\n== ratel vs clamscan on custom hash/fp DB")
    print(table([[k, v["files"], v["same_as_clamscan"]] for k, v in sorted(hb.items())],
                ["test", "files", "same-as-clamscan"]))
    print("\n== names ratel reports that clamscan does not (top): %s"
          % ", ".join("%s x%d" % kv for kv in extra_names.most_common(10)))
    print("== names clamscan reports that ratel does not (top): %s"
          % ", ".join("%s x%d" % kv for kv in missing_names.most_common(10)))
    print("\n== mismatches: %d (first %d)" % (len(mism), show))
    for x in sorted(mism, key=lambda x: x["kind"] != "missed-intended")[:show]:
        print("  [%s] %s %s %s/%s\n      clam=%s ratel=%s\n      %s"
              % (x["kind"], x["file"], x["name"], x["cat"], x["ocls"], x["clam"], x["ratel"], x["line"][:300]))
    for h in hmism[:show]:
        print("  [hash] %s" % h)
    return {"recall": {k: dict(v) for k, v in by.items()}, "extra_names": dict(extra_names),
            "missing_names": dict(missing_names), "mismatches": mism,
            "hash": {k: dict(v) for k, v in hb.items()}, "hash_mismatches": hmism}


def compare_fp(clam_fp, rat_fp, show):
    diffs = []
    for p in sorted(set(clam_fp) | set(k for k, v in rat_fp.items() if v)):
        cs, rs = set(clam_fp.get(p, [])), set(rat_fp.get(p, []))
        if cs != rs:
            diffs.append({"path": p, "clam": sorted(cs), "ratel": sorted(rs)})
    nr = sum(1 for v in rat_fp.values() if v)
    print("\n== benign trees: ratel flagged %d file(s), clamscan %d; %d differ"
          % (nr, sum(1 for v in clam_fp.values() if v), len(diffs)))
    for d in diffs[:show]:
        print("  %s clam=%s ratel=%s" % (d["path"], d["clam"], d["ratel"]))
    return {"ratel_flagged": nr, "diffs": diffs, "ratel_scanned": len(rat_fp)}


if __name__ == "__main__":
    main()
