//! File types as ClamAV signatures target them, executable layout (entry point,
//! sections) for EP/Sx offsets, and the normalized text buffers.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FType {
    Pe,
    Elf,
    MachO,
    Ole2,
    Html,
    Mail,
    Graphics,
    Pdf,
    Swf,
    Java,
    Text,
    Other,
}

impl FType {
    /// The ClamAV target type matched against the raw file (besides target 0).
    pub fn raw_target(self) -> Option<u8> {
        Some(match self {
            FType::Pe => 1,
            FType::Ole2 => 2,
            FType::Mail => 4,
            FType::Graphics => 5,
            FType::Elf => 6,
            FType::MachO => 9,
            FType::Pdf => 10,
            FType::Swf => 11,
            FType::Java => 12,
            _ => return None,
        })
    }
}

fn is_text(d: &[u8]) -> bool {
    let h = &d[..d.len().min(8192)];
    if h.is_empty() || h.contains(&0) {
        return false;
    }
    let ctl = h.iter().filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b)).count();
    ctl * 100 <= h.len()
}

fn has_ci(h: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n)))
}

pub fn detect(d: &[u8]) -> FType {
    let s = |n: usize| d.get(..n).unwrap_or(&[]);
    if s(2) == b"MZ" {
        let pe_off = d.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
        if pe_off.and_then(|o| d.get(o..o + 4)) == Some(b"PE\0\0") {
            return FType::Pe;
        }
    }
    if s(4) == b"\x7fELF" {
        return FType::Elf;
    }
    if matches!(s(4), [0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] | [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe]) {
        return FType::MachO;
    }
    if s(4) == [0xca, 0xfe, 0xba, 0xbe] {
        // fat Mach-O has a small architecture count where a class file has its version
        let n = d.get(4..8).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        return if n < 40 { FType::MachO } else { FType::Java };
    }
    if s(8) == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return FType::Ole2;
    }
    if d[..d.len().min(1024)].windows(5).any(|w| w == b"%PDF-") {
        return FType::Pdf;
    }
    if matches!(s(3), b"FWS" | b"CWS" | b"ZWS") {
        return FType::Swf;
    }
    if s(8) == b"\x89PNG\r\n\x1a\n" || s(3) == [0xff, 0xd8, 0xff] || s(4) == b"GIF8" || s(4) == b"II*\0" || s(4) == b"MM\0*" {
        return FType::Graphics;
    }
    if is_text(d) {
        let h = &d[..d.len().min(65536)];
        if has_ci(h, &[b"<html", b"<script", b"<body", b"<head", b"<!doctype html", b"<iframe"]) {
            return FType::Html;
        }
        let top = &d[..d.len().min(2048)];
        if (top.starts_with(b"From ") || top.starts_with(b"Received:") || top.starts_with(b"Return-Path:"))
            && has_ci(top, &[b"\nsubject:", b"\nfrom:", b"\nto:"])
        {
            return FType::Mail;
        }
        return FType::Text;
    }
    FType::Other
}

/// A binary format we recognise by magic (when no daily.ftm entry is loaded).
pub fn detect_magic_only(d: &[u8]) -> bool {
    !matches!(detect(d), FType::Text | FType::Html | FType::Mail | FType::Other)
}

#[derive(Default, Debug)]
pub struct Info {
    pub len: usize,
    pub ep: Option<usize>,
    /// (file offset, size) per section
    pub secs: Vec<(usize, usize)>,
    pub pe32: bool,
}

pub fn info(d: &[u8], t: FType) -> Info {
    let mut i = Info { len: d.len(), ..Default::default() };
    match t {
        FType::Pe => {
            use goblin::pe::{options::ParseOptions, PE};
            let mut o = ParseOptions::default();
            o.resolve_rva = false;
            o.parse_attribute_certificates = false;
            if let Ok(pe) = PE::parse_with_opts(d, &o) {
                i.pe32 = !pe.is_64;
                i.secs = pe.sections.iter().map(|s| (s.pointer_to_raw_data as usize, s.size_of_raw_data as usize)).collect();
                let rva = pe.entry as u32;
                i.ep = pe.sections.iter()
                    .find(|s| rva >= s.virtual_address && rva < s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data)))
                    .map(|s| (rva - s.virtual_address + s.pointer_to_raw_data) as usize);
            }
        }
        FType::Elf => {
            if let Ok(e) = goblin::elf::Elf::parse(d) {
                i.secs = e.section_headers.iter().map(|s| (s.sh_offset as usize, s.sh_size as usize)).collect();
                let ent = e.header.e_entry;
                i.ep = e.program_headers.iter()
                    .find(|p| p.p_type == goblin::elf::program_header::PT_LOAD && ent >= p.p_vaddr && ent < p.p_vaddr.saturating_add(p.p_filesz))
                    .map(|p| (ent - p.p_vaddr + p.p_offset) as usize);
            }
        }
        _ => {}
    }
    i
}

/// ClamAV's text typing (libclamav/textdet.c, `cli_texttype`) over the first 1024
/// bytes, used when no file-type magic matched: "ASCII" (no byte of class F, so high
/// bytes are fine) or UTF-16 (BOM; without one, big-endian pairs from offset 2 that
/// are all >= 128 or plain text characters). Random binary often passes the latter,
/// exactly as in clamscan. (td_isutf8 can't succeed after td_isascii failed.)
pub fn texttype(d: &[u8]) -> bool {
    let b = &d[..d.len().min(1024)];
    // class F: 0x00-0x06, 0x0b, 0x0e-0x1a, 0x1c-0x1f, 0x7f
    let f = |c: u8| matches!(c, 0x00..=0x06 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f | 0x7f);
    if !b.iter().any(|&c| f(c)) {
        return true;
    }
    if b.len() < 2 {
        return false;
    }
    let (be, nobom) = match (b[0], b[1]) {
        (0xff, 0xfe) => (false, false),
        (0xfe, 0xff) => (true, false),
        _ => (true, true),
    };
    let (mut bad, mut i) = (0usize, 2);
    while i + 1 < b.len() {
        let c = if be { b[i + 1] as u32 + 256 * b[i] as u32 } else { b[i] as u32 + 256 * b[i + 1] as u32 };
        if c == 0xfffe {
            return false;
        }
        if c < 128 && (f(c as u8) || (c as u8) >= 0x80) {
            if nobom {
                return false;
            }
            bad += 1;
        }
        i += 2;
    }
    nobom || bad < b.len() / 2
}

/// Target 7 (ASCII text), as clamscan normalizes it (libclamav/textnorm.c): A-Z
/// lowercased, any run of whitespace (0x09-0x0d, space) becomes one space, other
/// control bytes and bytes >= 0x80 are dropped, 0x21-0x7f copied.
pub fn norm_text(d: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(d.len());
    let mut ws = false;
    for &b in d {
        match b {
            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' => {
                if !ws {
                    o.push(b' ');
                }
                ws = true;
            }
            0x21..=0x7f => {
                o.push(b.to_ascii_lowercase());
                ws = false;
            }
            _ => {}
        }
    }
    o
}

/// Target 3 (HTML): lowercase, whitespace runs become one space (an approximation of
/// ClamAV's HTML normalizer, which also rewrites tags and decodes scripts).
pub fn norm_html(d: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(d.len());
    let mut ws = false;
    for &b in d {
        if b.is_ascii_whitespace() {
            if !ws {
                o.push(b' ');
            }
            ws = true;
        } else {
            o.push(b.to_ascii_lowercase());
            ws = false;
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn types() {
        assert_eq!(detect(b"\x7fELF\x02\x01\x01"), FType::Elf);
        assert_eq!(detect(b"#!/bin/sh\necho hi\n"), FType::Text);
        assert_eq!(detect(b"<HTML><body>x</body>"), FType::Html);
        assert_eq!(detect(b"%PDF-1.7\n"), FType::Pdf);
        assert_eq!(detect(&[0u8, 1, 2, 3, 0, 9]), FType::Other);
        assert_eq!(norm_html(b"A  \n\tB"), b"a b");
        assert_eq!(norm_text(b"Hello \t\r\n World\x00\x01\xe9!"), b"hello world!");
        assert!(texttype(b"plain \xe9 text with high bytes"));
        assert!(!texttype(b"ab\x00\x01cdef\x00"), "a NUL-led pair below 128 is not text");
        assert!(texttype(&[0xff, 0xfe, b'h', 0, b'i', 0]));
        assert!(texttype(&[0x12, 0x34, 0xc3, 0x55, 0x91, 0x00, 0xa0, 0x20]), "BOM-less big-endian pairs >= 128");
    }
}
