//! Provenance: is this exact file something we already know?
//!
//! * Package databases: pacman (`/var/lib/pacman/local/*/mtree`, SHA-256) and
//!   apk (`/lib/apk/db/installed`, SHA-1). A file whose hash matches what its
//!   package installed is "package-verified"; a package-owned file whose hash does
//!   NOT match was modified after installation, a classic rootkit trait.
//! * Hash allowlists: lines of `<sha256> [anything]`, from /etc/ratel/allow.list,
//!   $XDG_CONFIG_HOME/ratel/allow.list (or ~/.config/...), and --allow FILE.
//!   `ratel allow PATH...` prints such lines (a baseline of what's there now).
//!
//! Only hashes are trusted, never paths or names: dropping a file into
//! /usr/bin does not make it trusted, and neither does calling it "qemu".

use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PkgKind {
    Pacman,
    Apk,
    None,
}

const PACMAN_DB: &str = "/var/lib/pacman/local";
const APK_DB: &str = "/lib/apk/db/installed";

pub fn detect_pkg_kind() -> PkgKind {
    if Path::new(APK_DB).is_file() {
        PkgKind::Apk
    } else if Path::new(PACMAN_DB).is_dir() {
        PkgKind::Pacman
    } else {
        PkgKind::None
    }
}

/// Hashes of one file, computed by the scanning worker (only for files that need them).
#[derive(Clone)]
pub struct Hashes {
    pub sha256: [u8; 32],
    pub sha1: Option<[u8; 20]>,
}

pub fn hash(data: &[u8], kind: PkgKind) -> Hashes {
    let sha256: [u8; 32] = Sha256::digest(data).into();
    let sha1 = (kind == PkgKind::Apk).then(|| Sha1::digest(data).into());
    Hashes { sha256, sha1 }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    /// sha256 is in an allowlist.
    Allowlisted,
    /// Owned by a package and unchanged since installation.
    Package { pkg: String },
    /// Owned by a package but the content differs from what was installed.
    Modified { pkg: String },
    /// Not owned by any package, not allowlisted.
    Unknown,
}

enum PkgDigest {
    Sha256([u8; 32]),
    Sha1([u8; 20]),
}

pub struct Trust {
    allow: HashSet<[u8; 32]>,
    /// canonical path -> (package, digest). Only paths that are being scanned.
    owned: HashMap<PathBuf, (String, PkgDigest)>,
}

impl Trust {
    /// `wanted`: canonical paths of the files being scanned; the package database is
    /// filtered down to these so memory stays proportional to the scan, not the system.
    pub fn load(kind: PkgKind, allow_files: &[(String, bool)], wanted: &HashSet<PathBuf>) -> Result<Trust, String> {
        let mut allow = HashSet::new();
        for (f, explicit) in allow_files {
            match std::fs::read_to_string(f) {
                Ok(s) => parse_allowlist(&s, &mut allow),
                Err(e) if *explicit => return Err(format!("{f}: {e}")),
                Err(_) => {}
            }
        }
        let mut owned = HashMap::new();
        match kind {
            PkgKind::Pacman => load_pacman(wanted, &mut owned),
            PkgKind::Apk => load_apk(wanted, &mut owned),
            PkgKind::None => {}
        }
        Ok(Trust { allow, owned })
    }

    pub fn origin(&self, canonical: &Path, h: &Hashes) -> Origin {
        if self.allow.contains(&h.sha256) {
            return Origin::Allowlisted;
        }
        match self.owned.get(canonical) {
            Some((pkg, d)) => {
                let ok = match d {
                    PkgDigest::Sha256(x) => *x == h.sha256,
                    PkgDigest::Sha1(x) => h.sha1.as_ref() == Some(x),
                };
                if ok { Origin::Package { pkg: pkg.clone() } } else { Origin::Modified { pkg: pkg.clone() } }
            }
            None => Origin::Unknown,
        }
    }
}

pub fn default_allowlists() -> Vec<String> {
    let mut v = vec!["/etc/ratel/allow.list".to_string()];
    let cfg = std::env::var("XDG_CONFIG_HOME").ok().filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.config")));
    if let Some(c) = cfg {
        v.push(format!("{c}/ratel/allow.list"));
    }
    v
}

fn parse_allowlist(s: &str, out: &mut HashSet<[u8; 32]>) {
    for line in s.lines() {
        let tok = line.split_whitespace().next().unwrap_or("");
        if tok.starts_with('#') || tok.len() != 64 {
            continue;
        }
        let mut h = [0u8; 32];
        if (0..32).all(|i| u8::from_str_radix(&tok[2 * i..2 * i + 2], 16).map(|b| h[i] = b).is_ok()) {
            out.insert(h);
        }
    }
}

/// mtree paths escape odd bytes as \NNN (octal).
fn mtree_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn load_pacman(wanted: &HashSet<PathBuf>, owned: &mut HashMap<PathBuf, (String, PkgDigest)>) {
    let Ok(rd) = std::fs::read_dir(PACMAN_DB) else { return };
    for e in rd.flatten() {
        let dir = e.path();
        let Ok(mt) = std::fs::File::open(dir.join("mtree")) else { continue };
        let name = std::fs::read_to_string(dir.join("desc")).ok()
            .and_then(|d| d.split("%NAME%\n").nth(1).and_then(|r| r.lines().next()).map(str::to_string))
            .unwrap_or_else(|| dir.file_name().unwrap_or_default().to_string_lossy().into_owned());
        let rdr = BufReader::new(flate2::read::GzDecoder::new(mt));
        for line in rdr.lines() {
            let Ok(line) = line else { break };
            let Some(rest) = line.strip_prefix("./") else { continue };
            let mut it = rest.split(' ');
            let Some(p) = it.next() else { continue };
            let path = PathBuf::from(format!("/{}", mtree_unescape(p)));
            if !wanted.contains(&path) {
                continue;
            }
            if let Some(d) = it.find_map(|kv| kv.strip_prefix("sha256digest=")).and_then(unhex::<32>) {
                owned.insert(path, (name.clone(), PkgDigest::Sha256(d)));
            }
        }
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = vec![];
    let (mut acc, mut bits) = (0u32, 0);
    for &c in s {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn load_apk(wanted: &HashSet<PathBuf>, owned: &mut HashMap<PathBuf, (String, PkgDigest)>) {
    let Ok(f) = std::fs::File::open(APK_DB) else { return };
    let (mut pkg, mut dir, mut file) = (String::new(), String::new(), None::<PathBuf>);
    for line in BufReader::new(f).lines() {
        let Ok(line) = line else { break };
        if line.is_empty() {
            pkg.clear();
            dir.clear();
            file = None;
            continue;
        }
        match line.split_at_checked(2) {
            Some(("P:", v)) => pkg = v.to_string(),
            Some(("F:", v)) => {
                dir = v.to_string();
                file = None;
            }
            Some(("R:", v)) => {
                let p = PathBuf::from(if dir.is_empty() { format!("/{v}") } else { format!("/{dir}/{v}") });
                file = wanted.contains(&p).then_some(p);
            }
            Some(("Z:", v)) => {
                // "Q1" + base64(sha1)
                if let (Some(p), Some(b)) = (file.take(), v.strip_prefix("Q1").and_then(b64_decode)) {
                    if let Ok(d) = <[u8; 20]>::try_from(b.as_slice()) {
                        owned.insert(p, (pkg.clone(), PkgDigest::Sha1(d)));
                    }
                }
            }
            _ => {}
        }
    }
}

/// `ratel allow PATH...`: print `<sha256>  <path>` for every ELF/PE file.
pub fn print_allow_lines(files: &[PathBuf], max: u64) {
    for p in files {
        if let Some(d) = crate::read_candidate(p, max) {
            println!("{}  {}", hex(&Sha256::digest(&d[..])), p.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtree_and_b64() {
        assert_eq!(mtree_unescape("usr/share/a\\040b"), "usr/share/a b");
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        let mut s = HashSet::new();
        parse_allowlist(&format!("# c\n{}  /x\nzz\n", "ab".repeat(32)), &mut s);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn origin_verdicts() {
        let good = hash(b"original", PkgKind::Pacman);
        let bad = hash(b"trojaned", PkgKind::Pacman);
        let mut owned = HashMap::new();
        owned.insert(PathBuf::from("/usr/bin/ls"), ("coreutils".to_string(), PkgDigest::Sha256(good.sha256)));
        let t = Trust { allow: HashSet::from([hash(b"mine", PkgKind::Pacman).sha256]), owned };
        assert!(matches!(t.origin(Path::new("/usr/bin/ls"), &good), Origin::Package { .. }));
        assert!(matches!(t.origin(Path::new("/usr/bin/ls"), &bad), Origin::Modified { .. }));
        assert!(matches!(t.origin(Path::new("/opt/x"), &bad), Origin::Unknown));
        assert!(matches!(t.origin(Path::new("/opt/x"), &hash(b"mine", PkgKind::Pacman)), Origin::Allowlisted));
        // apk: SHA-1 records
        let a = hash(b"busybox", PkgKind::Apk);
        let mut owned = HashMap::new();
        owned.insert(PathBuf::from("/bin/busybox"), ("busybox".to_string(), PkgDigest::Sha1(a.sha1.unwrap())));
        let t = Trust { allow: HashSet::new(), owned };
        assert!(matches!(t.origin(Path::new("/bin/busybox"), &a), Origin::Package { .. }));
        assert!(matches!(t.origin(Path::new("/bin/busybox"), &hash(b"evil", PkgKind::Apk)), Origin::Modified { .. }));
    }
}
