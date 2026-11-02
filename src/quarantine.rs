//! File quarantine: move a suspicious file into a vault, like an AV's quarantine.
//!
//! ratel runs as root over world-writable directories (/tmp, /var/tmp, /dev/shm), so every
//! step assumes the file's owner is racing us:
//!
//! * The parent directory is resolved once and opened with `O_DIRECTORY|O_NOFOLLOW`; the
//!   kernel's view of where that fd really is (`/proc/self/fd`) must equal what was resolved.
//!   Everything after that is relative to the directory fd, so a directory swapped for a
//!   symlink later can't redirect us.
//! * The file is opened once (`O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`): no symlinks, FIFOs or
//!   devices. Size, type, identity and content all come from that one fd.
//! * The content is copied into the vault and synced (data, meta.json, directories) before
//!   the original is touched. Then the name is re-checked with
//!   `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`: it must still be the same dev/ino we read,
//!   or nothing is removed and the vault entry is discarded. The remaining window between
//!   that check and `unlinkat` only lets someone who can already rename entries in that
//!   directory make us remove one of *their* entries (sticky dirs stop them renaming ours),
//!   which gains them nothing.
//!
//! The stored copy is **neutralised, not encrypted**: an 8-byte header (so it never starts
//! with `\x7fELF`, `MZ` or `#!`) followed by the content XORed with a 4 KiB pad derived
//! from the item id. That keeps other scanners (ClamAV, a backup's AV) from re-detecting
//! the vault, stops anyone from executing or `dlopen`ing it by accident, and makes the
//! files useless to copy out naively. The store is 0700 and its files 0600.
//!
//! Layout: `<store>/<id>/data` + `<store>/<id>/meta.json` (a `QItem`). An entry without
//! meta.json is an interrupted quarantine and is ignored by `list`.

use crate::safety::{safe, safe_path};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

pub const DEFAULT_STORE: &str = "/var/lib/ratel/quarantine";
/// Files larger than this are refused.
pub const MAX_SIZE: u64 = 512 << 20;
const MAGIC: &[u8; 8] = b"RATELQ\x00\x01";
const PAD_LEN: usize = 4096;
const CHUNK: usize = 1 << 16;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct QItem {
    pub id: String,
    /// Where the file was (parent directory resolved, so a later symlink can't redirect a restore).
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    /// Link count when quarantined: > 1 means other hard links still hold the content.
    pub nlink: u64,
    pub t: f64,
    pub detector: String,
    pub reason: Vec<String>,
    /// (dev, inode, owner) of the directory it came from: a restore only writes back
    /// into that same directory (not one put in its place since).
    #[serde(default)]
    pub parent: Option<(u64, u64, u32)>,
}

pub const USAGE: &str = "file quarantine:
  ratel quarantine list                          what is in the vault
  ratel quarantine add PATH [--reason TEXT]      move a file into the vault
  ratel quarantine show ID                       details of one entry
  ratel quarantine restore ID [--to PATH] [--force]   put it back (verified), then drop the entry
  ratel quarantine delete ID                     drop an entry for good
common: --store DIR (default /var/lib/ratel/quarantine), --json
";

// ---------------------------------------------------------------- small helpers

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Days since 1970-01-01 -> (year, month, day) (H. Hinnant's civil_from_days).
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn utc_parts(t: f64) -> (i64, u32, u32, i64, i64, i64) {
    let s = t.floor() as i64;
    let (y, mo, d) = civil(s.div_euclid(86_400));
    let r = s.rem_euclid(86_400);
    (y, mo, d, r / 3600, r % 3600 / 60, r % 60)
}

/// `20261102T153012Z`: id-safe UTC timestamp.
pub(crate) fn utc_stamp(t: f64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(t);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// `2026-11-02 15:30:12Z`
pub(crate) fn utc_human(t: f64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(t);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

/// Ids name directories in the store: only `[0-9A-Za-z-]`, so no `/`, `.` or `..`.
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 96 && !id.starts_with('-') && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cstr(b: &[u8]) -> Result<CString, String> {
    CString::new(b).map_err(|_| "path contains a NUL byte".to_string())
}

fn errno_str() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// 4 KiB pad derived from the id (SHA-256 in counter mode).
fn pad(id: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(PAD_LEN);
    let mut i = 0u32;
    while p.len() < PAD_LEN {
        let mut h = Sha256::new();
        h.update(b"ratel-quarantine-pad\0");
        h.update(id.as_bytes());
        h.update(i.to_be_bytes());
        p.extend_from_slice(&h.finalize());
        i += 1;
    }
    p
}

fn xor_at(buf: &mut [u8], off: u64, pad: &[u8]) {
    let mut k = (off % PAD_LEN as u64) as usize;
    for b in buf.iter_mut() {
        *b ^= pad[k];
        k = (k + 1) % PAD_LEN;
    }
}

/// A directory opened without following a link at its last component, plus where the
/// kernel says it is.
struct Dir {
    fd: File,
    real: PathBuf,
}

/// Opens the parent of `path` and returns it with the final name. The directory is
/// opened one component at a time from `/` without following links, so no component
/// can be a symlink when we act on it. `resolve`: canonicalize the parent first
/// (quarantine, where scanned paths may legitimately go through /bin -> usr/bin);
/// restore passes false: the recorded path is already canonical, and a directory since
/// replaced by a symlink is refused rather than followed.
fn open_parent(path: &Path, resolve: bool) -> Result<(Dir, CString, PathBuf), String> {
    use std::path::Component;
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(path)
    };
    let name = abs.file_name().ok_or_else(|| format!("{} has no file name", safe_path(path)))?.to_os_string();
    let parent = abs.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("/"));
    let parent = if resolve { std::fs::canonicalize(parent).map_err(|e| format!("{}: {e}", safe_path(parent)))? } else { parent.to_path_buf() };
    let root = cstr(b"/")?;
    // SAFETY: valid C string; the fd is owned by the File below.
    let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("/: {}", errno_str()));
    }
    // SAFETY: fresh descriptor we own.
    let mut cur = unsafe { File::from_raw_fd(fd) };
    let mut real = PathBuf::from("/");
    for c in parent.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => {
                let cn = cstr(n.as_bytes())?;
                // SAFETY: valid fd and C string; result owned below.
                let fd = unsafe { libc::openat(cur.as_raw_fd(), cn.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                if fd < 0 {
                    return Err(format!("{}: {} (a symlinked or missing directory is never followed)", safe_path(&real.join(n)), errno_str()));
                }
                // SAFETY: fresh descriptor we own.
                cur = unsafe { File::from_raw_fd(fd) };
                real.push(n);
            }
            _ => return Err(format!("{}: relative components are not allowed", safe_path(&parent))),
        }
    }
    let full = real.join(&name);
    Ok((Dir { fd: cur, real }, cstr(name.as_bytes())?, full))
}

/// (dev, inode, owner) of an open directory.
fn dir_id(d: &Dir) -> Option<(u64, u64, u32)> {
    let md = d.fd.metadata().ok()?;
    Some((md.dev(), md.ino(), md.uid()))
}

fn refuse_special(dir: &Path) -> Result<(), String> {
    if dir.starts_with("/dev/shm") || dir.starts_with("/dev/mqueue") {
        return Ok(()); // tmpfs: regular files, a favourite drop spot
    }
    for p in ["/proc", "/sys", "/dev"] {
        if dir.starts_with(p) {
            return Err(format!("refusing to touch files under {p}"));
        }
    }
    Ok(())
}

/// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`: (dev, ino, mode) of whatever is at the name now.
fn stat_at(dir: &Dir, name: &CString) -> std::io::Result<(u64, u64, u32)> {
    // SAFETY: zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, C string and out-pointer.
    let r = unsafe { libc::fstatat(dir.fd.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if r != 0 {
        return Err(errno_str());
    }
    Ok((st.st_dev as u64, st.st_ino as u64, st.st_mode as u32))
}

fn unlink_at(dir: &Dir, name: &CString) -> std::io::Result<()> {
    // SAFETY: valid fd and C string.
    if unsafe { libc::unlinkat(dir.fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(errno_str());
    }
    Ok(())
}

fn fsync_dir(p: &Path) {
    if let Ok(f) = File::open(p) {
        let _ = f.sync_all();
    }
}

/// Creates the store (0700) if missing and checks nobody else can write it.
fn prepare_store(store: &Path, create: bool) -> Result<PathBuf, String> {
    if create && std::fs::symlink_metadata(store).is_err() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(store)
            .map_err(|e| format!("{}: {e}", safe_path(store)))?;
    }
    let md = std::fs::symlink_metadata(store).map_err(|e| format!("{}: {e}", safe_path(store)))?;
    if !md.is_dir() {
        return Err(format!("store {} is not a directory (symlinks are refused)", safe_path(store)));
    }
    crate::safety::trusted_dir(store, false).map_err(|e| format!("untrusted store: {}", safe(&e)))?;
    crate::safety::trusted_ancestors(store).map_err(|e| format!("untrusted store: {}", safe(&e)))?;
    if md.mode() & 0o077 != 0 {
        std::fs::set_permissions(store, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", safe_path(store)))?;
    }
    std::fs::canonicalize(store).map_err(|e| format!("{}: {e}", safe_path(store)))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------- quarantine

/// Move `path` into the vault. `expect_sha256`: only if the file still has exactly this
/// content (what was scanned). If the file has other hard links, a warning is appended to
/// the item's `reason` (they still hold the content).
pub fn quarantine_file(store: &Path, path: &Path, expect_sha256: Option<&str>, detector: &str, reason: Vec<String>) -> Result<QItem, String> {
    quarantine_inner(store, path, expect_sha256, detector, reason, &mut || {})
}

/// `before_unlink` runs after the vault copy is durable and just before the identity
/// re-check (tests swap the file there).
fn quarantine_inner(store: &Path, path: &Path, expect_sha256: Option<&str>, detector: &str, mut reason: Vec<String>,
                    before_unlink: &mut dyn FnMut()) -> Result<QItem, String> {
    let expect = match expect_sha256 {
        Some(e) if !is_hex64(e) => return Err(format!("bad expected sha256 {}", safe(e))),
        e => e.map(str::to_ascii_lowercase),
    };
    let store = prepare_store(store, true)?;
    let (dir, name, full) = open_parent(path, true)?;
    let shown = safe_path(&full);
    refuse_special(&dir.real)?;
    if dir.real.starts_with(&store) {
        return Err(format!("{shown} is inside the quarantine store"));
    }

    // SAFETY: valid fd and C string; the result is owned by the File below.
    let fd = unsafe {
        libc::openat(dir.fd.as_raw_fd(), name.as_ptr(),
                     libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
    };
    if fd < 0 {
        let e = errno_str();
        return Err(if e.raw_os_error() == Some(libc::ELOOP) {
            format!("{shown} is a symlink; refused (quarantine the target itself)")
        } else {
            format!("{shown}: {e}")
        });
    }
    // SAFETY: fresh fd we own.
    let file = unsafe { File::from_raw_fd(fd) };
    let md = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !md.is_file() {
        return Err(format!("{shown} is not a regular file; refused"));
    }
    // SAFETY: zeroed statfs is a valid out-parameter.
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and out-pointer.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut sfs) } == 0 {
        let ft = sfs.f_type as u64;
        if ft == 0x9fa0 || ft == 0x6265_6572 {
            return Err(format!("{shown} is on procfs/sysfs; refused"));
        }
    }
    if let Ok(me) = std::fs::metadata("/proc/self/exe") {
        if me.dev() == md.dev() && me.ino() == md.ino() {
            return Err(format!("{shown} is ratel's own executable; refused"));
        }
    }
    if md.len() > MAX_SIZE {
        return Err(format!("{shown} is larger than {} MB; refused", MAX_SIZE >> 20));
    }

    // Two passes when nothing was scanned before (the id, and so the pad, needs the hash);
    // one when the caller already knows what the content must be.
    let pre = match &expect {
        Some(e) => e.clone(),
        None => hash_fd(&file).map_err(|e| format!("{shown}: {e}"))?,
    };
    if expect.is_none() && pre.len() != 64 {
        return Err(format!("{shown}: hashing failed"));
    }
    let t = now();
    let (id, item_dir) = new_item_dir(&store, t, &pre)?;
    let cleanup = |msg: String| -> String {
        let _ = std::fs::remove_dir_all(&item_dir);
        fsync_dir(&store);
        msg
    };

    let (sha, size) = match copy_in(&file, &item_dir.join("data"), &pad(&id)) {
        Ok(v) => v,
        Err(e) => return Err(cleanup(format!("{shown}: {e}"))),
    };
    if sha != pre {
        return Err(cleanup(match &expect {
            Some(_) => format!("{shown} no longer has the scanned content (sha256 {sha}, expected {pre}); left in place"),
            None => format!("{shown} changed while it was being read; left in place"),
        }));
    }
    if md.nlink() > 1 {
        reason.push(format!("warning: {} other hard link(s) still hold this content", md.nlink() - 1));
    }
    let item = QItem {
        id: id.clone(),
        path: full.to_string_lossy().into_owned(),
        sha256: sha,
        size,
        mode: md.mode(),
        uid: md.uid(),
        gid: md.gid(),
        mtime: md.mtime(),
        nlink: md.nlink(),
        t,
        detector: detector.to_string(),
        reason,
        parent: dir_id(&dir),
    };
    if let Err(e) = write_meta(&item_dir, &item) {
        return Err(cleanup(e));
    }
    fsync_dir(&item_dir);
    fsync_dir(&store);

    before_unlink();
    match stat_at(&dir, &name) {
        Ok((dev, ino, _)) if dev == md.dev() && ino == md.ino() => {}
        Ok(_) => return Err(cleanup(format!("{shown} was replaced by a different file (or a symlink) since it was opened; nothing removed"))),
        Err(e) => return Err(cleanup(format!("{shown} disappeared or moved since it was opened ({e}); nothing removed"))),
    }
    if let Err(e) = unlink_at(&dir, &name) {
        return Err(cleanup(format!("{shown}: cannot remove the original: {e}")));
    }
    let _ = dir.fd.sync_all();
    Ok(item)
}

fn hash_fd(f: &File) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut off = 0u64;
    loop {
        let n = f.read_at(&mut buf, off)?;
        if n == 0 {
            break;
        }
        off += n as u64;
        if off > MAX_SIZE {
            return Err(std::io::Error::other("grew past the size limit"));
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Copies the file into `dst` neutralised; returns (sha256 of the plain content, size).
fn copy_in(src: &File, dst: &Path, pad: &[u8]) -> Result<(String, u64), String> {
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dst).map_err(|e| format!("vault: {e}"))?;
    out.write_all(MAGIC).map_err(|e| format!("vault: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut off = 0u64;
    loop {
        let n = src.read_at(&mut buf, off).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if off + n as u64 > MAX_SIZE {
            return Err("grew past the size limit".into());
        }
        h.update(&buf[..n]);
        xor_at(&mut buf[..n], off, pad);
        out.write_all(&buf[..n]).map_err(|e| format!("vault: {e}"))?;
        off += n as u64;
    }
    out.sync_all().map_err(|e| format!("vault: {e}"))?;
    Ok((hex(&h.finalize()), off))
}

/// Claims `<store>/<stamp>-<sha12>[-N]` with an atomic mkdir.
fn new_item_dir(store: &Path, t: f64, sha: &str) -> Result<(String, PathBuf), String> {
    let base = format!("{}-{}", utc_stamp(t), &sha[..12]);
    for n in 1..10_000 {
        let id = if n == 1 { base.clone() } else { format!("{base}-{n}") };
        let d = store.join(&id);
        match std::fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => return Ok((id, d)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", safe_path(&d))),
        }
    }
    Err("could not allocate a vault id".into())
}

fn write_meta(item_dir: &Path, item: &QItem) -> Result<(), String> {
    let tmp = item_dir.join("meta.json.tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp).map_err(|e| format!("vault meta: {e}"))?;
    let j = serde_json::to_vec_pretty(item).map_err(|e| e.to_string())?;
    f.write_all(&j).and_then(|_| f.sync_all()).map_err(|e| format!("vault meta: {e}"))?;
    std::fs::rename(&tmp, item_dir.join("meta.json")).map_err(|e| format!("vault meta: {e}"))
}

fn read_meta(item_dir: &Path) -> Result<QItem, String> {
    let b = crate::safety::trusted_read(&item_dir.join("meta.json"), 1 << 20)?;
    serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", safe_path(&item_dir.join("meta.json"))))
}

// ---------------------------------------------------------------- list / restore / delete

/// Every complete entry in the vault, oldest first. An untrusted or missing store is empty.
pub fn list(store: &Path) -> Vec<QItem> {
    let Ok(store) = prepare_store(store, false) else { return vec![] };
    let Ok(rd) = std::fs::read_dir(&store) else { return vec![] };
    let mut v: Vec<QItem> = rd.filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| valid_id(n))
        .filter_map(|n| read_meta(&store.join(&n)).ok().filter(|i| i.id == n))
        .collect();
    v.sort_by(|a, b| a.t.total_cmp(&b.t).then_with(|| a.id.cmp(&b.id)));
    v
}

fn entry(store: &Path, id: &str) -> Result<(PathBuf, QItem), String> {
    if !valid_id(id) {
        return Err(format!("invalid id {}", safe(id)));
    }
    let store = prepare_store(store, false)?;
    let d = store.join(id);
    if !std::fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir()) {
        return Err(format!("no vault entry {id}"));
    }
    let item = read_meta(&d)?;
    if item.id != id {
        return Err(format!("vault entry {id} has mismatched metadata"));
    }
    Ok((store, item))
}

/// Decodes the vault copy, streaming chunks to `sink`; returns the sha256 of the decoded data.
fn decode(data: &Path, id: &str, size: u64, mut sink: impl FnMut(&[u8]) -> std::io::Result<()>) -> Result<String, String> {
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(data).map_err(|e| format!("vault data: {e}"))?;
    let md = f.metadata().map_err(|e| e.to_string())?;
    if !md.is_file() || md.len() != size + MAGIC.len() as u64 {
        return Err("vault data has the wrong size".into());
    }
    let mut head = [0u8; 8];
    f.read_exact_at(&mut head, 0).map_err(|e| format!("vault data: {e}"))?;
    if &head != MAGIC {
        return Err("vault data has a bad header".into());
    }
    let pad = pad(id);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut off = 0u64;
    while off < size {
        let want = ((size - off) as usize).min(CHUNK);
        f.read_exact_at(&mut buf[..want], off + MAGIC.len() as u64).map_err(|e| format!("vault data: {e}"))?;
        xor_at(&mut buf[..want], off, &pad);
        h.update(&buf[..want]);
        sink(&buf[..want]).map_err(|e| e.to_string())?;
        off += want as u64;
    }
    Ok(hex(&h.finalize()))
}

/// Writes the file back to its original path (or `to`), verified against the recorded
/// sha256, with mode/owner/mtime restored, then removes the vault entry. Never follows a
/// symlink at the target; an existing target is only replaced with `force` (atomically,
/// by rename, so a symlink there is replaced, not followed).
pub fn restore(store: &Path, id: &str, to: Option<&Path>, force: bool) -> Result<PathBuf, String> {
    let (store, item) = entry(store, id)?;
    let item_dir = store.join(id);
    let data = item_dir.join("data");
    let target = to.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&item.path));
    let (dir, name, full) = open_parent(&target, false)?;
    let shown = safe_path(&full);
    refuse_special(&dir.real)?;
    let now = dir_id(&dir).ok_or("cannot stat the target directory")?;
    if to.is_none() {
        if let Some((dev, ino, _)) = item.parent {
            if (dev, ino) != (now.0, now.1) {
                return Err(format!("{} is not the directory {id} came from (it was replaced since); \
                                    restore elsewhere with --to", safe_path(&dir.real)));
            }
        }
    }
    // a directory someone else controls could be swapped under us between checks and use
    if now.2 != 0 && now.2 != item.uid {
        return Err(format!("{} is owned by uid {}, neither root nor the file's owner (uid {}); restore elsewhere with --to",
            safe_path(&dir.real), now.2, item.uid));
    }
    if dir.real.starts_with(&store) {
        return Err(format!("{shown} is inside the quarantine store"));
    }
    match stat_at(&dir, &name) {
        Ok((_, _, mode)) if mode & libc::S_IFMT == libc::S_IFDIR => return Err(format!("{shown} is a directory")),
        Ok(_) if !force => return Err(format!("{shown} already exists; use --force to replace it")),
        _ => {}
    }
    // verify before writing anything outside the vault
    let sha = decode(&data, id, item.size, |_| Ok(()))?;
    if sha != item.sha256 {
        return Err(format!("vault entry {id} is corrupt (sha256 {sha}, expected {})", item.sha256));
    }

    let tmp = cstr(format!(".ratel-restore-{id}").as_bytes())?;
    // SAFETY: valid fd and C string; result owned by the File below.
    let fd = unsafe {
        libc::openat(dir.fd.as_raw_fd(), tmp.as_ptr(),
                     libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY, 0o600 as libc::c_uint)
    };
    if fd < 0 {
        return Err(format!("{shown}: cannot create a temporary file next to it: {}", errno_str()));
    }
    // SAFETY: fresh fd we own.
    let mut out = unsafe { File::from_raw_fd(fd) };
    let fail = |m: String| -> String {
        let _ = unlink_at(&dir, &tmp);
        m
    };
    let sha = match decode(&data, id, item.size, |b| out.write_all(b)) {
        Ok(s) => s,
        Err(e) => return Err(fail(format!("{shown}: {e}"))),
    };
    if sha != item.sha256 {
        return Err(fail(format!("vault entry {id} changed while restoring")));
    }
    if let Err(e) = set_attrs(&out, &item) {
        return Err(fail(format!("{shown}: {e}")));
    }
    if let Err(e) = out.sync_all() {
        return Err(fail(format!("{shown}: {e}")));
    }
    drop(out);
    let dfd = dir.fd.as_raw_fd();
    if force {
        // SAFETY: valid fds and C strings.
        if unsafe { libc::renameat(dfd, tmp.as_ptr(), dfd, name.as_ptr()) } != 0 {
            return Err(fail(format!("{shown}: {}", errno_str())));
        }
    } else {
        // link() never replaces: an entry created meanwhile makes it fail with EEXIST
        // SAFETY: valid fds and C strings.
        if unsafe { libc::linkat(dfd, tmp.as_ptr(), dfd, name.as_ptr(), 0) } != 0 {
            let e = errno_str();
            return Err(fail(if e.raw_os_error() == Some(libc::EEXIST) {
                format!("{shown} already exists; use --force to replace it")
            } else {
                format!("{shown}: {e}")
            }));
        }
        let _ = unlink_at(&dir, &tmp);
    }
    let _ = dir.fd.sync_all();
    std::fs::remove_dir_all(&item_dir).map_err(|e| format!("restored, but the vault entry could not be removed: {e}"))?;
    fsync_dir(&store);
    Ok(full)
}

fn set_attrs(f: &File, item: &QItem) -> Result<(), String> {
    let fd = f.as_raw_fd();
    // SAFETY: trivial libc calls on a valid fd.
    unsafe {
        let euid = libc::geteuid();
        if libc::fchown(fd, item.uid, item.gid) != 0 && euid == 0 {
            return Err(format!("chown: {}", errno_str()));
        }
        // after chown (which clears set-id bits)
        if libc::fchmod(fd, (item.mode & 0o7777) as libc::mode_t) != 0 {
            return Err(format!("chmod: {}", errno_str()));
        }
        let ts = [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW },
            libc::timespec { tv_sec: item.mtime as _, tv_nsec: 0 },
        ];
        if libc::futimens(fd, ts.as_ptr()) != 0 {
            return Err(format!("utimes: {}", errno_str()));
        }
    }
    Ok(())
}

/// Removes a vault entry for good.
pub fn delete(store: &Path, id: &str) -> Result<(), String> {
    if !valid_id(id) {
        return Err(format!("invalid id {}", safe(id)));
    }
    let store = prepare_store(store, false)?;
    let d = store.join(id);
    if !std::fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir()) {
        return Err(format!("no vault entry {id}"));
    }
    std::fs::remove_dir_all(&d).map_err(|e| format!("{}: {e}", safe_path(&d)))?;
    fsync_dir(&store);
    Ok(())
}

// ---------------------------------------------------------------- CLI

fn print_item(i: &QItem, long: bool) {
    if !long {
        println!("{}  {}  {:>10}  {:<10} {}", i.id, utc_human(i.t), i.size, safe(&i.detector), safe(&i.path));
        return;
    }
    println!("id        {}", i.id);
    println!("path      {}", safe(&i.path));
    println!("when      {}", utc_human(i.t));
    println!("sha256    {}", i.sha256);
    println!("size      {}", i.size);
    println!("mode      {:o}  uid {}  gid {}  mtime {}", i.mode & 0o7777, i.uid, i.gid, utc_human(i.mtime as f64));
    println!("links     {}", i.nlink);
    println!("detector  {}", safe(&i.detector));
    for r in &i.reason {
        println!("reason    {}", safe(r));
    }
}

/// `ratel quarantine ...`; returns the exit code.
pub fn cli(args: &[String]) -> i32 {
    let mut store = PathBuf::from(DEFAULT_STORE);
    let (mut json, mut force) = (false, false);
    let (mut reason, mut to): (Option<String>, Option<PathBuf>) = (None, None);
    let mut pos: Vec<String> = vec![];
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(a, "--store" | "--reason" | "--to") {
            let Some(v) = args.get(i + 1).cloned() else {
                eprintln!("ratel: {a} needs a value");
                return 2;
            };
            match a {
                "--store" => store = PathBuf::from(v),
                "--reason" => reason = Some(v),
                _ => to = Some(PathBuf::from(v)),
            }
            i += 2;
            continue;
        }
        match a {
            "--json" => json = true,
            "--force" => force = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            s if s.starts_with("--") => {
                eprintln!("ratel: unknown option {}\n\n{USAGE}", safe(s));
                return 2;
            }
            s => pos.push(s.to_string()),
        }
        i += 1;
    }
    let sub = pos.first().map(String::as_str).unwrap_or("list");
    let arg = pos.get(1);
    let need = |what: &str| -> i32 {
        eprintln!("ratel: quarantine {sub} needs {what}\n\n{USAGE}");
        2
    };
    let fail = |e: String| -> i32 {
        eprintln!("ratel: {e}");
        1
    };
    match sub {
        "list" => {
            let v = list(&store);
            if json {
                println!("{}", serde_json::to_string(&v).unwrap_or_default());
            } else {
                for it in &v {
                    print_item(it, false);
                }
                eprintln!("{} item(s) in {}", v.len(), safe_path(&store));
            }
            0
        }
        "add" => {
            let Some(p) = arg else { return need("a PATH") };
            let reasons = vec![reason.unwrap_or_else(|| "manual quarantine".into())];
            match quarantine_file(&store, Path::new(p), None, "manual", reasons) {
                Ok(it) => {
                    if json {
                        println!("{}", serde_json::to_string(&it).unwrap_or_default());
                    } else {
                        println!("quarantined {} as {}", safe(&it.path), it.id);
                    }
                    if it.nlink > 1 {
                        eprintln!("ratel: warning: {} other hard link(s) to {} still hold this content (find them with: find / -xdev -inum <inode>)",
                                  it.nlink - 1, safe(&it.path));
                    }
                    0
                }
                Err(e) => fail(e),
            }
        }
        "show" => {
            let Some(id) = arg else { return need("an ID") };
            match entry(&store, id) {
                Ok((_, it)) => {
                    if json {
                        println!("{}", serde_json::to_string(&it).unwrap_or_default());
                    } else {
                        print_item(&it, true);
                    }
                    0
                }
                Err(e) => fail(e),
            }
        }
        "restore" => {
            let Some(id) = arg else { return need("an ID") };
            match restore(&store, id, to.as_deref(), force) {
                Ok(p) => {
                    if json {
                        println!("{}", serde_json::json!({"id": id, "restored": p.to_string_lossy()}));
                    } else {
                        println!("restored {} to {}", safe(id), safe_path(&p));
                    }
                    0
                }
                Err(e) => fail(e),
            }
        }
        "delete" => {
            let Some(id) = arg else { return need("an ID") };
            match delete(&store, id) {
                Ok(()) => {
                    if json {
                        println!("{}", serde_json::json!({"id": id, "deleted": true}));
                    } else {
                        println!("deleted {}", safe(id));
                    }
                    0
                }
                Err(e) => fail(e),
            }
        }
        s => {
            eprintln!("ratel: unknown quarantine command {}\n\n{USAGE}", safe(s));
            2
        }
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ratel-q-{tag}-{}-{}", std::process::id(), (now() * 1e6) as u64));
        std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        d
    }

    fn sha(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    const BODY: &[u8] = b"\x7fELF\x02\x01\x01\0 pretend malware payload, with a signature: EICAR-ish \x00\x01\x02";

    #[test]
    fn time_format() {
        assert_eq!(utc_stamp(0.0), "19700101T000000Z");
        assert_eq!(utc_human(1_793_621_412.0), "2026-11-02 12:10:12Z");
        assert_eq!(utc_stamp(951_782_400.0), "20000229T000000Z");
    }

    #[test]
    fn round_trip_preserves_content_mode_mtime() {
        let d = tmpdir("rt");
        let store = d.join("store");
        let f = d.join("evil.bin");
        let big: Vec<u8> = BODY.iter().copied().cycle().take(200_000).collect();
        std::fs::write(&f, &big).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o751)).unwrap();
        let mt = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        File::options().write(true).open(&f).unwrap().set_modified(mt).unwrap();

        let it = quarantine_file(&store, &f, Some(&sha(&big)), "test", vec!["why".into()]).unwrap();
        assert!(!f.exists(), "original removed");
        assert_eq!(it.sha256, sha(&big));
        assert_eq!(it.size, big.len() as u64);
        assert!(valid_id(&it.id) && it.id.ends_with(&sha(&big)[..12]));
        assert_eq!(std::fs::metadata(&store).unwrap().mode() & 0o777, 0o700);
        let data = store.join(&it.id).join("data");
        assert_eq!(std::fs::metadata(&data).unwrap().mode() & 0o777, 0o600);
        let stored = std::fs::read(&data).unwrap();
        assert!(stored.starts_with(MAGIC));
        assert_ne!(&stored[8..], &big[..], "vault content is neutralised");
        assert!(!stored.windows(BODY.len()).any(|w| w == BODY), "no plaintext signature in the vault");
        assert_eq!(list(&store).len(), 1);

        // same content again gets its own id
        std::fs::write(&f, &big).unwrap();
        let it2 = quarantine_file(&store, &f, None, "test", vec![]).unwrap();
        assert_ne!(it.id, it2.id);
        assert_eq!(list(&store).len(), 2);
        delete(&store, &it2.id).unwrap();

        let back = restore(&store, &it.id, None, false).unwrap();
        assert_eq!(back, std::fs::canonicalize(&d).unwrap().join("evil.bin"));
        assert_eq!(std::fs::read(&f).unwrap(), big);
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!(md.mode() & 0o7777, 0o751);
        assert_eq!(md.mtime(), 1_700_000_000);
        assert!(list(&store).is_empty(), "entry removed after restore");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn expected_hash_mismatch_leaves_original() {
        let d = tmpdir("mm");
        let store = d.join("store");
        let f = d.join("x");
        std::fs::write(&f, BODY).unwrap();
        let e = quarantine_file(&store, &f, Some(&sha(b"something else")), "t", vec![]).unwrap_err();
        assert!(e.contains("no longer has the scanned content"), "{e}");
        assert_eq!(std::fs::read(&f).unwrap(), BODY);
        assert!(std::fs::read_dir(&store).unwrap().next().is_none(), "no leftover vault entry");
        assert!(quarantine_file(&store, &f, Some("../../etc"), "t", vec![]).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_symlinks_and_special_files() {
        let d = tmpdir("sl");
        let store = d.join("store");
        let target = d.join("victim");
        std::fs::write(&target, BODY).unwrap();
        let l = d.join("link");
        std::os::unix::fs::symlink(&target, &l).unwrap();
        let e = quarantine_file(&store, &l, None, "t", vec![]).unwrap_err();
        assert!(e.contains("symlink"), "{e}");
        assert!(target.exists() && l.symlink_metadata().is_ok());
        assert!(quarantine_file(&store, &d, None, "t", vec![]).is_err(), "directory");
        assert!(quarantine_file(&store, Path::new("/proc/self/status"), None, "t", vec![]).is_err());
        assert!(quarantine_file(&store, Path::new("/dev/null"), None, "t", vec![]).is_err());
        let e = quarantine_file(&store, &std::env::current_exe().unwrap(), None, "t", vec![]).unwrap_err();
        assert!(e.contains("own executable"), "{e}");
        // an untrusted (world-writable) store is refused
        let bad = d.join("badstore");
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(quarantine_file(&bad, &target, None, "t", vec![]).unwrap_err().contains("untrusted store"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn swapped_file_is_not_removed() {
        let d = tmpdir("swap");
        let store = d.join("store");
        let f = d.join("payload");
        std::fs::write(&f, BODY).unwrap();
        let other = d.join("innocent");
        std::fs::write(&other, b"innocent data").unwrap();
        let (f2, o2) = (f.clone(), other.clone());
        let e = quarantine_inner(&store, &f, None, "t", vec![], &mut || std::fs::rename(&o2, &f2).unwrap()).unwrap_err();
        assert!(e.contains("replaced by a different file"), "{e}");
        assert_eq!(std::fs::read(&f).unwrap(), b"innocent data", "the swapped-in file survives");
        assert!(list(&store).is_empty() && std::fs::read_dir(&store).unwrap().next().is_none());

        // swapped for a symlink
        std::fs::write(&f, BODY).unwrap();
        let (f3, t3) = (f.clone(), d.join("innocent2"));
        std::fs::write(&t3, b"x").unwrap();
        let e = quarantine_inner(&store, &f, None, "t", vec![], &mut || {
            std::fs::remove_file(&f3).unwrap();
            std::os::unix::fs::symlink(&t3, &f3).unwrap();
        }).unwrap_err();
        assert!(e.contains("replaced"), "{e}");
        assert!(f.symlink_metadata().unwrap().is_symlink() && t3.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hard_links_are_reported() {
        let d = tmpdir("hl");
        let store = d.join("store");
        let f = d.join("a");
        std::fs::write(&f, BODY).unwrap();
        std::fs::hard_link(&f, d.join("b")).unwrap();
        let it = quarantine_file(&store, &f, None, "t", vec![]).unwrap();
        assert_eq!(it.nlink, 2);
        assert!(it.reason.iter().any(|r| r.contains("1 other hard link")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ids_are_validated() {
        let d = tmpdir("id");
        let store = d.join("store");
        std::fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        std::fs::write(d.join("secret"), b"s").unwrap();
        for bad in ["..", "../secret", "a/b", ".", "", "-x", "a.b", "a\nb"] {
            assert!(!valid_id(bad), "{bad:?}");
            assert!(restore(&store, bad, None, false).unwrap_err().contains("invalid id"));
            assert!(delete(&store, bad).unwrap_err().contains("invalid id"));
        }
        assert!(d.join("secret").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restore_never_goes_through_a_swapped_directory() {
        // quarantined from d/u/x.sh; then d/u becomes a symlink to a directory the
        // attacker wants a file in (e.g. /etc/profile.d): restore must refuse
        let d = tmpdir("swap");
        let store = d.join("store");
        let (u, target) = (d.join("u"), d.join("profile.d"));
        std::fs::create_dir(&u).unwrap();
        std::fs::create_dir(&target).unwrap();
        let f = u.join("x.sh");
        std::fs::write(&f, BODY).unwrap();
        let it = quarantine_file(&store, &f, Some(&sha(BODY)), "test", vec![]).unwrap();
        assert!(it.parent.is_some());
        std::fs::rename(&u, d.join("u.old")).unwrap();
        std::os::unix::fs::symlink(&target, &u).unwrap();
        let e = restore(&store, &it.id, None, true).unwrap_err();
        assert!(e.contains("never followed"), "{e}");
        assert!(!target.join("x.sh").exists(), "nothing written through the link");
        // a directory recreated in its place (same name, another inode) is refused too
        std::fs::remove_file(&u).unwrap();
        std::fs::create_dir(&u).unwrap();
        let e = restore(&store, &it.id, None, false).unwrap_err();
        assert!(e.contains("not the directory"), "{e}");
        // --to an explicit place still works
        let out = restore(&store, &it.id, Some(&d.join("restored.sh")), false).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), BODY);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restore_refuses_overwrite_and_never_follows_links() {
        let d = tmpdir("ow");
        let store = d.join("store");
        let f = d.join("x");
        std::fs::write(&f, BODY).unwrap();
        let it = quarantine_file(&store, &f, None, "t", vec![]).unwrap();
        std::fs::write(&f, b"new file").unwrap();
        let e = restore(&store, &it.id, None, false).unwrap_err();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(std::fs::read(&f).unwrap(), b"new file");
        assert_eq!(list(&store).len(), 1, "entry kept after a refused restore");

        // --force over a symlink replaces the link, not its target
        std::fs::remove_file(&f).unwrap();
        let victim = d.join("victim");
        std::fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, &f).unwrap();
        assert!(restore(&store, &it.id, None, false).is_err());
        restore(&store, &it.id, None, true).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
        assert!(!f.symlink_metadata().unwrap().is_symlink());
        assert_eq!(std::fs::read(&f).unwrap(), BODY);

        // --to somewhere else; a corrupt entry is refused
        let it = quarantine_file(&store, &f, None, "t", vec![]).unwrap();
        let data = store.join(&it.id).join("data");
        let mut b = std::fs::read(&data).unwrap();
        b[20] ^= 1;
        std::fs::write(&data, &b).unwrap();
        assert!(restore(&store, &it.id, Some(&d.join("y")), false).unwrap_err().contains("corrupt"));
        assert!(!d.join("y").exists());
        b[20] ^= 1;
        std::fs::write(&data, &b).unwrap();
        restore(&store, &it.id, Some(&d.join("y")), false).unwrap();
        assert_eq!(std::fs::read(d.join("y")).unwrap(), BODY);
        let _ = std::fs::remove_dir_all(&d);
    }
}
