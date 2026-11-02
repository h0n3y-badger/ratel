//! Shared defences against injection.
//!
//! * `safe()`: attacker-controlled text (file names, command lines, DNS names, process
//!   names) is shown with control characters, ANSI escape sequences, bidi overrides and
//!   invisible characters escaped. Without it a crafted file name could rewrite the
//!   admin's terminal (`ratel scan /tmp`) or forge lines in an XMPP alert.
//! * `trusted_file()` / `trusted_dir()`: configuration, state, allowlists and package
//!   databases are only believed if nobody but root (or our own user) can have written them.
//! * `trusted_read()`: the same, race-free, for files ratel parses (config, state,
//!   allowlists, feedback): open without following links, check the open file, walk every
//!   ancestor directory.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn is_invisible(c: char) -> bool {
    let u = c as u32;
    c.is_control()
        || (0x200B..=0x200F).contains(&u)
        || (0x2028..=0x202E).contains(&u)
        || (0x2060..=0x2069).contains(&u)
        || (0xFE00..=0xFE0F).contains(&u)      // variation selectors
        || (0xE0000..=0xE007F).contains(&u)    // tag characters
        || (0xE0100..=0xE01EF).contains(&u)    // variation selectors supplement
        || matches!(u, 0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180E | 0x3164 | 0xFEFF | 0xFFA0)
}

/// Text that is safe to print to a terminal, a log line or a chat message.
pub fn safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_invisible(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// For identifiers built from attacker-controlled text (entity names): like `safe`, but
/// also escapes `\\` so the result is injective: a file literally named `x\\u{a}` can't
/// share a key (and a baseline) with `x<newline>`. `safe(safe_key(x)) == safe_key(x)`.
pub fn safe_key(s: &str) -> String {
    safe(&s.replace('\\', "\\\\"))
}

/// Like `safe`, for a path.
pub fn safe_path(p: &Path) -> String {
    safe(&p.to_string_lossy())
}

fn euid() -> u32 {
    // SAFETY: trivial libc call.
    unsafe { libc::geteuid() }
}

/// A file (and the directory holding it) that only root or we can have written.
/// `group_write_ok` allows group-writable files (none of ours need it).
pub fn trusted_file(p: &Path) -> Result<(), String> {
    let md = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    check_owner(p, &md, false)?;
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        trusted_dir(dir, false)?;
    }
    Ok(())
}

/// A directory nobody else can add or replace files in.
pub fn trusted_dir(p: &Path, group_write_ok: bool) -> Result<(), String> {
    let md = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    check_owner(p, &md, group_write_ok)
}

/// Every directory from `/` down to `dir` must be one nobody else can rename or replace
/// entries in. Root-owned sticky directories (/tmp) are allowed: there others can add
/// files but not replace ours, and the file itself is checked separately.
pub fn trusted_ancestors(dir: &Path) -> Result<(), String> {
    // the path as written (a symlink component is governed by the directory holding it,
    // so links themselves are skipped)...
    let abs = if dir.is_absolute() { dir.to_path_buf() } else { std::env::current_dir().map_err(|e| e.to_string())?.join(dir) };
    for a in abs.ancestors() {
        let md = std::fs::symlink_metadata(a).map_err(|e| format!("{}: {e}", a.display()))?;
        if md.file_type().is_symlink() || (md.uid() == 0 && md.mode() & 0o1000 != 0) {
            continue;
        }
        check_owner(a, &md, false)?;
    }
    // ...and where it really leads
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for a in dir.ancestors() {
        let md = std::fs::metadata(a).map_err(|e| format!("{}: {e}", a.display()))?;
        if md.uid() == 0 && md.mode() & 0o1000 != 0 {
            continue; // root-owned sticky
        }
        check_owner(a, &md, false)?;
    }
    Ok(())
}

/// Read a configuration/state file only if root (or we) wrote it and nobody else could
/// have swapped it: no symlink at the last component, the *opened* file is checked (no
/// check-then-open race), and all ancestor directories are trusted. At most `max` bytes.
pub fn trusted_read(p: &Path, max: u64) -> Result<Vec<u8>, String> {
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    trusted_ancestors(parent)?;
    read_regular(p, max, true)
}

/// Read an *untrusted* file defensively: no symlinks, no FIFOs/devices (which could hang
/// or flood a root daemon), at most `max` bytes even if it grows while we read.
pub fn bounded_read(p: &Path, max: u64) -> Result<Vec<u8>, String> {
    read_regular(p, max, false)
}

fn read_regular(p: &Path, max: u64, owner_check: bool) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    let md = f.metadata().map_err(|e| format!("{}: {e}", p.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", p.display()));
    }
    if owner_check {
        check_owner(p, &md, false)?;
    }
    if md.len() > max {
        return Err(format!("{} is larger than {max} bytes", p.display()));
    }
    let mut b = Vec::with_capacity(md.len() as usize);
    f.take(max + 1).read_to_end(&mut b).map_err(|e| format!("{}: {e}", p.display()))?;
    if b.len() as u64 > max {
        return Err(format!("{} grew past {max} bytes", p.display()));
    }
    Ok(b)
}

/// `trusted_read` as UTF-8 text.
pub fn trusted_read_string(p: &Path, max: u64) -> Result<String, String> {
    String::from_utf8(trusted_read(p, max)?).map_err(|_| format!("{} is not UTF-8", p.display()))
}

fn check_owner(p: &Path, md: &std::fs::Metadata, group_write_ok: bool) -> Result<(), String> {
    let me = euid();
    if md.uid() != 0 && md.uid() != me {
        return Err(format!("{} is owned by uid {}, not root{}", p.display(), md.uid(), if me != 0 { " or us" } else { "" }));
    }
    let mode = md.mode();
    if mode & 0o002 != 0 {
        return Err(format!("{} is world-writable", p.display()));
    }
    if mode & 0o020 != 0 && !group_write_ok {
        return Err(format!("{} is group-writable", p.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_and_bidi_tricks() {
        assert_eq!(safe("ok-name.py"), "ok-name.py");
        assert_eq!(safe("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(safe("x\nHIGH all clear"), "x\\u{a}HIGH all clear");
        assert_eq!(safe("evil\u{202e}gpj.exe"), "evil\\u{202e}gpj.exe");
        assert_eq!(safe("ünïcödé"), "ünïcödé");
        // keys are injective: a literal backslash-u can't impersonate an escape
        assert_ne!(safe_key("x\\u{a}"), safe_key("x\n"));
        assert_eq!(safe(&safe_key("a\\b\n")), safe_key("a\\b\n"));
    }

    #[test]
    fn trust_checks() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("ratel-trust-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = d.join("conf");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(trusted_file(&f).is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(trusted_file(&f).is_err());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(trusted_file(&f).is_err());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_file(&f).is_err(), "world-writable parent directory");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        // trusted_read: the opened file is checked, symlinks refused, size capped
        assert_eq!(trusted_read(&f, 10).unwrap(), b"x");
        assert!(trusted_read(&f, 0).is_err(), "size cap");
        let l = d.join("link");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        assert!(trusted_read(&l, 10).is_err(), "symlink at the last component");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o646)).unwrap();
        assert!(trusted_read(&f, 10).is_err());
        assert_eq!(bounded_read(&f, 10).unwrap(), b"x", "untrusted read skips the owner check only");
        assert!(bounded_read(&l, 10).is_err());
        // a symlinked directory component inside an untrusted directory
        let ud = d.join("open");
        std::fs::create_dir(&ud).unwrap();
        std::os::unix::fs::symlink(&d, ud.join("via")).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(trusted_read(&ud.join("via").join("conf"), 10).is_ok());
        std::fs::set_permissions(&ud, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_read(&ud.join("via").join("conf"), 10).is_err(), "link lives in a world-writable dir");
        std::fs::set_permissions(&ud, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
