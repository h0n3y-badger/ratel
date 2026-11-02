//! Confinement for `ratel web`, applied before it handles any request:
//! 1. drop root (setgroups/setgid/setuid to an unprivileged user; verified),
//! 2. no core dumps, not ptrace-attachable, no new privileges (setuid binaries,
//!    file capabilities can't elevate it),
//! 3. Landlock: the process can read only ratel's state/log/status directories
//!    and write only the feedback inbox; with kernel support it also can't open
//!    outbound TCP connections or bind other ports, connect to abstract UNIX
//!    sockets of other domains or signal processes outside its domain.
//! Landlock needs Linux >= 5.13; each ABI level adds restrictions, and what the
//! running kernel enforced is reported.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// Drop root to `user` (and its primary group, no supplementary groups).
pub fn drop_privileges(user: &str) -> Result<(), String> {
    // SAFETY: plain libc calls; getpwnam's result is copied out before any other call.
    unsafe {
        if libc::geteuid() != 0 {
            return Ok(());
        }
        let c = CString::new(user).map_err(|_| "bad user name")?;
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            return Err(format!("user {user} doesn't exist (create it, or run ratel web as an unprivileged user)"));
        }
        let (uid, gid) = ((*pw).pw_uid, (*pw).pw_gid);
        if uid == 0 {
            return Err(format!("{user} is root; refusing"));
        }
        if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(format!("dropping to {user} failed: {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(0) == 0 || libc::geteuid() == 0 {
            return Err("privilege drop could be undone; refusing to continue".into());
        }
    }
    Ok(())
}

/// No core dumps (session secrets), no ptrace by other same-uid processes, no new privileges.
pub fn harden_process() -> Result<(), String> {
    // SAFETY: prctl/setrlimit with constant arguments.
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        let nofile = libc::rlimit { rlim_cur: 256, rlim_max: 256 };
        libc::setrlimit(libc::RLIMIT_NOFILE, &nofile);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

// ---- Landlock (uapi/linux/landlock.h)
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;
const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
const ACCESS_NET_BIND_UDP: u64 = 1 << 2;
const ACCESS_NET_CONNECT_SEND_UDP: u64 = 1 << 3;
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Everything filesystem-related this ABI can restrict (bits 0..=12, +REFER v2,
/// +TRUNCATE v3, +IOCTL_DEV v5).
fn fs_all(abi: i64) -> u64 {
    let mut a = (1u64 << 13) - 1;
    if abi >= 2 {
        a |= 1 << 13;
    }
    if abi >= 3 {
        a |= 1 << 14;
    }
    if abi >= 5 {
        a |= 1 << 15;
    }
    if abi >= 9 {
        a |= ACCESS_FS_RESOLVE_UNIX; // connecting to pathname UNIX sockets
    }
    a
}

fn net_all(abi: i64) -> u64 {
    let mut a = 0;
    if abi >= 4 {
        a |= ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP;
    }
    if abi >= 10 {
        a |= ACCESS_NET_BIND_UDP | ACCESS_NET_CONNECT_SEND_UDP;
    }
    a
}

pub struct Rules<'a> {
    pub read_dirs: Vec<&'a Path>,
    pub write_dirs: Vec<&'a Path>,
}

/// Applies Landlock; returns a human-readable description of what is enforced.
pub fn landlock(r: &Rules) -> Result<String, String> {
    // SAFETY: Landlock syscalls with correctly sized, initialised structures; fds are owned.
    unsafe {
        let abi = libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0usize, CREATE_RULESET_VERSION);
        if abi < 1 {
            return Err(format!("Landlock not available ({}); needs Linux >= 5.13 with landlock in the LSM list",
                std::io::Error::last_os_error()));
        }
        // Ask for everything this ABI knows; if the kernel rejects a bit (ABI numbering
        // differs from our table), step down one ABI level at a time.
        let mut level = abi;
        let (fd, handled_fs, handled_net) = loop {
            let attr = RulesetAttr {
                handled_access_fs: fs_all(level),
                handled_access_net: net_all(level),
                scoped: if level >= 6 { SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL } else { 0 },
            };
            let size = if level >= 6 { 24 } else if level >= 4 { 16 } else { 8 };
            let fd = libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size as usize, 0u32);
            if fd >= 0 {
                break (fd, attr.handled_access_fs, attr.handled_access_net);
            }
            if level <= 1 {
                return Err(format!("landlock_create_ruleset: {}", std::io::Error::last_os_error()));
            }
            level -= 1;
        };
        let abi = level;
        let ruleset = OwnedFd::from_raw_fd(fd as i32);
        let add = |p: &Path, access: u64| -> Result<(), String> {
            let c = CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| "bad path")?;
            let pfd = libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if pfd < 0 {
                return Ok(()); // missing directory: nothing to allow
            }
            let pfd = OwnedFd::from_raw_fd(pfd);
            let rule = PathBeneathAttr { allowed_access: access & handled_fs, parent_fd: pfd.as_raw_fd() };
            if libc::syscall(libc::SYS_landlock_add_rule, ruleset.as_raw_fd(), RULE_PATH_BENEATH, &rule as *const PathBeneathAttr, 0u32) != 0 {
                return Err(format!("landlock_add_rule {}: {}", p.display(), std::io::Error::last_os_error()));
            }
            Ok(())
        };
        for d in &r.read_dirs {
            add(d, ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR)?;
        }
        for d in &r.write_dirs {
            add(d, ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_WRITE_FILE | ACCESS_FS_MAKE_REG)?;
        }
        let _ = ACCESS_FS_EXECUTE;
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) != 0 {
            return Err(format!("landlock_restrict_self: {}", std::io::Error::last_os_error()));
        }
        Ok(format!("Landlock ABI {abi}: filesystem limited to ratel's directories{}{}{}{}",
            if handled_net & ACCESS_NET_CONNECT_TCP != 0 { ", no outbound TCP / other binds" } else { "" },
            if handled_net & ACCESS_NET_CONNECT_SEND_UDP != 0 { ", no UDP" } else { "" },
            if handled_fs & ACCESS_FS_RESOLVE_UNIX != 0 { ", no UNIX-socket connects" } else { "" },
            if abi >= 6 { ", no abstract-socket or signal access outside" } else { "" }))
    }
}

/// Cryptographically secure random bytes from the kernel (no file access needed).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let mut got = 0;
    while got < N {
        // SAFETY: getrandom into our buffer.
        let n = unsafe { libc::getrandom(b[got..].as_mut_ptr() as *mut libc::c_void, N - got, 0) };
        if n <= 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("getrandom failed: {e}");
        }
        got += n as usize;
    }
    b
}
