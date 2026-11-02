//! Socket inode -> process attribution, "entity" naming, and process-level red
//! flags for processes that hold network sockets.
//!
//! An entity is what baselines are learned for: the executable path, plus the
//! container it runs in, plus the script for interpreters (so every Python
//! script doesn't share one profile).

use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub exe: String,
    pub cmdline: String,
    pub ent: String,
    /// The program actually running (differs from exe when started via the dynamic loader).
    pub prog: String,
    /// For loader-launched processes: what the loader really mapped, as (file to read via
    /// /proc/pid/map_files, path for display/provenance). Empty otherwise.
    pub mapped: Vec<(std::path::PathBuf, String)>,
    /// Socket inodes on stdin/stdout/stderr.
    pub std_socks: Vec<u64>,
    /// All socket inodes it holds.
    pub socks: Vec<u64>,
}

const INTERPRETERS: &[&str] = &["python", "perl", "ruby", "node", "php", "java", "lua", "bun", "deno", "pwsh", "tclsh"];
pub const SHELLS: &[&str] = &["sh", "bash", "ash", "dash", "zsh", "ksh", "mksh", "fish", "busybox", "csh", "tcsh"];

fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

pub fn is_interp(exe: &str) -> bool {
    let b = base(exe);
    INTERPRETERS.iter().any(|i| b.starts_with(i))
}

/// The dynamic loader run directly (`/lib/ld-musl-x86_64.so.1 ./prog`): /proc/pid/exe
/// then names the loader, a verified package file, instead of the real program.
pub fn is_loader(exe: &str) -> bool {
    let b = base(exe.trim_end_matches(" (deleted)"));
    b.starts_with("ld-musl") || b.starts_with("ld-linux") || b == "ld.so"
}

/// The program a loader was asked to run, resolved against the process's cwd.
pub fn loader_program(pid: u32, args: &[String]) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(a, "--library-path" | "--preload" | "--argv0" | "--audit" | "--inhibit-rpath" | "--glibc-hwcaps-prepend" | "--glibc-hwcaps-mask") {
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            i += 1;
            continue;
        }
        let p = std::path::Path::new(a);
        let full = if p.is_absolute() { p.to_path_buf() } else {
            std::fs::read_link(format!("/proc/{pid}/cwd")).map(|c| c.join(p)).unwrap_or_else(|_| p.to_path_buf())
        };
        return Some(full.to_string_lossy().into_owned());
    }
    None
}

/// Objects a loader-launched process really runs: file mappings at offset 0 (not the
/// loader itself) whose ELF headers request an interpreter (PT_INTERP), i.e. programs
/// rather than libraries. From /proc/pid/maps (kernel-written; argv and cwd are not), read
/// through /proc/pid/map_files (pins the exact inode, works across mount namespaces;
/// needs root, else falls back to /proc/pid/root/<path>).
pub fn loader_mapped(pid: u32) -> Vec<(std::path::PathBuf, String)> {
    use std::os::unix::fs::MetadataExt;
    let loader_ino = std::fs::metadata(format!("/proc/{pid}/exe")).map(|m| m.ino()).unwrap_or(0);
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else { return vec![] };
    let mut seen = HashSet::new();
    let mut out = vec![];
    for l in maps.lines() {
        let mut it = l.splitn(6, ' ');
        let (Some(range), Some(_perms), Some(off), Some(_dev), Some(ino), Some(path)) =
            (it.next(), it.next(), it.next(), it.next(), it.next(), it.next()) else { continue };
        let path = path.trim_start();
        let ino: u64 = ino.parse().unwrap_or(0);
        if ino == 0 || ino == loader_ino || off.trim_start_matches('0') != "" || !path.starts_with('/') || !seen.insert(ino) {
            continue;
        }
        let mf = std::path::PathBuf::from(format!("/proc/{pid}/map_files/{range}"));
        let file = if std::fs::metadata(&mf).is_ok() { mf } else {
            std::path::PathBuf::from(format!("/proc/{pid}/root{}", path.trim_end_matches(" (deleted)")))
        };
        if has_interp(&file) {
            out.push((file, path.to_string()));
            if out.len() >= 16 {
                break;
            }
        }
    }
    out
}

/// ELF with a PT_INTERP program header.
fn has_interp(p: &std::path::Path) -> bool {
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY).open(p) else { return false };
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    let mut h = [0u8; 64];
    if f.read_exact_at(&mut h, 0).is_err() || &h[..4] != b"\x7fELF" || h[5] != 1 {
        return false;
    }
    let u16_at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]) as u64;
    let (phoff, phentsize, phnum) = if h[4] == 2 {
        (u64::from_le_bytes(h[0x20..0x28].try_into().unwrap()), u16_at(0x36), u16_at(0x38))
    } else {
        (u32::from_le_bytes(h[0x1c..0x20].try_into().unwrap()) as u64, u16_at(0x2a), u16_at(0x2c))
    };
    if !(32..=64).contains(&phentsize) || phnum == 0 || phnum > 128 {
        return false;
    }
    let mut ph = vec![0u8; (phentsize * phnum) as usize];
    if f.read_exact_at(&mut ph, phoff).is_err() {
        return false;
    }
    ph.chunks(phentsize as usize).any(|e| u32::from_le_bytes(e[..4].try_into().unwrap()) == 3)
}

/// The program name for a loader-launched process: argv's claim only if it names one of
/// the objects really mapped; otherwise the first mapped program that isn't a libc.
fn pick_program(pid: u32, args: &[String], mapped: &[(std::path::PathBuf, String)]) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let ino = |p: &std::path::Path| std::fs::metadata(p).map(|m| (m.dev(), m.ino())).ok();
    if let Some(claim) = loader_program(pid, args) {
        let real = ino(std::path::Path::new(&format!("/proc/{pid}/root{claim}")));
        if real.is_some() && mapped.iter().any(|(f, _)| ino(f) == real) {
            return Some(claim);
        }
    }
    let not_lib = |p: &&(std::path::PathBuf, String)| {
        let b = base(&p.1);
        !(b.starts_with("libc") || b.starts_with("ld-") || b.contains(".so"))
    };
    mapped.iter().find(not_lib).or(mapped.first()).map(|(_, p)| p.clone())
        .or_else(|| loader_program(pid, args).map(|c| format!("{c} (unverified)")))
}

/// Does `pid` hold socket `inode` right now? (For sockets newer than the last /proc scan.)
pub fn holds_socket(pid: u32, inode: u64) -> bool {
    let want = format!("socket:[{inode}]");
    std::fs::read_dir(format!("/proc/{pid}/fd")).into_iter().flatten().flatten()
        .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == want.as_str()))
}

fn mnt_ns(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok().map(|l| l.to_string_lossy().into_owned())
}

pub fn is_shell(exe: &str) -> bool {
    SHELLS.contains(&base(exe.trim_end_matches(" (deleted)")))
}

pub fn container_of(pid: u32) -> Option<String> {
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in cg.lines() {
        for key in ["docker-", "/docker/", "libpod-", "/libpod/", "containerd/", "/lxc/", "lxc.payload."] {
            if let Some(i) = line.find(key) {
                let id: String = line[i + key.len()..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
                if !id.is_empty() {
                    return Some(id.chars().take(12).collect());
                }
            }
        }
    }
    None
}

/// `prog`: for loader-launched processes, the verified program (see `pick_program`).
pub fn entity_name(pid: u32, uid: u32, comm: &str, exe: &str, args: &[String], prog: Option<&str>) -> String {
    let path = exe.trim_end_matches(" (deleted)");
    let mut name = if path.is_empty() {
        format!("uid:{uid}:{comm}")
    } else if let Some(m) = path.strip_prefix("/memfd:") {
        format!("memfd:{}", m.split(' ').next().unwrap_or(""))
    } else if let Some(p) = &prog {
        format!("{p} (via {})", base(path))
    } else {
        path.to_string()
    };
    if is_interp(path) {
        // The script by its *full* path (relative ones resolved against the process's
        // cwd): argv is attacker-controlled, so `python3 /tmp/x/backup.py` must not
        // share a baseline (and its "normal" uploads) with /opt/backup/backup.py.
        let script = args.iter().skip(1).find(|a| !a.starts_with('-')).map(|a| {
            let p = std::path::Path::new(a);
            let full = if p.is_absolute() { p.to_path_buf() } else {
                std::fs::read_link(format!("/proc/{pid}/cwd")).map(|c| c.join(p)).unwrap_or_else(|_| p.to_path_buf())
            };
            let s = full.to_string_lossy().into_owned();
            if s.chars().count() > 160 { format!("…{}", s.chars().rev().take(159).collect::<Vec<_>>().into_iter().rev().collect::<String>()) } else { s }
        });
        let inline = args.iter().skip(1).any(|a| a == "-c" || a == "-e");
        match (script, inline) {
            (_, true) => name += " [-c]",
            (Some(s), _) => name += &format!(" [{s}]"),
            _ => {}
        }
    }
    // Different users running the same program get separate baselines: an unprivileged
    // user can't "train" what is normal for root's processes.
    if !path.is_empty() && uid != 0 && uid != u32::MAX {
        name += &format!(" (uid {uid})");
    }
    if let Some(c) = container_of(pid) {
        name = format!("ctr:{c}:{name}");
    } else if let (Some(m), Some(init)) = (mnt_ns(pid), mnt_ns(1)) {
        // a private mount namespace can bind-mount anything over a trusted path
        if m != init {
            name = format!("mntns:{}:{name}", m.trim_start_matches("mnt:[").trim_end_matches(']'));
        }
    }
    crate::safety::safe_key(&name)
}

#[derive(Default)]
pub struct Procs {
    pub by_inode: HashMap<u64, usize>,
    pub list: Vec<ProcInfo>,
    pub denied: usize,
}

impl Procs {
    /// Full rescan of /proc/*/fd. A few ms to a few tens of ms on a server.
    pub fn scan() -> Procs {
        let mut p = Procs::default();
        let Ok(rd) = std::fs::read_dir("/proc") else { return p };
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                p.denied += 1;
                continue;
            };
            let mut socks = vec![];
            let mut std_socks = vec![];
            for fd in fds.flatten() {
                let Ok(t) = std::fs::read_link(fd.path()) else { continue };
                let t = t.to_string_lossy();
                if let Some(n) = t.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) {
                    socks.push(n);
                    if matches!(fd.file_name().to_str(), Some("0" | "1" | "2")) {
                        std_socks.push(n);
                    }
                }
            }
            if socks.is_empty() {
                continue;
            }
            let base_p = format!("/proc/{pid}");
            // uid first, from the owner of /proc/<pid> (a process reaped mid-read must not
            // end up with root's entity name); drop records we can't read consistently
            use std::os::unix::fs::MetadataExt;
            let Ok(uid) = std::fs::metadata(&base_p).map(|m| m.uid()) else { continue };
            let comm = std::fs::read_to_string(format!("{base_p}/comm")).unwrap_or_default().trim().to_string();
            let args: Vec<String> = std::fs::read(format!("{base_p}/cmdline")).unwrap_or_default()
                .split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
            let exe = std::fs::read_link(format!("{base_p}/exe")).map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
            if !std::path::Path::new(&base_p).exists() {
                continue; // exited while we read it
            }
            let (mapped, prog) = if is_loader(exe.trim_end_matches(" (deleted)")) {
                let m = loader_mapped(pid);
                let p = pick_program(pid, &args, &m);
                (m, p)
            } else {
                (vec![], None)
            };
            let ent = entity_name(pid, uid, &comm, &exe, &args, prog.as_deref());
            let prog = prog.unwrap_or_else(|| exe.clone());
            let idx = p.list.len();
            for s in &socks {
                p.by_inode.entry(*s).or_insert(idx);
            }
            p.list.push(ProcInfo { pid, exe: crate::safety::safe(&exe), prog: crate::safety::safe(&prog), mapped, cmdline: crate::safety::safe(&args.join(" ")),
                ent, std_socks, socks });
        }
        p
    }

    pub fn get(&self, inode: u64) -> Option<&ProcInfo> {
        self.by_inode.get(&inode).map(|&i| &self.list[i])
    }
}

/// Process red flags. `ext_tcp`: socket inodes of TCP connections to non-local hosts.
pub fn flags(p: &ProcInfo, ext_tcp: &HashSet<u64>) -> Vec<(&'static str, u8, String)> {
    let mut f = vec![];
    let exe = p.exe.as_str();
    // judge the program actually running (not the dynamic loader that started it)
    let path = p.prog.trim_end_matches(" (deleted)");
    if p.std_socks.iter().any(|s| ext_tcp.contains(s)) {
        let shellish = is_shell(path) || is_interp(path);
        f.push(("reverse_shell", if shellish { 3 } else { 2 },
            format!("{} (pid {}) has stdin/stdout connected to a remote TCP peer: {}", base(path), p.pid, p.cmdline.chars().take(120).collect::<String>())));
    }
    if exe.starts_with("/memfd:") {
        f.push(("fileless_exe", 3, format!("pid {} runs from {exe} (no file on disk)", p.pid)));
    }
    if ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"].iter().any(|d| path.starts_with(d)) {
        f.push(("exe_in_temp", 3, format!("pid {} runs from a world-writable temp dir: {path}", p.pid)));
    } else if base(path).starts_with('.') {
        f.push(("hidden_exe", 2, format!("pid {} binary has a hidden name: {path}", p.pid)));
    }
    if p.cmdline.starts_with('[') && !exe.is_empty() {
        f.push(("fake_kernel_thread", 3, format!("pid {} is named like a kernel thread ({}) but runs {exe}", p.pid, p.cmdline)));
    }
    if exe.ends_with(" (deleted)") && !exe.starts_with("/memfd:") {
        f.push(("deleted_exe", 1, format!("pid {} binary was deleted after start: {path} (also normal after upgrades)", p.pid)));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/python3.12", &a(&["python3", "/opt/backup.py", "-v"]), None), "/usr/bin/python3.12 [/opt/backup.py]");
        assert_eq!(entity_name(999_999_999, 1000, "x", "/usr/bin/curl", &a(&["curl"]), None), "/usr/bin/curl (uid 1000)");
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/a\x1b[2Jb", &[], None), "/usr/bin/a\\u{1b}[2Jb");
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/bash", &a(&["bash"]), None), "/usr/bin/bash");
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/perl", &a(&["perl", "-e", "..."]), None), "/usr/bin/perl [-c]");
        assert_eq!(entity_name(999_999_999, 33, "kw", "", &[], None), "uid:33:kw");
        assert_eq!(entity_name(999_999_999, 0, "x", "/memfd:payload (deleted)", &[], None), "memfd:payload");
    }
}
