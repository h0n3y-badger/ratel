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

pub fn entity_name(pid: u32, uid: u32, comm: &str, exe: &str, args: &[String]) -> String {
    let path = exe.trim_end_matches(" (deleted)");
    let mut name = if path.is_empty() {
        format!("uid:{uid}:{comm}")
    } else if let Some(m) = path.strip_prefix("/memfd:") {
        format!("memfd:{}", m.split(' ').next().unwrap_or(""))
    } else {
        path.to_string()
    };
    if is_interp(path) {
        let script = args.iter().skip(1).find(|a| !a.starts_with('-')).map(|a| base(a).chars().take(40).collect::<String>());
        let inline = args.iter().skip(1).any(|a| a == "-c" || a == "-e");
        match (script, inline) {
            (_, true) => name += " [-c]",
            (Some(s), _) => name += &format!(" [{s}]"),
            _ => {}
        }
    }
    if let Some(c) = container_of(pid) {
        name = format!("ctr:{c}:{name}");
    }
    name
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
            let comm = std::fs::read_to_string(format!("{base_p}/comm")).unwrap_or_default().trim().to_string();
            let args: Vec<String> = std::fs::read(format!("{base_p}/cmdline")).unwrap_or_default()
                .split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
            let exe = std::fs::read_link(format!("{base_p}/exe")).map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
            let uid = std::fs::read_to_string(format!("{base_p}/status")).ok()
                .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
                .unwrap_or(u32::MAX);
            let ent = entity_name(pid, uid, &comm, &exe, &args);
            let idx = p.list.len();
            for s in &socks {
                p.by_inode.entry(*s).or_insert(idx);
            }
            p.list.push(ProcInfo { pid, exe, cmdline: args.join(" "), ent, std_socks, socks });
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
    let path = exe.trim_end_matches(" (deleted)");
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
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/python3.12", &a(&["python3", "/opt/backup.py", "-v"])), "/usr/bin/python3.12 [backup.py]");
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/bash", &a(&["bash"])), "/usr/bin/bash");
        assert_eq!(entity_name(999_999_999, 0, "x", "/usr/bin/perl", &a(&["perl", "-e", "..."])), "/usr/bin/perl [-c]");
        assert_eq!(entity_name(999_999_999, 33, "kw", "", &[]), "uid:33:kw");
        assert_eq!(entity_name(999_999_999, 0, "x", "/memfd:payload (deleted)", &[]), "memfd:payload");
    }
}
