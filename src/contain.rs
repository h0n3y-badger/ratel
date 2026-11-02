//! Containment: freeze a suspicious process tree so it can be inspected, then release or
//! kill it.
//!
//! * **cgroup v2 freezer** (preferred): a new cgroup `<cgroup2>/ratel-contain/<id>` is
//!   frozen *before* anything is moved into it, so every process lands frozen. The root is
//!   moved first, then its descendants (found by ppid in /proc) are moved repeatedly until
//!   two passes in a row find nothing new: processes forked meanwhile are caught, and a
//!   frozen process can't fork any more. Each pid's original cgroup (the `0::` line of
//!   /proc/<pid>/cgroup) is recorded so `release` can put it back. A frozen task can't be
//!   thawed by its owner (only by whoever can write the cgroup, i.e. root), and
//!   `cgroup.kill` / SIGKILL still work on it.
//! * **SIGSTOP** (fallback when no writable cgroup2 mount exists): the root is stopped
//!   first, then descendants, until stable. This is weaker: any process of the same uid
//!   (or the tree itself, via a helper started elsewhere) can SIGCONT a stopped process, and
//!   a parent sees its children stop (SIGCHLD). Use it only when cgroups are unavailable.
//!
//! Never frozen: pid 1, ratel itself and every ancestor of it (the admin's shell, sshd),
//! kernel threads (no /proc/<pid>/exe, PF_KTHREAD, or children of kthreadd), and any
//! process whose executable is in `Policy::never`. Against PID reuse, each process's start
//! time (field 22 of /proc/<pid>/stat) is captured when it is chosen and re-checked right
//! before it is moved or signalled, and again by `release`/`kill` later (`starts`).

use crate::quarantine::{utc_human, utc_stamp, valid_id};
use crate::safety::{safe, safe_path};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_STATE: &str = "/var/lib/ratel/contained.json";
const PF_KTHREAD: u64 = 0x0020_0000;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Contained {
    pub id: String,
    pub root_pid: u32,
    pub pids: Vec<u32>,
    pub exe: String,
    /// "cgroup" | "sigstop"
    pub method: String,
    /// The containment cgroup, relative to the cgroup2 mount (`/ratel-contain/<id>`).
    pub cgroup: Option<String>,
    /// (pid, original cgroup relative to the mount), for `release`.
    pub orig_cgroups: Vec<(u32, String)>,
    pub t: f64,
    pub reason: String,
    /// (pid, start time in clock ticks): identity checks against PID reuse at release/kill.
    #[serde(default)]
    pub starts: Vec<(u32, u64)>,
}

pub struct Policy {
    /// Executable paths that are never frozen.
    pub never: Vec<String>,
}

impl Policy {
    /// Things whose freezing would cut the admin off or take the server down.
    pub fn server_default() -> Policy {
        Policy {
            never: ["/sbin/init", "/sbin/openrc", "/sbin/openrc-run", "/sbin/supervise-daemon", "/sbin/start-stop-daemon",
                    "/usr/sbin/sshd", "/usr/bin/sshd", "/usr/sbin/tailscaled", "/usr/bin/tailscaled",
                    "/usr/bin/dockerd", "/usr/bin/containerd", "/usr/bin/prosody", "/usr/bin/lua5.4@prosody"]
                .iter().map(|s| s.to_string()).collect(),
        }
    }
}

pub const USAGE: &str = "process containment:
  ratel contain list                          contained process trees
  ratel contain freeze PID [--reason TEXT]    freeze PID and all its descendants
  ratel contain release ID                    unfreeze, move back to the original cgroups
  ratel contain kill ID                       SIGKILL the whole tree (works while frozen)
common: --state FILE (default /var/lib/ratel/contained.json), --json,
        --cg-root DIR (cgroup2 mount; default: found in /proc/self/mountinfo)
";

type Writer<'a> = &'a mut dyn FnMut(&Path, &str) -> std::io::Result<()>;

fn real_write(p: &Path, s: &str) -> std::io::Result<()> {
    std::fs::write(p, s)
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

// ---------------------------------------------------------------- /proc

struct Stat {
    state: char,
    ppid: u32,
    flags: u64,
    start: u64,
}

fn stat(pid: u32) -> Option<Stat> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let r = s.rfind(')')?;
    let f: Vec<&str> = s.get(r + 2..)?.split_whitespace().collect();
    Some(Stat {
        state: f.first()?.chars().next()?,
        ppid: f.get(1)?.parse().ok()?,
        flags: f.get(6)?.parse().ok()?,
        start: f.get(19)?.parse().ok()?,
    })
}

/// Still the process we chose (not exited, not a reused pid).
fn same(pid: u32, start: u64) -> bool {
    stat(pid).is_some_and(|s| s.start == start)
}

fn gone(pid: u32, start: u64) -> bool {
    stat(pid).is_none_or(|s| s.start != start || matches!(s.state, 'Z' | 'X' | 'x'))
}

fn snapshot() -> Vec<(u32, u32)> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return vec![] };
    rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|p| stat(p).map(|s| (p, s.ppid)))
        .collect()
}

/// All descendants of `roots` (excluding `roots`).
fn descendants(roots: &HashSet<u32>) -> Vec<u32> {
    let mut kids: HashMap<u32, Vec<u32>> = HashMap::new();
    for (p, pp) in snapshot() {
        kids.entry(pp).or_default().push(p);
    }
    let mut out = vec![];
    let mut seen: HashSet<u32> = roots.clone();
    let mut stack: Vec<u32> = roots.iter().copied().collect();
    while let Some(p) = stack.pop() {
        for &k in kids.get(&p).map(Vec::as_slice).unwrap_or(&[]) {
            if seen.insert(k) {
                out.push(k);
                stack.push(k);
            }
        }
    }
    out
}

/// pid 1, ourselves and every ancestor of ours.
fn protected_set() -> HashSet<u32> {
    let mut s = HashSet::from([1u32, std::process::id()]);
    let mut p = std::process::id();
    while let Some(st) = stat(p) {
        if st.ppid <= 1 || !s.insert(st.ppid) {
            break;
        }
        p = st.ppid;
    }
    s
}

fn exe_of(pid: u32) -> std::io::Result<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.to_string_lossy().into_owned())
}

/// Is this a process we may freeze? Returns its start time and executable.
fn check(pid: u32, policy: &Policy, prot: &HashSet<u32>) -> Result<(u64, String), String> {
    if pid <= 1 {
        return Err(format!("refusing to freeze pid {pid} (init)"));
    }
    if pid == std::process::id() {
        return Err("refusing to freeze ratel itself".into());
    }
    if prot.contains(&pid) {
        return Err(format!("refusing to freeze pid {pid}: it is an ancestor of ratel"));
    }
    let st = stat(pid).ok_or_else(|| format!("no such process {pid}"))?;
    if pid == 2 || st.ppid == 2 || st.flags & PF_KTHREAD != 0 {
        return Err(format!("refusing to freeze pid {pid}: kernel thread"));
    }
    let exe = match exe_of(pid) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("refusing to freeze pid {pid}: no executable (kernel thread or zombie)"))
        }
        Err(e) => return Err(format!("pid {pid}: cannot read its executable: {e}")),
    };
    let bare = exe.strip_suffix(" (deleted)").unwrap_or(&exe);
    // entries are an executable, or `exe@user` (an interpreter anyone can run, protected
    // only for the service account: prosody runs as /usr/bin/lua5.4)
    use std::os::unix::fs::MetadataExt;
    let puid = std::fs::metadata(format!("/proc/{pid}")).map(|m| m.uid()).ok();
    let hit = |n: &String| match n.split_once('@') {
        Some((e, user)) => (e == exe || e == bare) && puid.is_some() && user_uid(user) == puid,
        None => n == &exe || n == bare,
    };
    if policy.never.iter().any(hit) {
        return Err(format!("refusing to freeze pid {pid}: {} is on the never-freeze list", safe(&exe)));
    }
    Ok((st.start, exe))
}

fn user_uid(name: &str) -> Option<u32> {
    let pw = std::fs::read_to_string("/etc/passwd").ok()?;
    pw.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.first() == Some(&name)).then(|| f.get(2)?.parse().ok()).flatten()
    })
}

/// Start time of `pid` (clock ticks since boot): with the pid, a process's identity.
pub fn start_time(pid: u32) -> Option<u64> {
    stat(pid).map(|s| s.start)
}

fn orig_cgroup(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("0::")).map(str::to_string)
}

/// A cgroup path relative to the mount: absolute, no `..`/`.` components.
fn valid_cg(rel: &str) -> bool {
    rel.starts_with('/') && !rel.contains('\0') && rel.split('/').all(|c| c != ".." && c != ".")
}

fn cg_join(root: &Path, rel: &str) -> Result<PathBuf, String> {
    if !valid_cg(rel) {
        return Err(format!("bad cgroup path {}", safe(rel)));
    }
    Ok(root.join(rel.trim_start_matches('/')))
}

/// The cgroup2 mount point from /proc/self/mountinfo.
fn cgroup2_mount() -> Option<PathBuf> {
    let s = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    s.lines().find_map(|l| {
        let (left, right) = l.split_once(" - ")?;
        if right.split_whitespace().next()? != "cgroup2" {
            return None;
        }
        Some(PathBuf::from(left.split_whitespace().nth(4)?.replace("\\040", " ")))
    })
}

/// Can we create containment cgroups under `root`?
fn cg_usable(root: &Path) -> bool {
    let base = root.join("ratel-contain");
    match std::fs::create_dir(&base) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => std::fs::symlink_metadata(&base).is_ok_and(|m| m.is_dir()),
        Err(_) => false,
    }
}

fn read_pids(p: &Path) -> Vec<u32> {
    std::fs::read_to_string(p).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect()
}

fn signal(pid: u32, sig: i32) -> std::io::Result<()> {
    // SAFETY: plain kill(2).
    if unsafe { libc::kill(pid as libc::pid_t, sig) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn is_esrch(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ESRCH)
}

// ---------------------------------------------------------------- freeze

/// Freeze `pid` and all its descendants. Uses the cgroup v2 freezer under `cg_root` (or
/// the system's cgroup2 mount) when it is writable, SIGSTOP otherwise. The caller stores
/// the result with `record`.
pub fn freeze_tree(pid: u32, reason: &str, policy: &Policy, cg_root: Option<&Path>) -> Result<Contained, String> {
    freeze_tree_at(pid, None, reason, policy, cg_root)
}

/// `freeze_tree`, but only if `pid` is still the process that started at `expect_start`
/// (seen when the detection happened): a pid that was freed and reused by an innocent
/// process is refused.
pub fn freeze_tree_at(pid: u32, expect_start: Option<u64>, reason: &str, policy: &Policy, cg_root: Option<&Path>) -> Result<Contained, String> {
    let (start, _) = check(pid, policy, &protected_set())?; // refuse before touching any cgroup
    if expect_start.is_some_and(|s| s != start) {
        return Err(format!("pid {pid} is a different process now (the detected one exited and its pid was reused)"));
    }
    let root = match cg_root {
        Some(r) => Some(r.to_path_buf()),
        None => cgroup2_mount(),
    }
    .filter(|r| cg_usable(r));
    let c = freeze_with(pid, reason, policy, root.as_deref(), &mut real_write)?;
    if expect_start.is_some_and(|s| c.starts.iter().find(|(p, _)| *p == pid).is_some_and(|(_, st)| *st != s)) {
        // reused between the two checks: undo at once
        let _ = release_with(&c, root.as_deref(), &mut real_write);
        return Err(format!("pid {pid} was reused while freezing; released again"));
    }
    Ok(c)
}

fn freeze_with(pid: u32, reason: &str, policy: &Policy, cg: Option<&Path>, w: Writer) -> Result<Contained, String> {
    let prot = protected_set();
    let (start, exe) = check(pid, policy, &prot)?;
    let t = now();
    let mut c = Contained {
        id: format!("{}-{pid}", utc_stamp(t)),
        root_pid: pid, pids: vec![], exe, method: String::new(), cgroup: None, orig_cgroups: vec![],
        t, reason: reason.to_string(), starts: vec![],
    };
    if let Some(root) = cg {
        match freeze_cgroup(&mut c, root, start, policy, &prot, w) {
            Ok(()) => return Ok(c),
            // nothing was moved: fall back to signals
            Err(e) if c.pids.is_empty() => c.reason = format!("{reason} [cgroup freezer failed ({e}); used SIGSTOP]"),
            Err(e) => return Err(e),
        }
    }
    freeze_signal(&mut c, start, policy, &prot)?;
    Ok(c)
}

/// Adds descendants of the contained processes until two passes in a row find none.
/// `act` moves/stops one process; `want_orig` records its original cgroup first.
fn sweep(c: &mut Contained, policy: &Policy, prot: &HashSet<u32>, want_orig: bool,
         act: &mut dyn FnMut(u32) -> std::io::Result<()>) {
    let mut skipped: HashSet<u32> = HashSet::new();
    let mut errors = 0usize;
    let mut quiet = 0;
    for _ in 0..500 {
        let have: HashSet<u32> = c.pids.iter().copied().collect();
        let new: Vec<u32> = descendants(&have).into_iter().filter(|p| !skipped.contains(p)).collect();
        if new.is_empty() {
            quiet += 1;
            if quiet >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        quiet = 0;
        for p in new {
            let Ok((st, _)) = check(p, policy, prot) else {
                skipped.insert(p);
                continue;
            };
            let orig = if want_orig { orig_cgroup(p) } else { None };
            if !same(p, st) || (want_orig && orig.is_none()) {
                skipped.insert(p);
                continue;
            }
            match act(p) {
                Ok(()) => {
                    c.pids.push(p);
                    c.starts.push((p, st));
                    if let Some(o) = orig {
                        c.orig_cgroups.push((p, o));
                    }
                }
                Err(e) => {
                    if !is_esrch(&e) {
                        errors += 1;
                    }
                    skipped.insert(p);
                }
            }
        }
    }
    let live_skipped = skipped.iter().filter(|p| stat(**p).is_some()).count();
    if live_skipped > 0 || errors > 0 {
        c.reason.push_str(&format!(" [{live_skipped} descendant(s) left running (policy/errors: {errors})]"));
    }
}

fn freeze_cgroup(c: &mut Contained, root: &Path, start: u64, policy: &Policy, prot: &HashSet<u32>, w: Writer) -> Result<(), String> {
    let base = root.join("ratel-contain");
    if let Err(e) = std::fs::create_dir(&base) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!("{}: {e}", safe_path(&base)));
        }
    }
    let mut dir = PathBuf::new();
    for n in 1..1000 {
        let id = if n == 1 { c.id.clone() } else { format!("{}-{n}", c.id) };
        let d = base.join(&id);
        match std::fs::DirBuilder::new().mode(0o755).create(&d) {
            Ok(()) => {
                c.id = id;
                dir = d;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", safe_path(&d))),
        }
    }
    if dir.as_os_str().is_empty() {
        return Err("could not allocate a cgroup".into());
    }
    let undo = |w: Writer, dir: &Path| {
        let _ = w(&dir.join("cgroup.freeze"), "0");
        let _ = std::fs::remove_dir(dir);
    };
    // frozen before anything enters it
    if let Err(e) = w(&dir.join("cgroup.freeze"), "1") {
        undo(w, &dir);
        return Err(format!("cgroup.freeze: {e}"));
    }
    let pid = c.root_pid;
    let Some(orig) = orig_cgroup(pid).filter(|o| valid_cg(o)) else {
        undo(w, &dir);
        return Err(format!("pid {pid} has no cgroup v2 membership"));
    };
    if !same(pid, start) {
        undo(w, &dir);
        return Err(format!("pid {pid} exited or was replaced"));
    }
    if let Err(e) = w(&dir.join("cgroup.procs"), &pid.to_string()) {
        undo(w, &dir);
        return Err(format!("moving pid {pid}: {e}"));
    }
    c.method = "cgroup".into();
    c.cgroup = Some(format!("/ratel-contain/{}", c.id));
    c.pids.push(pid);
    c.starts.push((pid, start));
    c.orig_cgroups.push((pid, orig));
    let procs = dir.join("cgroup.procs");
    sweep(c, policy, prot, true, &mut |p| w(&procs, &p.to_string()));

    // a real cgroupfs reports when every task is frozen; a fake root (tests) has no events file
    let events = dir.join("cgroup.events");
    if events.exists() {
        let t0 = Instant::now();
        loop {
            if std::fs::read_to_string(&events).unwrap_or_default().lines().any(|l| l.trim() == "frozen 1") {
                break;
            }
            if t0.elapsed() > Duration::from_secs(2) {
                c.reason.push_str(" [not confirmed frozen after 2 s: tasks in uninterruptible sleep?]");
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(())
}

fn freeze_signal(c: &mut Contained, start: u64, policy: &Policy, prot: &HashSet<u32>) -> Result<(), String> {
    let pid = c.root_pid;
    if !same(pid, start) {
        return Err(format!("pid {pid} exited or was replaced"));
    }
    signal(pid, libc::SIGSTOP).map_err(|e| format!("SIGSTOP {pid}: {e}"))?;
    c.method = "sigstop".into();
    c.pids.push(pid);
    c.starts.push((pid, start));
    sweep(c, policy, prot, false, &mut |p| signal(p, libc::SIGSTOP));
    // wait (bounded) until they all show as stopped
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(1) {
        if c.starts.iter().all(|&(p, s)| gone(p, s) || stat(p).is_some_and(|st| matches!(st.state, 'T' | 't'))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

// ---------------------------------------------------------------- release / kill

fn start_map(c: &Contained) -> HashMap<u32, u64> {
    c.starts.iter().copied().collect()
}

/// Members of the containment: the cgroup's processes plus recorded pids that are still
/// the same processes.
fn members(c: &Contained, dir: Option<&Path>) -> Vec<u32> {
    let starts = start_map(c);
    let mut v: Vec<u32> = c.starts.iter().filter(|&&(p, s)| !gone(p, s)).map(|&(p, _)| p).collect();
    if let Some(d) = dir {
        for p in read_pids(&d.join("cgroup.procs")) {
            // a recorded pid whose start changed was reused (only possible on a fake root)
            if !v.contains(&p) && starts.get(&p).is_none_or(|&s| same(p, s)) && stat(p).is_some() {
                v.push(p);
            }
        }
    }
    v
}

fn cg_root_for(cg_root: Option<&Path>) -> Result<PathBuf, String> {
    cg_root.map(Path::to_path_buf).or_else(cgroup2_mount).ok_or_else(|| "no cgroup2 mount found".to_string())
}

fn release_with(c: &Contained, cg_root: Option<&Path>, w: Writer) -> Result<(), String> {
    match c.method.as_str() {
        "cgroup" => {
            let root = cg_root_for(cg_root)?;
            let dir = cg_join(&root, c.cgroup.as_deref().unwrap_or(""))?;
            let orig: HashMap<u32, &str> = c.orig_cgroups.iter().map(|(p, o)| (*p, o.as_str())).collect();
            let fallback = orig.get(&c.root_pid).copied().unwrap_or("/");
            let mut errs = vec![];
            for p in members(c, Some(&dir)) {
                let dest = orig.get(&p).copied().unwrap_or(fallback);
                let r = cg_join(&root, dest).map_err(std::io::Error::other)
                    .and_then(|d| w(&d.join("cgroup.procs"), &p.to_string()));
                match r {
                    Ok(()) => {}
                    Err(e) if is_esrch(&e) => {}
                    // the original cgroup may be gone (container stopped): the root cgroup then
                    Err(_) => match w(&root.join("cgroup.procs"), &p.to_string()) {
                        Ok(()) => {}
                        Err(e) if is_esrch(&e) => {}
                        Err(e) => errs.push(format!("moving {p} back: {e}")),
                    },
                }
            }
            if let Err(e) = w(&dir.join("cgroup.freeze"), "0") {
                errs.push(format!("unfreeze: {e}"));
            }
            remove_cg(&dir);
            if errs.is_empty() { Ok(()) } else { Err(errs.join("; ")) }
        }
        "sigstop" => {
            for &(p, s) in &c.starts {
                if same(p, s) {
                    let _ = signal(p, libc::SIGCONT);
                }
            }
            Ok(())
        }
        m => Err(format!("unknown containment method {}", safe(m))),
    }
}

/// rmdir a containment cgroup (retries while it drains); a fake root's leftovers stay.
fn remove_cg(dir: &Path) {
    for _ in 0..50 {
        if std::fs::remove_dir(dir).is_ok() || !dir.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_gone(pids: &[(u32, u64)]) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(2) {
        if pids.iter().all(|&(p, s)| gone(p, s)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn kill_with(c: &Contained, cg_root: Option<&Path>, w: Writer) -> Result<(), String> {
    let mut targets: Vec<(u32, u64)>;
    let mut dir = None;
    match c.method.as_str() {
        "cgroup" => {
            let root = cg_root_for(cg_root)?;
            let d = cg_join(&root, c.cgroup.as_deref().unwrap_or(""))?;
            targets = members(c, Some(&d)).into_iter().filter_map(|p| stat(p).map(|s| (p, s.start))).collect();
            let kill_file = d.join("cgroup.kill");
            if kill_file.exists() && w(&kill_file, "1").is_ok() {
            } else {
                for &(p, s) in &targets {
                    if same(p, s) {
                        let _ = signal(p, libc::SIGKILL);
                    }
                }
            }
            dir = Some(d);
        }
        "sigstop" => {
            // include anything forked after someone SIGCONTed part of the tree; stop all
            // first so nothing forks or reparents between kills
            targets = c.starts.iter().copied().filter(|&(p, s)| same(p, s)).collect();
            let have: HashSet<u32> = targets.iter().map(|t| t.0).collect();
            let prot = protected_set();
            for p in descendants(&have) {
                if prot.contains(&p) {
                    continue;
                }
                if let Some(s) = stat(p) {
                    targets.push((p, s.start));
                }
            }
            for &(p, s) in &targets {
                if same(p, s) {
                    let _ = signal(p, libc::SIGSTOP);
                }
            }
            for &(p, s) in &targets {
                if same(p, s) {
                    let _ = signal(p, libc::SIGKILL);
                }
            }
        }
        m => return Err(format!("unknown containment method {}", safe(m))),
    }
    let ok = wait_gone(&targets);
    if let Some(d) = dir {
        let _ = w(&d.join("cgroup.freeze"), "0");
        remove_cg(&d);
    }
    if ok {
        Ok(())
    } else {
        let left: Vec<String> = targets.iter().filter(|&&(p, s)| !gone(p, s)).map(|t| t.0.to_string()).collect();
        Err(format!("still alive after SIGKILL: {}", left.join(" ")))
    }
}

// ---------------------------------------------------------------- state file

fn load(state: &Path) -> Result<Vec<Contained>, String> {
    match std::fs::symlink_metadata(state) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        _ => {}
    }
    let b = crate::safety::trusted_read(state, 4 << 20)?;
    serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", safe_path(state)))
}

fn state_dir(state: &Path) -> Result<PathBuf, String> {
    let dir = state.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
    if std::fs::symlink_metadata(&dir).is_err() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", safe_path(&dir)))?;
    }
    crate::safety::trusted_dir(&dir, false)?;
    crate::safety::trusted_ancestors(&dir)?;
    Ok(dir)
}

fn save(state: &Path, v: &[Contained]) -> Result<(), String> {
    let dir = state_dir(state)?;
    let name = state.file_name().ok_or("state path has no file name")?.to_string_lossy().into_owned();
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp).map_err(|e| format!("{}: {e}", safe_path(&tmp)))?;
    let j = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    f.write_all(&j).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", safe_path(&tmp)))?;
    std::fs::rename(&tmp, state).map_err(|e| format!("{}: {e}", safe_path(state)))?;
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Serialises read-modify-write of the state file between the daemon and the CLI.
fn locked<T>(state: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let dir = state_dir(state)?;
    let name = state.file_name().ok_or("state path has no file name")?.to_string_lossy().into_owned();
    let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dir.join(format!(".{name}.lock")))
        .map_err(|e| format!("state lock: {e}"))?;
    // SAFETY: flock on a valid fd; released when `lock` is dropped.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!("state lock: {}", std::io::Error::last_os_error()));
    }
    f()
}

/// Adds (or replaces, by id) a containment record.
pub fn record(state: &Path, c: &Contained) -> Result<(), String> {
    locked(state, || {
        let mut v = load(state)?;
        v.retain(|x| x.id != c.id);
        v.push(c.clone());
        save(state, &v)
    })
}

/// Recorded containments; an unreadable or untrusted state file reads as empty.
#[allow(dead_code)] // for the daemon; the CLI uses `load` to report errors
pub fn list(state: &Path) -> Vec<Contained> {
    load(state).unwrap_or_default()
}

fn act_on(state: &Path, id: &str, f: impl FnOnce(&Contained) -> Result<(), String>) -> Result<(), String> {
    if !valid_id(id) {
        return Err(format!("invalid id {}", safe(id)));
    }
    locked(state, || {
        let mut v = load(state)?;
        let c = v.iter().find(|c| c.id == id).cloned().ok_or_else(|| format!("no containment {id}"))?;
        f(&c)?;
        v.retain(|x| x.id != id);
        save(state, &v)
    })
}

/// Unfreeze `id` and move its processes back to their original cgroups; drops the record.
pub fn release(state: &Path, id: &str, cg_root: Option<&Path>) -> Result<(), String> {
    act_on(state, id, |c| release_with(c, cg_root, &mut real_write))
}

/// SIGKILL the contained tree (works while frozen); drops the record.
pub fn kill(state: &Path, id: &str, cg_root: Option<&Path>) -> Result<(), String> {
    act_on(state, id, |c| kill_with(c, cg_root, &mut real_write))
}

// ---------------------------------------------------------------- CLI

/// `ratel contain ...`; returns the exit code.
pub fn cli(args: &[String]) -> i32 {
    let mut state = PathBuf::from(DEFAULT_STATE);
    let mut cg_root: Option<PathBuf> = None;
    let mut reason = "manual containment".to_string();
    let mut json = false;
    let mut pos: Vec<String> = vec![];
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(a, "--state" | "--reason" | "--cg-root") {
            let Some(v) = args.get(i + 1).cloned() else {
                eprintln!("ratel: {a} needs a value");
                return 2;
            };
            match a {
                "--state" => state = PathBuf::from(v),
                "--reason" => reason = v,
                _ => cg_root = Some(PathBuf::from(v)),
            }
            i += 2;
            continue;
        }
        match a {
            "--json" => json = true,
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
    let fail = |e: String| -> i32 {
        eprintln!("ratel: {}", safe(&e));
        1
    };
    let done = |what: &str, id: &str| {
        if json {
            println!("{}", serde_json::json!({"id": id, "done": what}));
        } else {
            println!("{what} {}", safe(id));
        }
    };
    match sub {
        "list" => {
            let v = match load(&state) {
                Ok(v) => v,
                Err(e) => return fail(e),
            };
            if json {
                println!("{}", serde_json::to_string(&v).unwrap_or_default());
                return 0;
            }
            for c in &v {
                let alive = c.starts.iter().filter(|&&(p, s)| !gone(p, s)).count();
                println!("{}  {}  {:<7} pid {:<7} {} of {} alive  {}", c.id, utc_human(c.t), c.method, c.root_pid, alive, c.pids.len(), safe(&c.exe));
                println!("    {}", safe(&c.reason));
            }
            eprintln!("{} containment(s)", v.len());
            0
        }
        "freeze" => {
            let Some(pid) = arg.and_then(|a| a.parse::<u32>().ok()) else {
                eprintln!("ratel: contain freeze needs a PID\n\n{USAGE}");
                return 2;
            };
            let c = match freeze_tree(pid, &reason, &Policy::server_default(), cg_root.as_deref()) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            if let Err(e) = record(&state, &c) {
                eprintln!("ratel: frozen but NOT recorded ({}): release with kill -CONT / the cgroup by hand", safe(&e));
            }
            if json {
                println!("{}", serde_json::to_string(&c).unwrap_or_default());
            } else {
                println!("froze {} process(es) of pid {pid} ({}) by {} as {}", c.pids.len(), safe(&c.exe), c.method, c.id);
                if c.method == "sigstop" {
                    eprintln!("ratel: warning: SIGSTOP fallback; processes of the same user can resume it");
                }
            }
            0
        }
        "release" | "kill" => {
            let Some(id) = arg else {
                eprintln!("ratel: contain {sub} needs an ID\n\n{USAGE}");
                return 2;
            };
            let r = if sub == "release" { release(&state, id, cg_root.as_deref()) } else { kill(&state, id, cg_root.as_deref()) };
            match r {
                Ok(()) => {
                    done(if sub == "release" { "released" } else { "killed" }, id);
                    0
                }
                Err(e) => fail(e),
            }
        }
        s => {
            eprintln!("ratel: unknown contain command {}\n\n{USAGE}", safe(s));
            2
        }
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ratel-c-{tag}-{}-{}", std::process::id(), (now() * 1e6) as u64));
        std::fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        d
    }

    /// `sh` with two sleeping children (one backgrounded, one foreground).
    fn tree() -> (Child, Vec<u32>) {
        let child = Command::new("sh").arg("-c").arg("sleep 30 & sleep 30; :").spawn().unwrap();
        let pid = child.id();
        let t0 = Instant::now();
        loop {
            let d = descendants(&HashSet::from([pid]));
            if d.len() >= 2 && d.iter().all(|p| exe_of(*p).is_ok_and(|e| e.ends_with("sleep"))) {
                let mut all = vec![pid];
                all.extend(d);
                return (child, all);
            }
            assert!(t0.elapsed() < Duration::from_secs(5), "tree did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_state(p: u32, want: impl Fn(char) -> bool) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(2) {
            if stat(p).is_some_and(|s| want(s.state)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    fn no_policy() -> Policy {
        Policy { never: vec![] }
    }

    #[test]
    fn refusals() {
        let p = no_policy();
        assert!(freeze_with(1, "t", &p, None, &mut real_write).unwrap_err().contains("init"));
        assert!(freeze_with(std::process::id(), "t", &p, None, &mut real_write).unwrap_err().contains("ratel itself"));
        // SAFETY: trivial libc call
        let parent = unsafe { libc::getppid() } as u32;
        assert!(freeze_with(parent, "t", &p, None, &mut real_write).unwrap_err().contains("ancestor"));
        assert!(freeze_with(2, "t", &p, None, &mut real_write).unwrap_err().contains("kernel thread"));
        let (mut ch, _) = tree();
        let exe = exe_of(ch.id()).unwrap();
        let e = freeze_with(ch.id(), "t", &Policy { never: vec![exe] }, None, &mut real_write).unwrap_err();
        assert!(e.contains("never-freeze"), "{e}");
        let _ = ch.kill();
        let _ = ch.wait();
        assert!(!valid_cg("/a/../b") && !valid_cg("a") && valid_cg("/user.slice/x"));
    }

    #[test]
    fn sigstop_freeze_release_kill() {
        let d = tmpdir("sig");
        let state = d.join("contained.json");
        let (mut ch, all) = tree();
        let c = freeze_with(ch.id(), "test", &no_policy(), None, &mut real_write).unwrap();
        assert_eq!(c.method, "sigstop");
        for p in &all {
            assert!(c.pids.contains(p), "pid {p} contained");
            assert!(wait_state(*p, |s| s == 'T'), "pid {p} stopped");
        }
        record(&state, &c).unwrap();
        assert_eq!(list(&state).len(), 1);
        release(&state, &c.id, None).unwrap();
        assert!(list(&state).is_empty());
        for p in &all {
            assert!(wait_state(*p, |s| s != 'T' && s != 't'), "pid {p} resumed");
        }

        let c = freeze_with(ch.id(), "test", &no_policy(), None, &mut real_write).unwrap();
        record(&state, &c).unwrap();
        assert!(release(&state, "../x", None).unwrap_err().contains("invalid id"));
        kill(&state, &c.id, None).unwrap();
        let st = ch.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(st.signal(), Some(libc::SIGKILL));
        let starts = c.starts.clone();
        assert!(wait_gone(&starts), "whole tree killed");
        assert!(list(&state).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cgroup_write_sequence_on_fake_root() {
        let d = tmpdir("cg");
        let root = d.join("cgroot");
        std::fs::create_dir(&root).unwrap();
        let (mut ch, all) = tree();
        let mut log: Vec<(PathBuf, String)> = vec![];
        let mut w = |p: &Path, s: &str| -> std::io::Result<()> {
            log.push((p.to_path_buf(), s.to_string()));
            let mut f = std::fs::OpenOptions::new().append(true).create(true).open(p)?;
            writeln!(f, "{s}")
        };
        assert!(cg_usable(&root));
        let c = freeze_with(ch.id(), "test", &no_policy(), Some(&root), &mut w).unwrap();
        assert_eq!(c.method, "cgroup");
        assert_eq!(c.cgroup.as_deref(), Some(format!("/ratel-contain/{}", c.id).as_str()));
        let dir = root.join("ratel-contain").join(&c.id);
        assert_eq!(log[0], (dir.join("cgroup.freeze"), "1".to_string()), "freeze written before any move");
        assert_eq!(log[1], (dir.join("cgroup.procs"), ch.id().to_string()), "root moved first");
        for p in &all {
            assert!(log.iter().any(|(f, s)| f == &dir.join("cgroup.procs") && s == &p.to_string()), "pid {p} moved");
            let orig = orig_cgroup(*p).unwrap();
            assert!(c.orig_cgroups.contains(&(*p, orig)), "orig cgroup of {p} recorded");
        }
        assert_eq!(c.pids.len(), all.len());

        // release moves each pid back to where it came from, then thaws
        for (_, o) in &c.orig_cgroups {
            std::fs::create_dir_all(cg_join(&root, o).unwrap()).unwrap();
        }
        log.clear();
        let mut w = |p: &Path, s: &str| -> std::io::Result<()> {
            log.push((p.to_path_buf(), s.to_string()));
            let mut f = std::fs::OpenOptions::new().append(true).create(true).open(p)?;
            writeln!(f, "{s}")
        };
        release_with(&c, Some(&root), &mut w).unwrap();
        for (p, o) in &c.orig_cgroups {
            let target = cg_join(&root, o).unwrap().join("cgroup.procs");
            assert!(log.iter().any(|(f, s)| f == &target && s == &p.to_string()), "pid {p} moved back");
        }
        assert_eq!(log.last().unwrap(), &(dir.join("cgroup.freeze"), "0".to_string()));

        // kill without cgroup.kill falls back to SIGKILL of the members
        kill_with(&c, Some(&root), &mut real_write).unwrap();
        let _ = ch.wait();
        assert!(wait_gone(&c.starts));
        let _ = std::fs::remove_dir_all(&d);
    }
}
