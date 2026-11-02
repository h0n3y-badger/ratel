//! Automatic response: quarantine files and freeze processes, under a policy that the
//! dashboard (or the config) can switch at run time.
//!
//! Quarantine modes:
//! * `signatures`: files matching a ClamAV signature.
//! * `suspicious` (default): also "obviously bad" executables in world-writable temp
//!   directories (/tmp, /var/tmp, /dev/shm): two or more evasion capabilities
//!   (anti-debug, anti-VM, obfuscation, packing) at confidence >= 0.85 that no
//!   legitimate role explains. Measured: 0 of 5,791 system/Alpine binaries, 3 of 2,232
//!   unpackaged legit programs (a DRM'd game, VirtualBox, qemu; none live in /tmp);
//!   ~20% of synthetic samples with 2+ evasion tricks, ~35% with 3+. Also: a temp-dir
//!   executable whose process was frozen for a high behaviour alert.
//! * `off`.
//!
//! Containment modes: `signatures` (default: processes running a matching file, or an
//! "obviously bad" one), `high` (also the processes behind high behaviour alerts), `off`.
//!
//! Never automatic: moving a file that belongs to a package or is allowlisted, or (with
//! no trusted package database) anything in a system directory; freezing the protected
//! processes in `contain::Policy` (+ `contain-never`); re-quarantining a file the admin
//! restored. Everything is undoable and reported in the alert.

use crate::contain;
use crate::quarantine;
use crate::report::Assessment;
use crate::trust::Origin;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};

const SYSTEM_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/boot", "/opt"];
pub const TEMP_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/shm"];
const EVASIVE: &[&str] = &["anti_debug", "anti_vm", "obfuscation", "packed"];
/// Confidence each evasive capability needs for the `suspicious` rule.
pub const SUSPICIOUS_CONF: f64 = 0.85;

pub const Q_MODES: &[&str] = &["off", "signatures", "suspicious"];
pub const C_MODES: &[&str] = &["off", "signatures", "high"];

pub struct Response {
    qmode: AtomicU8,
    cmode: AtomicU8,
    pub store: Option<PathBuf>,
    pub state: Option<PathBuf>,
    dir: Option<PathBuf>,
    pub policy: contain::Policy,
}

fn mode_index(modes: &[&str], v: &str, what: &str) -> Result<u8, String> {
    modes.iter().position(|m| *m == v).map(|i| i as u8).ok_or_else(|| format!("{what} must be one of {}, not {v}", modes.join(", ")))
}

impl Response {
    /// Config/command line modes; a mode set from the dashboard (persisted in
    /// <state>/response-policy.json) takes precedence until changed again.
    pub fn new(quarantine: &str, contain: &str, never: &[String], state_dir: &Option<String>) -> Result<Response, String> {
        let q = mode_index(Q_MODES, if quarantine.is_empty() { "suspicious" } else { quarantine }, "quarantine")?;
        let c = mode_index(C_MODES, if contain.is_empty() { "signatures" } else { contain }, "contain")?;
        let mut policy = contain::Policy::server_default();
        policy.never.extend(never.iter().cloned());
        let dir = state_dir.as_ref().map(PathBuf::from);
        let r = Response {
            qmode: AtomicU8::new(q),
            cmode: AtomicU8::new(c),
            store: dir.as_ref().map(|d| d.join("quarantine")),
            state: dir.as_ref().map(|d| d.join("contained.json")),
            dir,
            policy,
        };
        if let Some(p) = r.dir.as_ref().map(|d| d.join("response-policy.json")) {
            if p.exists() {
                // root-only file: a forged one could switch protection off
                match crate::safety::trusted_read(&p, 4096).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) {
                    Some(v) => {
                        if let Some(i) = v["quarantine"].as_str().and_then(|m| mode_index(Q_MODES, m, "").ok()) {
                            r.qmode.store(i, Ordering::Relaxed);
                        }
                        if let Some(i) = v["contain"].as_str().and_then(|m| mode_index(C_MODES, m, "").ok()) {
                            r.cmode.store(i, Ordering::Relaxed);
                        }
                    }
                    None => eprintln!("ratel: ignoring untrusted or unreadable {}", p.display()),
                }
            }
        }
        Ok(r)
    }

    /// Only for manual scans (`ratel scan --quarantine`): quarantine signature matches.
    pub fn manual(store: PathBuf) -> Response {
        Response { qmode: AtomicU8::new(1), cmode: AtomicU8::new(0), store: Some(store), state: None, dir: None,
            policy: contain::Policy::server_default() }
    }

    pub fn modes(&self) -> (&'static str, &'static str) {
        (Q_MODES[self.qmode.load(Ordering::Relaxed) as usize], C_MODES[self.cmode.load(Ordering::Relaxed) as usize])
    }

    pub fn quarantine_on(&self) -> bool {
        self.store.is_some() && self.qmode.load(Ordering::Relaxed) >= 1
    }
    pub fn suspicious_on(&self) -> bool {
        self.store.is_some() && self.qmode.load(Ordering::Relaxed) >= 2
    }
    pub fn contain_sig(&self) -> bool {
        self.state.is_some() && self.cmode.load(Ordering::Relaxed) >= 1
    }
    pub fn contain_high(&self) -> bool {
        self.state.is_some() && self.cmode.load(Ordering::Relaxed) >= 2
    }

    /// Switch modes at run time (dashboard) and persist the choice.
    pub fn set_modes(&self, q: Option<&str>, c: Option<&str>) -> Result<(), String> {
        let qi = q.map(|m| mode_index(Q_MODES, m, "quarantine")).transpose()?;
        let ci = c.map(|m| mode_index(C_MODES, m, "contain")).transpose()?;
        if let Some(i) = qi {
            self.qmode.store(i, Ordering::Relaxed);
        }
        if let Some(i) = ci {
            self.cmode.store(i, Ordering::Relaxed);
        }
        if let Some(d) = &self.dir {
            let (q, c) = self.modes();
            let p = d.join("response-policy.json");
            let tmp = p.with_extension("tmp");
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
            use std::io::Write;
            write!(f, "{}", serde_json::json!({"quarantine": q, "contain": c})).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn restored(&self, sha256: &str) -> bool {
        self.store.as_ref().is_some_and(|s| quarantine::was_restored(s, sha256))
    }

    /// Quarantine `path` (content must still be `sha256`). Returns the evidence line.
    pub fn quarantine(&self, path: &Path, sha256: &str, origin: &Option<Origin>, detector: &str, reason: Vec<String>) -> String {
        let (Some(store), true) = (&self.store, self.quarantine_on()) else {
            return "not quarantined (quarantine = off)".into();
        };
        match origin {
            Some(Origin::Package { pkg }) | Some(Origin::Modified { pkg }) => {
                return format!("not quarantined automatically: file of package {} (reinstall it, or `ratel quarantine add`)", crate::safety::safe(pkg));
            }
            Some(Origin::Allowlisted) => return "not quarantined: allowlisted".into(),
            Some(Origin::Unknown) => {}
            // no trusted package database: system directories are off limits
            None if SYSTEM_DIRS.iter().any(|d| path.starts_with(d)) => {
                return "not quarantined automatically: system directory and no package database to tell \
                        whether the file belongs there (`ratel quarantine add` to do it by hand)".into();
            }
            None => {}
        }
        if self.restored(sha256) {
            return "not quarantined: this content was restored from quarantine before (treated as a false positive)".into();
        }
        match quarantine::quarantine_file(store, path, Some(sha256), detector, reason) {
            Ok(it) => {
                let links = if it.nlink > 1 { format!("; {} other hard link(s) still hold the content", it.nlink - 1) } else { String::new() };
                format!("quarantined as {} (undo: ratel quarantine restore {}, or the dashboard){links}", it.id, it.id)
            }
            Err(e) => format!("quarantine failed: {}", crate::safety::safe(&e)),
        }
    }

    /// Freeze `pid` and its descendants, if it is still the process that started at
    /// `start` (when known). Returns the evidence line.
    pub fn contain(&self, pid: u32, start: Option<u64>, reason: &str) -> String {
        let Some(state) = &self.state else { return "process not frozen (no state directory)".into() };
        match contain::freeze_tree_at(pid, start, reason, &self.policy, None) {
            Ok(c) => {
                let rec = contain::record(state, &c).err().map(|e| format!(" (not recorded: {e})")).unwrap_or_default();
                format!("process tree frozen ({} process(es), {}) as {} (undo: ratel contain release {}; end: ratel contain kill {}){rec}",
                    c.pids.len(), c.method, c.id, c.id, c.id)
            }
            Err(e) => format!("process not frozen: {}", crate::safety::safe(&e)),
        }
    }

    /// Processes currently running the file with this (dev, inode).
    pub fn running(dev: u64, ino: u64) -> Vec<u32> {
        use std::os::unix::fs::MetadataExt;
        let mut v = vec![];
        for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            if let Ok(m) = std::fs::metadata(format!("/proc/{pid}/exe")) {
                if m.dev() == dev && m.ino() == ino {
                    v.push(pid);
                }
            }
        }
        v
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.store.as_ref().map_or(0, |s| quarantine::list(s).len()), self.state.as_ref().map_or(0, |s| contain::list(s).len()))
    }

    /// What the dashboard shows: modes, vault, frozen trees (written to
    /// <state>/response.json, group-readable; the vault itself is root-only).
    pub fn snapshot(&self, results: &[serde_json::Value]) -> serde_json::Value {
        let (q, c) = self.modes();
        let items: Vec<serde_json::Value> = self.store.as_ref().map(|s| quarantine::list(s)).unwrap_or_default().into_iter().map(|it| {
            serde_json::json!({"id": it.id, "path": it.path, "sha256": it.sha256, "size": it.size, "t": it.t,
                "detector": it.detector, "reason": it.reason, "nlink": it.nlink, "uid": it.uid})
        }).collect();
        let frozen: Vec<serde_json::Value> = self.state.as_ref().map(|s| contain::list(s)).unwrap_or_default().into_iter().map(|c| {
            let alive = c.pids.iter().filter(|p| Path::new(&format!("/proc/{p}")).exists()).count();
            serde_json::json!({"id": c.id, "root_pid": c.root_pid, "pids": c.pids.len(), "alive": alive, "exe": c.exe,
                "method": c.method, "t": c.t, "reason": c.reason})
        }).collect();
        serde_json::json!({"updated": super::now(), "quarantine": q, "contain": c,
            "quarantine_modes": Q_MODES, "contain_modes": C_MODES, "available": self.dir.is_some(),
            "suspicious_rule": format!("2+ of anti-debug, anti-VM, obfuscation, packing at confidence >= {SUSPICIOUS_CONF}, in {}", TEMP_DIRS.join(", ")),
            "vault": items, "frozen": frozen, "results": results})
    }
}

pub fn in_temp(p: &Path) -> bool {
    TEMP_DIRS.iter().any(|d| p.starts_with(d))
}

/// The strict static rule: evasive capabilities at high confidence that no
/// legitimate role (hypervisor, debugger, DRM...) explains.
pub fn suspicious(r: &Assessment) -> Option<String> {
    let hits: Vec<String> = r.caps.iter()
        .filter(|c| EVASIVE.contains(&c.cap) && c.conf >= SUSPICIOUS_CONF && c.excused_by.is_none())
        .map(|c| format!("{} {:.2}", c.cap, c.conf)).collect();
    (hits.len() >= 2).then(|| format!("static: {}", hits.join(", ")))
}

/// One dashboard request (from <state>/feedback.d/control.req). Returns
/// (ok, message, severity of the announcement).
pub fn execute(resp: &Response, v: &serde_json::Value) -> (bool, String, &'static str) {
    let id = v["id"].as_str().unwrap_or("");
    let id_ok = !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let res = |r: Result<String, String>, sev: &'static str| match r {
        Ok(m) => (true, m, sev),
        Err(e) => (false, crate::safety::safe(&e), "low"),
    };
    match v["action"].as_str().unwrap_or("") {
        "policy" => {
            let before = resp.modes();
            let r = resp.set_modes(v["quarantine"].as_str(), v["contain"].as_str());
            let after = resp.modes();
            // turning protection down is the interesting direction
            let weaker = mode_index(Q_MODES, after.0, "").unwrap_or(0) < mode_index(Q_MODES, before.0, "").unwrap_or(0)
                || mode_index(C_MODES, after.1, "").unwrap_or(0) < mode_index(C_MODES, before.1, "").unwrap_or(0);
            let mut ch = vec![];
            if before.0 != after.0 {
                ch.push(format!("quarantine {} -> {}", before.0, after.0));
            }
            if before.1 != after.1 {
                ch.push(format!("contain {} -> {}", before.1, after.1));
            }
            if ch.is_empty() {
                ch.push(format!("unchanged (quarantine {}, contain {})", after.0, after.1));
            }
            res(r.map(|_| format!("response policy: {}", ch.join(", "))),
                if weaker { "high" } else { "medium" })
        }
        _ if !id_ok => (false, "bad id".into(), "low"),
        "restore" => match &resp.store {
            Some(s) => res(quarantine::restore(s, id, None, false).map(|p| format!("restored quarantined {id} to {}", crate::safety::safe_path(&p))), "high"),
            None => (false, "no quarantine store".into(), "low"),
        },
        "delete" => match &resp.store {
            Some(s) => res(quarantine::delete(s, id).map(|_| format!("deleted quarantined {id} for good")), "medium"),
            None => (false, "no quarantine store".into(), "low"),
        },
        "release" => match &resp.state {
            Some(s) => res(contain::release(s, id, None).map(|_| format!("released frozen process tree {id} (it runs again)")), "high"),
            None => (false, "no containment state".into(), "low"),
        },
        "kill" => match &resp.state {
            Some(s) => res(contain::kill(s, id, None).map(|_| format!("killed frozen process tree {id}")), "medium"),
            None => (false, "no containment state".into(), "low"),
        },
        a => (false, format!("unknown action {}", crate::safety::safe(a)), "low"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Assessment, CapScore};

    fn cap(c: &'static str, conf: f64, excused: Option<&'static str>) -> CapScore {
        CapScore { cap: c, conf, model: Some(conf), rules: conf, model_only: false, excused_by: excused, why: String::new() }
    }
    fn assess(caps: Vec<CapScore>) -> Assessment {
        Assessment { caps, risk: 0.9, verdict: "high", findings: vec![], format: "elf", roles: vec![], roles_applied: false,
            origin: None, signatures: vec![], sig_limited: false }
    }

    #[test]
    fn strict_static_rule() {
        assert!(suspicious(&assess(vec![cap("anti_debug", 0.9, None), cap("packed", 0.95, None)])).is_some());
        assert!(suspicious(&assess(vec![cap("anti_debug", 0.9, None), cap("packed", 0.8, None)])).is_none(), "below 0.85");
        assert!(suspicious(&assess(vec![cap("anti_vm", 0.99, Some("hypervisor")), cap("anti_debug", 0.9, None)])).is_none(), "role excuses");
        assert!(suspicious(&assess(vec![cap("crypto", 0.99, None), cap("network", 0.99, None)])).is_none(), "not evasive");
        assert!(in_temp(Path::new("/tmp/x")) && in_temp(Path::new("/dev/shm/y")) && !in_temp(Path::new("/tmpfoo/x")) && !in_temp(Path::new("/usr/bin/x")));
    }

    #[test]
    fn modes_persist_and_requests_are_validated() {
        let d = std::env::temp_dir().join(format!("ratel-resp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sd = Some(d.to_string_lossy().into_owned());
        let r = Response::new("", "", &[], &sd).unwrap();
        assert_eq!(r.modes(), ("suspicious", "signatures"));
        let (ok, msg, sev) = execute(&r, &serde_json::json!({"action": "policy", "quarantine": "off", "contain": "high"}));
        assert!(ok && msg.contains("quarantine suspicious -> off") && msg.contains("contain signatures -> high") && sev == "high", "weakening is a high announcement: {msg}");
        assert!(!r.quarantine_on() && r.contain_high());
        // survives a restart, over the config default
        let r2 = Response::new("signatures", "signatures", &[], &sd).unwrap();
        assert_eq!(r2.modes(), ("off", "high"));
        assert!(!execute(&r2, &serde_json::json!({"action": "policy", "quarantine": "all"})).0);
        assert!(!execute(&r2, &serde_json::json!({"action": "restore", "id": "../x"})).0);
        assert!(!execute(&r2, &serde_json::json!({"action": "format-disk", "id": "a"})).0);
        assert!(!execute(&r2, &serde_json::json!({"action": "restore", "id": "nope-123"})).0, "unknown vault id");
        let _ = std::fs::remove_dir_all(&d);
    }
}
