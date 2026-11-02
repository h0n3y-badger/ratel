//! Automatic response: quarantine files and freeze processes, under a policy.
//!
//! Defaults (`ratel watch`): act on ClamAV signature matches only. Those are exact
//! matches against known malware, so acting on them costs almost nothing in false
//! positives, and everything is undoable (`ratel quarantine restore`, `ratel contain
//! release`) and reported in the alert. Behaviour-based detections (exfiltration,
//! reverse shells) only freeze processes with `contain = high`.
//!
//! Never automatic: moving a file that belongs to a package or is allowlisted
//! (a trojaned /usr/bin/sshd is reported, and the admin reinstalls the package),
//! freezing the protected processes in `contain::Policy` (+ `contain-never`).

use crate::contain;
use crate::quarantine;
use crate::trust::Origin;
use std::path::{Path, PathBuf};

const SYSTEM_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/boot", "/opt"];

pub struct Response {
    pub quarantine: bool,
    pub contain_sig: bool,
    pub contain_high: bool,
    pub store: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub policy: contain::Policy,
}

impl Response {
    pub fn new(quarantine: &str, contain: &str, never: &[String], state_dir: &Option<String>) -> Result<Response, String> {
        let q = match quarantine {
            "off" => false,
            "signatures" | "" => true,
            x => return Err(format!("quarantine must be off or signatures, not {x}")),
        };
        let (cs, ch) = match contain {
            "off" => (false, false),
            "signatures" | "" => (true, false),
            "high" => (true, true),
            x => return Err(format!("contain must be off, signatures or high, not {x}")),
        };
        let mut policy = contain::Policy::server_default();
        policy.never.extend(never.iter().cloned());
        let dir = state_dir.as_ref().map(PathBuf::from);
        Ok(Response {
            quarantine: q && dir.is_some(),
            contain_sig: cs && dir.is_some(),
            contain_high: ch && dir.is_some(),
            store: dir.as_ref().map(|d| d.join("quarantine")),
            state: dir.map(|d| d.join("contained.json")),
            policy,
        })
    }

    /// Quarantine `path` (content must still be `sha256`). Returns the evidence line.
    pub fn quarantine(&self, path: &Path, sha256: &str, origin: &Option<Origin>, names: &[String]) -> String {
        let (Some(store), true) = (&self.store, self.quarantine) else {
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
        let reason: Vec<String> = names.iter().map(|n| format!("clamav:{n}")).collect();
        match quarantine::quarantine_file(store, path, Some(sha256), "clamav", reason) {
            Ok(it) => {
                let links = if it.nlink > 1 { format!("; {} other hard link(s) still hold the content", it.nlink - 1) } else { String::new() };
                format!("quarantined as {} (undo: ratel quarantine restore {}){links}", it.id, it.id)
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
}
