mod clamav;
mod features;
mod indicators;
mod model;
mod net;
mod report;
mod quarantine;
mod contain;
mod safety;
mod trust;
mod watch;
mod web;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

const USAGE: &str = "ratel — static capability scanner for ELF/PE files

usage:
  ratel scan [opts] PATH...       scan files / directories (recursive)
      --json                      JSON lines output
      --all                       also print files that look clean
      --min-risk X                only print files with risk >= X (0..1)
      --explain                   list every rule finding, not just the top ones
      --allow FILE                extra sha256 allowlist (repeatable); defaults:
                                  /etc/ratel/allow.list, ~/.config/ratel/allow.list
      --no-pkg-trust              don't cap package-verified files at `low`
      --integrity                 hash every file and check it against the package
                                  database (finds modified package files even if clean)
      --clamav-db DIR             ClamAV databases (default /var/lib/clamav, kept current
                                  by freshclam); every file is matched, not only ELF/PE
      --no-clamav                 don't use ClamAV signatures
      --pua                       also load ClamAV's potentially-unwanted (PUA) signatures
      --quarantine                move files matching a ClamAV signature into the vault
                                  (not package-owned or allowlisted ones; see ratel quarantine)
      --quarantine-store DIR      vault directory (default /var/lib/ratel/quarantine)
  ratel allow PATH...             print `<sha256>  <path>` allowlist lines (baseline)
  ratel features [opts] PATH...   dump feature vectors as JSON lines (training)
      --list FILE                 read paths from FILE (one per line)
  ratel feature-names             print the feature names, one per line
  ratel net [opts]                inspect sockets of running processes (/proc)
      --json                      JSON output
      --watch SECS                sample for SECS seconds to find beaconing
      --interval MS               sampling interval for --watch (default 1000)
      --scan-exes                 statically scan each networked process's executable
  ratel info                      show embedded model info
  ratel watch [opts]              network behaviour monitor with alerts (see ratel watch --help)
  ratel alerts | explain ID | ack ID [--fp] | status   review what the monitor found
  ratel quarantine list|add PATH|show ID|restore ID|delete ID   file quarantine vault (--help)
  ratel contain list|freeze PID|release ID|kill ID      freeze a process tree (--help)
  ratel web [opts]                hardened dashboard (see ratel web --help)

common opts:
  --jobs N        worker threads (default: number of CPUs, max 4)
  --max-size MB   skip files larger than this (default 128)
  --model FILE    use a model JSON instead of the embedded one
";

pub struct Opts {
    pub json: bool,
    pub all: bool,
    pub explain: bool,
    pub min_risk: f64,
    pub jobs: usize,
    pub max_size: u64,
    pub model: Option<String>,
    pub list: Option<String>,
    pub watch: u64,
    pub interval_ms: u64,
    pub scan_exes: bool,
    pub allow: Vec<String>,
    pub no_pkg_trust: bool,
    pub integrity: bool,
    pub clamav_db: Option<String>,
    pub no_clamav: bool,
    pub pua: bool,
    pub quarantine: bool,
    pub quarantine_store: Option<String>,
    pub paths: Vec<PathBuf>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        json: false, all: false, explain: false, min_risk: 0.0,
        jobs: std::thread::available_parallelism().map_or(2, |n| n.get()).min(4),
        max_size: 128, model: None, list: None, watch: 0, interval_ms: 1000, scan_exes: false,
        allow: vec![], no_pkg_trust: false, integrity: false, clamav_db: None, no_clamav: false, pua: false, quarantine: false, quarantine_store: None, paths: vec![],
    };
    let mut i = 0;
    let val = |i: &mut usize| -> Result<String, String> {
        *i += 1;
        args.get(*i).cloned().ok_or_else(|| format!("{} needs a value", args[*i - 1]))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--json" => o.json = true,
            "--all" => o.all = true,
            "--explain" => o.explain = true,
            "--scan-exes" => o.scan_exes = true,
            "--no-pkg-trust" => o.no_pkg_trust = true,
            "--integrity" => o.integrity = true,
            "--clamav-db" => o.clamav_db = Some(val(&mut i)?),
            "--no-clamav" => o.no_clamav = true,
            "--pua" => o.pua = true,
            "--quarantine" => o.quarantine = true,
            "--quarantine-store" => o.quarantine_store = Some(val(&mut i)?),
            "--allow" => o.allow.push(val(&mut i)?),
            "--min-risk" => o.min_risk = val(&mut i)?.parse().map_err(|_| "bad --min-risk")?,
            "--jobs" | "-j" => o.jobs = val(&mut i)?.parse::<usize>().map_err(|_| "bad --jobs")?.max(1),
            "--max-size" => o.max_size = val(&mut i)?.parse().map_err(|_| "bad --max-size")?,
            "--model" => o.model = Some(val(&mut i)?),
            "--list" => o.list = Some(val(&mut i)?),
            "--watch" => o.watch = val(&mut i)?.parse().map_err(|_| "bad --watch")?,
            "--interval" => o.interval_ms = val(&mut i)?.parse::<u64>().map_err(|_| "bad --interval")?.max(50),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option {s}")),
            s => o.paths.push(PathBuf::from(s)),
        }
        i += 1;
    }
    Ok(o)
}

/// ClamAV databases: --clamav-db DIR, else /var/lib/clamav if it exists.
fn load_clamav(o: &Opts) -> Option<std::sync::Arc<clamav::Db>> {
    if o.no_clamav {
        return None;
    }
    let dir = o.clamav_db.clone().unwrap_or_else(|| clamav::DEFAULT_DIR.into());
    if o.clamav_db.is_none() && !Path::new(&dir).is_dir() {
        return None;
    }
    let t = std::time::Instant::now();
    match clamav::Db::load(Path::new(&dir), o.pua) {
        Ok(db) => {
            if std::env::var_os("RATEL_DEBUG_MEM").is_some() {
                let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                eprintln!("ratel: memory after ClamAV load: {}", st.lines().filter(|l| l.starts_with("VmRSS") || l.starts_with("VmHWM")).collect::<Vec<_>>().join(" "));
            }
            if !o.json {
                let (s, _) = db.stats();
                eprintln!("ratel: ClamAV {} ({} hash, {} body, {} logical signatures; {} skipped; {:.1}s)",
                    db.version, s.hashes, s.body, s.logical, s.skipped, t.elapsed().as_secs_f64());
            }
            Some(std::sync::Arc::new(db))
        }
        Err(e) if o.clamav_db.is_some() => die(&format!("ClamAV databases: {e}")),
        Err(e) => {
            eprintln!("ratel: ClamAV databases not used: {e}");
            None
        }
    }
}

pub fn load_model(o: &Opts) -> model::Model {
    let json = match &o.model {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|e| die(&format!("{p}: {e}"))),
        None => model::EMBEDDED.to_string(),
    };
    model::Model::load(&json).unwrap_or_else(|e| die(&e))
}

fn die(msg: &str) -> ! {
    eprintln!("ratel: {msg}");
    std::process::exit(2);
}

/// Walk inputs; yields regular files. Paths given on the command line are followed
/// if they are symlinks (on usr-merged systems /bin -> usr/bin); symlinks found
/// while walking are not.
fn collect(paths: &[PathBuf], out: &mut Vec<PathBuf>) {
    for p in paths {
        // resolve a symlinked argument once, here, so later opens never follow links
        let p = &if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_symlink()) {
            std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())
        } else {
            p.clone()
        };
        let Ok(md) = std::fs::symlink_metadata(p) else {
            eprintln!("ratel: cannot stat {}", safety::safe_path(p));
            continue;
        };
        if md.is_dir() {
            let Ok(rd) = std::fs::read_dir(p) else { continue };
            let mut kids: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
            kids.sort();
            walk(&kids, out);
        } else if md.is_file() {
            out.push(p.clone());
        }
    }
}

fn walk(paths: &[PathBuf], out: &mut Vec<PathBuf>) {
    for p in paths {
        let Ok(md) = std::fs::symlink_metadata(p) else {
            eprintln!("ratel: cannot stat {}", p.display());
            continue;
        };
        if md.is_dir() {
            let Ok(rd) = std::fs::read_dir(p) else { continue };
            let mut kids: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
            kids.sort();
            walk(&kids, out);
        } else if md.is_file() {
            out.push(p.clone());
        }
    }
}

/// File contents: memory-mapped for regular files (page cache, not heap), read
/// into memory for things that can't be mapped (/proc/<pid>/exe of a memfd).
pub enum Bytes {
    Map(memmap2::Mmap),
    Heap(Vec<u8>),
}
impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Map(m) => m,
            Bytes::Heap(v) => v,
        }
    }
}

/// Like `read_candidate`, but always reads into memory (no mmap).
pub fn read_candidate_heap(p: &Path, max: u64) -> Option<Bytes> {
    use std::io::Read;
    let fh = open_scan(p)?;
    let md = fh.metadata().ok()?;
    if !md.is_file() || md.len() < 64 || md.len() > max {
        return None;
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    fh.take(max).read_to_end(&mut buf).ok()?;
    if buf.len() < 64 || (&buf[..4] != b"\x7fELF" && &buf[..2] != b"MZ") {
        return None;
    }
    Some(Bytes::Heap(buf))
}

/// Opens a file for scanning without following symlinks (a file swapped for a link to
/// /etc/shadow mid-scan isn't read) and without blocking (a file swapped for a FIFO
/// can't hang the scanner); only regular files pass. /proc/<pid>/exe is a magic link,
/// so it is the one place links are followed.
fn open_scan(p: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY;
    if !p.starts_with("/proc/") {
        flags |= libc::O_NOFOLLOW;
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(flags).open(p).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    Some(f)
}

/// What was actually read: identity of the opened file (not of whatever the path
/// names later) and where the kernel says it is. Responses act on this, never on a
/// path re-resolved after the scan (a directory swapped for a symlink to /bin
/// mustn't turn "quarantine /tmp/u/x" into "freeze every /bin/x").
#[derive(Default, Clone)]
pub struct Seen {
    pub sha256: Option<String>,
    pub dev: u64,
    pub ino: u64,
    /// /proc/self/fd/N of the open file: its real location at read time
    pub path: Option<PathBuf>,
}

fn seen_of(fh: &std::fs::File) -> Seen {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let md = fh.metadata().ok();
    Seen {
        sha256: None,
        dev: md.as_ref().map_or(0, |m| m.dev()),
        ino: md.as_ref().map_or(0, |m| m.ino()),
        path: std::fs::read_link(format!("/proc/self/fd/{}", fh.as_raw_fd())).ok(),
    }
}

/// Opens any regular file under the size cap (for signature matching).
pub fn read_any(p: &Path, max: u64, heap: bool) -> Option<Bytes> {
    read_any_seen(p, max, heap).map(|(b, _)| b)
}

pub fn read_any_seen(p: &Path, max: u64, heap: bool) -> Option<(Bytes, Seen)> {
    use std::io::Read;
    let fh = open_scan(p)?;
    let seen = seen_of(&fh);
    let len = fh.metadata().ok()?.len();
    if len == 0 || len > max {
        return None;
    }
    if !heap {
        // SAFETY: as in read_candidate.
        if let Ok(m) = unsafe { memmap2::MmapOptions::new().len(len as usize).map(&fh) } {
            return Some((Bytes::Map(m), seen));
        }
    }
    let mut buf = Vec::with_capacity(len as usize);
    fh.take(max).read_to_end(&mut buf).ok()?;
    Some((Bytes::Heap(buf), seen))
}

fn is_exec(d: &[u8]) -> bool {
    d.len() >= 64 && (&d[..4] == b"\x7fELF" || &d[..2] == b"MZ")
}

/// Opens a file if it looks like ELF/PE and is under the size cap.
pub fn read_candidate(p: &Path, max: u64) -> Option<Bytes> {
    use std::io::Read;
    let mut fh = open_scan(p)?;
    let md = fh.metadata().ok()?;
    let len = md.len();
    if !md.is_file() || len < 64 || len > max {
        return None;
    }
    let mut head = [0u8; 4];
    fh.read_exact(&mut head).ok()?;
    if &head != b"\x7fELF" && &head[..2] != b"MZ" {
        return None;
    }
    // SAFETY: read-only private mapping; if the file is truncated underneath us the
    // process could SIGBUS, which for a scanner of mostly-static binaries is acceptable.
    if let Ok(m) = unsafe { memmap2::MmapOptions::new().len(len as usize).map(&fh) } {
        #[cfg(unix)]
        let _ = m.advise(memmap2::Advice::Sequential);
        return Some(Bytes::Map(m));
    }
    let mut buf = head.to_vec();
    buf.reserve(len as usize);
    fh.read_to_end(&mut buf).ok()?;
    Some(Bytes::Heap(buf))
}

pub struct ScanCfg {
    /// Read files into memory instead of mmapping them: a file truncated while being
    /// scanned can't SIGBUS the process (the daemon scans world-writable dirs).
    pub heap: bool,
    pub jobs: usize,
    pub max: u64,
    pub allow: Vec<String>,
    pub integrity: bool,
    pub pkg_trust: bool,
    /// ClamAV signatures: every regular file is matched, not only ELF/PE.
    pub clam: Option<std::sync::Arc<clamav::Db>>,
}

/// Static scan with provenance. `sink` gets each result and, when the file was
/// hashed, its sha256. Returns the number of ELF/PE files scanned.
pub fn scan_files(paths: &[PathBuf], c: &ScanCfg, m: &model::Model,
                  mut sink: impl FnMut(&Path, &report::Assessment, &Seen)) -> Result<usize, String> {
    let mut files = vec![];
    collect(paths, &mut files);
    let kind = trust::detect_pkg_kind();
    let mut allow_files: Vec<(String, bool)> = trust::default_allowlists().into_iter().map(|f| (f, false)).collect();
    allow_files.extend(c.allow.iter().map(|f| (f.clone(), true)));
    let mut trust_db: Option<trust::Trust> = None;
    let mut err = None;
    let mut n = 0usize;
    par_files(&files, c.jobs, |p| {
        let (d, seen) = match &c.clam {
            Some(_) => read_any_seen(p, c.max, c.heap)?,
            None if c.heap => (read_candidate_heap(p, c.max)?, Seen::default()),
            None => (read_candidate(p, c.max)?, Seen::default()),
        };
        let (sigs, limited) = c.clam.as_ref().map(|db| db.scan_full(&d)).unwrap_or_default();
        if !is_exec(&d) {
            // other files only matter when a signature matched (or couldn't be ruled out)
            let mut r = report::signature_only("data", vec![]);
            r.sig_limited = limited;
            if limited {
                r.verdict = "inconclusive";
            }
            return (!sigs.is_empty() || limited).then(|| (r, Some(trust::hash(&d, kind)), sigs, seen));
        }
        let mut r = report::assess(&features::analyze(&d), m);
        r.sig_limited = limited;
        // Hash only what provenance can change: non-clean files (or all, with integrity checks).
        let h = (c.integrity || r.risk >= 0.25 || !sigs.is_empty()).then(|| trust::hash(&d, kind));
        Some((r, h, sigs, seen))
    }, |p, (mut r, h, sigs, mut seen)| {
        n += 1;
        let mut hex = None;
        if let Some(h) = h {
            if trust_db.is_none() && err.is_none() {
                let wanted = files.iter().filter_map(|f| std::fs::canonicalize(f).ok()).collect();
                match trust::Trust::load(kind, &allow_files, &wanted) {
                    Ok(t) => trust_db = Some(t),
                    Err(e) => err = Some(e),
                }
            }
            if let Some(t) = &trust_db {
                // provenance of the file that was read, not of what the path names now
                let canon = seen.path.clone().unwrap_or_else(|| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()));
                report::apply_origin(&mut r, t.origin(&canon, &h), c.pkg_trust);
            }
            hex = Some(trust::hex(&h.sha256));
        }
        report::apply_signatures(&mut r, sigs);
        seen.sha256 = hex;
        sink(p, &r, &seen);
    });
    match err {
        Some(e) => Err(e),
        None => Ok(n),
    }
}

/// Runs `work` over files on a small thread pool; results come back in any order.
fn par_files<T: Send>(files: &[PathBuf], jobs: usize, work: impl Fn(&Path) -> Option<T> + Sync, mut sink: impl FnMut(&Path, T)) {
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::sync_channel::<(usize, T)>(64);
    std::thread::scope(|s| {
        for _ in 0..jobs.min(files.len().max(1)) {
            let tx = tx.clone();
            let next = &next;
            let work = &work;
            s.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                if let Some(r) = work(&files[i]) {
                    if tx.send((i, r)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        for (i, r) in rx {
            sink(&files[i], r);
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        std::process::exit(2);
    };
    if cmd == "watch" {
        watch::run(&args[1..]);
        return;
    }
    if cmd == "web" {
        web::run(&args[1..]);
        return;
    }
    match cmd.as_str() {
        "alerts" => return watch::cli::alerts(&args[1..]),
        "quarantine" => std::process::exit(quarantine::cli(&args[1..])),
        "contain" => std::process::exit(contain::cli(&args[1..])),
        "explain" | "incident" => return watch::cli::explain(&args[1..]),
        "ack" => return watch::cli::ack(&args[1..]),
        "status" => return watch::cli::status(&args[1..]),
        _ => {}
    }
    if cmd == "net-feature-names" {
        println!("{}", serde_json::json!({"flow": watch::engine::FLOW_FEATURES, "dns": watch::engine::DNS_FEATURES}));
        return;
    }
    let o = parse_opts(&args[1..]).unwrap_or_else(|e| die(&e));
    let max = o.max_size << 20;
    match cmd.as_str() {
        "feature-names" => {
            for n in features::FEATURE_NAMES {
                println!("{n}");
            }
        }
        "info" => {
            let m = load_model(&o);
            println!("model version {} ({}), {} trees, {} scanner features, empty={}",
                m.version, m.trained, m.n_trees, features::FEATURE_NAMES.len(), m.is_empty());
            match model::NetModel::load(model::EMBEDDED_NET, &[("flow", watch::engine::FLOW_FEATURES), ("dns", watch::engine::DNS_FEATURES)]) {
                Ok(n) => println!("network model version {} ({}), units: {}", n.version, n.trained,
                    n.units.keys().cloned().collect::<Vec<_>>().join(", ")),
                Err(e) => println!("network model: {e}"),
            }
        }
        "features" => {
            let mut paths = o.paths.clone();
            if let Some(l) = &o.list {
                let s = std::fs::read_to_string(l).unwrap_or_else(|e| die(&format!("{l}: {e}")));
                paths.extend(s.lines().filter(|l| !l.is_empty()).map(PathBuf::from));
            }
            let mut files = vec![];
            collect(&paths, &mut files);
            let mut out = std::io::BufWriter::new(std::io::stdout().lock());
            par_files(&files, o.jobs, |p| read_candidate(p, max).map(|d| features::analyze(&d)), |p, a| {
                use std::io::Write;
                // Max rule strength per capability (CAPS order): used for weak labels on real files.
                let rules: Vec<u8> = features::CAPS.iter()
                    .map(|c| a.findings.iter().filter(|f| f.cap == *c).map(|f| f.strength).max().unwrap_or(0)).collect();
                let line = serde_json::json!({"path": p.to_string_lossy(), "features": a.feats, "rules": rules});
                let _ = writeln!(out, "{line}");
            });
        }
        "scan" => {
            if o.paths.is_empty() {
                die("scan needs at least one path");
            }
            let m = load_model(&o);
            if m.is_empty() {
                eprintln!("ratel: warning: no model embedded, rules only");
            }
            let mut worst = 0.0f64;
            let clam = load_clamav(&o);
            let cfg = ScanCfg { heap: false, jobs: o.jobs, max, allow: o.allow.clone(), integrity: o.integrity, pkg_trust: !o.no_pkg_trust, clam };
            let qr = o.quarantine.then(|| watch::respond::Response::manual(
                o.quarantine_store.clone().unwrap_or_else(|| quarantine::DEFAULT_STORE.into()).into()));
            if o.quarantine && cfg.clam.is_none() {
                die("--quarantine needs ClamAV signatures (only signature matches are quarantined)");
            }
            let n = scan_files(&o.paths, &cfg, &m, |p, r, seen| {
                worst = worst.max(report::alerting_risk(r));
                report::print(p, r, &o);
                if let (Some(q), Some(sha), "malware") = (&qr, &seen.sha256, r.verdict) {
                    if !r.signatures.is_empty() {
                        let at = seen.path.as_deref().unwrap_or(p);
                        eprintln!("    {:<12} {}", "quarantine", q.quarantine(at, sha, &r.origin, "clamav",
                            r.signatures.iter().map(|n| format!("clamav:{n}")).collect()));
                    }
                }
            }).unwrap_or_else(|e| die(&e));
            if !o.json {
                eprintln!("ratel: scanned {n} file(s), highest risk {worst:.2}");
            }
            std::process::exit(if worst >= 0.75 { 1 } else { 0 });
        }
        "allow" => {
            let mut files = vec![];
            collect(&o.paths, &mut files);
            trust::print_allow_lines(&files, max);
        }
        "probs" => {
            // Raw model probabilities (for checking parity with the Python trainer).
            let m = load_model(&o);
            let mut files = vec![];
            collect(&o.paths, &mut files);
            for p in files {
                if let Some(d) = read_candidate(&p, max) {
                    let pr: Vec<Option<f64>> = m.predict(&features::analyze(&d).feats).into_iter().map(|x| x.map(|v| v.0)).collect();
                    println!("{}", serde_json::json!({"path": p.to_string_lossy(), "probs": pr}));
                }
            }
        }
        "net" => net::run(&o),
        "-h" | "--help" | "help" => print!("{USAGE}\n{}", watch::cli::USAGE),
        c => die(&format!("unknown command {c}\n\n{USAGE}")),
    }
}
