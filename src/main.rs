mod features;
mod indicators;
mod model;
mod net;
mod report;
mod trust;
mod watch;

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
    pub paths: Vec<PathBuf>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        json: false, all: false, explain: false, min_risk: 0.0,
        jobs: std::thread::available_parallelism().map_or(2, |n| n.get()).min(4),
        max_size: 128, model: None, list: None, watch: 0, interval_ms: 1000, scan_exes: false,
        allow: vec![], no_pkg_trust: false, integrity: false, paths: vec![],
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

/// Walk inputs without following symlinks; yields regular files.
fn collect(paths: &[PathBuf], out: &mut Vec<PathBuf>) {
    for p in paths {
        let Ok(md) = std::fs::symlink_metadata(p) else {
            eprintln!("ratel: cannot stat {}", p.display());
            continue;
        };
        if md.is_dir() {
            let Ok(rd) = std::fs::read_dir(p) else { continue };
            let mut kids: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
            kids.sort();
            collect(&kids, out);
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

/// Opens a file if it looks like ELF/PE and is under the size cap.
pub fn read_candidate(p: &Path, max: u64) -> Option<Bytes> {
    use std::io::Read;
    let mut fh = std::fs::File::open(p).ok()?;
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
    pub jobs: usize,
    pub max: u64,
    pub allow: Vec<String>,
    pub integrity: bool,
    pub pkg_trust: bool,
}

/// Static scan with provenance. `sink` gets each result and, when the file was
/// hashed, its sha256. Returns the number of ELF/PE files scanned.
pub fn scan_files(paths: &[PathBuf], c: &ScanCfg, m: &model::Model,
                  mut sink: impl FnMut(&Path, &report::Assessment, Option<String>)) -> Result<usize, String> {
    let mut files = vec![];
    collect(paths, &mut files);
    let kind = trust::detect_pkg_kind();
    let mut allow_files: Vec<(String, bool)> = trust::default_allowlists().into_iter().map(|f| (f, false)).collect();
    allow_files.extend(c.allow.iter().map(|f| (f.clone(), true)));
    let mut trust_db: Option<trust::Trust> = None;
    let mut err = None;
    let mut n = 0usize;
    par_files(&files, c.jobs, |p| read_candidate(p, c.max).map(|d| {
        let r = report::assess(&features::analyze(&d), m);
        // Hash only what provenance can change: non-clean files (or all, with integrity checks).
        let h = (c.integrity || r.risk >= 0.25).then(|| trust::hash(&d, kind));
        (r, h)
    }), |p, (mut r, h)| {
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
                let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                report::apply_origin(&mut r, t.origin(&canon, &h), c.pkg_trust);
            }
            hex = Some(trust::hex(&h.sha256));
        }
        sink(p, &r, hex);
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
            let cfg = ScanCfg { jobs: o.jobs, max, allow: o.allow.clone(), integrity: o.integrity, pkg_trust: !o.no_pkg_trust };
            let n = scan_files(&o.paths, &cfg, &m, |p, r, _| {
                worst = worst.max(report::alerting_risk(r));
                report::print(p, r, &o);
            }).unwrap_or_else(|e| die(&e));
            if !o.json {
                eprintln!("ratel: scanned {n} ELF/PE file(s), highest risk {worst:.2}");
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
        "-h" | "--help" | "help" => print!("{USAGE}"),
        c => die(&format!("unknown command {c}\n\n{USAGE}")),
    }
}
