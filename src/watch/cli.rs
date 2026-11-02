//! Reviewing what the monitor found: `ratel alerts`, `ratel explain <incident>`,
//! `ratel ack <incident> [--fp]`, `ratel status`.

use super::incidents::local_time;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "reviewing alerts:
  ratel alerts [--since 24h] [--min low|medium|high] [--json]   list alerts (from /var/log/ratel/alerts.jsonl)
  ratel explain INCIDENT                                       evidence, process context, activity timeline
  ratel ack INCIDENT [--fp [--any-dest]] [--note TEXT]         mark reviewed; --fp: false alarm, stop alerting on it
  ratel status                                                 is the monitor running and healthy
common: --state DIR (default /var/lib/ratel), --log FILE
";

struct Paths {
    state: PathBuf,
    log: PathBuf,
}

fn die(m: &str) -> ! {
    eprintln!("ratel: {m}");
    std::process::exit(2);
}

fn parse_common(args: &[String]) -> (Paths, Vec<String>, HashMap<String, String>) {
    let mut state = PathBuf::from("/var/lib/ratel");
    let mut log = PathBuf::from("/var/log/ratel/alerts.jsonl");
    let mut pos = vec![];
    let mut kv = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let takes = matches!(a, "--state" | "--log" | "--since" | "--min" | "--note" | "--status");
        if takes {
            let v = args.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{a} needs a value")));
            match a {
                "--state" => state = PathBuf::from(&v),
                "--log" => log = PathBuf::from(&v),
                _ => {
                    kv.insert(a.to_string(), v);
                }
            }
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            kv.insert(a.to_string(), String::new());
        } else {
            pos.push(a.to_string());
        }
        i += 1;
    }
    (Paths { state, log }, pos, kv)
}

fn dur(s: &str) -> f64 {
    let (n, u) = s.split_at(s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len()));
    let n: f64 = n.parse().unwrap_or_else(|_| die(&format!("bad duration {s}")));
    n * match u {
        "s" => 1.0, "m" => 60.0, "h" | "" => 3600.0, "d" => 86_400.0, "w" => 604_800.0,
        _ => die(&format!("bad duration unit in {s}")),
    }
}

fn sev_rank(s: &str) -> u8 {
    super::notify::sev_rank(s)
}

pub fn alerts(args: &[String]) {
    let (p, _, kv) = parse_common(args);
    let since = super::now() - dur(kv.get("--since").map(String::as_str).unwrap_or("24h"));
    let min = sev_rank(kv.get("--min").map(String::as_str).unwrap_or("low"));
    let text = std::fs::read_to_string(&p.log).unwrap_or_else(|e| die(&format!("{}: {e}", p.log.display())));
    let mut n: BTreeMap<String, u32> = BTreeMap::new();
    let mut last_inc = String::new();
    for line in text.lines() {
        let Ok(a) = serde_json::from_str::<Value>(line) else { continue };
        let t = a["t"].as_f64().unwrap_or(0.0);
        let sev = a["severity"].as_str().unwrap_or("");
        if t < since || sev_rank(sev) < min {
            continue;
        }
        *n.entry(sev.to_string()).or_default() += 1;
        if kv.contains_key("--json") {
            println!("{line}");
            continue;
        }
        let inc = a["incident"].as_str().unwrap_or("");
        if inc != last_inc && !inc.is_empty() {
            println!("── incident {inc}  (ratel explain {inc})");
            last_inc = inc.to_string();
        }
        println!("{}  {:<6} {}", local_time(t), sev.to_uppercase(), crate::safety::safe(a["title"].as_str().unwrap_or("")));
        for e in a["evidence"].as_array().into_iter().flatten().take(3) {
            println!("                       - {}", crate::safety::safe(e.as_str().unwrap_or("")));
        }
    }
    if !kv.contains_key("--json") {
        eprintln!("{}", if n.is_empty() { "no alerts in that window".to_string() } else {
            n.iter().map(|(k, v)| format!("{v} {k}")).collect::<Vec<_>>().join(", ")
        });
    }
}

fn incident_file(p: &Paths, id: &str) -> PathBuf {
    let f = p.state.join("incidents").join(format!("{id}.jsonl"));
    if f.exists() {
        return f;
    }
    // allow any unique part of the id ("exfil", "1920", ...)
    let dir = p.state.join("incidents");
    let m: Vec<PathBuf> = std::fs::read_dir(&dir).map(|d| d.flatten().map(|e| e.path())
        .filter(|x| x.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.contains(id))).collect()).unwrap_or_default();
    match m.len() {
        1 => m[0].clone(),
        0 => die(&format!("no incident {id} in {}", dir.display())),
        _ => die(&format!("{id} matches {} incidents; be more specific", m.len())),
    }
}

fn human(b: f64) -> String {
    super::engine::human(b)
}

pub fn explain(args: &[String]) {
    let (p, pos, _) = parse_common(args);
    let Some(id) = pos.first() else { die("explain needs an incident id (see `ratel alerts`)") };
    let f = incident_file(&p, id);
    let text = std::fs::read_to_string(&f).unwrap_or_else(|e| die(&format!("{}: {e}", f.display())));
    let lines: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let head = lines.iter().find(|l| l["type"] == "incident").cloned().unwrap_or(Value::Null);
    println!("Incident {}  opened {}", head["id"].as_str().unwrap_or(id), crate::safety::safe(head["time"].as_str().unwrap_or("?")));
    println!("\nAlerts:");
    let mut ctx = Value::Null;
    for l in lines.iter().filter(|l| l["type"] == "alert") {
        let a = &l["alert"];
        println!("  {}  {:<6} {}", local_time(a["t"].as_f64().unwrap_or(0.0)), crate::safety::safe(a["severity"].as_str().unwrap_or("")).to_uppercase(),
            a["title"].as_str().unwrap_or(""));
        for e in a["evidence"].as_array().into_iter().flatten() {
            println!("      - {}", crate::safety::safe(e.as_str().unwrap_or("")));
        }
        if ctx.is_null() && !a["context"].is_null() {
            ctx = a["context"].clone();
        }
    }
    let pr = &ctx["process"];
    if !pr.is_null() {
        println!("\nProcess:");
        if pr["gone"] == true {
            println!("  pid {} had already exited when the alert fired", pr["pid"]);
        } else {
            println!("  pid {}  user {}  started {}", pr["pid"], crate::safety::safe(pr["user"].as_str().unwrap_or("?")), crate::safety::safe(pr["started"].as_str().unwrap_or("?")));
            println!("  exe      {}", crate::safety::safe(pr["exe"].as_str().unwrap_or("?")));
            println!("  sha256   {}", crate::safety::safe(pr["sha256"].as_str().unwrap_or("?")));
            let origin = match pr["origin"]["kind"].as_str() {
                Some("package") => format!("package {} (unchanged since install)", crate::safety::safe(pr["origin"]["pkg"].as_str().unwrap_or("?"))),
                Some("modified") => format!("MODIFIED file of package {}", crate::safety::safe(pr["origin"]["pkg"].as_str().unwrap_or("?"))),
                Some("allowlisted") => "allowlisted hash".into(),
                Some("unknown") => "not from any package".into(),
                _ => "?".into(),
            };
            println!("  origin   {origin}");
            println!("  cmdline  {}", crate::safety::safe(pr["cmdline"].as_str().unwrap_or("?")));
            println!("  cwd      {}", crate::safety::safe(pr["cwd"].as_str().unwrap_or("?")));
            if let Some(c) = pr["container"].as_str() {
                println!("  container {c}");
            }
            for (i, par) in pr["parents"].as_array().into_iter().flatten().enumerate() {
                println!("  {}└ {}", "  ".repeat(i), crate::safety::safe(par.as_str().unwrap_or("")));
            }
        }
    }
    let pf = &ctx["profile"];
    if !pf.is_null() {
        println!("\nWhat ratel had learned about it:");
        println!("  first seen {}, server: {}, knows {} destination networks",
            pf["first_seen"].as_f64().map(local_time).unwrap_or_default(), pf["server"], pf["known_destinations"]);
        println!("  usual peak hourly upload {}, largest hour to one host {}",
            pf["usual_peak_hour_upload"].as_f64().map(human).unwrap_or_else(|| "(still learning)".into()),
            human(pf["largest_hour_to_one_host"].as_f64().unwrap_or(0.0)));
        if let Some(s) = pf["static"].as_str() {
            println!("  static scan of the binary: {s}");
        }
    }
    let d = &ctx["destination"];
    if !d.is_null() {
        println!("\nDestination {}{}", crate::safety::safe(d["ip"].as_str().unwrap_or("?")),
            d["dns_name"].as_str().map(|n| format!(" ({n})")).unwrap_or_else(|| " (no DNS lookup returned it)".into()));
        println!("  first contacted by this process: {}; by anything here: {}",
            d["first_seen_by_entity"].as_str().unwrap_or("never before"), d["first_seen_here"].as_str().unwrap_or("never before"));
    }
    // ---- activity timeline from recorded events
    #[derive(Default)]
    struct Agg {
        out: u64,
        inn: u64,
        conns: u32,
        first: f64,
        last: f64,
    }
    let mut per: BTreeMap<String, Agg> = BTreeMap::new();
    let mut seen: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut dns: BTreeMap<String, u32> = BTreeMap::new();
    let mut flags = vec![];
    let (mut n_before, mut n_after) = (0, 0);
    for l in &lines {
        let phase = l["type"].as_str().unwrap_or("");
        if phase != "before" && phase != "after" {
            continue;
        }
        if phase == "before" { n_before += 1 } else { n_after += 1 }
        let e = &l["ev"];
        let t = e["t"].as_f64().unwrap_or(0.0);
        match e["e"].as_str() {
            Some("tcp") | Some("udp") => {
                let key = format!("{}:{}", crate::safety::safe(e["rip"].as_str().unwrap_or("?")), e["rport"]);
                let a = per.entry(key).or_insert_with(|| Agg { first: t, ..Default::default() });
                a.last = t;
                if e["e"] == "udp" {
                    let b = e["len"].as_u64().unwrap_or(0) * e["scale"].as_u64().unwrap_or(1);
                    if e["inbound"] == true { a.inn += b } else { a.out += b }
                } else {
                    let id = e["id"].as_u64().unwrap_or(0);
                    let (s, r) = (e["sent"].as_u64().unwrap_or(0), e["recv"].as_u64().unwrap_or(0));
                    match seen.get(&id) {
                        Some((ps, pr)) => {
                            a.out += s.saturating_sub(*ps);
                            a.inn += r.saturating_sub(*pr);
                        }
                        None => {
                            a.conns += 1;
                            if phase == "after" {
                                a.out += s;
                                a.inn += r;
                            }
                        }
                    }
                    seen.insert(id, (s, r));
                }
            }
            Some("dns") if e["resp"] != true => *dns.entry(e["name"].as_str().unwrap_or("?").to_string()).or_default() += 1,
            Some("proc") => flags.push(format!("{} {}: {}", local_time(t), crate::safety::safe(e["rule"].as_str().unwrap_or("")), crate::safety::safe(e["detail"].as_str().unwrap_or("")))),
            _ => {}
        }
    }
    println!("\nActivity recorded ({n_before} events from the 15 min before, {n_after} after):");
    let mut rows: Vec<(&String, &Agg)> = per.iter().collect();
    rows.sort_by(|a, b| (b.1.out + b.1.inn).cmp(&(a.1.out + a.1.inn)));
    for (k, a) in rows.iter().take(15) {
        println!("  {:<28} sent {:>9}  received {:>9}  {} conn  {} → {}", k, human(a.out as f64), human(a.inn as f64), a.conns,
            &local_time(a.first)[11..], &local_time(a.last)[11..]);
    }
    if rows.len() > 15 {
        println!("  … {} more endpoints", rows.len() - 15);
    }
    if !dns.is_empty() {
        let mut v: Vec<(&String, &u32)> = dns.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        println!("  DNS lookups: {}", v.iter().take(8).map(|(n, c)| format!("{n} ×{c}")).collect::<Vec<_>>().join(", "));
    }
    for f in flags.iter().take(10) {
        println!("  flag {f}");
    }
    let id = head["id"].as_str().unwrap_or(id);
    println!("\nNext:\n  ratel ack {id}                 reviewed, nothing to do\n  ratel ack {id} --fp            false alarm: stop alerting on this process + destination + kind\n  ratel ack {id} --fp --any-dest false alarm for any destination of this process\n  full record: {}", f.display());
}

pub fn ack(args: &[String]) {
    let (p, pos, kv) = parse_common(args);
    let Some(id) = pos.first() else { die("ack needs an incident id") };
    let f = incident_file(&p, id);
    let text = std::fs::read_to_string(&f).unwrap_or_else(|e| die(&format!("{}: {e}", f.display())));
    let fp = kv.contains_key("--fp");
    let any = kv.contains_key("--any-dest");
    let alerts: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|l| l["type"] == "alert")
        .map(|l| l["alert"].clone()).collect();
    let sup: Vec<(String, String, String)> = super::incidents::suppressions_for(&alerts, any).into_iter()
        .map(|[a, b, c]| (a, b, c)).collect();
    if fp && sup.is_empty() {
        die("these alerts come from unidentified processes (or have no concrete destination); they can't be silenced — use `ratel ack ID` without --fp");
    }
    let id = f.file_stem().and_then(|s| s.to_str()).unwrap_or(id).to_string();
    let line = serde_json::json!({"id": id, "t": super::now(), "fp": fp, "note": kv.get("--note"),
        "suppress": if fp { sup.iter().map(|(a, b, c)| vec![a, b, c]).collect::<Vec<_>>() } else { vec![] }});
    let fb = p.state.join("feedback.jsonl");
    let mut o = std::fs::OpenOptions::new().create(true).append(true).open(&fb).unwrap_or_else(|e| die(&format!("{}: {e}", fb.display())));
    writeln!(o, "{line}").unwrap_or_else(|e| die(&e.to_string()));
    if fp {
        println!("marked {id} as a false alarm; the running monitor stops alerting on (within a minute):");
        for (e, d, k) in &sup {
            println!("  {k:<8} {e} -> {d}");
        }
        println!("its recorded events can also become training negatives (train/net/import_feedback.py)");
    } else {
        println!("marked {id} as reviewed");
    }
}

pub fn status_path(state: &Path) -> PathBuf {
    if Path::new("/run/ratel").is_dir() { PathBuf::from("/run/ratel/status.json") } else { state.join("status.json") }
}

pub fn status(args: &[String]) {
    let (p, _, kv) = parse_common(args);
    let sp = kv.get("--status").map(PathBuf::from).unwrap_or_else(|| status_path(&p.state));
    let Ok(t) = std::fs::read_to_string(&sp) else { die(&format!("no status at {} (is `ratel watch` running?)", sp.display())) };
    let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
    if kv.contains_key("--json") {
        println!("{v}");
        return;
    }
    let pid = v["pid"].as_u64().unwrap_or(0);
    let alive = Path::new(&format!("/proc/{pid}")).exists();
    let age = super::now() - v["updated"].as_f64().unwrap_or(0.0);
    let e = &v["engine"];
    let stopped = v["stopped"].as_bool() == Some(true);
    println!("ratel watch: {} (pid {pid}, status {:.0}s old)",
        if stopped { "stopped cleanly" } else if alive && age < 120.0 { "running" } else { "NOT RUNNING or stuck (not stopped cleanly)" }, age);
    println!("  up {:.1} h, {} events, {} network namespaces", v["uptime_s"].as_f64().unwrap_or(0.0) / 3600.0, v["events"], v["netns"]);
    println!("  tracking {} processes, {} flows, {} connections, {} DNS domains", e["entities"], e["flows"], e["connections"], e["dns_domains"]);
    println!("  {} (history {} h)", if e["learning"] == true { "still learning baselines" } else { "baselines active" }, e["history_hours"]);
    let (cp, cd) = (v["capture"]["packets"].as_u64().unwrap_or(0), v["capture"]["dropped"].as_u64().unwrap_or(0));
    println!("  capture: {} packets reached userspace, {cd} dropped by the kernel", cp.saturating_sub(cd));
    let al = &v["alerts"];
    let n = |k: &str| al[k].as_u64().unwrap_or(0);
    println!("  alerts since start: {} high, {} medium, {} low", n("high"), n("medium"), n("low"));
    if let Some(l) = v["last_alert"].as_object() {
        println!("  last alert {} {}", crate::safety::safe(l["time"].as_str().unwrap_or("")), crate::safety::safe(l["title"].as_str().unwrap_or("")));
    }
    if v["notify_failures"].as_u64().unwrap_or(0) > 0 {
        println!("  XMPP notify failures: {} (see syslog)", v["notify_failures"]);
    }
    if !(alive && age < 120.0) {
        std::process::exit(1);
    }
}
