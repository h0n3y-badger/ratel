//! Turns features + rule findings + model scores into a per-file verdict.
//!
//! Capability confidence = max(model probability rescaled by its threshold,
//! rule confidence). Risk is a fixed, documented formula over capabilities —
//! it is NOT a trained "malware" score (there is no malware ground truth here):
//! it measures how evasive/hidden a binary is, which commercial DRM and
//! anti-cheat also score high on.

use crate::features::{Analysis, Finding, CAPS};
use crate::model::Model;
use crate::Opts;
use std::path::Path;

pub struct Assessment {
    pub caps: Vec<CapScore>,
    pub risk: f64,
    pub verdict: &'static str,
    pub findings: Vec<Finding>,
    pub format: &'static str,
}

#[derive(serde::Serialize, Clone)]
pub struct CapScore {
    pub cap: &'static str,
    /// Final confidence 0..1 (>= 0.5 means "detected").
    pub conf: f64,
    pub model: Option<f64>,
    pub rules: f64,
}

/// Risk weights per capability (index = CAPS order).
const W: [f64; 6] = [0.30, 0.35, 0.25, 0.30, 0.05, 0.10];

fn rule_conf(fs: &[&Finding]) -> f64 {
    let s3 = fs.iter().filter(|f| f.strength >= 3).count();
    let s2 = fs.iter().filter(|f| f.strength == 2).count();
    let s1 = fs.iter().filter(|f| f.strength == 1).count();
    if s3 > 0 {
        0.9
    } else if s2 >= 2 || (s2 == 1 && s1 >= 2) {
        0.75
    } else if s2 == 1 {
        0.55
    } else if s1 >= 3 {
        0.45
    } else if s1 > 0 {
        0.25
    } else {
        0.0
    }
}

/// Map a model probability so its decision threshold lands on 0.5.
fn calibrate(p: f64, thr: f64) -> f64 {
    let thr = thr.clamp(0.01, 0.99);
    if p < thr { 0.5 * p / thr } else { 0.5 + 0.5 * (p - thr) / (1.0 - thr) }
}

pub fn assess(a: &Analysis, m: &Model) -> Assessment {
    let preds = m.predict(&a.feats);
    let mut caps = vec![];
    for (ci, cap) in CAPS.iter().enumerate() {
        let fs: Vec<&Finding> = a.findings.iter().filter(|f| f.cap == *cap).collect();
        let rules = rule_conf(&fs);
        let model = preds[ci].map(|(p, t)| calibrate(p, t));
        let conf = model.unwrap_or(0.0).max(rules);
        caps.push(CapScore { cap, conf, model, rules });
    }
    let c = |n: &str| caps.iter().find(|x| x.cap == n).unwrap().conf;
    let mut keep = 1.0;
    for (i, cs) in caps.iter().enumerate() {
        keep *= 1.0 - W[i] * cs.conf;
    }
    let mut risk = 1.0 - keep;
    let evasive = c("anti_debug").max(c("anti_vm"));
    let hiding = c("obfuscation").max(c("packed"));
    if evasive >= 0.5 && hiding >= 0.5 {
        risk = risk.max(0.7);
        if c("network") >= 0.5 {
            risk = risk.max(0.85);
        }
    }
    let verdict = match risk {
        r if r < 0.25 => "clean",
        r if r < 0.5 => "low",
        r if r < 0.75 => "suspicious",
        _ => "high",
    };
    let mut findings = a.findings.clone();
    findings.sort_by(|x, y| y.strength.cmp(&x.strength));
    let format = match a.format {
        crate::features::Format::Elf => "elf",
        crate::features::Format::Pe => "pe",
        crate::features::Format::Other => "other",
    };
    Assessment { caps, risk, verdict, findings, format }
}

pub fn print(p: &Path, r: &Assessment, o: &Opts) {
    if r.risk < o.min_risk || (!o.all && r.verdict == "clean" && !o.json) {
        return;
    }
    if o.json {
        let caps: serde_json::Map<String, serde_json::Value> = r.caps.iter()
            .map(|c| (c.cap.to_string(), serde_json::json!({"conf": round(c.conf), "model": c.model.map(round), "rules": round(c.rules)})))
            .collect();
        let line = serde_json::json!({
            "path": p.to_string_lossy(), "format": r.format, "risk": round(r.risk), "verdict": r.verdict,
            "detected": r.caps.iter().filter(|c| c.conf >= 0.5).map(|c| c.cap).collect::<Vec<_>>(),
            "caps": caps, "findings": r.findings,
        });
        println!("{line}");
        return;
    }
    let det: Vec<String> = r.caps.iter().filter(|c| c.conf >= 0.5).map(|c| format!("{}({:.2})", c.cap, c.conf)).collect();
    println!("{:<10} {:.2}  {}  [{}]", r.verdict.to_uppercase(), r.risk, p.display(),
        if det.is_empty() { "-".to_string() } else { det.join(" ") });
    let limit = if o.explain { usize::MAX } else { 4 };
    for f in r.findings.iter().filter(|f| o.explain || f.strength >= 2).take(limit) {
        println!("    {:<12} {:<26} {}", f.cap, f.rule, f.evidence);
    }
}

fn round(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}
