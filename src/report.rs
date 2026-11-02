//! Turns features + rule findings + model scores into a per-file verdict.
//!
//! Capability confidence = max(model probability rescaled by its threshold,
//! rule confidence). Risk is a fixed, documented formula over capabilities —
//! it is NOT a trained "malware" score (there is no malware ground truth here):
//! it measures how evasive/hidden a binary is, which commercial DRM and
//! anti-cheat also score high on.

use crate::features::{Analysis, Finding, CAPS};
use crate::indicators::ROLES;
use crate::trust::Origin;
use crate::model::Model;
use crate::Opts;
use std::path::Path;

pub struct Assessment {
    pub caps: Vec<CapScore>,
    pub risk: f64,
    pub verdict: &'static str,
    pub findings: Vec<Finding>,
    pub format: &'static str,
    /// Legitimate roles found (name, evidence) and whether they were applied.
    pub roles: Vec<(&'static str, String)>,
    pub roles_applied: bool,
    pub origin: Option<Origin>,
}

#[derive(serde::Serialize, Clone)]
pub struct CapScore {
    pub cap: &'static str,
    /// Final confidence 0..1 (>= 0.5 means "detected").
    pub conf: f64,
    pub model: Option<f64>,
    pub rules: f64,
    /// Detected by the model with no supporting rule finding.
    pub model_only: bool,
    /// A legitimate role that explains this capability (e.g. "hypervisor" for anti_vm).
    pub excused_by: Option<&'static str>,
    /// Strongest model reasons: "feature (+contribution)".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub why: String,
}

/// Calibrated model confidence needed to report a capability with no rule evidence.
const MODEL_ONLY_MIN: f64 = 0.8;

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

pub fn assess(a: &Analysis, m_: &Model) -> Assessment {
    let preds = m_.predict(&a.feats);
    let mut caps = vec![];
    for (ci, cap) in CAPS.iter().enumerate() {
        let fs: Vec<&Finding> = a.findings.iter().filter(|f| f.cap == *cap).collect();
        let rules = rule_conf(&fs);
        let model = preds[ci].map(|(p, t)| calibrate(p, t));
        // Without any rule evidence for this capability, the model alone only
        // counts when it is very confident: every report should have a "why".
        let m = model.unwrap_or(0.0);
        let m = if fs.is_empty() && m < MODEL_ONLY_MIN { m.min(0.49) } else { m };
        let conf = m.max(rules);
        let why = if model.unwrap_or(0.0) >= 0.5 {
            crate::watch::engine::top_reasons(crate::features::FEATURE_NAMES, &m_.explain(&a.feats, ci), 3)
        } else {
            String::new()
        };
        caps.push(CapScore { cap, conf, model, rules, model_only: fs.is_empty() && conf >= 0.5, excused_by: None, why });
    }
    let raw = |caps: &[CapScore], n: &str| caps.iter().find(|x| x.cap == n).unwrap().conf;
    // Roles excuse capabilities only when the binary doesn't also hide its code:
    // "I'm a hypervisor" from a packed binary is not believable.
    // memfd + fexecve on its own is how runc/crun/podman/firecracker re-exec themselves
    // (CVE-2019-5736 defence), so it doesn't void a role; real code-hiding evidence does.
    let packed_ci = CAPS.iter().position(|c| *c == "packed").unwrap();
    let hiding_fs: Vec<&Finding> = a.findings.iter()
        .filter(|f| f.cap == "packed" && !MEMFD_RULES.contains(&f.rule)).collect();
    let packed_hiding = rule_conf(&hiding_fs).max(caps[packed_ci].model.unwrap_or(0.0).min(
        if hiding_fs.is_empty() && caps[packed_ci].model.unwrap_or(0.0) < MODEL_ONLY_MIN { 0.49 } else { 1.0 }));
    let roles_applied = raw(&caps, "obfuscation").max(packed_hiding) < 0.5;
    if roles_applied {
        for (ri, _) in &a.roles {
            for ex in ROLES[*ri].excuses {
                if let Some(cs) = caps.iter_mut().find(|x| x.cap == *ex) {
                    cs.excused_by.get_or_insert(ROLES[*ri].name);
                }
            }
        }
    }
    // Effective confidence for risk: an excused capability counts a quarter.
    let eff = |cs: &CapScore| if cs.excused_by.is_some() { cs.conf * EXCUSED_FACTOR } else { cs.conf };
    let c = |n: &str| eff(caps.iter().find(|x| x.cap == n).unwrap());
    let mut keep = 1.0;
    for (i, cs) in caps.iter().enumerate() {
        keep *= 1.0 - W[i] * eff(cs);
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
    let verdict = verdict_of(risk);
    let mut findings = a.findings.clone();
    findings.sort_by(|x, y| y.strength.cmp(&x.strength));
    let format = match a.format {
        crate::features::Format::Elf => "elf",
        crate::features::Format::Pe => "pe",
        crate::features::Format::Other => "other",
    };
    let roles = a.roles.iter().map(|(ri, ev)| (ROLES[*ri].name, ev.clone())).collect();
    Assessment { caps, risk, verdict, findings, format, roles, roles_applied, origin: None }
}

const EXCUSED_FACTOR: f64 = 0.25;
const MEMFD_RULES: &[&str] = &["api_memfd", "raw_memfd_syscall"];
/// Highest risk a package-verified file can get: it stays visible as `low`, never alerts.
const PKG_RISK_CAP: f64 = 0.49;

fn verdict_of(risk: f64) -> &'static str {
    match risk {
        r if r < 0.25 => "clean",
        r if r < 0.5 => "low",
        r if r < 0.75 => "suspicious",
        _ => "high",
    }
}

/// Apply provenance: allowlisted files are `allowed`, package-verified files are
/// capped at `low`, and package files modified after installation become `high`.
pub fn apply_origin(r: &mut Assessment, origin: Origin, pkg_trust: bool) {
    match &origin {
        Origin::Allowlisted => r.verdict = "allowed",
        Origin::Package { .. } if pkg_trust => {
            r.risk = r.risk.min(PKG_RISK_CAP);
            r.verdict = verdict_of(r.risk);
        }
        Origin::Modified { pkg } => {
            r.risk = r.risk.max(0.8);
            r.verdict = verdict_of(r.risk);
            r.findings.insert(0, Finding { cap: "integrity", rule: "modified_package_file", strength: 3,
                evidence: format!("content differs from what package {pkg} installed") });
        }
        _ => {}
    }
    r.origin = Some(origin);
}

/// Whether this result should count toward the exit status / alerting.
pub fn alerting_risk(r: &Assessment) -> f64 {
    if r.verdict == "allowed" { 0.0 } else { r.risk }
}

pub fn print(p: &Path, r: &Assessment, o: &Opts) {
    if alerting_risk(r) < o.min_risk || (!o.all && matches!(r.verdict, "clean" | "allowed") && !o.json) {
        return;
    }
    let origin_tag = match &r.origin {
        Some(Origin::Allowlisted) => "allowlisted".to_string(),
        Some(Origin::Package { pkg }) => format!("pkg {pkg}"),
        Some(Origin::Modified { pkg }) => format!("MODIFIED pkg {pkg}"),
        Some(Origin::Unknown) => "unknown origin".to_string(),
        None => String::new(),
    };
    if o.json {
        let caps: serde_json::Map<String, serde_json::Value> = r.caps.iter()
            .map(|c| (c.cap.to_string(), serde_json::json!({"conf": round(c.conf), "model": c.model.map(round), "rules": round(c.rules),
                "model_only": c.model_only, "why": c.why})))
            .collect();
        let line = serde_json::json!({
            "path": p.to_string_lossy(), "format": r.format, "risk": round(r.risk), "verdict": r.verdict,
            "detected": r.caps.iter().filter(|c| c.conf >= 0.5).map(|c| c.cap).collect::<Vec<_>>(),
            "caps": caps, "findings": r.findings,
            "excused": r.caps.iter().filter_map(|c| c.excused_by.map(|e| (c.cap, e))).collect::<std::collections::BTreeMap<_, _>>(),
            "roles": r.roles.iter().map(|(n, e)| serde_json::json!({"role": n, "evidence": e, "applied": r.roles_applied})).collect::<Vec<_>>(),
            "origin": r.origin,
        });
        println!("{line}");
        return;
    }
    let det: Vec<String> = r.caps.iter().filter(|c| c.conf >= 0.5)
        .map(|c| {
            let mut tags = vec![];
            if c.model_only { tags.push("model-only".to_string()); }
            if let Some(e) = c.excused_by { tags.push(format!("excused: {e}")); }
            format!("{}({:.2}{})", c.cap, c.conf, tags.iter().map(|t| format!(", {t}")).collect::<String>())
        }).collect();
    println!("{:<10} {:.2}  {}  [{}]{}", r.verdict.to_uppercase(), r.risk, crate::safety::safe_path(p),
        if det.is_empty() { "-".to_string() } else { det.join(" ") },
        if origin_tag.is_empty() { String::new() } else { format!("  ({origin_tag})") });
    for (n, ev) in &r.roles {
        println!("    {:<12} {:<26} {}{}", "role", n, ev, if r.roles_applied { "" } else { "  [ignored: binary hides its code]" });
    }
    for c in r.caps.iter().filter(|c| c.conf >= 0.5 && !c.why.is_empty() && (o.explain || c.model_only)) {
        println!("    {:<12} {:<26} {}", c.cap, "model", c.why);
    }
    let limit = if o.explain { usize::MAX } else { 4 };
    for f in r.findings.iter().filter(|f| o.explain || f.strength >= 2).take(limit) {
        println!("    {:<12} {:<26} {}", f.cap, f.rule, crate::safety::safe(&f.evidence));
    }
}

fn round(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}
