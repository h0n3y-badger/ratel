//! Gradient-boosted tree inference. The model is plain JSON (trained by
//! train/train.py) and is embedded into the binary at build time. Inference is
//! pure comparisons and additions: same input, same output, every time.

use crate::features::{FEATURE_NAMES, CAPS};
use serde::Deserialize;
use std::collections::HashMap;

pub const EMBEDDED: &str = include_str!("../models/ratel-model.json");
pub const EMBEDDED_NET: &str = include_str!("../models/ratel-net-model.json");

#[derive(Deserialize)]
struct Tree {
    /// Feature index into the model's own feature list, -1 for a leaf.
    f: Vec<i32>,
    t: Vec<f64>,
    l: Vec<u32>,
    r: Vec<u32>,
    /// Leaf values (learning rate already folded in).
    v: Vec<f64>,
}

#[derive(Deserialize)]
struct CapModel {
    base: f64,
    threshold: f64,
    trees: Vec<Tree>,
}

#[derive(Deserialize)]
struct ModelFile {
    version: u32,
    #[serde(default)]
    trained: String,
    features: Vec<String>,
    caps: HashMap<String, CapModel>,
}

pub struct Model {
    pub version: u32,
    pub trained: String,
    /// model feature i -> scanner feature index (None if the scanner lacks it)
    remap: Vec<Option<usize>>,
    caps: Vec<(usize, CapModel)>,
    pub n_trees: usize,
}

impl Model {
    pub fn load(json: &str) -> Result<Model, String> {
        let mf: ModelFile = serde_json::from_str(json).map_err(|e| format!("model parse: {e}"))?;
        let idx = crate::features::feature_index();
        let remap = mf.features.iter().map(|n| idx.get(n.as_str()).copied()).collect::<Vec<_>>();
        let mut caps = vec![];
        let mut n_trees = 0;
        for (name, cm) in mf.caps {
            let ci = CAPS.iter().position(|c| *c == name).ok_or(format!("unknown capability {name}"))?;
            for t in &cm.trees {
                let n = t.f.len();
                if t.t.len() != n || t.l.len() != n || t.r.len() != n || t.v.len() != n {
                    return Err(format!("{name}: ragged tree"));
                }
                for i in 0..n {
                    if t.f[i] >= 0 && ((t.f[i] as usize) >= remap.len() || t.l[i] as usize >= n || t.r[i] as usize >= n) {
                        return Err(format!("{name}: bad node {i}"));
                    }
                }
            }
            n_trees += cm.trees.len();
            caps.push((ci, cm));
        }
        caps.sort_by_key(|c| c.0);
        Ok(Model { version: mf.version, trained: mf.trained, remap, caps, n_trees })
    }

    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }

    /// Returns per-capability (probability, threshold), indexed like CAPS.
    pub fn predict(&self, feats: &[f32]) -> Vec<Option<(f64, f64)>> {
        debug_assert_eq!(feats.len(), FEATURE_NAMES.len());
        let x: Vec<f32> = self.remap.iter().map(|m| m.map_or(0.0, |i| feats[i])).collect();
        let mut out = vec![None; CAPS.len()];
        for (ci, cm) in &self.caps {
            let mut raw = cm.base;
            for t in &cm.trees {
                let mut n = 0usize;
                while t.f[n] >= 0 {
                    // sklearn semantics: x <= threshold goes left (x as float32).
                    n = if (x[t.f[n] as usize] as f64) <= t.t[n] { t.l[n] } else { t.r[n] } as usize;
                }
                raw += t.v[n];
            }
            out[*ci] = Some((1.0 / (1.0 + (-raw).exp()), cm.threshold));
        }
        out
    }
}

impl Tree {
    fn eval(&self, x: &[f32]) -> f64 {
        let mut n = 0usize;
        while self.f[n] >= 0 {
            n = if (x[self.f[n] as usize] as f64) <= self.t[n] { self.l[n] } else { self.r[n] } as usize;
        }
        self.v[n]
    }
    fn valid(&self, nfeat: usize) -> bool {
        let n = self.f.len();
        n > 0 && [self.t.len(), self.l.len(), self.r.len(), self.v.len()].iter().all(|&m| m == n)
            && (0..n).all(|i| self.f[i] < 0 || ((self.f[i] as usize) < nfeat && (self.l[i] as usize) < n && (self.r[i] as usize) < n))
    }
}

/// One gradient-boosted ensemble with its own named feature list (network models).
#[derive(Deserialize)]
pub struct Unit {
    features: Vec<String>,
    base: f64,
    pub threshold: f64,
    trees: Vec<Tree>,
    #[serde(skip)]
    remap: Vec<Option<usize>>,
}

impl Unit {
    /// Probability for a feature vector laid out like `names` (the scanner's order).
    pub fn predict(&self, x: &[f32]) -> f64 {
        let v: Vec<f32> = self.remap.iter().map(|m| m.map_or(0.0, |i| x[i])).collect();
        let raw = self.base + self.trees.iter().map(|t| t.eval(&v)).sum::<f64>();
        1.0 / (1.0 + (-raw).exp())
    }
}

#[derive(Deserialize)]
pub struct NetModel {
    pub version: u32,
    #[serde(default)]
    pub trained: String,
    #[serde(default)]
    pub units: HashMap<String, Unit>,
}

impl NetModel {
    /// `layouts`: unit name -> the engine's feature names for that unit.
    pub fn load(json: &str, layouts: &[(&str, &[&str])]) -> Result<NetModel, String> {
        let mut m: NetModel = serde_json::from_str(json).map_err(|e| format!("net model parse: {e}"))?;
        for (name, u) in m.units.iter_mut() {
            let Some((_, names)) = layouts.iter().find(|(n, _)| n == name) else {
                return Err(format!("net model: unknown unit {name}"));
            };
            u.remap = u.features.iter().map(|f| names.iter().position(|n| n == f)).collect();
            if u.remap.iter().any(|r| r.is_none()) {
                return Err(format!("net model {name}: feature the engine doesn't produce"));
            }
            if !u.trees.iter().all(|t| t.valid(u.features.len())) {
                return Err(format!("net model {name}: malformed tree"));
            }
        }
        Ok(m)
    }
    pub fn unit(&self, name: &str) -> Option<&Unit> {
        self.units.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_model_loads_and_matches_scanner_features() {
        let m = Model::load(EMBEDDED).expect("embedded model parses");
        assert!(!m.is_empty(), "no model embedded");
        // Every model feature must exist in the scanner, or it would silently read 0.
        assert!(m.remap.iter().all(|r| r.is_some()), "model uses a feature the scanner doesn't produce");
        let p = m.predict(&vec![0.0; FEATURE_NAMES.len()]);
        assert!(p.iter().all(|x| x.map_or(true, |(v, t)| (0.0..=1.0).contains(&v) && (0.0..1.0).contains(&t))));
    }

    #[test]
    fn deterministic() {
        let m = Model::load(EMBEDDED).unwrap();
        let x: Vec<f32> = (0..FEATURE_NAMES.len()).map(|i| (i % 7) as f32 * 0.5).collect();
        assert_eq!(format!("{:?}", m.predict(&x)), format!("{:?}", m.predict(&x)));
    }
}
