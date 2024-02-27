use crate::config::ShieldConfig;
use crate::errors::BSError;
use crate::utils::get_hash;
use aho_corasick::AhoCorasick;
use moka::future::Cache;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
enum ContextOp {
    Eq,
    StartsWith,
    EndsWith,
    Contains,
}

impl ContextOp {
    fn from_str(s: &str) -> Result<ContextOp, anyhow::Error> {
        let op = match s.trim().to_lowercase().as_str() {
            "eq" => ContextOp::Eq,
            "starts_with" => ContextOp::StartsWith,
            "ends_with" => ContextOp::EndsWith,
            "contains" => ContextOp::Contains,
            _ => {
                return Err(BSError::InvalidAttributeType {
                    attribute: "Invalid process_label",
                    value: s.to_string(),
                }
                .into());
            }
        };
        Ok(op)
    }
}

#[derive(Debug)]
struct ContextEntry {
    pub op: ContextOp,
    pub needle: String,
}

pub struct ContextTracker {
    patterns: HashMap<String, (AhoCorasick, Vec<ContextEntry>)>,
    labels: HashMap<String, i64>,
}

impl ContextTracker {
    pub fn new(config: &ShieldConfig) -> Result<ContextTracker, anyhow::Error> {
        let mut patterns = HashMap::new();
        let mut labels = HashMap::new();
        for (label, pats) in config.process_labels.iter() {
            let mut entries = Vec::new();
            for pat in pats.iter() {
                for (s_op, needle) in pat.iter() {
                    let entry = ContextEntry {
                        op: ContextOp::from_str(s_op.as_str())?,
                        needle: needle.trim().to_ascii_lowercase(),
                    };
                    entries.push(entry);
                }
            }

            let match_strs: Vec<&str> = entries.iter().map(|e| e.needle.as_str()).collect();
            let ac = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(match_strs)?;

            labels.insert(label.to_string(), get_hash(label) as i64);
            patterns.insert(label.to_string(), (ac, entries));
        }
        Ok(ContextTracker { patterns, labels })
    }

    pub fn check_process_label(&self, p_name: &str) -> Option<Vec<i64>> {
        let mut labels = Vec::new();
        let hay_end = p_name.len();
        for (label, (ac, entries)) in self.patterns.iter() {
            for m in ac.find_iter(p_name) {
                if let Some(mat) = entries.get(m.pattern().as_usize()) {
                    let mat_start = m.start();
                    let mat_end = m.end();

                    let matched = match mat.op {
                        ContextOp::Eq => mat_start == 0 && hay_end == mat_end,
                        ContextOp::StartsWith => mat_start == 0,
                        ContextOp::EndsWith => hay_end == mat_end,
                        ContextOp::Contains => true,
                    };
                    if matched {
                        if let Some(h) = self.labels.get(label) {
                            labels.push(*h);
                        }
                    }
                }
            }
        }
        if labels.is_empty() {
            None
        } else {
            Some(labels)
        }
    }

    pub fn get_labels(&self) -> &HashMap<String, i64> {
        &self.labels
    }
}

#[cfg(test)]
mod tests {
    use super::ContextTracker;
    use crate::config;

    #[test]
    fn check_container_label() {
        let config = config::load_config().unwrap();
        let ct = ContextTracker::new(&config).unwrap();
        let labels = ct.check_process_label("/usr/bin/containerd-shim-runc-v2");
        assert_eq!(labels, Some(vec![6027998744940314019]));
    }
}
