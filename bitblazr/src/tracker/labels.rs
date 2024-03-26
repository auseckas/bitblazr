use crate::config::ShieldConfig;
use crate::errors::BSError;
use crate::utils::get_hash;
use crate::PsLabels;
use aho_corasick::AhoCorasick;
use bitblazr_common::utils;
use bitblazr_common::BlazrEvent;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, warn};

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
    labels_rev: HashMap<i64, String>,
}

impl ContextTracker {
    pub fn new(config: &ShieldConfig) -> Result<ContextTracker, anyhow::Error> {
        let mut patterns = HashMap::new();
        let mut labels = HashMap::new();
        let mut labels_rev = HashMap::new();
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
            labels_rev.insert(get_hash(label) as i64, label.to_string());
            patterns.insert(label.to_string(), (ac, entries));
        }
        Ok(ContextTracker {
            patterns,
            labels,
            labels_rev,
        })
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

    pub fn process_event(&self, be: &mut BlazrEvent, snd: mpsc::Sender<PsLabels>) {
        let mut event_ctx = [0i64; 5];
        let mut ctx = self
            .check_process_label(utils::str_from_buf_nul(&be.path).unwrap_or(""))
            .unwrap_or(Vec::new());

        let mut propogate_to_parent = false;
        if ctx.is_empty() {
            ctx = self
                .check_process_label(utils::str_from_buf_nul(&be.p_path).unwrap_or(""))
                .unwrap_or(Vec::new());
            if !ctx.is_empty() {
                propogate_to_parent = true;
            }
        }

        for (i, c) in ctx.into_iter().enumerate() {
            if i >= 5 {
                break;
            }
            event_ctx[i] = c;
        }

        be.labels = event_ctx;
        debug!(
            "Path: {}, PPatth: {}, ppid: {:?}, pid: {}, labels: {:?}",
            utils::str_from_buf_nul(&be.path).unwrap_or(""),
            utils::str_from_buf_nul(&be.p_path).unwrap_or(""),
            be.ppid,
            be.pid,
            be.labels
        );

        let mut parent_labels = None;
        if propogate_to_parent {
            parent_labels = Some(PsLabels {
                ppid: be.ppid.unwrap_or(0),
                pid: be.ppid.unwrap_or(0),
                labels: be.labels,
            });
        }
        let child_labels = PsLabels {
            ppid: be.ppid.unwrap_or(0),
            pid: be.pid,
            labels: be.labels,
        };

        tokio::spawn(async move {
            if let Some(pl) = parent_labels {
                if let Err(e) = snd.send(pl).await {
                    warn!("Could not send Labels. Err: {}", e);
                }
            }

            if let Err(e) = snd.send(child_labels).await {
                warn!("Could not send Labels. Err: {}", e);
            }
        });
    }

    pub fn get_labels(&self) -> &HashMap<String, i64> {
        &self.labels
    }

    pub fn hashes_to_labels(&self, hashes: &[i64]) -> String {
        let mut s = "[".to_string();

        for h in hashes.iter() {
            if let Some(l) = self.labels_rev.get(h) {
                s.push_str(l.as_str());
                s.push_str(",");
            }
        }
        if s.chars().last() == Some(',') {
            s.pop();
        }

        s.push(']');
        s
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
