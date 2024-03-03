use super::get_field;
use crate::BSError;
use aho_corasick::{AhoCorasick, PatternID};
use bpfshield_common::{rules::*, BShieldAction, BShieldEventType};
use config::{Config, File, FileFormat};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::env;

#[derive(Debug)]
enum UserspaceVar {
    Number(i64),
    String(String),
    MultiString(AhoCorasick),
}

#[derive(Debug)]
struct UserspaceOp {
    pub target: BShieldRuleTarget,
    pub negate: bool,
    pub command: BShieldRuleCommand,
    pub var: UserspaceVar,
}

#[derive(Debug)]
struct UserspaceRule {
    pub id: u16,
    pub class: BShieldRuleClass,
    pub event: BShieldEventType,
    pub context: Vec<i64>,
    pub ops: Vec<UserspaceOp>,
    pub action: BShieldAction,
}

pub(crate) struct BShieldRuleEngine {
    rules: Vec<UserspaceRule>,
}

impl BShieldRuleEngine {
    fn parse_rule(target: &BShieldRuleTarget, rs: &mut Value) -> Result<(), anyhow::Error> {
        match rs {
            Value::Array(a) => {
                for obj in a {
                    if !obj.is_object() {
                        return Err(BSError::InvalidAttributeType {
                            attribute: "rule_op_value",
                            value: obj.to_string(),
                        }
                        .into());
                    }

                    let mut ops = Vec::new();
                    for (c, v) in obj.as_object_mut().unwrap_or(&mut Map::new()) {
                        let comm = BShieldRuleCommand::from_str(c.trim().to_string().as_mut_str());
                        if comm.is_undefined() {
                            return Err(BSError::InvalidAttribute {
                                attribute: "command",
                                value: c.to_string(),
                            }
                            .into());
                        }

                        // if matches!(comm, BShieldRuleCommand::Not) {
                        //     let ids = parse_ops(
                        //         shield_ops,
                        //         target,
                        //         labels,
                        //         &mut Value::from(vec![v.clone()]),
                        //     )?;
                        //     for id in ids {
                        //         shield_ops.get_mut(id as usize).map(|op| op.negate = true);
                        //         ops_idx.push(id);
                        //     }
                        //     continue;
                        // }

                        println!("Command: {:?}, value: {:?}", comm, v);

                        let var = match v {
                            Value::Number(n) => UserspaceVar::Number(match n.as_i64() {
                                Some(n) => n,
                                None => {
                                    return Err(BSError::InvalidAttribute {
                                        attribute: "var not compatible with i64",
                                        value: v.to_string(),
                                    }
                                    .into());
                                }
                            }),
                            Value::String(s) => UserspaceVar::String(s.to_string()),
                            Value::Array(a) => {
                                let mut vars = Vec::new();
                                for vs in a {
                                    if let Some(s) = vs.as_str() {
                                        vars.push(s.to_string());
                                    } else {
                                        return Err(BSError::InvalidAttribute {
                                            attribute: "var not a string",
                                            value: v.to_string(),
                                        }
                                        .into());
                                    }
                                }

                                let ac = AhoCorasick::new(vars)?;
                                UserspaceVar::MultiString(ac)
                            }
                            _ => {
                                return Err(BSError::InvalidAttribute {
                                    attribute: "var",
                                    value: v.to_string(),
                                }
                                .into());
                            }
                        };

                        ops.push(UserspaceOp {
                            target: target.clone(),
                            negate: false,
                            command: comm,
                            var: var,
                        });
                    }
                    println!("Ops: {:?}", ops);
                }
            }
            _ => {
                return Err(BSError::InvalidAttributeType {
                    attribute: "rule_ops",
                    value: rs.to_string(),
                }
                .into());
            }
        }
        Ok(())
    }

    pub(crate) fn load_rules(
        rules_section: &str,
        labels: &HashMap<String, i64>,
        mut rules: HashMap<String, Value>,
    ) -> Result<(), anyhow::Error> {
        if let Some(defs) = rules.get_mut(rules_section) {
            for (rule_id, mut rule) in defs
                .as_array_mut()
                .unwrap_or(&mut Vec::new())
                .into_iter()
                .enumerate()
            {
                let class: BShieldRuleClass = get_field(&mut rule, "class")?;
                let event: BShieldEventType = get_field(&mut rule, "event")?;
                let action: BShieldAction = get_field(&mut rule, "action")?;

                let mut ctx = Vec::new();
                if let Some(values) = rule.get("context").and_then(|ctx| ctx.as_array()) {
                    for v in values.iter() {
                        let i_label = match labels.get(v.as_str().unwrap_or("")) {
                            Some(l) => l,
                            None => {
                                return Err(BSError::InvalidAttribute {
                                    attribute: "context",
                                    value: v.as_str().unwrap_or("").to_string(),
                                }
                                .into());
                            }
                        };
                        ctx.push(*i_label);
                    }
                }

                println!("Rule id: {}, action: {:?}", rule_id, action);

                for (t, rs) in rule
                    .get_mut("rules")
                    .and_then(|tg| tg.as_object_mut())
                    .unwrap_or(&mut Map::new())
                {
                    let target: BShieldRuleTarget =
                        BShieldRuleTarget::from_str(t.to_string().as_mut_str());

                    if target.is_undefined() {
                        return Err(BSError::InvalidAttribute {
                            attribute: "target",
                            value: t.to_string(),
                        }
                        .into());
                    }
                    BShieldRuleEngine::parse_rule(&target, rs);
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn load_rules_from_config(
    rules_section: &str,
    labels: &HashMap<String, i64>,
) -> Result<(), anyhow::Error> {
    let mut config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config/".into());
    if !config_dir.ends_with('/') {
        config_dir.push('/');
    }

    let rule_config = Config::builder()
        .add_source(File::new(
            &format!("{}{}_rules.json5", config_dir, rules_section),
            FileFormat::Json5,
        ))
        .build()?;

    let rules: HashMap<String, Value> = rule_config
        .try_deserialize()
        .map_err(|e| BSError::Deserialize(e.to_string()))?;

    BShieldRuleEngine::load_rules(rules_section, labels, rules)
}
