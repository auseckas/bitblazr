use super::get_field;
use crate::BSError;
use bitblazr_common::{rules::*, BlazrAction, BlazrEventType, OPS_PER_RULE};
use config::{Config, File, FileFormat};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::env;

fn value_to_var(
    comm: &BlazrRuleCommand,
    target: &BlazrRuleTarget,
    src: &mut Value,
) -> Result<BlazrVar, anyhow::Error> {
    let var = match *target {
        BlazrRuleTarget::Port => {
            let port = match src.as_u64() {
                Some(p) => p as i64,
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "port",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };

            BlazrVar {
                var_type: BlazrVarType::Int,
                int: port,
                sbuf: [0; 25],
                sbuf_len: 0,
            }
        }
        BlazrRuleTarget::Path => {
            let path = match src.as_str() {
                Some(s) => s,
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "path",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };
            if path.len() > 25 {
                return Err(BSError::InvalidAttribute {
                    attribute: "path",
                    value: format!(
                        "Path string used in rules should not exceed 25 chars. Path: {:?}",
                        path
                    ),
                }
                .into());
            }

            let mut sbuf = [0; 25];
            let sbuf_len = path.len() as u16;

            // Reverse buffer for EndsWith, to make verifier on the other side happy
            if matches!(comm, BlazrRuleCommand::EndsWith) {
                for (i, ch) in path.as_bytes().iter().rev().enumerate() {
                    sbuf[i] = *ch;
                }
            } else {
                for (i, ch) in path.as_bytes().iter().enumerate() {
                    sbuf[i] = *ch;
                }
            }

            BlazrVar {
                var_type: BlazrVarType::String,
                int: 0,
                sbuf: sbuf,
                sbuf_len: sbuf_len,
            }
        }
        BlazrRuleTarget::IpVersion => {
            let ip_version = match src.as_u64() {
                Some(p) => p as i64,
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "ip_version",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };

            match ip_version {
                4 | 6 => (),
                _ => {
                    return Err(BSError::InvalidAttribute {
                        attribute: "ip_version",
                        value: format!("{}", ip_version),
                    }
                    .into());
                }
            };

            BlazrVar {
                var_type: BlazrVarType::Int,
                int: ip_version,
                sbuf: [0; 25],
                sbuf_len: 0,
            }
        }
        BlazrRuleTarget::IpType => {
            let ip_type = match src.as_str() {
                Some(s) => BlazrIpType::from_str(s.to_string().as_mut_str()),
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "ip_type",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };

            if ip_type.is_undefined() {
                return Err(BSError::InvalidAttribute {
                    attribute: "ip_type",
                    value: format!("{:?}", src),
                }
                .into());
            }

            BlazrVar {
                var_type: BlazrVarType::Int,
                int: ip_type as i64,
                sbuf: [0; 25],
                sbuf_len: 0,
            }
        }
        BlazrRuleTarget::IpProto => {
            let ip_proto = match src.as_str() {
                Some(s) => BlazrIpProto::from_str(s.to_string().as_mut_str()),
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "ip_proto",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };

            if ip_proto.is_undefined() {
                return Err(BSError::InvalidAttribute {
                    attribute: "ip_proto",
                    value: format!("{:?}", src),
                }
                .into());
            }

            BlazrVar {
                var_type: BlazrVarType::Int,
                int: ip_proto as i64,
                sbuf: [0; 25],
                sbuf_len: 0,
            }
        }
        _ => {
            return Err(BSError::InvalidAttribute {
                attribute: "target",
                value: format!("{:?}", target),
            }
            .into());
        }
    };

    Ok(var)
}

fn parse_ops(
    shield_ops: &mut Vec<BlazrOp>,
    target: &BlazrRuleTarget,
    labels: &HashMap<String, i64>,
    cs: &mut Value,
) -> Result<Vec<i32>, anyhow::Error> {
    let mut ops_idx: Vec<i32> = Vec::new();

    match cs {
        Value::Array(a) => {
            for obj in a {
                if !obj.is_object() {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "rule_op_value",
                        value: obj.to_string(),
                    }
                    .into());
                }
                for (c, v) in obj.as_object_mut().unwrap_or(&mut Map::new()) {
                    let comm = BlazrRuleCommand::from_str(c.trim().to_string().as_mut_str());
                    if comm.is_undefined() {
                        return Err(BSError::InvalidAttribute {
                            attribute: "command",
                            value: cs.to_string(),
                        }
                        .into());
                    }
                    if matches!(comm, BlazrRuleCommand::Not) {
                        let ids = parse_ops(
                            shield_ops,
                            target,
                            labels,
                            &mut Value::from(vec![v.clone()]),
                        )?;
                        for id in ids {
                            shield_ops.get_mut(id as usize).map(|op| op.negate = true);
                            ops_idx.push(id);
                        }
                        continue;
                    }

                    let var = value_to_var(&comm, target, v)?;

                    let op = BlazrOp {
                        target: *target,
                        negate: false,
                        command: comm,
                        var: var,
                    };
                    shield_ops.push(op);
                    let idx = shield_ops.len() - 1;
                    ops_idx.push(idx as i32);
                }
            }
        }
        _ => {
            return Err(BSError::InvalidAttributeType {
                attribute: "rule_ops",
                value: cs.to_string(),
            }
            .into());
        }
    }

    Ok(ops_idx)
}

pub(crate) fn load_rules_from_config(
    rules_section: &str,
    labels: &HashMap<String, i64>,
) -> Result<(HashMap<BlazrRulesKey, Vec<BlazrRule>>, Vec<BlazrOp>), anyhow::Error> {
    let mut config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config/".into());
    if !config_dir.ends_with('/') {
        config_dir.push('/');
    }

    let rule_config = Config::builder()
        .add_source(File::new(
            &format!("{}rules.json5", config_dir),
            FileFormat::Json5,
        ))
        .build()?;

    let rules: HashMap<String, Value> = rule_config
        .try_deserialize()
        .map_err(|e| BSError::Deserialize(e.to_string()))?;

    load_rules(rules_section, labels, rules)
}

pub(crate) fn load_rules(
    rules_section: &str,
    labels: &HashMap<String, i64>,
    mut rules: HashMap<String, Value>,
) -> Result<(HashMap<BlazrRulesKey, Vec<BlazrRule>>, Vec<BlazrOp>), anyhow::Error> {
    let mut shield_rules: HashMap<BlazrRulesKey, Vec<BlazrRule>> = HashMap::new();
    let mut shield_ops: Vec<BlazrOp> = Vec::new();

    if let Some(defs) = rules.get_mut(rules_section) {
        for (rule_id, mut rule) in defs
            .as_array_mut()
            .unwrap_or(&mut Vec::new())
            .into_iter()
            .enumerate()
        {
            let mut shield_ops_idx: Vec<i32> = Vec::new();

            let class: BlazrRuleClass = get_field(&mut rule, "class")?;
            let event: BlazrEventType = get_field(&mut rule, "event")?;
            let action: BlazrAction = get_field(&mut rule, "action")?;
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

            let mut context = [0; 5];
            for (i, l) in ctx.into_iter().enumerate() {
                if i >= 5 {
                    break;
                }
                context[i] = l;
            }

            let key = BlazrRulesKey {
                class: class as i32,
                event_type: event as i32,
            };

            for (t, rs) in rule
                .get_mut("rules")
                .and_then(|tg| tg.as_object_mut())
                .unwrap_or(&mut Map::new())
            {
                let target: BlazrRuleTarget = BlazrRuleTarget::from_str(t.to_string().as_mut_str());
                if !class.is_supported_target(&target) {
                    return Err(BSError::InvalidAttribute {
                        attribute: "target",
                        value: t.to_string(),
                    }
                    .into());
                }
                shield_ops_idx.append(&mut parse_ops(&mut shield_ops, &target, labels, rs)?);
            }

            let mut rule_ops_idx = [-1i32; OPS_PER_RULE];
            let rule_ops_len = shield_ops_idx.len();
            for (i, idx) in shield_ops_idx.into_iter().enumerate() {
                if i >= OPS_PER_RULE {
                    return Err(BSError::ArrayLimitReached {
                        attribute: "ops per rule",
                        limit: OPS_PER_RULE,
                    }
                    .into());
                }
                rule_ops_idx[i] = idx;
            }

            let shield_rule = BlazrRule {
                id: (rule_id as u16) + 1,
                class: class,
                event: event,
                context: context,
                ops: rule_ops_idx,
                ops_len: rule_ops_len as u16,
                action: action,
            };

            let entry = shield_rules.entry(key).or_insert(Vec::new());
            entry.push(shield_rule);
        }
    }

    Ok((shield_rules, shield_ops))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::HashMap;

    use super::load_rules;
    use crate::utils::get_hash;
    use bitblazr_common::rules::BlazrRuleTarget;
    use serde_json::Value;

    #[test]
    fn check_rules_basic() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
            "kernel": [
                {
                    "action": "block",
                    "class": "socket",
                    "event": "listen",
                    "rules": {
                        "port": [
                            {
                                "neq": 80,
                            },
                            {
                                "neq": 443,
                            }
                        ]
                    }
                }

            ]
        });
        // let rules = HashMap::new();
        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };
        let (shield_rules, _shield_ops) = load_rules("kernel", &labels, rules_obj).unwrap();
        assert_eq!(shield_rules.iter().next().unwrap().1[0].ops[0], 0);
        assert_eq!(shield_rules.iter().next().unwrap().1[0].ops[1], 1);
    }

    #[test]
    fn check_rules_bad_op() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
            "kernel": [
                {
                    "action": "block",
                    "class": "socket",
                    "event": "listen",
                    "rules": {
                        "bad_target": "Bah",
                        "port": [
                            {
                                "neq": 80,
                            },
                            {
                                "neq": 443,
                            }
                        ]
                    }
                }

            ]
        });
        // let rules = HashMap::new();
        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };
        let result = load_rules("kernel", &labels, rules_obj);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                "Invalid attribute: \"target\", value: \"bad_target\""
            );
        }
    }

    #[test]
    fn check_rules_context() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
            "kernel": [
                {
                    "action": "block",
                    "class": "socket",
                    "event": "listen",
                    "context": ["container"],
                    "rules": {
                        "port": [
                            {
                                "neq": 80,
                            },
                            {
                                "neq": 443,
                            }
                        ]
                    }
                }

            ]
        });
        // let rules = HashMap::new();
        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };
        let (shield_rules, _shield_ops) = load_rules("kernel", &labels, rules_obj).unwrap();

        assert!(shield_rules
            .values()
            .next()
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .context
            .contains(&(get_hash("container") as i64)));
    }

    #[test]
    fn check_invalid_op() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
            "kernel": [
                {
                    "action": "block",
                    "class": "socket",
                    "event": "listen",
                    "rules": {
                        "context": ["container"],
                        "port": [
                            {
                                "neq": 80,
                            },
                            {
                                "neq": 443,
                            }
                        ]
                    }
                }

            ]
        });
        // let rules = HashMap::new();
        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };
        let result = load_rules("kernel", &labels, rules_obj);

        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid attribute"));
        } else {
            panic!("Expected an error");
        }
    }

    #[test]
    fn check_bad_rules_context() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
            "kernel": [
                {
                    "action": "block",
                    "class": "socket",
                    "event": "listen",
                    "context": ["bad_context"],
                    "rules": {
                        "port": [
                            {
                                "neq": 80,
                            },
                            {
                                "neq": 443,
                            }
                        ]
                    }
                }

            ]
        });
        // let rules = HashMap::new();
        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };
        let result = load_rules("kernel", &labels, rules_obj);

        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid attribute"));
        } else {
            panic!("Expected an error");
        }
    }
}
