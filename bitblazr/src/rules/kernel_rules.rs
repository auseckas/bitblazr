use super::get_field;
use crate::BSError;
use aya::maps::lpm_trie::Key;
use bitblazr_common::{rules::*, BlazrAction, BlazrEventType, OPS_PER_RULE};
use config::{Config, File, FileFormat};
use no_std_net::Ipv4Addr;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::env;
use std::mem::size_of;
use std::str::FromStr;
use tracing::debug;

fn get_trie_key(
    rule_id: u32,
    op_id: i32,
    buf: &[u8],
    buf_len: usize,
) -> Result<Key<SearchKey>, anyhow::Error> {
    let mut search_buf = [0; 52];

    for (i, ch) in buf.iter().enumerate() {
        search_buf[i] = *ch;
    }

    Ok(Key::new(
        64 + (buf_len as u32 * 8),
        SearchKey {
            rule_id: (rule_id + 1).to_be(),
            op_id: op_id.to_be(),
            buf: search_buf,
        },
    ))
}

struct BlazrVar {
    pub var_type: BlazrVarType,
    pub var_len: u16,
}

fn value_to_var(
    rule_id: usize,
    target: &BlazrRuleTarget,
    ip_ranges: &mut Vec<Key<TrieKey>>,
    search_keys: &mut Vec<Key<SearchKey>>,
    op_id: usize,
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
            search_keys.push(get_trie_key(
                rule_id as u32,
                op_id as i32,
                &port.to_be_bytes(),
                size_of::<i64>(),
            )?);

            BlazrVar {
                var_type: BlazrVarType::Int,
                var_len: size_of::<i64>() as u16,
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
            if path.len() > 50 {
                return Err(BSError::InvalidAttribute {
                    attribute: "path",
                    value: format!(
                        "Path string used in rules should not exceed 50 chars. Path: {:?}",
                        path
                    ),
                }
                .into());
            }

            search_keys.push(get_trie_key(
                rule_id as u32,
                op_id as i32,
                path.as_bytes(),
                path.len(),
            )?);

            BlazrVar {
                var_type: BlazrVarType::String,
                var_len: path.len() as u16,
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
            search_keys.push(get_trie_key(
                rule_id as u32,
                op_id as i32,
                &ip_version.to_be_bytes(),
                size_of::<i64>(),
            )?);

            BlazrVar {
                var_type: BlazrVarType::Int,
                var_len: size_of::<i64>() as u16,
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

            search_keys.push(get_trie_key(
                rule_id as u32,
                op_id as i32,
                &(ip_type as i64).to_be_bytes(),
                size_of::<i64>(),
            )?);

            BlazrVar {
                var_type: BlazrVarType::Int,
                var_len: size_of::<i64>() as u16,
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

            search_keys.push(get_trie_key(
                rule_id as u32,
                op_id as i32,
                &(ip_proto as i64).to_be_bytes(),
                size_of::<i64>(),
            )?);

            BlazrVar {
                var_type: BlazrVarType::Int,
                var_len: size_of::<i64>() as u16,
            }
        }
        BlazrRuleTarget::IpAddr => {
            let mut s = match src.as_str() {
                Some(s) => s.trim(),
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "ip_addr",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };

            let mut prefix = 32;
            if s.contains("/") {
                let ip_mask: Vec<&str> = s.splitn(2, '/').collect();
                if ip_mask.len() == 2 {
                    s = ip_mask[0];
                    let p = ip_mask[1];
                    prefix = match p.parse::<u32>() {
                        Ok(n) => n,
                        Err(_) => {
                            return Err(BSError::InvalidAttributeType {
                                attribute: "ip_addr_prefix",
                                value: format!("{:?}", p),
                            }
                            .into());
                        }
                    }
                };
            }
            let ip_addr = match Ipv4Addr::from_str(s) {
                Ok(ip) => u32::from(ip).to_be(),
                Err(_) => {
                    return Err(BSError::InvalidAttribute {
                        attribute: "ip_addr",
                        value: format!("{:?}", s),
                    }
                    .into());
                }
            };

            debug!(
                "Adding key, prefix: {}, op_id: {}, ip: {}",
                prefix, op_id, ip_addr
            );
            let key = Key::new(
                prefix + 32,
                TrieKey {
                    op_id: op_id as u32,
                    ip: ip_addr,
                },
            );

            debug!("Key: {:?}", unsafe {
                ::core::slice::from_raw_parts(
                    (&key as *const Key<TrieKey>) as *const u8,
                    ::core::mem::size_of::<Key<TrieKey>>(),
                )
            });
            ip_ranges.push(key);

            BlazrVar {
                var_type: BlazrVarType::IpAddr,
                var_len: 0,
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
    rule_id: usize,
    shield_ops: &mut Vec<BlazrOp>,
    ip_ranges: &mut Vec<Key<TrieKey>>,
    search_keys: &mut Vec<Key<SearchKey>>,
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
                            rule_id,
                            shield_ops,
                            ip_ranges,
                            search_keys,
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

                    let idx = shield_ops.len();
                    let var = value_to_var(rule_id, target, ip_ranges, search_keys, idx, v)?;

                    let op = BlazrOp {
                        target: *target,
                        negate: false,
                        command: comm,
                        var_type: var.var_type,
                        var_len: var.var_len,
                    };
                    shield_ops.push(op);
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
) -> Result<
    (
        HashMap<BlazrRulesKey, Vec<BlazrRule>>,
        Vec<BlazrOp>,
        Vec<Key<SearchKey>>,
        Vec<Key<TrieKey>>,
    ),
    anyhow::Error,
> {
    let mut config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config/".into());
    if !config_dir.ends_with('/') {
        config_dir.push('/');
    }

    let rule_config = Config::builder()
        .add_source(File::new(
            &format!("{}blocking_rules.yaml", config_dir),
            FileFormat::Yaml,
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
) -> Result<
    (
        HashMap<BlazrRulesKey, Vec<BlazrRule>>,
        Vec<BlazrOp>,
        Vec<Key<SearchKey>>,
        Vec<Key<TrieKey>>,
    ),
    anyhow::Error,
> {
    let mut shield_rules: HashMap<BlazrRulesKey, Vec<BlazrRule>> = HashMap::new();
    let mut shield_ops: Vec<BlazrOp> = Vec::new();
    let mut ip_ranges: Vec<Key<TrieKey>> = Vec::new();
    let mut search_keys: Vec<Key<SearchKey>> = Vec::new();

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
                shield_ops_idx.append(&mut parse_ops(
                    rule_id,
                    &mut shield_ops,
                    &mut ip_ranges,
                    &mut search_keys,
                    &target,
                    labels,
                    rs,
                )?);
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

    Ok((shield_rules, shield_ops, search_keys, ip_ranges))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::HashMap;

    use super::load_rules;
    use crate::utils::get_hash;
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
        let (shield_rules, _shield_ops, _, _) = load_rules("kernel", &labels, rules_obj).unwrap();
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
        let (shield_rules, _shield_ops, _, _) = load_rules("kernel", &labels, rules_obj).unwrap();

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
