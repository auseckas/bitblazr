use crate::BSError;
use bpfshield_common::{rules::*, BShieldAction, BShieldEventClass, BShieldEventType};
use config::{Config, File, FileFormat};
use log::warn;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::env;
use std::hash::Hash;

fn get_field<T: BSRuleVar>(src: &mut Value, f: &str) -> Result<T, anyhow::Error> {
    let mut class_str = src
        .get_mut(f)
        .and_then(|c| c.as_str())
        .ok_or(BSError::MissingAttribute(format!(
            "Rule definition has no field \"{}\"",
            f
        )))?
        .to_string();

    let var = T::from_str(class_str.as_mut_str());
    if var.is_undefined() {
        return Err(BSError::InvalidAttribute {
            attribute: "class",
            value: class_str,
        }
        .into());
    }

    Ok(var)
}

fn value_to_buf(target: &BSRuleTarget, src: &mut Value) -> Result<[u8; 25], anyhow::Error> {
    let mut buf: [u8; 25] = [0; 25];
    match *target {
        BSRuleTarget::Port => {
            let port = match src.as_u64() {
                Some(p) => p as u16,
                None => {
                    return Err(BSError::InvalidAttributeType {
                        attribute: "port",
                        value: format!("{:?}", src),
                    }
                    .into());
                }
            };
            buf[0..2].clone_from_slice(&port.to_be_bytes());
        }
        _ => {
            return Err(BSError::InvalidAttribute {
                attribute: "target",
                value: format!("{:?}", target),
            }
            .into());
        }
    }

    Ok(buf)
}

// fn parse_cond_array(
//     target: &BSRuleTarget,
//     cs: &mut Value,
// ) -> Result<Vec<BShieldOp>, anyhow::Error> {
//     let mut ops = Vec::new();
//     for obj in cs.as_array_mut().unwrap_or(&mut Vec::new()) {
//         for (c, v) in obj.as_object_mut().unwrap_or(&mut Map::new()) {
//             let comm = BSRuleCommand::from_str(c.to_string().as_mut_str());
//             if comm.is_undefined() {
//                 return Err(BSError::InvalidAttribute {
//                     attribute: "command",
//                     value: c.to_string(),
//                 }
//                 .into());
//             }
//             let val = value_to_buf(target, v)?;
//             let op = BShieldOp {
//                 command: comm,
//                 buf: val,
//             };
//             ops.push(op);
//         }
//     }

//     Ok(ops)
// }

fn parse_ops(
    shield_ops: &mut Vec<BShieldOp>,
    target: &BSRuleTarget,
    cs: &mut Value,
) -> Result<Vec<i32>, anyhow::Error> {
    let mut ops_idx: Vec<i32> = Vec::new();

    for obj in cs.as_array_mut().unwrap_or(&mut Vec::new()) {
        for (c, v) in obj.as_object_mut().unwrap_or(&mut Map::new()) {
            let comm = BSRuleCommand::from_str(c.to_string().as_mut_str());
            if comm.is_undefined() {
                return Err(BSError::InvalidAttribute {
                    attribute: "command",
                    value: c.to_string(),
                }
                .into());
            }
            let op = BShieldOp {
                target: *target,
                command: comm,
                offset: 0,
                len: 0,
                var_type: BShieldVarType::Undefined,
            };
            shield_ops.push(op);
            let idx = shield_ops.len() - 1;
            ops_idx.push(idx as i32);
        }
    }

    Ok(ops_idx)
}

pub(crate) fn load_rules(
) -> Result<(HashMap<BShieldRulesKey, Vec<BShieldRule>>, Vec<BShieldOp>), anyhow::Error> {
    let mut shield_rules: HashMap<BShieldRulesKey, Vec<BShieldRule>> = HashMap::new();
    let mut shield_ops: Vec<BShieldOp> = Vec::new();

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

    let mut rules: HashMap<String, Value> = rule_config.try_deserialize().unwrap();

    if let Some(defs) = rules.get_mut("definitions") {
        for mut rule in defs.as_array_mut().unwrap_or(&mut Vec::new()) {
            let mut shield_ops_idx: Vec<i32> = Vec::new();

            let class: BSRuleClass = get_field(&mut rule, "class")?;
            let event: BShieldEventType = get_field(&mut rule, "event")?;
            let action: BShieldAction = get_field(&mut rule, "action")?;

            let key = BShieldRulesKey {
                class: class as i32,
                event_type: event as i32,
            };

            println!("Rule: {:?}", rule);

            let mut bad_target = false;

            for (t, rs) in rule
                .get_mut("rules")
                .and_then(|tg| tg.as_object_mut())
                .unwrap_or(&mut Map::new())
            {
                let target: BSRuleTarget = BSRuleTarget::from_str(t.to_string().as_mut_str());
                if !class.is_supported_target(&target) {
                    warn!(
                        "Unsupported target: {:?}, for class: {:?}. Skipping the rule.",
                        target, class
                    );
                    bad_target = true;
                    break;
                }
                shield_ops_idx.append(&mut parse_ops(&mut shield_ops, &target, rs)?);
            }
            if bad_target {
                continue;
            }

            let mut rule_ops_idx = [-1i32; 25];
            for (i, idx) in shield_ops_idx.into_iter().enumerate() {
                rule_ops_idx[i] = idx;
            }

            let shield_rule = BShieldRule {
                class: class,
                event: event,
                ops: rule_ops_idx,
                action: action,
            };
            let entry = shield_rules.entry(key).or_insert(Vec::new());
            entry.push(shield_rule);
        }
    }

    Ok((shield_rules, shield_ops))
}
