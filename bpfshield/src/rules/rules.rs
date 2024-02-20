use crate::BSError;
use bpfshield_common::rules::*;
use config::{Config, File, FileFormat};
use serde_json::Value;
use std::collections::HashMap;
use std::env;

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

pub(crate) fn load_rules() -> Result<(), anyhow::Error> {
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
            let class: BSRuleClass = get_field(&mut rule, "class")?;

            println!("Class: {:?}, Rule: {:#?}", class, rule);
        }
    }

    Ok(())
}
