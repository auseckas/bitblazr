pub mod kernel_rules;
pub(crate) use kernel_rules::load_rules_from_config as load_kernel_rules;

pub mod userspace_rules;
pub(crate) use userspace_rules::load_rules_from_config as load_userspace_rules;

use crate::BSError;
use bpfshield_common::rules::BShieldRuleVar;
use serde_json::Value;

fn get_field<T: BShieldRuleVar>(src: &mut Value, f: &str) -> Result<T, anyhow::Error> {
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
