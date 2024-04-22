use config::{Config, File, FileFormat};
use std::collections::HashMap;
use std::env;

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct ShieldLogEntry {
    pub enable: bool,
    pub target: String,
    pub directory: Option<String>,
    pub prefix: Option<String>,
    pub rotation: Option<String>,
    pub max_files: Option<usize>,
    pub format: Option<String>,
    pub mqtt_uri: Option<String>,
    pub mqtt_user: Option<String>,
    pub mqtt_pwd: Option<String>,
    pub mqtt_topic: Option<String>,
    pub mqtt_server_cert_auth: Option<bool>,
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct ShieldLogsConfig {
    pub default: ShieldLogEntry,
    pub errors: Option<ShieldLogEntry>,
    pub events: Option<ShieldLogEntry>,
    pub alerts: Option<ShieldLogEntry>,
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct ShieldFeatures {
    pub lsm: bool,
    pub tracepoints: bool,
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct BlazrLimits {
    pub max_events: u32,
    pub backoff: u32,
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct ShieldConfig {
    pub features: ShieldFeatures,
    pub limits: BlazrLimits,
    pub process_labels: HashMap<String, Vec<HashMap<String, String>>>,
    pub logs: ShieldLogsConfig,
}

pub(crate) fn load_config() -> Result<ShieldConfig, anyhow::Error> {
    let mut config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config/".into());
    if !config_dir.ends_with('/') {
        config_dir.push('/');
    }

    let config = Config::builder()
        .add_source(File::new(
            &format!("{}config.json5", config_dir),
            FileFormat::Json5,
        ))
        .build()?;

    let conf: ShieldConfig = config.try_deserialize().unwrap();

    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::load_config;

    #[test]
    fn load_config_test() {
        let r = load_config();
        assert!(r.unwrap().features.tracepoints);
    }
}
