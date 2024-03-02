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
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct ShieldLogsConfig {
    pub default: ShieldLogEntry,
    pub errors: Option<ShieldLogEntry>,
    pub events: Option<ShieldLogEntry>,
    pub alerts: Option<ShieldLogEntry>,
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
pub(crate) struct ShieldConfig {
    pub process_labels: HashMap<String, Vec<HashMap<String, String>>>,
    pub logs: ShieldLogsConfig,
}

pub(crate) fn load_config() -> Result<ShieldConfig, anyhow::Error> {
    let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "dev".into());
    let mut config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config/".into());
    if !config_dir.ends_with('/') {
        config_dir.push('/');
    }

    let config = Config::builder()
        .add_source(File::new(
            &format!("{}default.json5", config_dir),
            FileFormat::Json5,
        ))
        .add_source(File::new(
            &format!("{}{}.json5", config_dir, run_mode),
            FileFormat::Json5,
        ))
        .build()?;

    let conf: ShieldConfig = config.try_deserialize().unwrap();

    Ok(conf)
}
