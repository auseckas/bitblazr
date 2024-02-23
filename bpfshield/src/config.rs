use config::{Config, File, FileFormat};
use std::env;

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
struct AppConfig {
    list: Vec<String>,
}

pub(crate) fn load_config() -> Result<(), anyhow::Error> {
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

    let app: AppConfig = config.try_deserialize().unwrap();
    println!("App: {:?}", app);

    Ok(())
}
