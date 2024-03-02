use crate::config::{ShieldConfig, ShieldLogEntry};
use crate::errors::BSError;
use std::io::{self, Write};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{filter, EnvFilter, Layer};

pub struct BShieldLogs {
    _guards: Vec<WorkerGuard>,
}

impl BShieldLogs {
    fn parse_log_entry(
        entry: &ShieldLogEntry,
    ) -> Result<(NonBlocking, WorkerGuard), anyhow::Error> {
        match entry.target.as_str() {
            "stderr" => {
                let r = tracing_appender::non_blocking(std::io::stderr());
                Ok(r)
            }
            "stdout" => {
                let r = tracing_appender::non_blocking(std::io::stdout());
                Ok(r)
            }
            "file" => {
                let directory = match &entry.directory {
                    Some(d) => d.as_str(),
                    None => return Err(BSError::MissingAttribute("directory".to_string()).into()),
                };

                let prefix = match &entry.prefix {
                    Some(p) => p.as_str(),
                    None => return Err(BSError::MissingAttribute("prefix".to_string()).into()),
                };

                let s_rotation = match &entry.rotation {
                    Some(p) => p.as_str(),
                    None => "daily",
                };

                let rotation = match s_rotation.trim().to_ascii_lowercase().as_str() {
                    "hourly" => rolling::Rotation::HOURLY,
                    "daily" => rolling::Rotation::DAILY,
                    "never" => rolling::Rotation::NEVER,
                    _ => {
                        return Err(BSError::InvalidAttribute {
                            attribute: "Invalid log rotation",
                            value: s_rotation.to_string(),
                        }
                        .into());
                    }
                };

                let max_files = match entry.max_files {
                    Some(m) => m,
                    None => 5,
                };

                let appender = rolling::RollingFileAppender::builder()
                    .rotation(rotation)
                    .filename_prefix(prefix)
                    .max_log_files(max_files)
                    .build(directory)?;
                let r = tracing_appender::non_blocking(appender);

                Ok(r)
            }
            _ => {
                return Err(BSError::InvalidAttribute {
                    attribute: "Invalid log target",
                    value: entry.target.to_string(),
                }
                .into());
            }
        }
    }

    pub fn new(config: &ShieldConfig) -> Result<BShieldLogs, anyhow::Error> {
        let logs_conf = &config.logs;

        let mut layers = Vec::new();
        let mut guards = Vec::new();

        if logs_conf.default.enable {
            let (w, guard) = BShieldLogs::parse_log_entry(&logs_conf.default)?;
            guards.push(guard);
            layers.push(layer().with_writer(w).boxed());
        }

        if let Some(ref e) = logs_conf.errors {
            if e.enable {
                let (w, guard) = BShieldLogs::parse_log_entry(&e)?;
                guards.push(guard);
                let layer = layer().with_writer(w.with_max_level(tracing::Level::INFO));

                layers.push(
                    layer
                        .with_filter(filter::filter_fn(|metadata| metadata.target() == "error"))
                        .boxed(),
                );
            }
        }

        if let Some(ref e) = logs_conf.events {
            if e.enable {
                let (w, guard) = BShieldLogs::parse_log_entry(&e)?;
                guards.push(guard);
                let layer = layer().with_writer(w);
                layers.push(
                    layer
                        .with_filter(filter::filter_fn(|metadata| metadata.target() == "event"))
                        .boxed(),
                );
            }
        }

        if let Some(ref e) = logs_conf.alerts {
            if e.enable {
                let (w, guard) = BShieldLogs::parse_log_entry(&e)?;
                guards.push(guard);

                let format = tracing_subscriber::fmt::format()
                    .with_level(false)
                    .with_target(true)
                    .compact();

                let layer = layer().with_writer(w).event_format(format);
                layers.push(
                    layer
                        .with_filter(filter::filter_fn(|metadata| metadata.target() == "alert"))
                        .boxed(),
                );
            }
        }

        tracing_subscriber::registry()
            .with(layers)
            .with(EnvFilter::from_default_env())
            .init();

        Ok(BShieldLogs { _guards: guards })
    }
}
