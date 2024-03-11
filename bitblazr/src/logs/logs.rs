use crate::config::{ShieldConfig, ShieldLogEntry};
use crate::errors::BSError;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling;
use tracing_subscriber::fmt::{format, layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{filter, EnvFilter, Layer};

macro_rules! parse_filter {
    ($layers:expr, $layer:expr, $filter:expr) => {{
        if let Some(f) = $filter {
            $layers.push($layer.with_filter(f).boxed());
        } else {
            $layers.push($layer.boxed());
        }
    }};
}

macro_rules! parse_layer {
    ($layers:expr, $writer:expr, $format:expr, $filter:expr) => {{
        let s_format = match $format {
            Some(f) => f.as_str(),
            None => "full",
        };

        match s_format.trim().to_ascii_lowercase().as_str() {
            "compact" => {
                let layer = layer()
                    .with_writer($writer)
                    .event_format(format().with_target(true).with_level(false).compact());
                parse_filter!($layers, layer, $filter);
            }
            "pretty" => {
                let layer = layer()
                    .with_writer($writer)
                    .event_format(format().with_target(true).with_level(false).pretty());
                parse_filter!($layers, layer, $filter);
            }
            "json" => {
                let layer = layer().with_writer($writer).event_format(
                    format()
                        .with_target(true)
                        .with_level(false)
                        .json()
                        .flatten_event(true),
                );
                parse_filter!($layers, layer, $filter);
            }
            _ => {
                let layer = layer()
                    .with_writer($writer)
                    .event_format(format().with_target(true).with_level(false));
                parse_filter!($layers, layer, $filter);
            }
        }
    }};
}

pub struct BlazrLogs {
    _guards: Vec<WorkerGuard>,
}

impl BlazrLogs {
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

    pub fn new(config: &ShieldConfig) -> Result<BlazrLogs, anyhow::Error> {
        let logs_conf = &config.logs;

        let mut layers = Vec::new();
        let mut guards = Vec::new();

        if logs_conf.default.enable {
            let (w, guard) = BlazrLogs::parse_log_entry(&logs_conf.default)?;
            guards.push(guard);

            let mut filters = Vec::new();
            if logs_conf.errors.is_some() {
                filters.push("error");
            }
            if logs_conf.events.is_some() {
                filters.push("event");
            }
            if logs_conf.alerts.is_some() {
                filters.push("alert");
            }

            let f = filter::filter_fn(move |metadata| !filters.contains(&metadata.target()));
            parse_layer!(layers, w, &logs_conf.default.format, Some(f));
        }

        if let Some(ref e) = logs_conf.errors {
            if e.enable {
                let (w, guard) = BlazrLogs::parse_log_entry(&e)?;
                guards.push(guard);

                let f = filter::filter_fn(|metadata| metadata.target() == "error");
                parse_layer!(layers, w, &e.format, Some(f));
            }
        }

        if let Some(ref e) = logs_conf.events {
            if e.enable {
                let (w, guard) = BlazrLogs::parse_log_entry(&e)?;
                guards.push(guard);
                let f = filter::filter_fn(|metadata| metadata.target() == "event");
                parse_layer!(layers, w, &e.format, Some(f));
            }
        }

        if let Some(ref e) = logs_conf.alerts {
            if e.enable {
                let (w, guard) = BlazrLogs::parse_log_entry(&e)?;
                guards.push(guard);

                let f = filter::filter_fn(|metadata| metadata.target() == "alert");
                parse_layer!(layers, w, &e.format, Some(f));
            }
        }

        tracing_subscriber::registry()
            .with(layers)
            .with(EnvFilter::from_default_env())
            .init();

        Ok(BlazrLogs { _guards: guards })
    }
}
