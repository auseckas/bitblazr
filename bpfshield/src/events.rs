use std::collections::BTreeMap;

use crate::utils::debug_event;
use aya::maps::perf::PerfBufferError;
use bpfshield_common::{
    models::{BShieldEvent, BShieldEventClass},
    utils, BShieldEventType, ARGV_COUNT,
};
use chrono::{DateTime, Utc};
use crossbeam_channel;
use log::{error, warn};
use moka::future::Cache;
use std::sync::Arc;

#[derive(Debug)]
pub struct BSProcess {
    pub created: DateTime<Utc>,
    pub tgid: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub path: String,
    pub children: Vec<u32>, // [pid,...]
    pub argv: Vec<String>,
}

pub struct BSProcessTracker {
    pub snd: crossbeam_channel::Sender<BShieldEvent>,
}

impl BSProcessTracker {
    pub fn new() -> Result<BSProcessTracker, anyhow::Error> {
        let (snd, recv) = crossbeam_channel::bounded::<BShieldEvent>(100_000);

        let bes = BSProcessTracker { snd };
        bes.run(recv)?;
        Ok(bes)
    }

    pub fn run(
        &self,
        recv: crossbeam_channel::Receiver<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        let tracker: Cache<u32, Arc<BSProcess>> = Cache::new(100_000);
        let thread_tracker = tracker.clone();

        tokio::spawn(async move {
            loop {
                match recv.recv() {
                    Ok(event) => {
                        let entry = thread_tracker
                        .entry(event.pid)
                        .and_upsert_with(|loc| {
                            let entry = match loc {
                                Some(entry) => {
                                    entry.into_value()
                                },
                                None => {
                                    Arc::new(BSProcess {
                                        created: Utc::now(),
                                        tgid: event.tgid,
                                        pid: event.pid,
                                        ppid: event.ppid,
                                        uid: event.uid,
                                        gid: event.gid,
                                        path: utils::str_from_buf_nul(&event.path).unwrap_or("").to_string(),
                                        children: Vec::new(),
                                        argv: {
                                            let argv_count = match event.argv_count <= ARGV_COUNT as u8 {
                                                true => event.argv_count as usize,
                                                false => ARGV_COUNT,
                                            };
                                            let mut argv = Vec::with_capacity(argv_count);
                                            for i in 0..argv_count {
                                                let s = match utils::str_from_buf_nul(&event.argv[i]) {
                                                    Ok(s) => s,
                                                    Err(e) => {
                                                        warn!("Could not convert argv[{}] buffer into String. Err: {}", i, e);
                                                        continue;
                                                    }
                                                };
                                                argv.push(s.to_string());
                                            }
                                            argv
                                        },
                                    })
                                }
                            };
                            std::future::ready(entry)
                        })
                        .await;

                        if !entry.is_fresh() {
                            match event.class {
                                BShieldEventClass::Tracepoint => {
                                    println!("Got TP event: {:?}", debug_event(&event));
                                }
                                BShieldEventClass::BtfTracepoint => {
                                    println!("Got BtfTP event: {:?}", debug_event(&event));
                                }
                                BShieldEventClass::Lsm => {
                                    if matches!(event.event_type, BShieldEventType::Bprm) {
                                        println!("Got Bprm event: {:?}", debug_event(&event));
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Event loop stopped with error: {}", e);
                        break;
                    }
                }
            }
            Ok::<_, PerfBufferError>(())
        });
        Ok(())
    }
}
