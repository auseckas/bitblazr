use aya::maps::perf::PerfBufferError;
use bpfshield_common::{
    models::{BShieldAction, BShieldEvent, BShieldEventClass},
    utils, BShieldEventType, ARGV_COUNT,
};
use chrono::{DateTime, Utc};
use crossbeam_channel;
use log::{error, warn};
use moka::future::Cache;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct BSProtoPort {
    pub proto: u16,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct BSProcess {
    pub created: DateTime<Utc>,
    pub tgid: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub p_path: String,
    pub path: String,
    pub proto_port: Vec<BSProtoPort>,
    pub action: BShieldAction,
    pub rule_hits: Vec<u16>,
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

    fn process_argv(event: &BShieldEvent) -> Vec<String> {
        let argv_count = match event.argv_count <= ARGV_COUNT as u8 {
            true => event.argv_count as usize,
            false => ARGV_COUNT,
        };
        let mut argv = Vec::with_capacity(argv_count);
        for i in 0..argv_count {
            let s = match utils::str_from_buf_nul(&event.argv[i]) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Could not convert argv[{}] buffer into String. Err: {}",
                        i, e
                    );
                    continue;
                }
            };
            argv.push(s.to_string());
        }
        argv
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
                        match event.event_type {
                            BShieldEventType::Exit => {
                                // Remove from parent record and invalidate
                                if let Some(ppid) = event.ppid {
                                    if let Some(mut entry) = thread_tracker.get(&ppid).await {
                                        let e = Arc::<BSProcess>::make_mut(&mut entry);
                                        if let Some(pos) =
                                            e.children.iter().position(|e| *e == event.pid)
                                        {
                                            e.children.remove(pos);
                                        }
                                    }
                                }

                                thread_tracker.invalidate(&event.pid).await;
                                continue;
                            }
                            _ => (),
                        };

                        // If parent process exists, update children
                        if let Some(ppid) = event.ppid {
                            if let Some(mut entry) = thread_tracker.get(&ppid).await {
                                let e = Arc::<BSProcess>::make_mut(&mut entry);
                                if !e.children.contains(&event.pid) {
                                    e.children.push(event.pid);
                                }
                            }
                        }

                        thread_tracker
                            .entry(event.pid)
                            .and_upsert_with(|loc| {
                                let entry = match loc {
                                    Some(entry) => {
                                        let mut arc_e = entry.into_value();
                                        let e = Arc::<BSProcess>::make_mut(&mut arc_e);
                                        match event.class {
                                            BShieldEventClass::Tracepoint => {
                                                e.p_path = utils::str_from_buf_nul(&event.p_path)
                                                    .unwrap_or("")
                                                    .to_string();

                                                e.path = utils::str_from_buf_nul(&event.path)
                                                    .unwrap_or("")
                                                    .to_string();

                                                if e.argv.is_empty() && !event.argv.is_empty() {
                                                    e.argv = BSProcessTracker::process_argv(&event);
                                                }
                                                // If first argument is the command, remove it
                                                if !e.argv.is_empty() {
                                                    if e.path.ends_with(&e.argv[0]) {
                                                        e.argv.remove(0);
                                                    }
                                                }
                                            }
                                            BShieldEventClass::BtfTracepoint => {
                                                if matches!(e.ppid, None) {
                                                    e.ppid = event.ppid;
                                                }
                                            }
                                            BShieldEventClass::Lsm => {
                                                if matches!(e.ppid, None) {
                                                    e.ppid = event.ppid;
                                                }
                                            }
                                        }
                                        match event.event_type {
                                            BShieldEventType::Listen => {
                                                if event.protocol > 0 {
                                                    e.proto_port.push({
                                                        BSProtoPort {
                                                            proto: event.protocol,
                                                            port: event.port,
                                                        }
                                                    });
                                                }
                                            }
                                            _ => (),
                                        };
                                        for id in event.rule_hits.iter() {
                                            if *id != 0 && !e.rule_hits.contains(id) {
                                                e.rule_hits.push(*id);
                                            }
                                        }

                                        if matches!(event.action, BShieldAction::Block)
                                            && matches!(e.action, BShieldAction::Allow)
                                        {
                                            e.action = event.action;
                                        }
                                        arc_e
                                    }
                                    None => {
                                        let mut e = BSProcess {
                                            created: Utc::now(),
                                            tgid: event.tgid,
                                            pid: event.pid,
                                            ppid: event.ppid,
                                            uid: event.uid,
                                            gid: event.gid,
                                            path: utils::str_from_buf_nul(&event.path)
                                                .unwrap_or("")
                                                .to_string(),
                                            p_path: utils::str_from_buf_nul(&event.p_path)
                                                .unwrap_or("")
                                                .to_string(),
                                            proto_port: Vec::new(),
                                            action: event.action,
                                            rule_hits: event
                                                .rule_hits
                                                .into_iter()
                                                .filter(|h| *h != 0)
                                                .collect(),
                                            children: Vec::new(),
                                            argv: BSProcessTracker::process_argv(&event),
                                        };
                                        // If first argument is the command, remove it
                                        if !e.argv.is_empty() {
                                            if e.path.ends_with(&e.argv[0]) {
                                                e.argv.remove(0);
                                            }
                                        }
                                        match event.event_type {
                                            BShieldEventType::Listen => {
                                                if event.protocol > 0 {
                                                    e.proto_port.push({
                                                        BSProtoPort {
                                                            proto: event.protocol,
                                                            port: event.port,
                                                        }
                                                    });
                                                }
                                            }
                                            _ => (),
                                        };

                                        Arc::new(e)
                                    }
                                };

                                // if event.path.starts_with("/usr/bin".as_bytes()) {
                                //     println!("Entry: {:#?}", entry);
                                // }
                                if matches!(event.event_type, BShieldEventType::Listen)
                                    || matches!(event.event_type, BShieldEventType::Exec)
                                {
                                    println!("Entry: {:#?}", entry);
                                }
                                std::future::ready(entry)
                            })
                            .await;
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
