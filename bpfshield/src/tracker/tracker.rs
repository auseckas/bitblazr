use crate::ContextTracker;
use aya::maps::perf::PerfBufferError;
use bpfshield_common::{
    models::{BShieldAction, BShieldEvent, BShieldEventClass},
    utils::{self, str_from_buf_nul},
    BShieldEventType, ARGV_COUNT,
};
use chrono::{DateTime, Utc};
use std::{borrow::BorrowMut, time::Instant};
use tracing::Instrument;

use crate::rules::load_log_rules;
use crossbeam_channel;
use crossbeam_channel::TryRecvError;
use moka::future::Cache;
use moka::future::FutureExt;
use moka::notification::ListenerFuture;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

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
    pub context: Vec<i64>,
    pub argv: Vec<String>,
    pub logged: bool,
    pub delayed_logging: bool,
}

impl BSProcess {
    pub fn emit_log_entry(&mut self, target: &str) {
        if self.logged {
            return;
        }

        let mut proto = String::new();
        let mut ports = String::new();
        if !self.proto_port.is_empty() {
            proto = match self.proto_port[0].proto {
                1 => "ICP",
                6 => "TCP",
                17 => "UDP",
                _ => "N/A",
            }
            .to_string();

            for pp in &self.proto_port {
                let port = pp.port;
                if !ports.is_empty() {
                    ports.push_str(", ");
                } else {
                    ports.push_str("[");
                }
                ports.push_str(&port.to_string());
            }
            ports.push_str("]");
        }
        if proto.is_empty() {
            proto.push_str("N/A");
        }
        if ports.is_empty() {
            ports.push_str("N/A");
        }

        self.logged = true;

        match target {
            "event" => {
                info!(target: "event", tgid = self.tgid, pid = self.pid, uid = self.uid, gid = self.gid, path = self.path, argv = format!("{:?}", self.argv), proto = proto, ports = ports, action = format!("{:?}", self.action));
            }
            "alert" => {
                info!(target: "alert", tgid = self.tgid, pid = self.pid, uid = self.uid, gid = self.gid, path = self.path, argv = format!("{:?}", self.argv), proto = proto, ports = ports, action = format!("{:?}", self.action));
            }
            "error" => {
                info!(target: "error", tgid = self.tgid, pid = self.pid, uid = self.uid, gid = self.gid, path = self.path, argv = format!("{:?}", self.argv), proto = proto, ports = ports, action = format!("{:?}", self.action));
            }
            _ => (),
        }
    }
}

pub struct BSProcessTracker {
    pub snd: crossbeam_channel::Sender<BShieldEvent>,
}

impl BSProcessTracker {
    pub fn new(ctx_tracker: Arc<ContextTracker>) -> Result<BSProcessTracker, anyhow::Error> {
        let (snd, recv) = crossbeam_channel::bounded::<BShieldEvent>(100_000);

        let bes = BSProcessTracker { snd };
        bes.run(recv, ctx_tracker.clone())?;
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
                        "process_argv: Could not convert argv[{}] buffer into String. Err: {}",
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
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let eviction_listener = move |k: Arc<u32>, e: Arc<BSProcess>, cause| -> ListenerFuture {
            println!("\n== An entry has been evicted. k: {k:?}, cause: {cause:?}");

            async move {
                println!(
                    "E: path: {}, logged: {}, {:?}",
                    e.path, e.logged, e.delayed_logging
                );
            }
            .boxed()
        };

        let tracker: Cache<u32, Arc<BSProcess>> = Cache::builder()
            .max_capacity(100_000)
            // .time_to_live(Duration::from_secs(30 * 60))
            // .time_to_idle(Duration::from_secs(60))
            .async_eviction_listener(eviction_listener)
            .build();
        let thread_tracker = tracker.clone();
        let thread_ctx_tracker = ctx_tracker.clone();
        let log_rules = load_log_rules(thread_ctx_tracker.get_labels())?;

        tokio::spawn(async move {
            let mut event_tracker_timer = Instant::now();
            let mut event_tracker = 0;

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

                        let entry = thread_tracker
                            .entry(event.pid)
                            .and_upsert_with(|loc| {
                                event_tracker += 1;
                                let elapsed = event_tracker_timer.elapsed().as_secs();
                                if elapsed >= 60 {
                                    info!("Events Per Second: {}", event_tracker / elapsed);
                                    event_tracker = 0;
                                    event_tracker_timer = Instant::now();
                                }

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

                                        if event.labels[0] != 0 {
                                            for l in event.labels {
                                                if l == 0 {
                                                    break;
                                                }
                                                if !e.context.contains(&l) {
                                                    e.context.push(l);
                                                }
                                            }
                                        }
                                        // We could have multiple events for a single command, so emit log only if we have rule matches
                                        // Otherwise we delay logging, and clean it up every few seconds
                                        if let Ok(log_r) = log_rules.check_rules(&event) {
                                            if !e.rule_hits.is_empty() {
                                                if !log_r.ignore {
                                                    if matches!(e.action, BShieldAction::Block)
                                                        || log_r.alert
                                                    {
                                                        e.emit_log_entry("alert");
                                                    } else if log_r.log {
                                                        e.emit_log_entry("event");
                                                    }
                                                }
                                            } else {
                                                e.delayed_logging = true;
                                            }
                                        }

                                        arc_e
                                    }
                                    None => {
                                        let path = utils::str_from_buf_nul(&event.path)
                                            .unwrap_or("")
                                            .to_string();
                                        let p_path = utils::str_from_buf_nul(&event.p_path)
                                            .unwrap_or("")
                                            .to_string();

                                        let mut e = BSProcess {
                                            created: Utc::now(),
                                            tgid: event.tgid,
                                            pid: event.pid,
                                            ppid: event.ppid,
                                            uid: event.uid,
                                            gid: event.gid,
                                            path: path,
                                            p_path: p_path,
                                            proto_port: Vec::new(),
                                            action: event.action,
                                            rule_hits: event
                                                .rule_hits
                                                .into_iter()
                                                .filter(|h| *h != 0)
                                                .collect(),
                                            children: Vec::new(),
                                            context: Vec::new(),
                                            argv: BSProcessTracker::process_argv(&event),
                                            logged: false,
                                            delayed_logging: false,
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

                                        if event.labels[0] != 0 {
                                            for l in event.labels {
                                                if l == 0 {
                                                    break;
                                                }
                                                if !e.context.contains(&l) {
                                                    e.context.push(l);
                                                }
                                            }
                                        }

                                        // We could have multiple events for a single command, so emit log only if we have rule matches
                                        // Otherwise we delay logging, and clean it up every few seconds
                                        if let Ok(log_r) = log_rules.check_rules(&event) {
                                            if !e.rule_hits.is_empty() {
                                                if !log_r.ignore {
                                                    if matches!(e.action, BShieldAction::Block)
                                                        || log_r.alert
                                                    {
                                                        e.emit_log_entry("alert");
                                                    } else if log_r.log {
                                                        e.emit_log_entry("event");
                                                    }
                                                }
                                            } else {
                                                e.delayed_logging = true;
                                            }
                                        }

                                        Arc::new(e)
                                    }
                                };
                                std::future::ready(entry)
                            })
                            .instrument(tracing::info_span!("BpfShield"))
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
