use crate::{rules::log_rules::BlazrRuleResult, ContextTracker};
use aya::maps::perf::PerfBufferError;
use bitblazr_common::{
    models::{BlazrAction, BlazrEvent},
    utils::{self, str_from_buf_nul},
    BlazrEventType, ARGV_COUNT,
};
use chrono::{DateTime, Utc};
use std::time::Instant;
use tracing::Instrument;

use crate::rules::load_log_rules;
use moka::future::Cache;
use std::sync::Arc;
use tracing::{debug, trace, error, info, warn};
use no_std_net::{IpAddr, Ipv4Addr};
use names::Generator;
use std::collections::HashSet;
use crate::utils::vec_to_string;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct BSProtoPort {
    pub proto: u16,
    pub port: u16,
    pub ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct BSProcess {
    pub event_type: BlazrEventType,
    pub created: DateTime<Utc>,
    pub tgid: u32,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub p_path: String,
    pub path: String,
    pub proto_port: Vec<BSProtoPort>,
    pub action: BlazrAction,
    pub rule_hits: Vec<u16>,
    pub children: Vec<u32>, // [pid,...]
    pub context: Vec<i64>,
    pub argv: Vec<String>,
    pub exit_code: u8,
    pub run_time: i64,
    pub logged: bool,
}

impl BSProcess {
    pub fn emit_log_entry(&mut self, ctx_tracker: Arc<ContextTracker>, target: &str, sensor_name: &str, e: &BlazrEvent, mut results: Vec<BlazrRuleResult>, new_info: bool) {
        debug!("Logging event path: {:?}, p_path: {:?}, on record: {:?}", str_from_buf_nul(&e.path),str_from_buf_nul(&e.p_path), &self);
        let event_path = match str_from_buf_nul(&e.path) {
            Ok(p) => p,
            Err(e) => {
                error!(target: "error", "Could not convert path from &[u8]. Err: {}", e);
                return;
            }
        };
        
        let context = ctx_tracker.hashes_to_labels(&self.context);

        if self.logged && !new_info && self.path == event_path {
            return;
        }

        let mut proto = String::new();
        let mut ports_str = String::new();
        let mut ips_str = String::new();

        if !self.proto_port.is_empty() {
            proto = match self.proto_port[0].proto {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "N/A",
            }
            .to_string();

            let ports = self.proto_port.iter().map(|pp| pp.port).collect::<HashSet<_>>();
            let ips = self.proto_port.iter().map(|pp| pp.ip).collect::<HashSet<_>>();

            ports_str = vec_to_string(ports.into_iter().collect());
            ips_str = vec_to_string(ips.into_iter().collect());

        }
        if proto.is_empty() {
            proto.push_str("N/A");
        }
        if ports_str.is_empty() {
            ports_str.push_str("N/A");
        }

        let mut path = match e.event_type {
            BlazrEventType::Exec => self.path.as_str(),
            _ => event_path,
        };

        if path.is_empty() {
            path = match str_from_buf_nul(&e.p_path) {
                Ok(p) => p,
                Err(e) => {
                    error!(target: "error", "Could not convert path from &[u8]. Err: {}", e);
                    return;
                }
            };
        }

        let command = match self.event_type {
            BlazrEventType::Exec => self.path.as_str(),
            _ => self.p_path.as_str()
        };

        self.logged = true;

        let mut exit_code = None;
        let mut run_time = None;
        if self.run_time > -1 {
            exit_code = Some(self.exit_code);
            run_time = Some(self.run_time);
        }

        let mut rule_results = None;
        results = results.into_iter().filter(|r| r.description.is_some()).collect();
        if !results.is_empty() {
            let mut rr = results
                .into_iter()
                .fold(String::new(), |mut acc, r| {
                    acc.push_str(&format!("{};", r.description.unwrap_or(String::new())));
                    acc
                });
            rr.pop();
            rule_results = Some(rr);
        }

        match target {
            "event" => {
                info!(target: "event", sensor_name = sensor_name, event_type = format!("{:?}", e.event_type), context = context, ppid=self.ppid, tgid = self.tgid, pid = self.pid, uid = self.uid, gid = self.gid, command = command, path = path, argv = format!("{:?}", self.argv), proto = proto, ips = ips_str, ports = ports_str, run_time = run_time, exit_code = exit_code, description = rule_results, action = format!("{:?}", self.action));
            }
            "alert" => {
                info!(target: "alert", sensor_name = sensor_name, event_type = format!("{:?}", e.event_type), context = context, ppid=self.ppid, tgid = self.tgid, pid = self.pid, uid = self.uid, gid = self.gid, command = command, path = path, argv = format!("{:?}", self.argv), proto = proto, ips = ips_str, ports = ports_str, run_time = run_time, exit_code = exit_code, description = rule_results, action = format!("{:?}", self.action));
            }
            "error" => {
                info!(target: "error", sensor_name = sensor_name, event_type = format!("{:?}", e.event_type), context = context, ppid=self.ppid, tgid = self.tgid, pid = self.pid, uid = self.uid, gid = self.gid, command = command, path = path, argv = format!("{:?}", self.argv), proto = proto, ips = ips_str, ports = ports_str, run_time = run_time, exit_code = exit_code, description = rule_results, action = format!("{:?}", self.action));
            }
            _ => (),
        }
    }
}

pub struct BSProcessTracker {
    pub snd: mpsc::Sender<BlazrEvent>,
    sensor_name: String
}

impl BSProcessTracker {
    pub fn new(ctx_tracker: Arc<ContextTracker>, name: &str) -> Result<BSProcessTracker, anyhow::Error> {
        let sensor_name = match name.is_empty() {
            true => { let mut generator = Generator::default();
                generator.next().unwrap_or("unnamed".to_string())
            },
            false => name.to_string()
        };

        let (snd, recv) = mpsc::channel::<BlazrEvent>(100_000);

        let bes = BSProcessTracker { snd, sensor_name };
        bes.run(recv, ctx_tracker.clone())?;
        Ok(bes)
    }

    fn process_argv(event: &BlazrEvent) -> Vec<String> {
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
        mut recv: mpsc::Receiver<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        // Eviction listener is used to log events that match log rules but not any kernel rules
        // Better to log late than never.
        // let eviction_listener =
        //     move |_k: Arc<u32>, mut e: Arc<BSProcess>, cause| -> ListenerFuture {
        //         async move {
        //             if !matches!(cause, RemovalCause::Replaced) && e.delayed_logging && !e.logged {
        //                 Arc::make_mut(&mut e).emit_log_entry("event")
        //             }
        //         }
        //         .boxed()
        //     };

        let tracker: Cache<u32, Arc<BSProcess>> = Cache::builder()
            .max_capacity(100_000)
            // .time_to_live(Duration::from_secs(30 * 60))
            // .time_to_idle(Duration::from_secs(60))
            // .async_eviction_listener(eviction_listener)
            .build();
        let thread_tracker = tracker.clone();
        let thread_ctx_tracker = ctx_tracker.clone();
        let log_rules = load_log_rules(thread_ctx_tracker.get_labels())?;
        let th_sensor_name = self.sensor_name.clone();

        tokio::spawn(async move {
            let mut event_tracker_timer = Instant::now();
            let mut event_tracker = 0;

            loop {
                match recv.recv().await {
                    Some(event) => {
                        if matches!(event.event_type, BlazrEventType::Exit) {
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

                            // Check exit_code and run time to see if we need to log the event.
                            if let Some(mut entry) = thread_tracker.get(&event.pid).await {
                                let e = Arc::<BSProcess>::make_mut(&mut entry);
                                e.run_time = Utc::now().timestamp() - e.created.timestamp();
                                e.exit_code = event.exit_code;
                                debug!("Runtime: {}, exit_code: {}, type: {:?}, path: {}", e.run_time, e.exit_code, e.event_type, e.path);
                                if let Ok(log_r) = log_rules.check_rules(&event.log_class, &event.event_type, &e, &event) {
                                    if !log_r.ignore {
                                        if matches!(e.action, BlazrAction::Block) || log_r.alert {
                                            e.emit_log_entry(thread_ctx_tracker.clone(), "alert", th_sensor_name.as_str(), &event, log_r.results, true);
                                        } else if log_r.log {
                                            e.emit_log_entry(thread_ctx_tracker.clone(), "event", th_sensor_name.as_str(), &event, log_r.results,  true);
                                        }
                                    }
                                }
                            }

                            thread_tracker.invalidate(&event.pid).await;
                            continue;
                        }
                        

                        let mut ppid_context = Vec::new();
                        // If parent process exists, update children
                        if let Some(ppid) = event.ppid {
                            if let Some(mut entry) = thread_tracker.get(&ppid).await {
                                let e = Arc::<BSProcess>::make_mut(&mut entry);
                                if !e.children.contains(&event.pid) {
                                    e.children.push(event.pid);
                                }
                                for l in e.context.iter() {
                                    ppid_context.push(*l);
                                }
                            }
                        }

                        thread_tracker
                            .entry(event.pid)
                            .and_upsert_with(|loc| {
                                event_tracker += 1;
                                let elapsed = event_tracker_timer.elapsed().as_secs();
                                if elapsed >= 60 {
                                    info!(target: "event", "Events Per Second: {}", event_tracker / elapsed);
                                    event_tracker = 0;
                                    event_tracker_timer = Instant::now();
                                }

                                let entry = match loc {
                                    Some(entry) => {
                                        let mut new_info = false;
                                        let mut arc_e = entry.into_value();
                                        let e = Arc::<BSProcess>::make_mut(&mut arc_e);

                                        if e.argv.is_empty() && !event.argv.is_empty() {
                                            new_info = true;
                                            e.argv = BSProcessTracker::process_argv(&event);
                                                // If first argument is the command, remove it
                                            if !e.argv.is_empty() {
                                                if e.path.ends_with(&e.argv[0]) {
                                                    e.argv.remove(0);
                                                }
                                            }
                                        }
                                        if matches!(e.ppid, None) && event.ppid.is_none() {
                                            new_info = true;
                                            e.ppid = event.ppid;
                                        }

                                        if e.path.is_empty() && event.path[0] > 0 {
                                            new_info = true;
                                            e.path = utils::str_from_buf_nul(&event.path)
                                                .unwrap_or("")
                                                .to_string();
                                        }

                                        if e.p_path.is_empty() && event.p_path[0] > 0 {
                                            new_info = true;
                                            e.p_path = utils::str_from_buf_nul(&event.p_path)
                                                .unwrap_or("")
                                                .to_string();
                                        }
                                        if event.protocol > 0 || event.port > 0 {
                                            debug!("Proto: {}, port:{}, ip: {:?}", event.protocol, event.port, event.ip_addr);
                                            new_info = true;
                                            let mut changes = false;
                                            for pp in e.proto_port.iter_mut() {
                                                if pp.proto == 0 && event.protocol > 0 {
                                                    pp.proto = event.protocol;
                                                    changes = true;
                                                }
                                                else if pp.port == 0 && event.port > 0 {
                                                    pp.port = event.port;
                                                    pp.ip = event.ip_addr;
                                                    changes = true;
                                                }
                                            }

                                            if !changes && event.port > 0 && event.ip_addr != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) && !e.proto_port.iter().any(|pp| pp.port == event.port && pp.ip == event.ip_addr) {
                                                e.proto_port.push({
                                                    BSProtoPort {
                                                        proto: event.protocol,
                                                        port: event.port,
                                                        ip: event.ip_addr
                                                    }
                                                });
                                            }
                                        }
                                        for id in event.rule_hits.iter() {
                                            if *id != 0 && !e.rule_hits.contains(id) {
                                                new_info = true;
                                                e.rule_hits.push(*id);
                                            }
                                        }

                                        if matches!(event.action, BlazrAction::Block)
                                            && matches!(e.action, BlazrAction::Allow)
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
                                        // Of course alerts should be sent up right away even if we don't have all the data yet
                                        if let Ok(log_r) = log_rules.check_rules(&event.log_class, &event.event_type, &e, &event) {
                                            if !log_r.ignore {
                                                if matches!(e.action, BlazrAction::Block)
                                                    || log_r.alert
                                                {
                                                    debug!(
                                                        "Alert: {:?}, Action: {:?}, path: {}, event_pid: {}",
                                                        log_r, e.action, e.path, e.pid
                                                    );

                                                    e.emit_log_entry(thread_ctx_tracker.clone(), "alert", th_sensor_name.as_str(), &event, log_r.results, new_info);
                                                } else if log_r.log {
                                                    e.emit_log_entry(thread_ctx_tracker.clone(), "event", th_sensor_name.as_str(), &event, log_r.results, new_info);
                                                }
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
                                            event_type: event.event_type,
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
                                            run_time: -1,
                                            exit_code: 0,
                                            logged: false,
                                        };

                                        trace!("new event, path: {:?}", e.path);
                                        // If first argument is the command, remove it
                                        if !e.argv.is_empty() {
                                            if e.path.ends_with(&e.argv[0]) {
                                                e.argv.remove(0);
                                            }
                                        }
                                        
                                        if event.protocol > 0 || event.port > 0 {
                                            debug!("Proto: {}, port:{}, ip: {:?}", event.protocol, event.port, event.ip_addr);
                                            let mut changes = false;
                                            for pp in e.proto_port.iter_mut() {
                                                if pp.proto == 0 && event.protocol > 0 {
                                                    pp.proto = event.protocol;
                                                    changes = true;
                                                }
                                                else if pp.port == 0 && event.port > 0 {
                                                    pp.port = event.port;
                                                    pp.ip = event.ip_addr;
                                                    changes = true;
                                                }
                                            }

                                            if !changes && event.port > 0 && event.ip_addr != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) && !e.proto_port.iter().any(|pp| pp.port == event.port && pp.ip == event.ip_addr) {
                                                e.proto_port.push({
                                                    BSProtoPort {
                                                        proto: event.protocol,
                                                        port: event.port,
                                                        ip: event.ip_addr
                                                    }
                                                });
                                            }
                                        }

                                        // Context label inheritance
                                        for l in ppid_context {
                                            e.context.push(l);
                                        }

                                        if event.labels[0] != 0 {
                                            for l in event.labels {
                                                if l == 0 {
                                                    break;
                                                }
                                                if !e.context.contains(&l) {
                                                    debug!("Pushing label: {}, on path: {}", l, e.path);
                                                    e.context.push(l);
                                                }
                                            }
                                        }

                                        // We could have multiple events for a single command, so emit log only if we have rule matches
                                        // Otherwise we delay logging, and clean it up every few seconds
                                        // Of course alerts should be sent up right away even if we don't have all the data yet
                                        if let Ok(log_r) = log_rules.check_rules(&event.log_class, &event.event_type, &e, &event) {
                                            if !log_r.ignore {
                                                if matches!(e.action, BlazrAction::Block)
                                                    || log_r.alert
                                                {
                                                    debug!(
                                                        "Alert: ?{:?}, Action: {:?}, path: {}, event_pid: {}",
                                                        log_r, e.action, e.path, e.pid
                                                    );

                                                    e.emit_log_entry(thread_ctx_tracker.clone(),  "alert",th_sensor_name.as_str(), &event, log_r.results, false);
                                                } else if log_r.log {
                                                    e.emit_log_entry(thread_ctx_tracker.clone(), "event", th_sensor_name.as_str(), &event, log_r.results, false);
                                                }
                                            }
                                        }

                                        Arc::new(e)
                                    }
                                };
                                std::future::ready(entry)
                            })
                            .instrument(tracing::info_span!("BitBlazr"))
                            .await;
                    }
                    None => {
                        error!(target: "error", "Event loop stopped!");
                        break;
                    }
                }
            }
            Ok::<_, PerfBufferError>(())
        });
        Ok(())
    }
}
