use super::Probe;
use crate::probes::PsLabels;
use crate::rules;
use crate::ContextTracker;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::Lsm;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bpfshield_common::models::BShieldEvent;
use bpfshield_common::rules::{BShieldOp, BShieldRule, BShieldRuleClass, BShieldRulesKey};
use bpfshield_common::utils;
use bpfshield_common::{BShieldAction, BShieldEventType, OPS_PER_RULE, RULES_PER_KEY};
use bytes::BytesMut;
use crossbeam_channel;
use log::{error, warn};
use std::result::Result;
use std::sync::Arc;

pub struct LsmTracepoints {
    labels_snd: crossbeam_channel::Sender<PsLabels>,
}

impl LsmTracepoints {
    pub(crate) fn new(labels_snd: crossbeam_channel::Sender<PsLabels>) -> LsmTracepoints {
        LsmTracepoints { labels_snd }
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> =
            bpf.take_map("LSM_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut lsm_buf = tp_array.open(cpu_id, Some(128))?;
            let th_ctx_tracker = ctx_tracker.clone();
            let thread_snd = snd.clone();
            let th_labels_snd = self.labels_snd.clone();
            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BShieldEvent>()); 100];

                loop {
                    // wait for events
                    let events = lsm_buf.read_events(&mut buffer).await?;

                    if events.lost > 0 {
                        warn!("Events lost in LSM_BUFFER: {}", events.lost);
                    }

                    for buf in buffer.iter_mut().take(events.read) {
                        let be: &mut BShieldEvent =
                            unsafe { &mut *(buf.as_ptr() as *mut BShieldEvent) };

                        let mut event_ctx = [0i64; 5];
                        let ctx = th_ctx_tracker
                            .check_process_label(utils::str_from_buf_nul(&be.path).unwrap_or(""))
                            .or_else(|| {
                                th_ctx_tracker.check_process_label(
                                    utils::str_from_buf_nul(&be.p_path).unwrap_or(""),
                                )
                            })
                            .unwrap_or(Vec::new());

                        for (i, c) in ctx.into_iter().enumerate() {
                            if i >= 5 {
                                break;
                            }
                            event_ctx[i] = c;
                        }

                        be.labels = event_ctx;
                        if let Err(e) = th_labels_snd.send(PsLabels {
                            pid: be.pid,
                            labels: be.labels,
                        }) {
                            warn!("Could not send Labels. Err: {}", e);
                        }

                        if let Err(e) = thread_snd.send(be.clone()) {
                            warn!("Could not send Tracepoints event. Err: {}", e);
                        }
                    }
                }
                Ok::<_, PerfBufferError>(())
            });
        }
        Ok(())
    }

    fn load_program(&self, bpf: &mut Bpf, btf: &Btf, tp: &str) -> Result<(), anyhow::Error> {
        let program: &mut Lsm = bpf.program_mut(tp).unwrap().try_into()?;
        program.load(tp, &btf)?;
        program.attach()?;
        Ok(())
    }

    fn load_rules(
        &self,
        bpf: &mut Bpf,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        const RULE_UNDEFINED: BShieldRule = BShieldRule {
            id: 0,
            class: BShieldRuleClass::Undefined,
            event: BShieldEventType::Undefined,
            context: [0; 5],
            ops: [-1; OPS_PER_RULE],
            action: BShieldAction::Undefined,
        };

        let mut map_rules: AyaHashMap<&mut MapData, BShieldRulesKey, [BShieldRule; RULES_PER_KEY]> =
            AyaHashMap::try_from(bpf.map_mut("LSM_RULES").unwrap()).unwrap();

        let (lsm_rules, shield_ops) = rules::load_rules_from_config(ctx_tracker.get_labels())?;
        for (key, rules) in lsm_rules.into_iter() {
            let mut rules_buf = [RULE_UNDEFINED; RULES_PER_KEY];
            for (i, rule) in rules.into_iter().enumerate() {
                if i >= 25 {
                    break;
                }
                rules_buf[i] = rule;
            }

            map_rules.insert(key, rules_buf, 0)?;
        }

        let mut array_rule_ops: Array<&mut MapData, BShieldOp> =
            Array::try_from(bpf.map_mut("LSM_RULE_OPS").unwrap()).unwrap();

        for (i, op) in shield_ops.into_iter().enumerate() {
            array_rule_ops.set(i as u32, op, 0)?;
        }

        Ok(())
    }

    pub(crate) fn run_labels_loop(mut bpf: Bpf, recv: crossbeam_channel::Receiver<PsLabels>) {
        tokio::spawn(async move {
            let mut labels_map: AyaHashMap<&mut MapData, u32, [i64; 5]> =
                AyaHashMap::try_from(bpf.map_mut("LSM_CTX_LABELS").unwrap()).unwrap();

            loop {
                match recv.recv() {
                    Ok(ps_labels) => {
                        let mut shared_labels = labels_map.get(&ps_labels.pid, 0).unwrap_or([0; 5]);

                        let mut pos = shared_labels.iter().position(|l| *l == 0).unwrap_or(0);
                        for l in ps_labels.labels.into_iter() {
                            if pos >= 5 {
                                break;
                            }
                            shared_labels[pos] = l;
                            pos += 1;
                        }
                        if let Err(e) = labels_map.insert(ps_labels.pid, shared_labels, 0) {
                            error!("Could not insert new labels. Error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Error in labels loop. E: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

impl Probe for LsmTracepoints {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let btf = Btf::from_sys_fs()?;

        self.run(bpf, snd, ctx_tracker.clone())?;
        self.load_rules(bpf, ctx_tracker.clone())?;

        self.load_program(bpf, &btf, "file_open")?;
        self.load_program(bpf, &btf, "bprm_check_security")?;
        self.load_program(bpf, &btf, "socket_listen")?;

        Ok(())
    }
}
