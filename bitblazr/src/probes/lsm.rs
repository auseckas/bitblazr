use super::Probe;
use crate::probes::PsLabels;
use crate::rules;
use crate::BSError;
use crate::ContextTracker;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::LpmTrie;
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::Lsm;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bitblazr_common::models::BlazrEvent;
use bitblazr_common::rules::{
    BlazrOp, BlazrRule, BlazrRuleClass, BlazrRulesKey, SearchKey, TrieKey,
};
use bitblazr_common::{BlazrAction, BlazrEventType, OPS_PER_RULE, RULES_PER_KEY};
use bytes::BytesMut;
use std::collections::HashMap;
use std::result::Result;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, warn};

pub struct LsmTracepoints {
    labels_snd: Sender<PsLabels>,
}

impl LsmTracepoints {
    pub(crate) fn new(labels_snd: Sender<PsLabels>) -> LsmTracepoints {
        LsmTracepoints { labels_snd }
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> =
            bpf.take_map("LSM_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut lsm_buf = tp_array.open(cpu_id, Some(256))?;
            let th_ctx_tracker = ctx_tracker.clone();
            let thread_snd = snd.clone();
            let th_labels_snd = self.labels_snd.clone();
            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BlazrEvent>()); 100];

                loop {
                    // wait for events
                    let events = lsm_buf.read_events(&mut buffer).await?;

                    if events.lost > 0 {
                        warn!(target: "error", "Events lost in LSM_BUFFER: {}", events.lost);
                    }

                    for buf in buffer.iter_mut().take(events.read) {
                        let be: &mut BlazrEvent =
                            unsafe { &mut *(buf.as_ptr() as *mut BlazrEvent) };

                        th_ctx_tracker.process_event(be, th_labels_snd.clone());

                        if let Err(e) = thread_snd.send(be.clone()).await {
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
        const RULE_UNDEFINED: BlazrRule = BlazrRule {
            id: 0,
            class: BlazrRuleClass::Undefined,
            event: BlazrEventType::Undefined,
            context: [0; 5],
            ops: [-1; OPS_PER_RULE],
            ops_len: 0,
            action: BlazrAction::Undefined,
        };

        let mut map_rules: AyaHashMap<&mut MapData, BlazrRulesKey, [BlazrRule; RULES_PER_KEY]> =
            AyaHashMap::try_from(bpf.map_mut("LSM_RULES").unwrap()).unwrap();

        let (lsm_rules, shield_ops, search_keys, ip_ranges) =
            rules::load_kernel_rules("kernel", ctx_tracker.get_labels())?;

        let mut id_class = HashMap::new();
        for (_, rules) in lsm_rules.iter() {
            for r in rules {
                if id_class.contains_key(&r.id) {
                    panic!("This should never happen!");
                }

                id_class.insert(r.id, r.class);
            }
        }

        for (key, rules) in lsm_rules.into_iter() {
            let mut rules_buf = [RULE_UNDEFINED; RULES_PER_KEY];
            for (i, rule) in rules.into_iter().enumerate() {
                if i >= RULES_PER_KEY {
                    return Err(BSError::ArrayLimitReached {
                        attribute: "rules per key",
                        limit: RULES_PER_KEY,
                    }
                    .into());
                }
                rules_buf[i] = rule;
            }

            map_rules.insert(key, rules_buf, 0)?;
        }

        let mut array_rule_ops: Array<&mut MapData, BlazrOp> =
            Array::try_from(bpf.map_mut("LSM_RULE_OPS").unwrap()).unwrap();

        for (i, op) in shield_ops.into_iter().enumerate() {
            array_rule_ops.set(i as u32, op, 0)?;
        }

        let mut search_lists: LpmTrie<&mut MapData, SearchKey, u32> =
            LpmTrie::try_from(bpf.map_mut("LSM_SEARCH_LISTS").unwrap()).unwrap();

        for key in search_keys.into_iter() {
            search_lists.insert(&key, 1, 0)?;
        }

        let mut ip_lists: LpmTrie<&mut MapData, TrieKey, u32> =
            LpmTrie::try_from(bpf.map_mut("LSM_IP_LISTS").unwrap()).unwrap();

        for key in ip_ranges.into_iter() {
            ip_lists.insert(&key, 1, 0)?;
        }

        Ok(())
    }

    // Propogate labels back to kernel space
    pub(crate) fn run_labels_loop(mut bpf: Bpf, mut recv: Receiver<PsLabels>) {
        tokio::spawn(async move {
            let mut labels_map: AyaHashMap<&mut MapData, u32, [i64; 5]> =
                AyaHashMap::try_from(bpf.map_mut("LSM_CTX_LABELS").unwrap()).unwrap();

            loop {
                match recv.recv().await {
                    Some(ps_labels) => {
                        if ps_labels.pid == 0 {
                            continue;
                        } else if ps_labels.ppid == u32::MAX
                            && ps_labels.pid == u32::MAX
                            && ps_labels.labels[0] == i64::MAX
                        {
                            // Shutdown message received
                            break;
                        }
                        let mut new_labels = Vec::with_capacity(5);
                        let parent_labels = labels_map.get(&ps_labels.ppid, 0).unwrap_or([0; 5]);

                        let shared_labels = labels_map.get(&ps_labels.pid, 0).unwrap_or([0; 5]);

                        for l in parent_labels
                            .into_iter()
                            .chain(shared_labels.into_iter())
                            .chain(ps_labels.labels.into_iter())
                        {
                            if l != 0 && !new_labels.contains(&l) {
                                new_labels.push(l);
                            }
                        }

                        let mut parsed_labels = [0; 5];
                        for (i, l) in new_labels.into_iter().enumerate() {
                            if i >= 5 {
                                break;
                            }
                            parsed_labels[i] = l;
                        }

                        debug!(
                            "Inserting labels for pid: {}, labels: {:?}",
                            ps_labels.pid, parsed_labels
                        );
                        if let Err(e) = labels_map.insert(ps_labels.pid, parsed_labels, 0) {
                            error!("run_labels_loop: Could not insert new labels. Error: {}", e);
                        }
                    }
                    None => {
                        error!("run_labels_loop: Error in labels loop.");
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
        snd: Sender<BlazrEvent>,
        ctx_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        let btf = Btf::from_sys_fs()?;

        self.run(bpf, snd, ctx_tracker.clone())?;
        self.load_rules(bpf, ctx_tracker.clone())?;

        self.load_program(bpf, &btf, "file_open")?;
        self.load_program(bpf, &btf, "bprm_check_security")?;
        self.load_program(bpf, &btf, "socket_listen")?;
        self.load_program(bpf, &btf, "socket_connect")?;

        Ok(())
    }
}
