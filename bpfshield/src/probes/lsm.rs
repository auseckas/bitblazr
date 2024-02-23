use super::Probe;
use crate::rules;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::Lsm;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bpfshield_common::models::BShieldEvent;
use bpfshield_common::rules::{
    BSRuleClass, BSRuleCommand, BSRuleTarget, BShieldOp, BShieldRule, BShieldRules,
    BShieldRulesKey, BShieldVar,
};
use bpfshield_common::{BShieldAction, BShieldEventType};
use bytes::BytesMut;
use log::warn;
use std::collections::HashMap;
use std::result::Result;

pub struct LsmTracepoints {}

impl LsmTracepoints {
    pub fn new() -> LsmTracepoints {
        LsmTracepoints {}
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> =
            bpf.take_map("LSM_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut lsm_buf = tp_array.open(cpu_id, Some(128))?;

            let thread_snd = snd.clone();
            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BShieldEvent>()); 100];

                loop {
                    // wait for events
                    let events = lsm_buf.read_events(&mut buffer).await?;

                    if events.lost > 0 {
                        warn!("Events lost in LSM_BUFFER: {}", events.lost);
                    }

                    for buf in buffer.iter().take(events.read) {
                        let be: &BShieldEvent = unsafe { &*(buf.as_ptr() as *const BShieldEvent) };
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

    fn load_rules(&self, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
        const RULE_UNDEFINED: BShieldRule = BShieldRule {
            class: BSRuleClass::Undefined,
            event: BShieldEventType::Undefined,
            ops: [-1; 25],
            action: BShieldAction::Undefined,
        };

        let mut map_rules: AyaHashMap<&mut MapData, BShieldRulesKey, [BShieldRule; 25]> =
            AyaHashMap::try_from(bpf.map_mut("LSM_RULES").unwrap()).unwrap();

        let (lsm_rules, shield_ops) = rules::load_rules()?;
        for (key, rules) in lsm_rules.into_iter() {
            let mut rules_buf = [RULE_UNDEFINED; 25];
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
}

impl Probe for LsmTracepoints {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        let btf = Btf::from_sys_fs()?;

        self.run(bpf, snd)?;
        self.load_rules(bpf)?;

        self.load_program(bpf, &btf, "file_open")?;
        self.load_program(bpf, &btf, "bprm_check_security")?;
        self.load_program(bpf, &btf, "socket_listen")?;

        Ok(())
    }
}
