use super::Probe;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::MapData;
use aya::programs::Lsm;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bpfshield_common::models::BShieldEvent;
use bpfshield_common::BShieldEventType;
use bytes::BytesMut;
use log::warn;
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
}

impl Probe for LsmTracepoints {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        let btf = Btf::from_sys_fs()?;

        self.run(bpf, snd)?;

        self.load_program(bpf, &btf, "file_open")?;
        self.load_program(bpf, &btf, "bprm_check_security")?;
        self.load_program(bpf, &btf, "socket_listen")?;

        Ok(())
    }
}
