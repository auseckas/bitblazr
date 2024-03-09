use super::Probe;
use crate::ContextTracker;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::util::syscall_prefix;
use aya::Bpf;
use bpfshield_common::models::BShieldEvent;
use bytes::BytesMut;
use std::result::Result;
use std::sync::Arc;
use tracing::warn;

pub struct BShielProbes {}

impl BShielProbes {
    pub fn new() -> BShielProbes {
        BShielProbes {}
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        let mut kp_array: AsyncPerfEventArray<_> =
            bpf.take_map("KPROBE_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut kp_buf = kp_array.open(cpu_id, Some(128))?;
            let thread_snd = snd.clone();

            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BShieldEvent>()); 100];

                loop {
                    // wait for events
                    let events = kp_buf.read_events(&mut buffer).await?;

                    for i in 0..events.read {
                        let buf = &mut buffer[i];
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
}

impl Probe for BShielProbes {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
        _cxt_tracker: Arc<ContextTracker>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd)?;

        if let Ok(sys_prefix) = syscall_prefix() {
            let mut program: &mut aya::programs::KProbe =
                bpf.program_mut("bshield_open").unwrap().try_into()?;
            program.load()?;

            program.attach(format!("{}open", sys_prefix), 0).unwrap();

            program = bpf.program_mut("bshield_openat").unwrap().try_into()?;
            program.load()?;

            program.attach(format!("{}openat", sys_prefix), 0).unwrap();
        }

        Ok(())
    }
}
