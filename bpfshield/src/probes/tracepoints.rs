use super::Probe;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::MapData;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bpfshield_common::models::BShieldEvent;
use bytes::BytesMut;
use log::warn;
use std::result::Result;

pub struct Tracepoints {}

impl Tracepoints {
    pub fn new() -> Tracepoints {
        Tracepoints {}
    }

    #[allow(unreachable_code)]
    fn run(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        let mut tp_array: AsyncPerfEventArray<_> = bpf.take_map("TP_BUFFER").unwrap().try_into()?;

        for cpu_id in online_cpus()? {
            let mut tp_buf = tp_array.open(cpu_id, Some(128))?;
            let thread_snd = snd.clone();

            tokio::spawn(async move {
                let mut buffer =
                    vec![BytesMut::with_capacity(core::mem::size_of::<BShieldEvent>()); 100];

                loop {
                    // wait for events
                    let events = tp_buf.read_events(&mut buffer).await?;

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

impl Probe for Tracepoints {
    fn init(
        &self,
        bpf: &mut Bpf,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        self.run(bpf, snd)?;

        let program: &mut TracePoint = bpf.program_mut("tracepoints").unwrap().try_into()?;
        program.load()?;

        program.attach("syscalls", "sys_enter_execve")?;

        Ok(())
    }
}
