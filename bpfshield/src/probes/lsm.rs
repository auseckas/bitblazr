use super::Probe;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::MapData;
use aya::programs::Lsm;
use aya::util::online_cpus;
use aya::{Bpf, Btf};
use bpfshield_common::models::BShieldEvent;
use bytes::BytesMut;
use log::warn;
use std::result::Result;

pub struct LsmTracepoints {}

impl LsmTracepoints {
    pub fn new() -> LsmTracepoints {
        LsmTracepoints {}
    }

    fn run(
        &self,
        mut tp_array: AsyncPerfEventArray<MapData>,
        snd: crossbeam_channel::Sender<BShieldEvent>,
    ) -> Result<(), anyhow::Error> {
        for cpu_id in online_cpus()? {
            let mut buf = tp_array.open(cpu_id, None)?;

            let thread_snd = snd.clone();
            tokio::spawn(async move {
                let mut buffers = (0..20)
                    .map(|_| BytesMut::with_capacity(core::mem::size_of::<BShieldEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    // wait for events
                    let events = buf.read_events(&mut buffers).await?;

                    for i in 0..events.read {
                        let buf = &mut buffers[i];
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
        let tp_array = AsyncPerfEventArray::try_from(bpf.take_map("LSM_BUFFER").unwrap())?;

        self.run(tp_array, snd)?;

        self.load_program(bpf, &btf, "file_open")?;
        self.load_program(bpf, &btf, "bprm_check_security")?;

        Ok(())
    }
}
