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

                        // println!("PID: {}, Arg Count: {}, Args:", sc.pid, sc.argv_count);
                        // for i in 0..sc.argv_count {
                        //     println!("Arg: {:?}", str_from_buf_nul(&sc.argv[i as usize]));
                        // }
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
        let tp_array = AsyncPerfEventArray::try_from(bpf.take_map("TP_BUFFER").unwrap())?;

        self.run(tp_array, snd)?;

        let program: &mut TracePoint = bpf.program_mut("tracepoints").unwrap().try_into()?;
        program.load()?;

        program.attach("syscalls", "sys_enter_execve")?;

        Ok(())
    }
}
