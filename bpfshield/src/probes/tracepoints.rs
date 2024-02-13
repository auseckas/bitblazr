use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::maps::MapData;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bpfshield_common::{utils::str_from_buf_nul, Syscall};
use bytes::BytesMut;
use std::result::Result;

pub struct Tracepoints {}

impl Tracepoints {
    pub fn init(bpf: &mut Bpf) -> Result<Tracepoints, anyhow::Error> {
        let tp_array = AsyncPerfEventArray::try_from(bpf.take_map("TP_BUFFER").unwrap())?;

        let tps = Tracepoints {};
        tps.run(tp_array)?;

        let program: &mut TracePoint = bpf.program_mut("tracepoints").unwrap().try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_execve")?;

        Ok(tps)
    }

    fn run(&self, mut tp_array: AsyncPerfEventArray<MapData>) -> Result<(), anyhow::Error> {
        for cpu_id in online_cpus()? {
            let mut buf = tp_array.open(cpu_id, None)?;

            tokio::spawn(async move {
                let mut buffers = (0..20)
                    .map(|_| BytesMut::with_capacity(core::mem::size_of::<Syscall>()))
                    .collect::<Vec<_>>();

                loop {
                    // wait for events
                    let events = buf.read_events(&mut buffers).await?;

                    for i in 0..events.read {
                        let buf = &mut buffers[i];
                        let sc: &Syscall = unsafe { &*(buf.as_ptr() as *const Syscall) };

                        println!("PID: {}, Arg Count: {}, Args:", sc.pid, sc.argv_count);
                        for i in 0..sc.argv_count {
                            println!("Arg: {:?}", str_from_buf_nul(&sc.argv[i as usize]));
                        }
                    }
                }
                Ok::<_, PerfBufferError>(())
            });
        }
        Ok(())
    }
}
