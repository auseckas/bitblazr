use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bpfshield_common::{Syscall, utils::str_from_buf_nul};
use log::{info, warn, debug};
use tokio::signal;
use aya::maps::perf::{AsyncPerfEventArray, PerfBufferError};
use aya::util::online_cpus;
use bytes::BytesMut;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
   

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bpfshield"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bpfshield"
    ))?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("PERF_ARRAY").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

     tokio::spawn(async move {
         let mut buffers = (0..20)
             .map(|_| BytesMut::with_capacity(core::mem::size_of::<Syscall>()))
             .collect::<Vec<_>>();

         loop {
            // wait for events
             let events = buf.read_events(&mut buffers).await?;

             // events.read contains the number of events that have been read,
             // and is always <= buffers.len()
             for i in 0..events.read {
                 let buf = &mut buffers[i];
                 let sc: &Syscall = unsafe { &*(buf.as_ptr() as *const Syscall) };

                for arg in sc.argv {
                    if arg[0] != 0x00 {
                      println!("Arg: {:?}", str_from_buf_nul(&arg) );
                    }
                }

                //  println!("Syscall: {:?}", sc);

                 // process buf
             }
         }

         Ok::<_, PerfBufferError>(())
     });
    }
        
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut TracePoint = bpf.program_mut("bpfshield").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
