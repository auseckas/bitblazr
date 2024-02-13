use crate::probes::load_probes;
use aya::Bpf;
use aya_log::BpfLogger;
use log::{debug, info, warn};
use tokio::signal;

pub mod probes;

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

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/debug/tracepoints")?;
    // let mut bpf = Bpf::load(include_bytes_aligned!(
    //     "../../../probes/target/bpfel-unknown-none/debug/tracepoints"
    // ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../probes/target/bpfel-unknown-none/release/tracepoints"
    ))?;

    load_probes(&mut bpf)?;
    BpfLogger::init(&mut bpf)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
