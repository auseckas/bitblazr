use aya::{Bpf, BpfLoader};
use log::{debug, info, warn};
use tokio::signal;

use crate::loader::EbpfLoader;

extern crate crossbeam_channel;
extern crate serde_derive;

mod config;
mod events;
mod loader;
pub mod probes;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    config::load_config()?;

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

    let event_loop = events::BpfShieldEvents::new();
    let bpf_loader = EbpfLoader::new(event_loop);

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/debug/tracepoints")?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../probes/target/bpfel-unknown-none/release/tracepoints"
    ))?;

    bpf_loader.attach(
        &mut bpf,
        vec![
            Box::new(probes::tracepoints::Tracepoints::new()),
            Box::new(probes::btftracepoints::BtfTracepoints::new()),
        ],
    )?;

    #[cfg(debug_assertions)]
    let mut lsm_bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/debug/lsm")?;
    #[cfg(not(debug_assertions))]
    let mut lsm_bpf = Bpf::load(include_bytes_aligned!(
        "../../../probes/target/bpfel-unknown-none/release/lsm"
    ))?;

    bpf_loader.attach(
        &mut lsm_bpf,
        vec![Box::new(probes::lsm::LsmTracepoints::new())],
    )?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
