use aya::Bpf;
use log::{debug, info};
use tokio::signal;

use crate::loader::EbpfLoader;

extern crate crossbeam_channel;
extern crate serde_derive;
extern crate serde_json;

mod config;
mod errors;
mod loader;
pub mod probes;
mod rules;
mod tracker;
mod utils;

use tracker::labels::ContextTracker;

use crate::probes::PsLabels;
use errors::BSError;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let config = config::load_config()?;

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

    let bpf_context = Arc::new(ContextTracker::new(&config)?);

    let event_loop = tracker::BSProcessTracker::new(bpf_context.clone())?;
    let bpf_loader = EbpfLoader::new(event_loop);

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/debug/tracepoints")?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/release/tracepoints")?;

    bpf_loader.attach(
        &mut bpf,
        bpf_context.clone(),
        vec![
            Box::new(probes::tracepoints::Tracepoints::new()),
            Box::new(probes::btftracepoints::BtfTracepoints::new()),
        ],
    )?;

    #[cfg(debug_assertions)]
    let mut lsm_bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/debug/lsm")?;
    #[cfg(not(debug_assertions))]
    let mut lsm_bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/release/lsm")?;

    let (labels_snd, labels_recv) = crossbeam_channel::bounded::<PsLabels>(100);

    bpf_loader.attach(
        &mut lsm_bpf,
        bpf_context.clone(),
        vec![Box::new(probes::lsm::LsmTracepoints::new(
            labels_snd.clone(),
        ))],
    )?;

    probes::lsm::LsmTracepoints::run_labels_loop(lsm_bpf, labels_recv);

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
