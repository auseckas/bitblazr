extern crate crossbeam_channel;
extern crate serde_derive;
extern crate serde_json;

mod config;
mod errors;
mod loader;
mod logs;
pub mod probes;
mod rules;
mod tracker;
mod utils;

use aya::Bpf;
use tokio::signal;

use crate::loader::EbpfLoader;

use tracker::labels::ContextTracker;

use crate::probes::PsLabels;
use aya::maps::{Array, MapData};
use bitblazr_common::models::BlazrArch;
use bitblazr_common::rules::BlazrRuleVar;
use errors::BSError;
use logs::BlazrLogs;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = config::load_config()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let _logs = BlazrLogs::new(&config)?;

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let bpf_context = Arc::new(ContextTracker::new(&config)?);

    let event_loop = tracker::BSProcessTracker::new(bpf_context.clone())?;
    let bpf_loader = EbpfLoader::new(event_loop);

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load_file("probes/target/bpfel-unknown-none/debug/bitblazr-tracepoints")?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load_file("probes/target/bpfel-unknown-none/release/bitblazr-tracepoints")?;

    let mut tp_arch: Array<&mut MapData, BlazrArch> =
        Array::try_from(bpf.map_mut("TP_ARCH").unwrap()).unwrap();

    let arch = BlazrArch::from_str(std::env::consts::ARCH.to_string().as_mut_str());
    if arch.is_undefined() {
        error!(target: "error", "Usupported architecture: {}", std::env::consts::ARCH);
        return Ok(());
    }
    tp_arch.set(0, arch, 0)?;

    let (labels_snd, labels_recv) = crossbeam_channel::bounded::<PsLabels>(100);

    if Path::new("/sys/kernel/btf/vmlinux").exists() && config.features.tracepoints {
        bpf_loader.attach(
            &mut bpf,
            bpf_context.clone(),
            vec![Box::new(probes::btftracepoints::BtfTracepoints::new(
                &config,
                labels_snd.clone(),
            ))],
        )?;
    } else if config.features.tracepoints {
        error!(target: "error", "Syscalls FS directory missing. Attempting to fall back to raw syscalls");
        bpf_loader.attach(
            &mut bpf,
            bpf_context.clone(),
            vec![Box::new(probes::tracepoints::Tracepoints::new(
                &config,
                labels_snd.clone(),
            ))],
        )?;
    }

    let lsm_file = match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(s) => s,
        Err(_) => {
            error!(target: "error", "Cannot read '/sys/kernel/security/lsm' file, make sure the process is running with root privileges.");
            String::new()
        }
    };

    if lsm_file.contains("bpf") && config.features.lsm {
        #[cfg(debug_assertions)]
        let mut lsm_bpf = Bpf::load_file("probes/target/bpfel-unknown-none/debug/bitblazr-lsm")?;
        #[cfg(not(debug_assertions))]
        let mut lsm_bpf = Bpf::load_file("probes/target/bpfel-unknown-none/release/bitblazr-lsm")?;

        bpf_loader.attach(
            &mut lsm_bpf,
            bpf_context.clone(),
            vec![Box::new(probes::lsm::LsmTracepoints::new(
                labels_snd.clone(),
            ))],
        )?;
        probes::lsm::LsmTracepoints::run_labels_loop(lsm_bpf, labels_recv);
    } else {
        error!(target: "error", "LSM is disabled or kernel bpf extension is off. Skipping LSM modules");
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
