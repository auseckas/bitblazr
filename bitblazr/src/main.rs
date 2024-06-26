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
use bitblazr_common::models::{BlazrArch, BlazrKernelVersion, BlazrSysInfo};
use bitblazr_common::rules::BlazrRuleVar;
use clap::Parser;
use errors::BSError;
use logs::BlazrLogs;
use semver::{Prerelease, Version, VersionReq};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct BlazrArgs {
    /// Sensor name
    #[arg(short, long, default_value_t = String::new())]
    name: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = BlazrArgs::parse();
    let config = config::load_config()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let _logs = BlazrLogs::new(&config, &args.name)?;

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let bpf_context = Arc::new(ContextTracker::new(&config)?);

    let event_loop = tracker::BSProcessTracker::new(bpf_context.clone(), args.name.as_str())?;
    let bpf_loader = EbpfLoader::new(event_loop);

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load_file("probes/target/bpfel-unknown-none/debug/bitblazr-tracepoints")?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load_file("probes/target/bpfel-unknown-none/release/bitblazr-tracepoints")?;

    let mut tp_arch: Array<&mut MapData, BlazrSysInfo> =
        Array::try_from(bpf.map_mut("TP_SYSINFO").unwrap()).unwrap();

    let arch = BlazrArch::from_str(std::env::consts::ARCH.to_string().as_mut_str());
    if arch.is_undefined() {
        error!(target: "error", "Usupported architecture: {}", std::env::consts::ARCH);
        return Ok(());
    }

    let mut sys_info = BlazrSysInfo {
        arch: arch,
        kernel_ver: BlazrKernelVersion::Default,
    };

    let mut kernel_ver = Version::parse(&System::kernel_version().unwrap_or(String::new()))?;
    kernel_ver.pre = Prerelease::new("")?;
    let six_nine_plus = VersionReq::parse(">=6.9.0")?;

    sys_info.kernel_ver = {
        if six_nine_plus.matches(&kernel_ver) {
            BlazrKernelVersion::SixNinePlus
        } else {
            BlazrKernelVersion::Default
        }
    };
    tp_arch.set(0, sys_info, 0)?;

    let (labels_snd, labels_recv) = mpsc::channel::<PsLabels>(100);

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

        let mut tp_arch: Array<&mut MapData, BlazrSysInfo> =
            Array::try_from(lsm_bpf.map_mut("TP_SYSINFO").unwrap()).unwrap();

        tp_arch.set(0, sys_info, 0)?;

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
    warn!("Ctrl-C signal received");
    // Send shutdown message
    let _ = labels_snd.try_send(PsLabels {
        ppid: u32::MAX,
        pid: u32::MAX,
        labels: [i64::MAX; 5],
    });
    warn!("Exiting...");

    Ok(())
}
