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
use errors::BSError;
use logs::BShieldLogs;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info};

struct TestWriter;

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf_len = buf.len();

        println!("Blah: {}", String::from_utf8_lossy(buf));
        // io::stdout().write_all(buf).unwrap();
        Ok(buf_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = config::load_config()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let _logs = BShieldLogs::new(&config)?;

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

    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        // bpf_loader.attach(
        //     &mut bpf,
        //     bpf_context.clone(),
        //     vec![Box::new(probes::tracepoints::Tracepoints::new())],
        // )?;
        bpf_loader.attach(
            &mut bpf,
            bpf_context.clone(),
            vec![Box::new(probes::btftracepoints::BtfTracepoints::new())],
        )?;
    } else {
        error!(target: "error", "Syscalls FS directory missing. Attempting to fall back to Kprobes");
        bpf_loader.attach(
            &mut bpf,
            bpf_context.clone(),
            vec![Box::new(probes::tracepoints::Tracepoints::new())],
        )?;

        #[cfg(debug_assertions)]
        let mut kp_bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/debug/kprobes")?;
        #[cfg(not(debug_assertions))]
        let mut kp_bpf = Bpf::load_file("../../probes/target/bpfel-unknown-none/release/kprobes")?;

        bpf_loader.attach(
            &mut kp_bpf,
            bpf_context.clone(),
            vec![Box::new(probes::kprobes::BShielProbes::new())],
        )?;
    }

    let lsm_file = match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(s) => s,
        Err(_) => {
            error!(target: "error", "Cannot read '/sys/kernel/security/lsm' file, make sure the process is running with root privileges.");
            String::new()
        }
    };

    if lsm_file.contains("bpf") {
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
    } else {
        error!(target: "error", "LSM bpf extension is not enabled. Skipping LSM modules");
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
