use std::collections::BTreeMap;

use aya::maps::perf::PerfBufferError;
use bpfshield_common::models::BShieldEvent;
use crossbeam_channel;

#[derive(Debug)]
pub struct BSProcess {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub children: Vec<u32>, // [pid,...]
}

pub struct BSProcessTracker {
    pub snd: crossbeam_channel::Sender<BShieldEvent>,
    tracker: BTreeMap<u32, BSProcess>,
}

impl BSProcessTracker {
    pub fn new() -> BSProcessTracker {
        let (snd, recv) = crossbeam_channel::bounded::<BShieldEvent>(100_000);

        let bes = BSProcessTracker {
            snd,
            tracker: BTreeMap::new(),
        };
        bes.run(recv);
        bes
    }

    pub fn run(&self, recv: crossbeam_channel::Receiver<BShieldEvent>) {
        tokio::spawn(async move {
            loop {
                if let Ok(msg) = recv.recv() {
                    println!("Got event: {:?}", msg);
                } else {
                    break;
                }
            }
            Ok::<_, PerfBufferError>(())
        });
    }
}
