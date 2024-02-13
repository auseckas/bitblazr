use aya::maps::perf::PerfBufferError;
use crossbeam_channel;

#[derive(Debug)]
pub enum EbpfEventType {
    Exec,
    Open,
}

#[derive(Debug)]
pub struct EbpfEvent {
    pub ppid: Option<u32>,
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub event: EbpfEventType,
}

pub struct BpfShieldEvents {
    pub snd: crossbeam_channel::Sender<EbpfEvent>,
}

impl BpfShieldEvents {
    pub fn new() -> BpfShieldEvents {
        let (snd, recv) = crossbeam_channel::bounded::<EbpfEvent>(100_000);

        let bes = BpfShieldEvents { snd };
        bes.run(recv);
        bes
    }

    pub fn run(&self, recv: crossbeam_channel::Receiver<EbpfEvent>) {
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
