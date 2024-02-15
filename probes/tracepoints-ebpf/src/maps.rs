use aya_bpf::macros::map;
use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use bpfshield_common::BShieldEvent;

#[map]
pub(crate) static mut LOCAL_BUFFER: PerCpuArray<BShieldEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut TP_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);
