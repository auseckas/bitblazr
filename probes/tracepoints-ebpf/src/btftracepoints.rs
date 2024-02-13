use crate::vmlinux::task_struct;

use aya_bpf::BpfContext;

use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use aya_bpf::{
    helpers::bpf_get_current_comm, macros::btf_tracepoint, macros::map,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::info;

use bpfshield_common::{BtfEventType, BtfTraceEvent};

#[map]
static mut LOCAL_BUFFER_BTF: PerCpuArray<BtfTraceEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut BTP_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    match try_spe(ctx, BtfEventType::Exec) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> u32 {
    match try_spe(ctx, BtfEventType::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_spe(ctx: BtfTracePointContext, event_type: BtfEventType) -> Result<u32, u32> {
    info!(&ctx, "btf tracepoint called");

    let task: *const task_struct = unsafe { ctx.arg(0) };

    let ppid = unsafe { (*(*task).parent).pid };

    let buf_ptr = unsafe { LOCAL_BUFFER_BTF.get_ptr_mut(0).ok_or(1u32)? };
    let bte: &mut BtfTraceEvent = unsafe { &mut *buf_ptr };

    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    info!(&ctx, "Comm: {}", unsafe {
        core::str::from_utf8_unchecked(&comm)
    });

    bte.event_type = event_type;
    bte.ppid = ppid as u32;
    bte.pid = ctx.pid();
    bte.uid = ctx.uid();
    bte.gid = ctx.gid();

    unsafe {
        BTP_BUFFER.output(&ctx, bte.to_bytes(), 0);
    }

    Ok(0)
}
