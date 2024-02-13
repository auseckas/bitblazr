use aya_bpf::BpfContext;

use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use aya_bpf::{macros::map, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

use crate::common::read_list_u8;
use bpfshield_common::Syscall;

#[map]
static mut LOCAL_BUFFER: PerCpuArray<Syscall> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut TP_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[tracepoint]
pub fn tracepoints(ctx: TracePointContext) -> u32 {
    match try_tps(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tps(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint syscalls called");

    // let comm = ctx.command().map_err(|_| 1u32)?;

    // let s = unsafe { core::str::from_utf8_unchecked(&comm) };
    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let sc: &mut Syscall = unsafe { &mut *buf_ptr };

    sc.tgid = ctx.tgid();
    sc.pid = ctx.pid();
    sc.uid = ctx.uid();
    sc.gid = ctx.gid();

    let argv_p = unsafe { ctx.read_at::<*const *const u8>(24).map_err(|_| 1u32)? };
    sc.argv_count = read_list_u8(argv_p, &mut sc.argv)?;

    let enpv_p = unsafe { ctx.read_at::<*const *const u8>(32).map_err(|_| 1u32)? };
    sc.envp_count = read_list_u8(enpv_p, &mut sc.envp)?;

    unsafe {
        TP_BUFFER.output(&ctx, sc.to_bytes(), 0);
    }

    Ok(0)
}
