use aya_bpf::BpfContext;

use aya_bpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_bpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::debug;

use crate::common::read_list_u8;
use crate::maps;
use bpfshield_common::{BShieldAction, BShieldEvent, BShieldEventClass, BShieldEventType};

#[tracepoint]
pub fn tracepoints(ctx: TracePointContext) -> u32 {
    match try_tps(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tps(ctx: TracePointContext) -> Result<u32, u32> {
    debug!(&ctx, "tracepoint called");

    let comm = ctx.command().map_err(|_| 1u32)?;

    let buf_ptr = unsafe { maps::LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let be: &mut BShieldEvent = unsafe { &mut *buf_ptr };

    be.class = BShieldEventClass::Tracepoint;
    be.event_type = BShieldEventType::Exec;
    be.ppid = None;
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.action = BShieldAction::Allow;

    unsafe { bpf_probe_read_kernel_str_bytes(comm.as_ptr(), &mut be.path).map_err(|_| 1u32)? };

    let argv_p = unsafe { ctx.read_at::<*const *const u8>(24).map_err(|_| 1u32)? };
    be.argv_count = read_list_u8(argv_p, &mut be.argv)?;

    unsafe {
        maps::TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}
