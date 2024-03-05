use crate::vmlinux::task_struct;

use aya_bpf::BpfContext;

use aya_bpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::debug;

use bpfshield_common::rules::BShieldRuleClass;
use bpfshield_common::{BShieldAction, BShieldEvent, BShieldEventClass, BShieldEventType};

use crate::common::{LOCAL_BUFFER, TP_BUFFER};

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    match try_spe(ctx, BShieldEventType::Exec) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> u32 {
    match try_spe(ctx, BShieldEventType::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_spe(ctx: BtfTracePointContext, event_type: BShieldEventType) -> Result<u32, u32> {
    debug!(
        &ctx,
        "btf tracepoint called, call_type: {}", event_type as u16
    );

    let task: *const task_struct = unsafe { ctx.arg(0) };

    let ppid = unsafe { (*(*task).parent).pid };

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let be: &mut BShieldEvent = unsafe { &mut *buf_ptr };

    be.class = BShieldEventClass::BtfTracepoint;
    be.event_type = event_type;
    be.ppid = Some(ppid as u32);
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.action = BShieldAction::Allow;
    be.log_class = BShieldRuleClass::File;

    unsafe {
        TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}
