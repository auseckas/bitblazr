use crate::vmlinux::task_struct;

use aya_bpf::BpfContext;

use aya_bpf::helpers::bpf_probe_read_user_str_bytes;
use aya_bpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::{debug, info};

use bitblazr_common::rules::BlazrRuleClass;
use bitblazr_common::{BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType, ARGV_COUNT};

use crate::common::read_list_u8;
use crate::common::{LOCAL_BUFFER, TP_BUFFER};
use aya_bpf::PtRegs;

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    match try_spe(ctx, BlazrEventType::Exec) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> u32 {
    match try_spe(ctx, BlazrEventType::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "sys_enter")]
pub fn sys_enter(ctx: BtfTracePointContext) -> u32 {
    match process_sys_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_spe(ctx: BtfTracePointContext, event_type: BlazrEventType) -> Result<u32, u32> {
    debug!(
        &ctx,
        "btf tracepoint called, call_type: {}", event_type as u16
    );

    let task: *const task_struct = unsafe { ctx.arg(0) };

    let ppid = unsafe { (*(*task).parent).pid };

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    be.class = BlazrEventClass::BtfTracepoint;
    be.event_type = event_type;
    be.ppid = Some(ppid as u32);
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.action = BlazrAction::Allow;
    be.log_class = BlazrRuleClass::File;

    let mut argv_p: *const u8 = unsafe { (*(*task).mm).__bindgen_anon_1.arg_start as *const u8 };
    let mut argv_p_end: *const u8 = unsafe { (*(*task).mm).__bindgen_anon_1.arg_end as *const u8 };

    let mut count = 0;
    let mut offset = 0;
    for i in 0..ARGV_COUNT as isize {
        let ptr = unsafe { argv_p.offset(offset) };
        if ptr >= argv_p_end {
            break;
        }
        let r = unsafe {
            bpf_probe_read_user_str_bytes(ptr, &mut be.argv[i as usize]).map_err(|_| 1u32)?
        };
        let len = r.len();

        if len == 0 {
            break;
        }
        count += 1;
        offset += len as isize + 1;
    }

    be.argv_count = count;
    unsafe {
        TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

fn process_sys_enter(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let pt_regs = unsafe {
        PtRegs::new(
            ctx.arg::<*const aya_bpf::bindings::pt_regs>(0) as *mut aya_bpf::bindings::pt_regs
        )
    };
    let call_id: i64 = unsafe { ctx.arg(1) };

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    if call_id == 257 {
        let f_name: *const u8 = pt_regs.arg(1).ok_or(1u32)?;
        let res = unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

        if be.path.starts_with(b"/etc") {
            info!(
                &ctx,
                "Arch: , Call ID: {}, {}",
                // *arch as i8,
                call_id,
                unsafe { core::str::from_utf8_unchecked(&be.path) }
            );
        }
    }

    Ok(1)
}
