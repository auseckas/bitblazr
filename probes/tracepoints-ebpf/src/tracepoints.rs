use aya_bpf::BpfContext;

use aya_bpf::helpers::{
    bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_str_bytes,
    bpf_probe_read_user_str_bytes,
};
use aya_bpf::{macros::kprobe, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::{debug, info};

use crate::common::{LOCAL_BUFFER, TP_ARCH, TP_BUFFER};
// use crate::vmlinux::task_struct;
use bpfshield_common::models::BShieldArch;
use bpfshield_common::rules::BShieldRuleClass;
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

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let be: &mut BShieldEvent = unsafe { &mut *buf_ptr };

    be.class = BShieldEventClass::Tracepoint;
    be.event_type = BShieldEventType::Exec;
    be.ppid = None;
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.action = BShieldAction::Allow;
    be.log_class = BShieldRuleClass::File;

    let arch = unsafe { TP_ARCH.get(0).ok_or(1u32)? };

    let (syscall_id_open, syscall_id_openat) = match arch {
        BShieldArch::X86_64 => (2, 257),
        BShieldArch::Aarch64 => (0xffff, 56),
        _ => return Ok(1),
    };

    // let syscall_id = match arch {
    //     ARCH_X86_64 => 257,
    //     ARCH_ARM64 => 56,
    //     _ => return Ok(1),
    // };

    // let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    // let parent: *const task_struct = unsafe { bpf_probe_read(&(*task).parent).map_err(|_| 1u32)? };
    // be.ppid = Some(unsafe { bpf_probe_read(&(*parent).pid).map_err(|_| 1u32)? } as u32);

    let mut p_comm = ctx.command().map_err(|_| 1u32)?;
    unsafe {
        bpf_probe_read_kernel_str_bytes(p_comm.as_mut_ptr(), &mut be.p_path).map_err(|_| 1u32)?
    };

    let call_id: i64 = unsafe { ctx.read_at::<i64>(8).map_err(|_| 1u32)? };

    if call_id == syscall_id_openat {
        let args: [u64; 6] = unsafe { ctx.read_at::<[u64; 6]>(16).map_err(|_| 1u32)? };

        let f_name = args[1] as *const u8;
        let res = unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

        if be.path.starts_with(b"/etc") {
            info!(
                &ctx,
                "Arch: {}, Call ID: {}, {}",
                *arch as i8,
                call_id,
                unsafe { core::str::from_utf8_unchecked(&be.path) }
            );
        }
        // info!(&ctx, "Call ID: {}, {}", call_id, args[1]);
    }

    // let argv_p = unsafe { ctx.read_at::<*const *const u8>(24).map_err(|_| 1u32)? };
    // be.argv_count = read_list_u8(argv_p, &mut be.argv)?;

    unsafe {
        // TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}
