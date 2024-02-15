use aya_bpf::BpfContext;

use aya_bpf::helpers::{bpf_d_path, bpf_probe_read_kernel_str_bytes};
use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use aya_bpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::debug;

use crate::vmlinux::{file, linux_binprm, path as lnx_path};

use aya_bpf::bindings::path;

use bpfshield_common::{BShieldAction, BShieldEvent, BShieldEventClass, BShieldEventType};

#[map]
static mut LOCAL_BUFFER_LSM: PerCpuArray<BShieldEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut LSM_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, BShieldEventType::Open) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, BShieldEventType::Bprm) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn process_lsm(ctx: LsmContext, et: BShieldEventType) -> Result<i32, i32> {
    debug!(&ctx, "lsm tracepoint called, call_type: {}", et as u16);

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BShieldEvent = unsafe { &mut *buf_ptr };

    be.class = BShieldEventClass::Lsm;
    be.ppid = None;
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();

    match et {
        BShieldEventType::Open => process_lsm_file(ctx, be, et),
        BShieldEventType::Bprm => process_lsm_binprm(ctx, be, et),
        _ => Ok(0),
    }
}

fn process_lsm_file(
    ctx: LsmContext,
    be: &mut BShieldEvent,
    et: BShieldEventType,
) -> Result<i32, i32> {
    let f: *const file = unsafe { ctx.arg(0) };
    let p: *const lnx_path = unsafe { &(*f).f_path };

    be.event_type = et;
    be.action = BShieldAction::Allow;

    let _ = unsafe {
        bpf_d_path(
            p as *mut path,
            be.path.as_mut_ptr() as *mut i8,
            be.path.len() as u32,
        )
    };

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

fn process_lsm_binprm(
    ctx: LsmContext,
    be: &mut BShieldEvent,
    et: BShieldEventType,
) -> Result<i32, i32> {
    let lb: *const linux_binprm = unsafe { ctx.arg(0) };

    be.event_type = et;
    be.action = BShieldAction::Allow;

    unsafe {
        bpf_probe_read_kernel_str_bytes((*lb).filename as *const u8, &mut be.path)
            .map_err(|_| 0i32)?
    };

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}
