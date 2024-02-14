use aya_bpf::BpfContext;

use aya_bpf::helpers::{bpf_d_path, bpf_probe_read, bpf_probe_read_kernel_str_bytes};
use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use aya_bpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::info;

use crate::vmlinux::{dentry, file, linux_binprm, path as lnx_path};

use aya_bpf::bindings::path;

use bpfshield_common::{LsmAction, LsmEventType, LsmTraceEvent};

#[map]
static mut LOCAL_BUFFER_LSM: PerCpuArray<LsmTraceEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut LSM_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, LsmEventType::Open) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, LsmEventType::Bprm) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn process_lsm(ctx: LsmContext, et: LsmEventType) -> Result<i32, i32> {
    match et {
        LsmEventType::Open => process_lsm_file(ctx, et),
        LsmEventType::Bprm => process_lsm_binprm(ctx, et),
    }
}

fn process_lsm_file(ctx: LsmContext, et: LsmEventType) -> Result<i32, i32> {
    let f: *const file = unsafe { ctx.arg(0) };
    let p: *const lnx_path = unsafe { &(*f).f_path };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let lsm_te: &mut LsmTraceEvent = unsafe { &mut *buf_ptr };

    lsm_te.event_type = et;
    lsm_te.pid = ctx.pid();
    lsm_te.uid = ctx.uid();
    lsm_te.gid = ctx.gid();

    let len = unsafe {
        bpf_d_path(
            p as *mut path,
            lsm_te.path.as_mut_ptr() as *mut i8,
            lsm_te.path.len() as u32,
        )
    };

    unsafe {
        LSM_BUFFER.output(&ctx, lsm_te.to_bytes(), 0);
    }

    Ok(0)
}

fn process_lsm_binprm(ctx: LsmContext, et: LsmEventType) -> Result<i32, i32> {
    let lb: *const linux_binprm = unsafe { ctx.arg(0) };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let mut lsm_te: &mut LsmTraceEvent = unsafe { &mut *buf_ptr };

    lsm_te.event_type = et;
    lsm_te.pid = ctx.pid();
    lsm_te.uid = ctx.uid();
    lsm_te.gid = ctx.gid();

    unsafe {
        bpf_probe_read_kernel_str_bytes((*lb).filename as *const u8, &mut lsm_te.path)
            .map_err(|_| 0i32)?
    };

    let path = unsafe { core::str::from_utf8_unchecked(&lsm_te.path) };

    unsafe {
        LSM_BUFFER.output(&ctx, lsm_te.to_bytes(), 0);
    }

    Ok(0)
}
