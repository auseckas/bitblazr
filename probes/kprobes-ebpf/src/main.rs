#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::BpfContext;

use aya_bpf::helpers::{
    bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_str,
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
};
use aya_bpf::{macros::kprobe, macros::map, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::debug;

use crate::vmlinux::{filename, task_struct};
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::maps::PerCpuArray;
use aya_bpf::maps::PerfEventByteArray;
use aya_bpf::programs::ProbeContext;
use aya_bpf::PtRegs;
use aya_log_ebpf::info;
use bpfshield_common::rules::BShieldRuleClass;
use bpfshield_common::{BShieldAction, BShieldEvent, BShieldEventClass, BShieldEventType};

#[map]
pub(crate) static mut LOCAL_BUFFER: PerCpuArray<BShieldEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut KPROBE_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[kprobe]
pub fn bshield_open(ctx: ProbeContext) -> u32 {
    match try_open(ctx, 0) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

#[kprobe]
pub fn bshield_openat(ctx: ProbeContext) -> u32 {
    match try_open(ctx, 1) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn process_be(ctx: &ProbeContext, be: &mut BShieldEvent) -> Result<(), i32> {
    debug!(ctx, "lsm tracepoint called");

    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let parent: *const task_struct = unsafe { bpf_probe_read(&(*task).parent).map_err(|_| 0i32)? };
    let ppid = unsafe { bpf_probe_read(&(*parent).pid).map_err(|_| 0i32)? };

    let mut p_comm = ctx.command().map_err(|_| 0i32)?;
    unsafe {
        bpf_probe_read_kernel_str_bytes(p_comm.as_mut_ptr(), &mut be.p_path).map_err(|_| 0i32)?
    };

    be.class = BShieldEventClass::Lsm;
    be.ppid = Some(ppid as u32);
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.protocol = 0;
    be.port = 0;
    be.action = BShieldAction::Allow;
    be.path_len = 0;

    Ok(())
}

fn try_open(ctx: ProbeContext, fname_offset: usize) -> Result<u32, i64> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let f_name: *const u8 = regs.arg(fname_offset).ok_or(1u32)?;

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let mut be: &mut BShieldEvent = unsafe { &mut *buf_ptr };
    process_be(&ctx, &mut be)?;

    // info!(&ctx, "Got here");

    let res = unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };
    // info!(&ctx, "Got here 1");

    if res.starts_with(b"/proc/sys") || res.starts_with(b"/etc") {
        info!(
            &ctx,
            "Kprobe comm: {} path: {}",
            unsafe { core::str::from_utf8_unchecked(&be.p_path) },
            unsafe { core::str::from_utf8_unchecked(res) }
        );
    }

    unsafe {
        KPROBE_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
