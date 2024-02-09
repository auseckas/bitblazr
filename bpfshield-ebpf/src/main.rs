#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::helpers::bpf_probe_read_user_buf;
use aya_bpf::memcpy;
use vmlinux::{dentry, fdtable, file, task_struct};

use core::mem;
use core::str;

use aya_bpf::BpfContext;

use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use aya_bpf::{
    helpers::bpf_get_current_comm, helpers::bpf_get_current_pid_tgid, helpers::bpf_probe_read,
    helpers::bpf_probe_read_kernel_str_bytes, helpers::bpf_probe_read_user_str_bytes, macros::map,
    macros::tracepoint, programs::TracePointContext,
};
use aya_log_ebpf::info;
use core::ffi::{c_int, CStr};

use bpfshield_common::Syscall;

use crate::vmlinux::files_struct;

#[map]
pub static mut LOCAL_BUFFER: PerCpuArray<Syscall> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut PERF_ARRAY: PerfEventByteArray = PerfEventByteArray::new(0);

#[tracepoint]
pub fn bpfshield(ctx: TracePointContext) -> u32 {
    match try_bpfshield(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bpfshield(ctx: TracePointContext) -> Result<u32, u32> {
    let mut buf: [u8; 255] = [0; 255];

    info!(&ctx, "tracepoint sched_process_exec called");

    let tgid = ctx.tgid();
    let pid = ctx.pid();
    let uid = ctx.uid();
    let comm = ctx.command().map_err(|_| 1u32)?;

    // let ptr = unsafe { ctx.read_at::<*const u8>(16).map_err(|_| 1u32)? };
    // let f = unsafe { bpf_probe_read_user_str_bytes(ptr, &mut buf).map_err(|_| 1u32)? };
    let s = unsafe { core::str::from_utf8_unchecked(&comm) };

    let argv_p = unsafe { ctx.read_at::<*const *const u8>(24).map_err(|_| 1u32)? };

    // let arg1 = unsafe { bpf_probe_read(argv_p.offset(1)).map_err(|_| 1u32)? };

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let sc: &mut Syscall = unsafe { &mut *buf_ptr };

    // let argv_b = unsafe { bpf_probe_read_user_str_bytes(arg1, &mut buf).map_err(|_| 1u32)? };
    // let argv = unsafe { core::str::from_utf8_unchecked(argv_b) };

    sc.tgid = tgid;
    sc.pid = pid;
    sc.uid = uid;
    sc.gid = ctx.gid();

    let mut count = 0;
    let mut offset = 0;
    for i in 0..20 {
        unsafe {
            let res = bpf_probe_read(argv_p.offset(i)).map_err(|_| 1u32)?;
            if res.as_ref().is_none() {
                break;
            }

            let a =
                bpf_probe_read_user_str_bytes(res, &mut sc.argv[i as usize]).map_err(|_| 1u32)?;

            // offset += arg_len;

            // let argv = core::str::from_utf8_unchecked(a);

            // info!(&ctx, "Arg count: {}, s: {}", count, argv);
        }
        count += 1;
    }
    // sc.buf_len = offset as u32;

    unsafe {
        // bpf_probe_read_user_buf(argv_p as *const u8, &mut (sc.buf)).map_err(|_| 1u32)?;
        PERF_ARRAY.output(&ctx, sc.to_bytes(), 0);
    }

    // info!(
    //     &ctx,
    //     "uid: {}, tgid: {}, pid: {}, comm: {}, args: {}", uid, pid, pid, s, argv
    // );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
