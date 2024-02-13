use aya_bpf::BpfContext;

use aya_bpf::helpers::{bpf_d_path, bpf_probe_read, bpf_probe_read_kernel_str_bytes};
use aya_bpf::maps::{PerCpuArray, PerfEventByteArray};
use aya_bpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::info;

use crate::vmlinux::{dentry, file, path as lnx_path};

use aya_bpf::bindings::path;

use bpfshield_common::Syscall;

#[map]
static mut LOCAL_BUFFER_LSM: PerCpuArray<Syscall> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut LSM_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn process_lsm(ctx: LsmContext) -> Result<i32, i32> {
    let mut buf: [u8; 255] = [0; 255];
    let pid = ctx.pid();
    // info!(&ctx, "lsm tracepoint called");
    let p = unsafe {
        let f: *const file = ctx.arg(0);
        let p: *const lnx_path = &(*f).f_path;

        let len = bpf_d_path(
            p as *mut path,
            buf.as_mut_ptr() as *mut i8,
            buf.len() as u32,
        );
        let path = unsafe { core::str::from_utf8_unchecked(&buf) };
        // if path.starts_with("/etc") {
        //     info!(
        //         &ctx,
        //         "lsm tracepoint called, pid: {}, path: {}, len: {}", pid, path, len
        //     );
        // }
    };

    Ok(0)
}
