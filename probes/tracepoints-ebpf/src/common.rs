use aya_bpf::macros::map;
use aya_bpf::maps::{Array, PerCpuArray};
use aya_bpf::{helpers::bpf_probe_read, helpers::bpf_probe_read_user_str_bytes};
use bitblazr_common::models::BlazrArch;
use bitblazr_common::{BlazrEvent, ARGV_COUNT};

#[map]
pub(crate) static mut LOCAL_BUFFER: PerCpuArray<BlazrEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub(crate) static mut TP_ARCH: Array<BlazrArch> = Array::with_max_entries(1, 0);

#[inline]
pub(crate) fn read_list_u8(src: *const *const u8, dst: &mut [[u8; 200]]) -> Result<u8, u32> {
    let mut count = 0;
    for i in 0..ARGV_COUNT as isize {
        unsafe {
            let res = bpf_probe_read(src.offset(i)).map_err(|_| 1u32)?;
            if res.as_ref().is_none() {
                break;
            }

            let _ = bpf_probe_read_user_str_bytes(res, &mut dst[i as usize]).map_err(|_| 1u32)?;
        }
        count += 1;
    }
    Ok(count)
}

pub(crate) const AF_INET: u16 = 2;
pub(crate) const AF_INET6: u16 = 10;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
}

#[repr(C)]
pub(crate) struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_addr: [u8; 16],
}
