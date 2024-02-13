use aya_bpf::{helpers::bpf_probe_read, helpers::bpf_probe_read_user_str_bytes};

#[inline]
pub(crate) fn read_list_u8(src: *const *const u8, dst: &mut [[u8; 200]]) -> Result<u8, u32> {
    let mut count = 0;
    for i in 0..20 {
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
