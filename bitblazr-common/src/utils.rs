use core::str;
pub fn str_from_buf_nul(src: &[u8]) -> Result<&str, str::Utf8Error> {
    let end = src.iter().position(|&c| c == b'\0').unwrap_or(src.len());
    str::from_utf8(&src[0..end])
}

pub fn hash_nul_str(data: &[u8], len: usize) -> u32 {
    let mut hash: u32 = 0;
    for (i, ch) in data.iter().enumerate() {
        if *ch == 0u8 || i >= len {
            break;
        }
        hash = (hash << 5) | (hash >> 27);
        hash ^= *ch as u32;
    }
    hash
}

#[inline]
pub fn check_path(path: &[u8]) -> bool {
    path.starts_with(b"/proc/sys") || path.starts_with(b"/etc")
}
