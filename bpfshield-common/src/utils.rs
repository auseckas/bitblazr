use core::str;

pub fn str_from_buf_nul(src: &[u8]) -> Result<&str, str::Utf8Error> {
    let end = src.iter()
        .position(|&c| c == b'\0')
        .unwrap_or(src.len()); // default to length if no `\0` present
    str::from_utf8(&src[0..end])
}