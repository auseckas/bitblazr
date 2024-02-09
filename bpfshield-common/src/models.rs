const MAX_BUFFER: usize = 30_720;

#[derive(Debug)]
#[repr(C)]
pub struct Syscall {
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    // pub buf_len: u32,
    // pub buf: [u8; MAX_BUFFER],
    pub argv: [[u8; 255]; 20]
}

impl Syscall {
    pub fn to_bytes(&self) -> &[u8] {
        // let len = (self.buf_len as usize).min(MAX_BUFFER);
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                // core::mem::size_of::<Self>() - (MAX_BUFFER - len),
                core::mem::size_of::<Self>(),
            )
        }
    }
}