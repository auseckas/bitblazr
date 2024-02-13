#[derive(Debug)]
#[repr(C)]
pub struct Syscall {
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub argv_count: u8,
    pub argv: [[u8; 200]; 20],
    pub envp_count: u8,
    pub envp: [[u8; 200]; 20],
}

impl Syscall {
    pub fn to_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum BtfEventType {
    Exec = 0,
    Exit = 1,
}

#[derive(Debug)]
#[repr(C)]
pub struct BtfTraceEvent {
    pub event_type: BtfEventType,
    pub ppid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl BtfTraceEvent {
    pub fn to_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
