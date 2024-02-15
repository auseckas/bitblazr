#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BShieldEventClass {
    Tracepoint = 0,
    BtfTracepoint = 1,
    Lsm = 2,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BShieldEventType {
    Exec = 0,
    Exit = 1,
    Open = 2,
    Bprm = 3,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub enum BShieldAction {
    Allow = 0,
    Block = 1,
    Ignore = 2,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BShieldEvent {
    pub class: BShieldEventClass,
    pub event_type: BShieldEventType,
    pub ppid: Option<u32>,
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub action: BShieldAction,
    pub path: [u8; 255],
    pub argv_count: u8,
    pub argv: [[u8; 200]; 20],
}

impl BShieldEvent {
    pub fn to_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
