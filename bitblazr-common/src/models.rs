use crate::rules::{BlazrRuleClass, BlazrRuleVar};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BlazrEventClass {
    Tracepoint = 0,
    BtfTracepoint = 1,
    Lsm = 2,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BlazrArch {
    Undefined = -1,
    X86_64 = 0,
    Aarch64 = 1,
}

impl BlazrRuleVar for BlazrArch {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "x86_64" => BlazrArch::X86_64,
            "aarch64" => BlazrArch::Aarch64,
            _ => BlazrArch::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrArch::Undefined)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BlazrEventType {
    Undefined = -1,
    Exec = 0,
    Exit = 1,
    Open = 2,
    Listen = 3,
    Connect = 4,
}

impl BlazrRuleVar for BlazrEventType {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "exec" => BlazrEventType::Exec,
            "exit" => BlazrEventType::Exit,
            "open" => BlazrEventType::Open,
            "listen" => BlazrEventType::Listen,
            "connect" => BlazrEventType::Connect,
            _ => BlazrEventType::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrEventType::Undefined)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum BlazrAction {
    Undefined = -1,
    Allow = 0,
    Block = 1,
    Ignore = 2,
    Log = 3,
    Alert = 4,
}

impl BlazrRuleVar for BlazrAction {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "allow" => BlazrAction::Allow,
            "block" => BlazrAction::Block,
            "ignore" => BlazrAction::Ignore,
            "log" => BlazrAction::Log,
            "alert" => BlazrAction::Alert,
            _ => BlazrAction::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrAction::Undefined)
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BlazrEvent {
    pub class: BlazrEventClass,
    pub event_type: BlazrEventType,
    pub log_class: BlazrRuleClass,
    pub ppid: Option<u32>,
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub action: BlazrAction,
    pub protocol: u16,
    pub port: u16,
    pub rule_hits: [u16; 5],
    pub labels: [i64; 5],
    pub p_path: [u8; 255],
    pub path: [u8; 255],
    pub path_len: u16,
    pub argv_count: u8,
    pub argv: [[u8; 200]; crate::ARGV_COUNT],
}

impl BlazrEvent {
    pub fn to_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
