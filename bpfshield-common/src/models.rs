use crate::rules::BShieldRuleVar;

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
    Undefined = -1,
    Exec = 0,
    Exit = 1,
    Open = 2,
    Listen = 3,
    Connect = 4,
}

impl BShieldRuleVar for BShieldEventType {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "exec" => BShieldEventType::Exec,
            "exit" => BShieldEventType::Exit,
            "open" => BShieldEventType::Open,
            "listen" => BShieldEventType::Listen,
            "connect" => BShieldEventType::Connect,
            _ => BShieldEventType::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BShieldEventType::Undefined)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum BShieldAction {
    Undefined = -1,
    Allow = 0,
    Block = 1,
    Ignore = 2,
    Log = 3,
    Alert = 4,
}

impl BShieldRuleVar for BShieldAction {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "allow" => BShieldAction::Allow,
            "block" => BShieldAction::Block,
            "ignore" => BShieldAction::Ignore,
            "log" => BShieldAction::Log,
            "alert" => BShieldAction::Alert,
            _ => BShieldAction::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BShieldAction::Undefined)
    }
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
