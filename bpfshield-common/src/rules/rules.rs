use crate::{BShieldAction, BShieldEventType, OPS_PER_RULE};

pub trait BShieldRuleVar {
    fn from_str(_: &mut str) -> Self;
    fn is_undefined(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum BShieldIpType {
    Undefined = -1,
    Private = 0,
    Public = 1,
    Loopback = 2,
    Multicast = 3,
}

impl BShieldRuleVar for BShieldIpType {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "private" => BShieldIpType::Private,
            "public" => BShieldIpType::Public,
            "loopback" => BShieldIpType::Loopback,
            "multicast" => BShieldIpType::Multicast,
            _ => BShieldIpType::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BShieldIpType::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum BShieldRuleTarget {
    Undefined = -1,
    Port = 0,
    Path = 1,
    IpVersion = 2,
    IpType = 3,
}

impl BShieldRuleVar for BShieldRuleTarget {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "port" => BShieldRuleTarget::Port,
            "path" => BShieldRuleTarget::Path,
            "ip_version" => BShieldRuleTarget::IpVersion,
            "ip_type" => BShieldRuleTarget::IpType,
            _ => BShieldRuleTarget::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BShieldRuleTarget::Undefined)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BShieldRuleCommand {
    Undefined = -1,
    Eq = 0,
    Neq = 1,
    StartsWith = 2,
    EndsWith = 3,
    Not = 4,
}

impl BShieldRuleVar for BShieldRuleCommand {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "eq" => BShieldRuleCommand::Eq,
            "neq" => BShieldRuleCommand::Neq,
            "starts_with" => BShieldRuleCommand::StartsWith,
            "ends_with" => BShieldRuleCommand::EndsWith,
            "not" => BShieldRuleCommand::Not,
            _ => BShieldRuleCommand::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BShieldRuleCommand::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BShieldRuleClass {
    Undefined = -1,
    Socket = 0,
    File = 1,
}

impl BShieldRuleClass {
    pub fn is_supported_target(&self, t: &BShieldRuleTarget) -> bool {
        let socket_targets = &[
            BShieldRuleTarget::IpType,
            BShieldRuleTarget::IpVersion,
            BShieldRuleTarget::Port,
        ];
        let file_targets = &[BShieldRuleTarget::Path];
        match self {
            BShieldRuleClass::Socket => socket_targets.iter().find(|target| *target == t).is_some(),
            BShieldRuleClass::File => file_targets.iter().find(|target| *target == t).is_some(),
            _ => false,
        }
    }
}

impl BShieldRuleVar for BShieldRuleClass {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "socket" => BShieldRuleClass::Socket,
            "file" => BShieldRuleClass::File,
            _ => BShieldRuleClass::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BShieldRuleClass::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BShieldVarType {
    Undefined = -1,
    Int = 0,
    String = 1,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldVar {
    pub var_type: BShieldVarType,
    pub int: i64,
    pub sbuf: [u8; 25],
    pub sbuf_len: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldOp {
    pub target: BShieldRuleTarget,
    pub negate: bool,
    pub command: BShieldRuleCommand,
    pub var: BShieldVar,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldRule {
    pub id: u16,
    pub class: BShieldRuleClass,
    pub event: BShieldEventType,
    pub context: [i64; 5],
    pub ops: [i32; OPS_PER_RULE], // positions in Rule ops array
    pub ops_len: u16,
    pub action: BShieldAction,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub struct BShieldRulesKey {
    pub class: i32,
    pub event_type: i32,
}

#[cfg(feature = "user")]
mod maps {
    use crate::rules::{BShieldOp, BShieldRule, BShieldRulesKey, BShieldVar};
    use aya::Pod;
    unsafe impl Pod for BShieldRule {}
    unsafe impl Pod for BShieldRulesKey {}
    unsafe impl Pod for BShieldOp {}
    unsafe impl Pod for BShieldVar {}
}
