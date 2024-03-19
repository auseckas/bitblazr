use crate::{BlazrAction, BlazrEventType, OPS_PER_RULE};

pub trait BlazrRuleVar {
    fn from_str(_: &mut str) -> Self;
    fn is_undefined(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum BlazrIpProto {
    Undefined = -1,
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl BlazrRuleVar for BlazrIpProto {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "icmp" => BlazrIpProto::Icmp,
            "tcp" => BlazrIpProto::Tcp,
            "udp" => BlazrIpProto::Udp,
            _ => BlazrIpProto::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrIpProto::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum BlazrIpType {
    Undefined = -1,
    Private = 0,
    Public = 1,
    Loopback = 2,
    Multicast = 3,
}

impl BlazrRuleVar for BlazrIpType {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "private" => BlazrIpType::Private,
            "public" => BlazrIpType::Public,
            "loopback" => BlazrIpType::Loopback,
            "multicast" => BlazrIpType::Multicast,
            _ => BlazrIpType::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrIpType::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum BlazrRuleTarget {
    Undefined = -1,
    Port = 0,
    Path = 1,
    IpVersion = 2,
    IpType = 3,
    IpProto = 4,
    Context = 5,
    IpAddr = 6,
}

impl BlazrRuleVar for BlazrRuleTarget {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "port" => BlazrRuleTarget::Port,
            "path" => BlazrRuleTarget::Path,
            "ip_version" => BlazrRuleTarget::IpVersion,
            "ip_type" => BlazrRuleTarget::IpType,
            "ip_proto" => BlazrRuleTarget::IpProto,
            "ip_addr" => BlazrRuleTarget::IpAddr,
            "context" => BlazrRuleTarget::Context,
            _ => BlazrRuleTarget::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrRuleTarget::Undefined)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BlazrRuleCommand {
    Undefined = -1,
    Eq = 0,
    Neq = 1,
    StartsWith = 2,
    EndsWith = 3,
    Not = 4,
    Contains = 5,
}

impl BlazrRuleVar for BlazrRuleCommand {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "eq" => BlazrRuleCommand::Eq,
            "neq" => BlazrRuleCommand::Neq,
            "starts_with" => BlazrRuleCommand::StartsWith,
            "ends_with" => BlazrRuleCommand::EndsWith,
            "not" => BlazrRuleCommand::Not,
            "contains" => BlazrRuleCommand::Contains,
            _ => BlazrRuleCommand::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrRuleCommand::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BlazrRuleClass {
    Undefined = -1,
    Socket = 0,
    File = 1,
}

impl BlazrRuleClass {
    pub fn is_supported_target(&self, t: &BlazrRuleTarget) -> bool {
        let socket_targets = &[
            BlazrRuleTarget::IpType,
            BlazrRuleTarget::IpVersion,
            BlazrRuleTarget::Port,
            BlazrRuleTarget::IpProto,
            BlazrRuleTarget::IpAddr,
        ];
        let file_targets = &[BlazrRuleTarget::Path];
        match self {
            BlazrRuleClass::Socket => socket_targets.iter().find(|target| *target == t).is_some(),
            BlazrRuleClass::File => file_targets.iter().find(|target| *target == t).is_some(),
            _ => false,
        }
    }
}

impl BlazrRuleVar for BlazrRuleClass {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "socket" => BlazrRuleClass::Socket,
            "file" => BlazrRuleClass::File,
            _ => BlazrRuleClass::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BlazrRuleClass::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BlazrVarType {
    Undefined = -1,
    Int = 0,
    String = 1,
    IpAddr = 2,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BlazrVar {
    pub var_type: BlazrVarType,
    pub int: i64,
    pub sbuf: [u8; 25],
    pub sbuf_len: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BlazrOp {
    pub target: BlazrRuleTarget,
    pub negate: bool,
    pub command: BlazrRuleCommand,
    pub var: BlazrVar,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BlazrRule {
    pub id: u16,
    pub class: BlazrRuleClass,
    pub event: BlazrEventType,
    pub context: [i64; 5],
    pub ops: [i32; OPS_PER_RULE], // positions in Rule ops array
    pub ops_len: u16,
    pub action: BlazrAction,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[repr(C)]
pub struct BlazrRulesKey {
    pub class: i32,
    pub event_type: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrieKey {
    pub op_id: u32,
    pub ip: u32,
}

#[cfg(feature = "user")]
mod maps {
    use crate::models::BlazrArch;
    use crate::rules::{BlazrOp, BlazrRule, BlazrRulesKey, BlazrVar, TrieKey};
    use aya::Pod;
    unsafe impl Pod for BlazrRule {}
    unsafe impl Pod for BlazrRulesKey {}
    unsafe impl Pod for BlazrOp {}
    unsafe impl Pod for BlazrVar {}
    unsafe impl Pod for BlazrArch {}
    unsafe impl Pod for TrieKey {}
}
