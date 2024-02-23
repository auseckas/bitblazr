use crate::{BShieldAction, BShieldEventClass, BShieldEventType};

pub trait BSRuleVar {
    fn from_str(_: &mut str) -> Self;
    fn is_undefined(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub enum BSRuleTarget {
    Undefined = -1,
    Port = 0,
    Path = 1,
}

impl BSRuleVar for BSRuleTarget {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "port" => BSRuleTarget::Port,
            "path" => BSRuleTarget::Path,
            _ => BSRuleTarget::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BSRuleTarget::Undefined)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BSRuleCommand {
    Undefined = -1,
    Eq = 0,
    Neq = 1,
    StartsWith = 2,
    EndsWith = 3,
}

impl BSRuleVar for BSRuleCommand {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "eq" => BSRuleCommand::Eq,
            "neq" => BSRuleCommand::Neq,
            "starts_with" => BSRuleCommand::StartsWith,
            "ends_with" => BSRuleCommand::EndsWith,
            _ => BSRuleCommand::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BSRuleCommand::Undefined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum BSRuleClass {
    Undefined = -1,
    Socket = 0,
    File = 1,
}

impl BSRuleClass {
    pub fn is_supported_target(&self, t: &BSRuleTarget) -> bool {
        let socket_targets = &[BSRuleTarget::Port];
        let file_targets = &[BSRuleTarget::Path];
        match self {
            BSRuleClass::Socket => socket_targets.iter().find(|target| *target == t).is_some(),
            BSRuleClass::File => file_targets.iter().find(|target| *target == t).is_some(),
            _ => false,
        }
    }
}

impl BSRuleVar for BSRuleClass {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "socket" => BSRuleClass::Socket,
            "file" => BSRuleClass::File,
            _ => BSRuleClass::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BSRuleClass::Undefined)
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
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldOp {
    pub target: BSRuleTarget,
    pub command: BSRuleCommand,
    pub var: BShieldVar,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldRule {
    pub class: BSRuleClass,
    pub event: BShieldEventType,
    pub ops: [i32; 25], // positions in Rule ops array
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
