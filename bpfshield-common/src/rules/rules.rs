use crate::{BShieldAction, BShieldEventClass, BShieldEventType};

pub trait BSRuleVar {
    fn from_str(_: &mut str) -> Self;
    fn is_undefined(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
enum SocketTargets {
    Port = 0,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BSRuleCommand {
    Eq = 0,
    Neq = 1,
    StartsWith = 2,
    EndsWith = 3,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum BSRuleClass {
    Undefined = -1,
    Socket = 0,
}

impl BSRuleVar for BSRuleClass {
    fn from_str(s: &mut str) -> Self {
        s.make_ascii_lowercase();
        match s.trim() {
            "socket" => BSRuleClass::Socket,
            _ => BSRuleClass::Undefined,
        }
    }

    fn is_undefined(&self) -> bool {
        matches!(self, BSRuleClass::Undefined)
    }
}

impl BSRuleClass {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldOp {
    pub command: BSRuleCommand,
    pub buf: [u8; 25],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldCondition {
    pub target: u16,
    pub ops: [BShieldOp; 10],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BShieldRule {
    pub class: BSRuleClass,
    pub event: BShieldEventType,
    pub rules: [BShieldCondition; 10],
    pub action: BShieldAction,
}
