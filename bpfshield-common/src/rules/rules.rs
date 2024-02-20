use crate::{BShieldAction, BShieldEventClass};

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
    pub event: BShieldEventClass,
    pub rules: [BShieldCondition; 10],
    pub action: BShieldAction,
}
