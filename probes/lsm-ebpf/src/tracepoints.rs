use aya_bpf::BpfContext;

use aya_bpf::helpers::{
    bpf_d_path, bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_str_bytes,
};
use aya_bpf::maps::{Array, HashMap, PerCpuArray, PerfEventByteArray};
use aya_bpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::{debug, info};
use bpfshield_common::utils::str_from_buf_nul;

use crate::vmlinux::{file, linux_binprm, path as lnx_path, socket, task_struct};

use aya_bpf::bindings::path;

use bpfshield_common::{
    rules::BShieldOp, rules::BShieldRule, rules::BShieldRuleClass, rules::BShieldRuleCommand,
    rules::BShieldRuleTarget, rules::BShieldRulesKey, rules::BShieldVar, rules::BShieldVarType,
    BShieldAction, BShieldEvent, BShieldEventClass, BShieldEventType, RULES_PER_KEY,
};

#[map]
static mut LOCAL_BUFFER_LSM: PerCpuArray<BShieldEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut LSM_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[map]
pub(crate) static mut LSM_RULES: HashMap<BShieldRulesKey, [BShieldRule; RULES_PER_KEY]> =
    HashMap::with_max_entries(100, 0);

#[map]
pub(crate) static mut LSM_RULE_OPS: Array<BShieldOp> = Array::with_max_entries(1000, 0);

#[map]
pub(crate) static mut LSM_CTX_LABELS: HashMap<u32, [i64; 5]> = HashMap::with_max_entries(10_000, 0);

struct LsmRuleVar<'a> {
    target: BShieldRuleTarget,
    int: i64,
    sbuf: &'a [u8],
}

fn str_eq(var: &LsmRuleVar, needle_var: &BShieldVar) -> bool {
    let needle_len = needle_var.sbuf_len as usize;
    if needle_len < 25 {
        let needle = &needle_var.sbuf[0..needle_len];
        var.sbuf == needle
    } else {
        false
    }
}

fn starts_with(var: &LsmRuleVar, needle_var: &BShieldVar) -> bool {
    let needle_len = needle_var.sbuf_len as usize;
    if needle_len < 25 {
        let needle = &needle_var.sbuf[0..needle_len];
        var.sbuf.starts_with(needle)
    } else {
        false
    }
}

fn ends_with(var: &LsmRuleVar, needle_var: &BShieldVar) -> bool {
    let needle_len = needle_var.sbuf_len as usize;
    if needle_len < 25 {
        let needle = &needle_var.sbuf[0..needle_len];
        var.sbuf.ends_with(needle)
    } else {
        false
    }
}

fn check_rule_op(op: &BShieldOp, var: &LsmRuleVar) -> bool {
    if var.target != op.target {
        return false;
    }
    let var_type = op.var.var_type;

    if matches!(var_type, BShieldVarType::Int) {
        match op.command {
            BShieldRuleCommand::Eq => var.int == op.var.int,
            BShieldRuleCommand::Neq => var.int != op.var.int,
            _ => false,
        }
    } else if matches!(var_type, BShieldVarType::String) {
        match op.command {
            BShieldRuleCommand::Eq => str_eq(var, &op.var),
            BShieldRuleCommand::Neq => !str_eq(var, &op.var),
            BShieldRuleCommand::StartsWith => starts_with(var, &op.var),
            BShieldRuleCommand::EndsWith => ends_with(var, &op.var),
            _ => false,
        }
    } else {
        false
    }
}

fn check_context(op: &BShieldOp, be: &BShieldEvent) -> bool {
    false
}

struct RuleResult {
    hits: [u16; 5],
    action: BShieldAction,
}

fn process_lsm_rules(
    ctx: &LsmContext,
    key: BShieldRulesKey,
    var: LsmRuleVar,
    labels: &[i64; 5],
) -> Result<RuleResult, i32> {
    let mut rule_hits = RuleResult {
        hits: [0; 5],
        action: BShieldAction::Allow,
    };

    if let Some(rules) = unsafe { LSM_RULES.get(&key) } {
        for rule in rules {
            if matches!(rule.class, BShieldRuleClass::Undefined) {
                break;
            }

            let mut ctx_match = true;
            for l in rule.context {
                if l == 0 {
                    break;
                }
                if !labels.contains(&l) {
                    ctx_match = false;
                    break;
                }
            }

            if rule.ops[0] == -1 {
                continue;
            }
            // Starting with "true" for boolean and functionality on rule ops
            let mut matched = true;

            for idx in rule.ops {
                if idx < 0 {
                    break;
                }
                let op = unsafe { LSM_RULE_OPS.get(idx as u32).ok_or(0i32)? };
                let mut result = check_rule_op(op, &var);
                if op.negate {
                    result = !result;
                }
                if !result {
                    matched = false;
                    break;
                }
            }
            if matched && ctx_match {
                for hit in rule_hits.hits.iter_mut() {
                    if *hit == 0 {
                        *hit = rule.id;
                        break;
                    }
                }
                if matches!(rule.action, BShieldAction::Block) {
                    rule_hits.action = BShieldAction::Block;
                    break;
                }
            }
        }
    }
    Ok(rule_hits)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, BShieldEventType::Open) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, BShieldEventType::Exec) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "socket_listen")]
pub fn socket_listen(ctx: LsmContext) -> i32 {
    match { process_lsm(ctx, BShieldEventType::Listen) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn process_lsm(ctx: LsmContext, et: BShieldEventType) -> Result<i32, i32> {
    debug!(&ctx, "lsm tracepoint called, call_type: {}", et as u16);

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BShieldEvent = unsafe { &mut *buf_ptr };

    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let parent: *const task_struct = unsafe { bpf_probe_read(&(*task).parent).map_err(|_| 0i32)? };
    let ppid = unsafe { bpf_probe_read(&(*parent).pid).map_err(|_| 0i32)? };

    let mut p_comm = ctx.command().map_err(|_| 0i32)?;
    unsafe {
        bpf_probe_read_kernel_str_bytes(p_comm.as_mut_ptr(), &mut be.p_path).map_err(|_| 0i32)?
    };

    let labels = unsafe { LSM_CTX_LABELS.get(&(ppid as u32)).unwrap_or(&[0; 5]) };

    be.class = BShieldEventClass::Lsm;
    be.ppid = Some(ppid as u32);
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.protocol = 0;
    be.port = 0;
    be.event_type = et;
    be.action = BShieldAction::Allow;
    be.path_len = 0;

    match et {
        BShieldEventType::Open => process_lsm_file(ctx, be, labels),
        BShieldEventType::Exec => process_lsm_exec(ctx, be, labels),
        BShieldEventType::Listen => process_lsm_socket(ctx, be, labels),
        _ => Ok(0),
    }
}

fn process_lsm_file(ctx: LsmContext, be: &mut BShieldEvent, labels: &[i64; 5]) -> Result<i32, i32> {
    let f: *const file = unsafe { ctx.arg(0) };
    let p: *const lnx_path = unsafe { &(*f).f_path };

    let path_len = unsafe {
        bpf_d_path(
            p as *mut path,
            be.path.as_mut_ptr() as *mut i8,
            be.path.len() as u32,
        )
    } as usize;
    let mut sbuf: &[u8] = &be.path;
    be.path_len = path_len as u16;
    if path_len < 254 {
        sbuf = &be.path[0..path_len];
    }

    let key = BShieldRulesKey {
        class: BShieldRuleClass::File as i32,
        event_type: BShieldEventType::Open as i32,
    };

    let var = LsmRuleVar {
        target: BShieldRuleTarget::Path,
        int: be.path_len as i64, // Putting path lenth into int on string matches
        sbuf: sbuf,
    };

    let result = process_lsm_rules(&ctx, key, var, labels)?;

    be.rule_hits = result.hits;
    if matches!(result.action, BShieldAction::Block) {
        be.action = BShieldAction::Block;
    }

    unsafe {
        // LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    if matches!(result.action, BShieldAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn process_lsm_exec(ctx: LsmContext, be: &mut BShieldEvent, labels: &[i64; 5]) -> Result<i32, i32> {
    let lb: *const linux_binprm = unsafe { ctx.arg(0) };

    let path_len = unsafe {
        bpf_probe_read_kernel_str_bytes((*lb).filename as *const u8, &mut be.path)
            .map_err(|_| 0i32)?
    }
    .len() as usize;

    let mut sbuf: &[u8] = &be.path;
    be.path_len = path_len as u16;
    if path_len < 254 {
        sbuf = &be.path[0..path_len];
    }

    let key = BShieldRulesKey {
        class: BShieldRuleClass::File as i32,
        event_type: BShieldEventType::Exec as i32,
    };

    let var = LsmRuleVar {
        target: BShieldRuleTarget::Path,
        int: be.path_len as i64,
        sbuf: sbuf,
    };

    let result = process_lsm_rules(&ctx, key, var, labels)?;
    be.rule_hits = result.hits;
    if matches!(result.action, BShieldAction::Block) {
        be.action = BShieldAction::Block;
    }

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    if matches!(result.action, BShieldAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn process_lsm_socket(
    ctx: LsmContext,
    be: &mut BShieldEvent,
    labels: &[i64; 5],
) -> Result<i32, i32> {
    let socket: *const socket = unsafe { ctx.arg(0) };
    be.protocol = unsafe { (*(*socket).sk).sk_protocol };
    let port_pair: u32 = unsafe { (*(*socket).sk).__sk_common.__bindgen_anon_3.skc_portpair };
    be.port = (port_pair >> 16) as u16 & 0xffff;

    let key = BShieldRulesKey {
        class: BShieldRuleClass::Socket as i32,
        event_type: BShieldEventType::Listen as i32,
    };
    let var = LsmRuleVar {
        target: BShieldRuleTarget::Port,
        int: be.port as i64,
        sbuf: &[0; 0],
    };

    let result = process_lsm_rules(&ctx, key, var, labels)?;
    be.rule_hits = result.hits;
    if matches!(result.action, BShieldAction::Block) {
        be.action = BShieldAction::Block;
    }

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }
    if matches!(result.action, BShieldAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}
