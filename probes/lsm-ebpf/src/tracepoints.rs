use aya_bpf::BpfContext;

use aya_bpf::helpers::{
    bpf_d_path, bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_str_bytes,
};
use aya_bpf::maps::{Array, HashMap, PerCpuArray, PerfEventByteArray};
use aya_bpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::{debug, info};

use crate::vmlinux::{file, linux_binprm, path as lnx_path, socket, task_struct};

use aya_bpf::bindings::path;

use bpfshield_common::{
    rules::BShieldOp, rules::BShieldRule, rules::BShieldRuleClass, rules::BShieldRuleCommand,
    rules::BShieldRuleTarget, rules::BShieldRulesKey, rules::BShieldVarType, BShieldAction,
    BShieldEvent, BShieldEventClass, BShieldEventType, RULES_PER_KEY,
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

struct LsmRuleVar<'a> {
    target: BShieldRuleTarget,
    int: i64,
    sbuf: &'a [u8],
}
fn starts_with(stack: &[u8], needle: &[u8; 25]) -> bool {
    for i in 0..25 {
        if needle[i] == 0u8 {
            break;
        } else if stack[i] == 0u8 || stack[i] != needle[i] {
            return false;
        }
    }
    true
}

fn check_rule_op(
    target: BShieldRuleTarget,
    var_type: &BShieldVarType,
    op: &BShieldOp,
    int: i64,
    buf: &[u8],
) -> bool {
    if target != op.target {
        return false;
    }

    if matches!(*var_type, BShieldVarType::Int) {
        match op.command {
            BShieldRuleCommand::Eq => int == op.var.int,
            BShieldRuleCommand::Neq => int != op.var.int,
            _ => false,
        }
    } else if matches!(*var_type, BShieldVarType::String) {
        match op.command {
            BShieldRuleCommand::Eq => buf == op.var.sbuf,
            BShieldRuleCommand::Neq => buf != op.var.sbuf,
            BShieldRuleCommand::StartsWith => starts_with(buf, &op.var.sbuf),
            _ => false,
        }
    } else {
        false
    }
}

fn process_lsm_rules(ctx: &LsmContext, key: BShieldRulesKey, var: LsmRuleVar) -> Result<bool, i32> {
    if let Some(rules) = unsafe { LSM_RULES.get(&key) } {
        for rule in rules {
            if matches!(rule.class, BShieldRuleClass::Undefined) {
                break;
            }

            // Starting with "true" for boolean and functionality on rule ops
            let mut matched = true;

            for idx in rule.ops {
                if idx < 0 {
                    break;
                }
                let op = unsafe { LSM_RULE_OPS.get(idx as u32).ok_or(0i32)? };
                let mut result = check_rule_op(var.target, &op.var.var_type, op, var.int, var.sbuf);
                if op.negate {
                    result = !result;
                }
                if !result {
                    matched = false;
                    break;
                }
            }
            if matched && matches!(rule.action, BShieldAction::Block) {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
    match { process_lsm(ctx, BShieldEventType::Socket) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn process_lsm(ctx: LsmContext, et: BShieldEventType) -> Result<i32, i32> {
    debug!(&ctx, "lsm tracepoint called, call_type: {}", et as u16);

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BShieldEvent = unsafe { &mut *buf_ptr };

    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let parent: *const task_struct = unsafe { bpf_probe_read(&(*task).parent).map_err(|_| -1i32)? };
    let ppid = unsafe { bpf_probe_read(&(*parent).pid).map_err(|_| -1i32)? };

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
    be.path = [0; 255];

    match et {
        BShieldEventType::Open => process_lsm_file(ctx, be),
        BShieldEventType::Exec => process_lsm_exec(ctx, be),
        BShieldEventType::Socket => process_lsm_socket(ctx, be),
        _ => Ok(0),
    }
}

fn process_lsm_file(ctx: LsmContext, be: &mut BShieldEvent) -> Result<i32, i32> {
    let f: *const file = unsafe { ctx.arg(0) };
    let p: *const lnx_path = unsafe { &(*f).f_path };

    let _ = unsafe {
        bpf_d_path(
            p as *mut path,
            be.path.as_mut_ptr() as *mut i8,
            be.path.len() as u32,
        )
    };

    unsafe {
        // LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

fn process_lsm_exec(ctx: LsmContext, be: &mut BShieldEvent) -> Result<i32, i32> {
    let lb: *const linux_binprm = unsafe { ctx.arg(0) };

    unsafe {
        bpf_probe_read_kernel_str_bytes((*lb).filename as *const u8, &mut be.path)
            .map_err(|_| 0i32)?;
    };

    let key = BShieldRulesKey {
        class: BShieldRuleClass::File as i32,
        event_type: BShieldEventType::Exec as i32,
    };

    let var = LsmRuleVar {
        target: BShieldRuleTarget::Path,
        int: 0,
        sbuf: &be.path,
    };

    let result = process_lsm_rules(&ctx, key, var)?;

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    if result {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn process_lsm_socket(ctx: LsmContext, be: &mut BShieldEvent) -> Result<i32, i32> {
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
        sbuf: &[0; 1],
    };

    let result = process_lsm_rules(&ctx, key, var)?;

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }
    if result {
        Ok(-1)
    } else {
        Ok(0)
    }
}
