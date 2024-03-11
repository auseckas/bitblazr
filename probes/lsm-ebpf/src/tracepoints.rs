use aya_bpf::{cty::c_char, BpfContext};

use aya_bpf::bindings::sockaddr;
use aya_bpf::helpers::{
    bpf_d_path, bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_str_bytes,
};
use aya_bpf::maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, PerfEventByteArray};
use aya_bpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::debug;

use crate::vmlinux::{file, linux_binprm, path as lnx_path, socket, task_struct};

use aya_bpf::bindings::path;

use bitblazr_common::{
    rules::BlazrIpType, rules::BlazrOp, rules::BlazrRule, rules::BlazrRuleClass,
    rules::BlazrRuleCommand, rules::BlazrRuleTarget, rules::BlazrRulesKey, rules::BlazrVar,
    BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType, OPS_PER_RULE, RULES_PER_KEY,
};
use no_std_net::{Ipv4Addr, Ipv6Addr};

#[map]
pub static mut LSM_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[map]
pub(crate) static mut LSM_RULES: HashMap<BlazrRulesKey, [BlazrRule; RULES_PER_KEY]> =
    HashMap::with_max_entries(100, 0);

#[map]
pub(crate) static mut LSM_RULE_OPS: Array<BlazrOp> = Array::with_max_entries(1000, 0);

#[map]
pub(crate) static mut LSM_CTX_LABELS: HashMap<u32, [i64; 5]> = HashMap::with_max_entries(10_000, 0);

#[map]
static mut LOCAL_BUFFER_LSM: PerCpuArray<BlazrEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut LOCAL_CTX_RESULTS: PerCpuHashMap<u16, bool> =
    PerCpuHashMap::with_max_entries(RULES_PER_KEY as u32, 0);

#[map]
static mut LOCAL_OPS: PerCpuArray<[OpTracker; RULES_PER_KEY * OPS_PER_RULE]> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static mut LOCAL_OPS_RESULTS: PerCpuHashMap<i64, bool> =
    PerCpuHashMap::with_max_entries(RULES_PER_KEY as u32 * OPS_PER_RULE as u32, 0);

struct RuleVars<'a> {
    proto: u16,
    port: i64,
    ip_version: i64,
    ip_type: u32,
    path: &'a [u8],
}

struct RuleResult {
    hits: [u16; 5],
    action: BlazrAction,
}

fn process_lsm(ctx: &LsmContext, be: &mut BlazrEvent) -> Result<(), i32> {
    debug!(ctx, "lsm tracepoint called");

    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let parent: *const task_struct = unsafe { bpf_probe_read(&(*task).parent).map_err(|_| 0i32)? };
    let ppid = unsafe { bpf_probe_read(&(*parent).pid).map_err(|_| 0i32)? };

    let mut p_comm = ctx.command().map_err(|_| 0i32)?;
    unsafe {
        bpf_probe_read_kernel_str_bytes(p_comm.as_mut_ptr(), &mut be.p_path).map_err(|_| 0i32)?
    };

    be.class = BlazrEventClass::Lsm;
    be.ppid = Some(ppid as u32);
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.protocol = 0;
    be.port = 0;
    be.action = BlazrAction::Allow;
    be.path_len = 0;

    Ok(())
}

fn get_op_key(rule_id: u16, op_id: i32) -> i64 {
    (rule_id as i64) << 32 | op_id as i64
}

#[derive(Clone, Copy)]
#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

#[repr(C)]
struct sockaddr_in6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_addr: [u8; 16],
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn buf_eq(haystack: &[u8], needle_var: &BlazrVar) -> bool {
    let n_len = needle_var.sbuf_len as usize;
    if n_len < 25 {
        let needle = &needle_var.sbuf[0..n_len];
        haystack == needle
    } else {
        false
    }
}

fn buf_starts_with(haystack: &[u8], needle_var: &BlazrVar) -> bool {
    let n_len = needle_var.sbuf_len as usize;
    if n_len < 25 {
        let needle = &needle_var.sbuf[0..n_len];
        haystack.starts_with(needle)
    } else {
        false
    }
}

fn buf_ends_with(haystack: &[u8], needle_var: &BlazrVar) -> bool {
    if needle_var.sbuf_len == 0 {
        return false;
    }

    let mut hay_rev = haystack.iter().rev();
    let mut needle_iter = needle_var.sbuf.iter();

    for _ in 0..needle_var.sbuf_len {
        if let Some(ch) = needle_iter.next() {
            if let Some(h_ch) = hay_rev.next() {
                if *h_ch != *ch {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

fn process_labels(_ctx: &LsmContext, key: &BlazrRulesKey, ppid: u32) -> Result<(), i32> {
    if let Some(rules) = unsafe { LSM_RULES.get(key) } {
        for rule in rules {
            if matches!(rule.class, BlazrRuleClass::Undefined) {
                break;
            }

            let labels = unsafe { LSM_CTX_LABELS.get(&ppid).unwrap_or(&[0; 5]) };
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

            unsafe {
                LOCAL_CTX_RESULTS
                    .insert(&rule.id, &ctx_match, 0)
                    .map_err(|_| 0i32)?
            };
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Hash)]
struct OpTracker {
    pub rule_id: u16,
    pub op_id: i32,
}

type OpTrackers = [OpTracker; RULES_PER_KEY * OPS_PER_RULE];

fn prime_ops(_ctx: &LsmContext, key: &BlazrRulesKey) -> Result<(), i32> {
    let buf_ptr = unsafe { LOCAL_OPS.get_ptr_mut(0).ok_or(0i32)? };
    let results: &mut OpTrackers = unsafe { &mut *buf_ptr };

    let mut pos = 0;
    if let Some(rules) = unsafe { LSM_RULES.get(key) } {
        if rules.len() > RULES_PER_KEY {
            return Ok(());
        }
        for rule in rules {
            if matches!(rule.class, BlazrRuleClass::Undefined) {
                break;
            }
            if pos >= RULES_PER_KEY * OPS_PER_RULE - OPS_PER_RULE {
                break;
            }
            for j in 0..OPS_PER_RULE {
                let idx = rule.ops[j];
                if idx < 0 {
                    results[pos + j].op_id = -1;
                    break;
                }
                results[pos + j].rule_id = rule.id;
                results[pos + j].op_id = idx;
            }

            pos += rule.ops_len as usize;
        }
    }
    if pos < RULES_PER_KEY * OPS_PER_RULE {
        results[pos].op_id = -1;
    }
    Ok(())
}

fn buf_compare(command: &BlazrRuleCommand, haystack: &[u8], needle_var: &BlazrVar) -> bool {
    match *command {
        BlazrRuleCommand::Eq => buf_eq(haystack, needle_var),
        BlazrRuleCommand::Neq => !buf_eq(haystack, needle_var),
        BlazrRuleCommand::StartsWith => buf_starts_with(haystack, needle_var),
        BlazrRuleCommand::EndsWith => buf_ends_with(haystack, needle_var),
        _ => false,
    }
}

fn int_compare(command: &BlazrRuleCommand, left: i64, right: &BlazrVar) -> bool {
    match *command {
        BlazrRuleCommand::Eq => left == right.int,
        BlazrRuleCommand::Neq => left != right.int,
        _ => false,
    }
}

fn process_ops(_ctx: &LsmContext, var: RuleVars) -> Result<(), i32> {
    let buf_ptr = unsafe { LOCAL_OPS.get_ptr_mut(0).ok_or(0i32)? };
    let ops: &mut OpTrackers = unsafe { &mut *buf_ptr };
    for op_tracker in ops.iter_mut() {
        if op_tracker.op_id < 0 {
            break;
        }
        let op = unsafe { LSM_RULE_OPS.get(op_tracker.op_id as u32).ok_or(0i32)? };

        let mut result = match op.target {
            BlazrRuleTarget::Path => {
                if var.path.len() == 0 {
                    continue;
                }

                buf_compare(&op.command, var.path, &op.var)
            }
            BlazrRuleTarget::Port => {
                if var.port == 0 {
                    continue;
                }
                int_compare(&op.command, var.port, &op.var)
            }
            BlazrRuleTarget::IpProto => {
                if var.proto == 0 {
                    continue;
                }
                int_compare(&op.command, var.proto.into(), &op.var)
            }
            BlazrRuleTarget::IpVersion => {
                if var.ip_version == 0 {
                    continue;
                }
                int_compare(&op.command, var.ip_version, &op.var)
            }
            BlazrRuleTarget::IpType => {
                let res = match op.var.int {
                    _ if op.var.int == BlazrIpType::Private as i64 => {
                        (var.ip_type >> 24) & 0xFF != 0
                    }
                    _ if op.var.int == BlazrIpType::Public as i64 => {
                        (var.ip_type >> 16) & 0xFF != 0
                    }
                    _ if op.var.int == BlazrIpType::Loopback as i64 => {
                        (var.ip_type >> 8) & 0xFF != 0
                    }
                    _ if op.var.int == BlazrIpType::Multicast as i64 => var.ip_type & 0xFF != 0,
                    _ => false,
                };

                match op.command {
                    BlazrRuleCommand::Eq => res,
                    BlazrRuleCommand::Neq => !res,
                    _ => false,
                }
            }
            _ => continue,
        };

        if op.negate {
            result = !result;
        }

        let op_key = get_op_key(op_tracker.rule_id, op_tracker.op_id);

        unsafe {
            LOCAL_OPS_RESULTS
                .insert(&op_key, &result, 0)
                .map_err(|_| 0i32)?;
        }
    }
    Ok(())
}

fn finalize(ctx: &LsmContext, key: &BlazrRulesKey) -> Result<RuleResult, i32> {
    let mut rule_hits = RuleResult {
        hits: [0; 5],
        action: BlazrAction::Allow,
    };
    if let Some(rules) = unsafe { LSM_RULES.get(key) } {
        for rule in rules {
            if matches!(rule.class, BlazrRuleClass::Undefined) {
                break;
            }
            let mut matched = true;
            for idx in rule.ops {
                if idx < 0 {
                    break;
                }

                let op_key = get_op_key(rule.id, idx);

                let result = unsafe { LOCAL_OPS_RESULTS.get(&op_key).ok_or(0i32)? };

                if !result {
                    matched = false;
                    break;
                }
            }
            if rule.ops.is_empty() {
                matched = false;
            }
            let ctx_match = unsafe { *LOCAL_CTX_RESULTS.get(&rule.id).ok_or(0i32)? };
            if matched && ctx_match {
                for hit in rule_hits.hits.iter_mut() {
                    if *hit == 0 {
                        *hit = rule.id;
                        break;
                    }
                }
                debug!(ctx, "Matched rule: {}", rule.id);
                if matches!(rule.action, BlazrAction::Block) {
                    rule_hits.action = BlazrAction::Block;
                    break;
                }
            }
        }
    }
    Ok(rule_hits)
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let res = process_file_open(ctx);
    if let Ok(v) = res {
        v
    } else {
        res.err().unwrap_or(0)
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let res = process_file_exec(ctx);
    if let Ok(v) = res {
        v
    } else {
        res.err().unwrap_or(0)
    }
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    let res = process_socket_connect(ctx);
    if let Ok(v) = res {
        v
    } else {
        res.err().unwrap_or(0)
    }
}

#[lsm(hook = "socket_listen")]
pub fn socket_listen(ctx: LsmContext) -> i32 {
    let res = process_socket_listen(ctx);
    if let Ok(v) = res {
        v
    } else {
        res.err().unwrap_or(0)
    }
}

fn process_socket_connect(ctx: LsmContext) -> Result<i32, i32> {
    let socket: *const socket = unsafe { ctx.arg(0) };
    let sock_addr: *const sockaddr = unsafe { ctx.arg(1) };
    let sa_family: u16 = unsafe { (*sock_addr).sa_family };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    let proto: u16 = unsafe { (*(*socket).sk).sk_protocol };

    process_lsm(&ctx, be)?;
    be.event_type = BlazrEventType::Connect;

    let key = BlazrRulesKey {
        class: BlazrRuleClass::Socket as i32,
        event_type: BlazrEventType::Connect as i32,
    };

    be.log_class = BlazrRuleClass::Socket;

    let ppid = be.ppid.unwrap_or(0) as u32;

    process_labels(&ctx, &key, ppid)?;
    prime_ops(&ctx, &key)?;

    let ip_version = match sa_family {
        AF_INET => 4,
        AF_INET6 => 6,
        _ => 0,
    };

    let mut port = 0;
    let mut ip_type: u32 = 0;

    if sa_family == AF_INET {
        let sockaddr_in: *const sockaddr_in = unsafe { ctx.arg(1) };
        let int_ip = unsafe { (*sockaddr_in).sin_addr.to_be() };

        let addr = Ipv4Addr::from(int_ip);
        port = unsafe { (*sockaddr_in).sin_port.to_be() };

        let ip_private = addr.is_private();
        let ip_public = !ip_private;
        let ip_loopback = addr.is_loopback();
        let ip_multicast = addr.is_multicast();

        ip_type = (ip_private as u32) << 24
            | (ip_public as u32) << 16
            | (ip_loopback as u32) << 8
            | ip_multicast as u32;
    } else if sa_family == AF_INET6 {
        let sockaddr_in: sockaddr_in6 = match unsafe { bpf_probe_read(ctx.arg(1)) } {
            Ok(ip) => ip,
            Err(_) => return Ok(0),
        };

        let addr6 = Ipv6Addr::from(sockaddr_in.sin6_addr);
        port = sockaddr_in.sin6_port.to_be();

        ip_type |= 1u32 << 16;
        ip_type |= (addr6.is_loopback() as u32) << 8;

        let octets = addr6.octets();
        let fs = (octets[0] as u16) << 8 | (octets[1] as u16);
        let ip_multicast = fs & 0xff00 == 0xff00;
        ip_type |= ip_multicast as u32;
    }

    debug!(
        &ctx,
        "Port: {}, IP Version: {}, ip_type: {}", port, ip_version, ip_type
    );

    let var = RuleVars {
        proto: proto,
        port: port as i64,
        ip_version: ip_version as i64,
        ip_type: ip_type,
        path: &[0; 0],
    };
    process_ops(&ctx, var)?;
    let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    if matches!(be.action, BlazrAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn process_file_exec(ctx: LsmContext) -> Result<i32, i32> {
    let lb: *const linux_binprm = unsafe { ctx.arg(0) };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    process_lsm(&ctx, be)?;
    be.event_type = BlazrEventType::Exec;

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

    let key = BlazrRulesKey {
        class: BlazrRuleClass::File as i32,
        event_type: BlazrEventType::Exec as i32,
    };
    let ppid = be.ppid.unwrap_or(0) as u32;

    be.log_class = BlazrRuleClass::File;

    process_labels(&ctx, &key, ppid)?;
    prime_ops(&ctx, &key)?;

    let var = RuleVars {
        proto: 0,
        port: 0,
        ip_version: 0,
        ip_type: 0,
        path: sbuf,
    };
    process_ops(&ctx, var)?;
    let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    if matches!(be.action, BlazrAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn process_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let f: *const file = unsafe { ctx.arg(0) };
    let p: *const lnx_path = unsafe { &(*f).f_path };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    process_lsm(&ctx, be)?;
    be.event_type = BlazrEventType::Open;

    let path_len = unsafe {
        bpf_d_path(
            p as *mut path,
            be.path.as_mut_ptr() as *mut c_char,
            be.path.len() as u32,
        )
    } as usize;
    let mut sbuf: &[u8] = &be.path;
    be.path_len = path_len as u16;
    if path_len < 254 {
        sbuf = &be.path[0..path_len];
    }

    let key = BlazrRulesKey {
        class: BlazrRuleClass::File as i32,
        event_type: BlazrEventType::Open as i32,
    };
    be.log_class = BlazrRuleClass::File;

    let ppid = be.ppid.unwrap_or(0) as u32;

    process_labels(&ctx, &key, ppid)?;
    prime_ops(&ctx, &key)?;

    let var = RuleVars {
        proto: 0,
        port: 0,
        ip_version: 0,
        ip_type: 0,
        path: sbuf,
    };
    process_ops(&ctx, var)?;
    let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;

    if matches!(be.action, BlazrAction::Block)
        || be.path.starts_with(b"/proc/sys")
        || be.path.starts_with(b"/etc")
    {
        unsafe {
            LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }

    if matches!(be.action, BlazrAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}

fn process_socket_listen(ctx: LsmContext) -> Result<i32, i32> {
    let socket: *const socket = unsafe { ctx.arg(0) };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    process_lsm(&ctx, be)?;
    be.event_type = BlazrEventType::Listen;
    be.protocol = unsafe { (*(*socket).sk).sk_protocol };
    let port_pair: u32 = unsafe { (*(*socket).sk).__sk_common.__bindgen_anon_3.skc_portpair };
    be.port = (port_pair >> 16) as u16 & 0xffff;

    let key = BlazrRulesKey {
        class: BlazrRuleClass::Socket as i32,
        event_type: BlazrEventType::Listen as i32,
    };
    be.log_class = BlazrRuleClass::Socket;

    let ppid = be.ppid.unwrap_or(0) as u32;

    process_labels(&ctx, &key, ppid)?;
    prime_ops(&ctx, &key)?;

    let var = RuleVars {
        proto: 0,
        port: be.port as i64,
        ip_version: 0,
        ip_type: 0,
        path: &[0; 0],
    };
    process_ops(&ctx, var)?;
    let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;

    unsafe {
        LSM_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    if matches!(be.action, BlazrAction::Block) {
        Ok(-1)
    } else {
        Ok(0)
    }
}
