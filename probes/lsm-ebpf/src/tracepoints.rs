use aya_ebpf::{cty::c_char, EbpfContext};

use aya_ebpf::bindings::sockaddr;
use aya_ebpf::helpers::{
    bpf_d_path, bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_buf,
    bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{
    Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, PerCpuHashMap, PerfEventByteArray,
};
use aya_ebpf::{macros::lsm, macros::map, programs::LsmContext};
use aya_log_ebpf::debug;

use crate::vmlinux::vmlinux::{file, path as lnx_path, pid_t, socket};

use crate::{get_offset, probe_read};
use aya_ebpf::bindings::path;
use bitblazr_common::models::{BlazrKernelVersion, BlazrSysInfo};
use core::ffi::c_void;

// use aya_log_ebpf::info;
use bitblazr_common::{
    rules::BlazrIpType, rules::BlazrOp, rules::BlazrRule, rules::BlazrRuleClass,
    rules::BlazrRuleCommand, rules::BlazrRuleTarget, rules::BlazrRulesKey, BlazrAction, BlazrEvent,
    BlazrEventClass, BlazrEventType, OPS_PER_RULE, RULES_PER_KEY,
};
use core::mem::size_of;
use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[map]
pub(crate) static mut TP_SYSINFO: Array<BlazrSysInfo> = Array::with_max_entries(1, 0);

#[map]
pub static mut LSM_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[map]
pub(crate) static mut LSM_RULES: HashMap<BlazrRulesKey, [BlazrRule; RULES_PER_KEY]> =
    HashMap::with_max_entries(100, 0);

#[map]
pub(crate) static mut LSM_RULE_OPS: Array<BlazrOp> = Array::with_max_entries(1000, 0);

#[map]
pub(crate) static mut LSM_CTX_LABELS: LruHashMap<u32, [i64; 5]> =
    LruHashMap::with_max_entries(10_000, 0);

#[map]
static mut LOCAL_BUFFER_LSM: PerCpuArray<BlazrEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut LOCAL_CTX_RESULTS: PerCpuHashMap<u16, bool> =
    PerCpuHashMap::with_max_entries(RULES_PER_KEY as u32, 0);

#[repr(C)]
pub struct TrieIpKey {
    pub op_id: u32,
    pub ip: u32,
}

#[map]
pub(crate) static mut LSM_IP_LISTS: LpmTrie<TrieIpKey, u32> = LpmTrie::with_max_entries(1000, 0);

#[repr(C)]
pub struct SearchKey {
    pub rule_id: u32,
    pub op_id: i32,
    pub buf: [u8; 52],
}

#[map]
pub(crate) static mut LSM_SEARCH_LISTS: LpmTrie<SearchKey, u32> =
    LpmTrie::with_max_entries(RULES_PER_KEY as u32 * OPS_PER_RULE as u32, 0);

struct RuleVars<'a> {
    proto: u16,
    port: i64,
    ip_version: i64,
    ip_addr: u32,
    path: &'a [u8],
    path_len: u32,
}

struct RuleResult {
    hits: [u16; 5],
    action: BlazrAction,
}

fn process_lsm(ctx: &LsmContext, be: &mut BlazrEvent) -> Result<(), i32> {
    debug!(ctx, "lsm tracepoint called");
    let task: *const c_void = unsafe { bpf_get_current_task() as *const _ };
    let parent = probe_read!(task, task_struct, parent, *const c_void, 0i32);
    let ppid = probe_read!(parent, task_struct, pid, pid_t, 0i32);

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
    be.ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    be.action = BlazrAction::Allow;
    be.path_len = 0;
    be.path[0] = 0u8;
    be.argv_count = 0;

    Ok(())
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

fn trie_search(
    command: &BlazrRuleCommand,
    op_tracker: &OpTracker,
    haystack: &[u8],
    haystack_len: u32,
    var_len: u16,
) -> Result<bool, i32> {
    let n_len = var_len as u32;
    let mut s_key = Key::new(
        64 + (n_len * 8),
        SearchKey {
            rule_id: (op_tracker.rule_id as u32).to_be(),
            op_id: op_tracker.op_id.to_be(),
            buf: [0; 52],
        },
    );
    if matches!(command, BlazrRuleCommand::EndsWith) {
        let offset: isize = (haystack_len - n_len) as isize;
        if offset < 0 || offset > haystack_len as isize {
            return Ok(false);
        }
        unsafe {
            bpf_probe_read_kernel_str_bytes(haystack.as_ptr().offset(offset), &mut s_key.data.buf)
                .map_err(|_| 0i32)?;
        }
    } else {
        unsafe {
            bpf_probe_read_kernel_buf(haystack.as_ptr(), &mut s_key.data.buf).map_err(|_| 0i32)?;
        }
    }

    let res = unsafe { LSM_SEARCH_LISTS.get(&s_key).is_some() };
    Ok(match *command {
        BlazrRuleCommand::StartsWith | BlazrRuleCommand::EndsWith => res,
        BlazrRuleCommand::Eq => res && haystack_len == n_len,
        BlazrRuleCommand::Neq => !res || haystack_len != n_len,
        _ => false,
    })
}

fn process_op(_ctx: &LsmContext, rule_id: u16, op_id: i32, var: &RuleVars) -> Result<bool, i32> {
    let op_tracker = OpTracker { rule_id, op_id };
    let op = unsafe { LSM_RULE_OPS.get(op_id as u32).ok_or(0i32)? };
    let mut result = match op.target {
        BlazrRuleTarget::Path => {
            if var.path.len() == 0 {
                return Ok(false);
            }
            trie_search(&op.command, &op_tracker, var.path, var.path_len, op.var_len)?
        }
        BlazrRuleTarget::Port => {
            if var.port == 0 {
                return Ok(false);
            }
            trie_search(
                &op.command,
                &op_tracker,
                &var.port.to_be_bytes(),
                size_of::<i64>() as u32,
                op.var_len,
            )?
        }
        BlazrRuleTarget::IpProto => {
            if var.proto == 0 {
                return Ok(false);
            }

            trie_search(
                &op.command,
                &op_tracker,
                &(var.proto as i64).to_be_bytes(),
                size_of::<i64>() as u32,
                op.var_len,
            )?
        }
        BlazrRuleTarget::IpVersion => {
            if var.ip_version == 0 {
                return Ok(false);
            }

            trie_search(
                &op.command,
                &op_tracker,
                &var.ip_version.to_be_bytes(),
                size_of::<i64>() as u32,
                op.var_len,
            )?
        }
        BlazrRuleTarget::IpType => {
            let mut res = false;
            if var.ip_addr > 0 {
                let addr = Ipv4Addr::from(var.ip_addr);
                if addr.is_private() {
                    res = trie_search(
                        &op.command,
                        &op_tracker,
                        &(BlazrIpType::Private as i64).to_be_bytes(),
                        size_of::<i64>() as u32,
                        op.var_len,
                    )?;
                }

                if !res {
                    res = trie_search(
                        &op.command,
                        &op_tracker,
                        &(BlazrIpType::Public as i64).to_be_bytes(),
                        size_of::<i64>() as u32,
                        op.var_len,
                    )?;
                }
                if !res && addr.is_loopback() {
                    res = trie_search(
                        &op.command,
                        &op_tracker,
                        &(BlazrIpType::Loopback as i64).to_be_bytes(),
                        size_of::<i64>() as u32,
                        op.var_len,
                    )?;
                }
                if !res && addr.is_multicast() {
                    res = trie_search(
                        &op.command,
                        &op_tracker,
                        &(BlazrIpType::Multicast as i64).to_be_bytes(),
                        size_of::<i64>() as u32,
                        op.var_len,
                    )?;
                }
            }
            res
        }
        BlazrRuleTarget::IpAddr => {
            if var.ip_addr == 0 {
                false
            } else {
                let ip_key = Key::new(
                    64,
                    TrieIpKey {
                        op_id: op_id as u32,
                        ip: var.ip_addr,
                    },
                );

                let res = unsafe { LSM_IP_LISTS.get(&ip_key).is_some() };
                match &op.command {
                    BlazrRuleCommand::Eq => res,
                    BlazrRuleCommand::Neq => !res,
                    _ => false,
                }
            }
        }
        _ => return Ok(false),
    };

    if op.negate {
        result = !result;
    }

    Ok(result)
}

// use crate::vmlinux::bpf_map;
// use aya_ebpf::helpers::bpf_for_each_map_elem;
// use core::ffi::c_void;
// use core::ptr::addr_of;
// extern "C" fn callback_fn(
//     map: *mut bpf_map,
//     key: *mut c_void,
//     val: *mut c_void,
//     ctx: *mut c_void,
// ) -> i64 {
//     0
// }

fn process_ops(
    ctx: &LsmContext,
    key: &BlazrRulesKey,
    rule_vars: RuleVars,
) -> Result<RuleResult, i32> {
    let mut pos = 0;
    let mut rule_hits = RuleResult {
        hits: [0; 5],
        action: BlazrAction::Allow,
    };

    // let func_ptr = callback_fn as *mut c_void;
    // let this_key = 0u32;
    // unsafe {
    //     bpf_for_each_map_elem(
    //         addr_of!(LSM_RULE_OPS) as *mut c_void,
    //         func_ptr,
    //         this_key as *mut c_void,
    //         0,
    //     );
    // }

    if let Some(rules) = unsafe { LSM_RULES.get(key) } {
        if rules.len() > RULES_PER_KEY {
            return Err(0i32);
        }
        for i in 0..RULES_PER_KEY {
            let rule = rules.get(i).ok_or(0i32)?;
            if matches!(rule.class, BlazrRuleClass::Undefined) {
                break;
            }
            if pos >= RULES_PER_KEY * OPS_PER_RULE {
                break;
            }
            let mut matched = true;
            for j in 0..OPS_PER_RULE {
                let idx = rule.ops[j];
                if idx < 0 {
                    break;
                }
                let result = process_op(ctx, rule.id, idx, &rule_vars)?;
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
                // debug!(ctx, "Matched rule: {}", rule.id);
                if matches!(rule.action, BlazrAction::Block) {
                    rule_hits.action = BlazrAction::Block;
                    break;
                }
            }

            pos += rule.ops_len as usize;
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

    let ip_version = match sa_family {
        AF_INET => 4,
        AF_INET6 => 6,
        _ => 0,
    };

    let mut port = 0;
    let mut ip_addr = 0;

    if sa_family == AF_INET {
        let sockaddr_in: *const sockaddr_in = unsafe { ctx.arg(1) };
        ip_addr = unsafe { (*sockaddr_in).sin_addr.to_be() };

        let addr = Ipv4Addr::from(ip_addr);
        be.ip_addr = IpAddr::V4(addr);
        port = unsafe { (*sockaddr_in).sin_port.to_be() };
    } else if sa_family == AF_INET6 {
        let sockaddr_in: sockaddr_in6 = match unsafe { bpf_probe_read(ctx.arg(1)) } {
            Ok(ip) => ip,
            Err(_) => return Ok(0),
        };

        let addr6 = Ipv6Addr::from(sockaddr_in.sin6_addr);
        be.ip_addr = IpAddr::V6(addr6);
        port = sockaddr_in.sin6_port.to_be();

        let octets = addr6.octets();
        let fs = (octets[0] as u16) << 8 | (octets[1] as u16);
        let _ip_multicast = fs & 0xff00 == 0xff00;
    }

    debug!(&ctx, "Port: {}, IP Version: {}", port, ip_version);

    be.protocol = proto;
    be.port = port;
    let var = RuleVars {
        proto: proto,
        port: port as i64,
        ip_version: ip_version as i64,
        ip_addr: ip_addr.to_be(),
        path: &[0; 0],
        path_len: 0,
    };
    let rh = process_ops(&ctx, &key, var)?;
    // let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;

    if rh.hits[0] > 0 {
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

fn process_file_exec(ctx: LsmContext) -> Result<i32, i32> {
    let lb: *const c_void = unsafe { ctx.arg(0) };

    let buf_ptr = unsafe { LOCAL_BUFFER_LSM.get_ptr_mut(0).ok_or(0i32)? };
    let be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    process_lsm(&ctx, be)?;
    be.event_type = BlazrEventType::Exec;

    let path_len = {
        let filename = probe_read!(lb, linux_binprm, filename, *const u8, 0i32);
        unsafe { bpf_probe_read_kernel_str_bytes(filename, &mut be.path).map_err(|_| 0i32)? }
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

    let var = RuleVars {
        proto: 0,
        port: 0,
        ip_version: 0,
        ip_addr: 0,
        path: sbuf,
        path_len: path_len as u32,
    };
    let rh = process_ops(&ctx, &key, var)?;
    // let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;

    if rh.hits[0] > 0 {
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

    let var = RuleVars {
        proto: 0,
        port: 0,
        ip_version: 0,
        ip_addr: 0,
        path: sbuf,
        path_len: 0,
    };
    let rh = process_ops(&ctx, &key, var)?;

    // let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;
    be.path[0] = 0u8;

    if rh.hits[0] > 0 {
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

    let var = RuleVars {
        proto: 0,
        port: be.port as i64,
        ip_version: 0,
        ip_addr: 0,
        path: &[0; 0],
        path_len: 0,
    };
    let rh = process_ops(&ctx, &key, var)?;

    // let rh = finalize(&ctx, &key)?;
    be.rule_hits = rh.hits;
    be.action = rh.action;
    be.path[0] = 0u8;

    if rh.hits[0] > 0 {
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
