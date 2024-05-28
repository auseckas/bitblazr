use crate::vmlinux::{linux_binprm, sockaddr, task_struct};

use aya_ebpf::EbpfContext;

#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
use aya_ebpf::bindings::pt_regs;
#[cfg(target_arch = "aarch64")]
use aya_ebpf::bindings::user_pt_regs as pt_regs;

use aya_ebpf::helpers::{
    bpf_probe_read, bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
    bpf_probe_read_user_str_bytes,
};
use aya_ebpf::{macros::btf_tracepoint, macros::map, programs::BtfTracePointContext};
use aya_log_ebpf::debug;

use bitblazr_common::rules::BlazrRuleClass;
use bitblazr_common::{BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType, ARGV_COUNT};

use crate::common::{sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, LOCAL_BUFFER, TP_ARCH};
use aya_ebpf::helpers::bpf_get_current_task;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, LpmTrie, PerfEventByteArray};
use aya_ebpf::PtRegs;
use bitblazr_common::models::BlazrArch;
use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[map]
pub static mut BTP_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[repr(C)]
pub struct PrefixKey {
    pub buf: [u8; 27],
}

#[map]
pub(crate) static mut OPEN_PREFIX: LpmTrie<PrefixKey, u32> = LpmTrie::with_max_entries(100, 0);

#[map]
pub(crate) static mut OPEN_PREFIX_LEN: Array<u32> = Array::with_max_entries(100, 0);

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    match process_exec(ctx, BlazrEventType::Exec) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> u32 {
    match process_exec(ctx, BlazrEventType::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[btf_tracepoint(function = "sys_enter")]
pub fn sys_enter(ctx: BtfTracePointContext) -> u32 {
    match process_sys_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn init_be(ctx: &BtfTracePointContext, be: &mut BlazrEvent) -> Result<(), i32> {
    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let parent: *const task_struct = unsafe { bpf_probe_read(&(*task).parent).map_err(|_| 0i32)? };
    let ppid = unsafe { bpf_probe_read(&(*parent).pid).map_err(|_| 0i32)? };

    if get_parent_path(ctx, be).is_err() {
        let mut p_comm = ctx.command().map_err(|_| 0i32)?;
        unsafe {
            bpf_probe_read_kernel_str_bytes(p_comm.as_mut_ptr(), &mut be.p_path)
                .map_err(|_| 0i32)?
        };
    }

    be.class = BlazrEventClass::BtfTracepoint;
    be.ppid = Some(ppid as u32);
    be.tgid = ctx.tgid();
    be.pid = ctx.pid();
    be.uid = ctx.uid();
    be.gid = ctx.gid();
    be.protocol = 0;
    be.port = 0;
    be.action = BlazrAction::Allow;
    be.path_len = 0;
    be.ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    be.path[0] = 0u8;
    be.argv_count = 0;

    Ok(())
}

fn get_parent_path(_ctx: &BtfTracePointContext, be: &mut BlazrEvent) -> Result<(), i32> {
    let task: *const task_struct = unsafe { bpf_get_current_task() as *const _ };
    let mm: *mut crate::vmlinux::mm_struct =
        unsafe { bpf_probe_read(&(*task).mm).map_err(|_| 0i32)? };

    let argv_p = unsafe {
        bpf_probe_read(&(*mm).__bindgen_anon_1.arg_start).map_err(|_| 0i32)? as *const u8
    };

    unsafe { bpf_probe_read_user_str_bytes(argv_p, &mut be.p_path).map_err(|_| 0i32)? };

    Ok(())
}

fn process_exec(ctx: BtfTracePointContext, event_type: BlazrEventType) -> Result<u32, u32> {
    debug!(
        &ctx,
        "btf tracepoint called, call_type: {}", event_type as u16
    );

    let task: *const task_struct = unsafe { ctx.arg(0) };

    let ppid = unsafe { (*(*task).parent).pid } as u32;
    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let mut be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    init_be(&ctx, &mut be).map_err(|_| 1u32)?;

    be.event_type = event_type;
    be.log_class = BlazrRuleClass::File;
    be.ppid = Some(ppid);

    if matches!(event_type, BlazrEventType::Exit) {
        be.exit_code = unsafe { ((*task).exit_code & 0xff00) >> 8 } as u8;
    }

    if matches!(event_type, BlazrEventType::Exec) {
        let lb: *const linux_binprm = unsafe { ctx.arg(2) };
        unsafe {
            bpf_probe_read_kernel_str_bytes((*lb).filename as *const u8, &mut be.path)
                .map_err(|_| 0u32)?;
        }
    }

    let argv_p: *const u8 = unsafe { (*(*task).mm).__bindgen_anon_1.arg_start as *const u8 };
    let argv_p_end: *const u8 = unsafe { (*(*task).mm).__bindgen_anon_1.arg_end as *const u8 };

    let mut count = 0;
    let mut offset = 0;
    for i in 0..ARGV_COUNT as isize {
        let ptr = unsafe { argv_p.offset(offset) };
        if ptr >= argv_p_end {
            break;
        }
        let r = unsafe {
            bpf_probe_read_user_str_bytes(ptr, &mut be.argv[i as usize]).map_err(|_| 1u32)?
        };
        let len = r.len();

        if len == 0 {
            break;
        }
        count += 1;
        offset += len as isize + 1;
    }

    be.argv_count = count;

    unsafe {
        BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

fn process_sys_enter(ctx: BtfTracePointContext) -> Result<u32, u32> {
    let pt_regs = unsafe { PtRegs::new(ctx.arg::<*const pt_regs>(0) as *mut pt_regs) };
    let arch = unsafe { TP_ARCH.get(0).ok_or(1u32)? };
    let call_id: i64 = unsafe { ctx.arg(1) };

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let mut be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    init_be(&ctx, &mut be).map_err(|_| 0u32)?;

    match arch {
        BlazrArch::X86_64 => match call_id {
            2 | 85 => process_open(ctx, pt_regs, be),
            41 => process_socket(ctx, pt_regs, be),
            42 => process_connect(ctx, pt_regs, be),
            49 => process_bind(ctx, pt_regs, be),
            50 => process_listen(ctx, pt_regs, be),
            437 | 257 => process_openat(ctx, pt_regs, be),
            _ => Ok(0),
        },
        BlazrArch::Aarch64 => match call_id {
            56 | 437 => process_openat(ctx, pt_regs, be),
            198 => process_socket(ctx, pt_regs, be),
            200 => process_bind(ctx, pt_regs, be),
            201 => process_listen(ctx, pt_regs, be),
            203 => process_connect(ctx, pt_regs, be),
            _ => Ok(0),
        },
        BlazrArch::Arm => match call_id {
            5 | 8 => process_open(ctx, pt_regs, be),
            322 | 437 => process_openat(ctx, pt_regs, be),
            281 => process_socket(ctx, pt_regs, be),
            282 => process_bind(ctx, pt_regs, be),
            284 => process_listen(ctx, pt_regs, be),
            283 => process_connect(ctx, pt_regs, be),
            _ => Ok(0),
        },
        _ => Ok(0),
    }
}

fn process_open(
    ctx: BtfTracePointContext,
    pt_regs: PtRegs,
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    let f_name: *const u8 = pt_regs.arg(0).ok_or(1u32)?;
    unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

    be.event_type = BlazrEventType::Open;
    be.log_class = BlazrRuleClass::File;

    let mut p_key = Key::new(25, PrefixKey { buf: [0; 27] });

    unsafe {
        bpf_probe_read_kernel_buf(be.path.as_ptr(), &mut p_key.data.buf).map_err(|_| 0u32)?;
    }

    let mut matched = false;
    for i in 0..100u32 {
        let len = unsafe { *OPEN_PREFIX_LEN.get(i).unwrap_or(&27) };
        if len > 25 {
            break;
        }
        p_key.prefix_len = len * 8;
        if unsafe { OPEN_PREFIX.get(&p_key).is_some() } {
            matched = true;
            break;
        }
    }

    if matched {
        unsafe {
            BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }
    Ok(0)
}

fn process_openat(
    ctx: BtfTracePointContext,
    pt_regs: PtRegs,
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    let f_name: *const u8 = pt_regs.arg(1).ok_or(1u32)?;
    unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

    be.event_type = BlazrEventType::Open;
    be.log_class = BlazrRuleClass::File;

    let mut p_key = Key::new(25, PrefixKey { buf: [0; 27] });

    unsafe {
        bpf_probe_read_kernel_buf(be.path.as_ptr(), &mut p_key.data.buf).map_err(|_| 0u32)?;
    }

    let mut matched = false;
    for i in 0..100u32 {
        let len = unsafe { *OPEN_PREFIX_LEN.get(i).unwrap_or(&27) };
        if len > 25 {
            break;
        }
        p_key.prefix_len = len * 8;
        if unsafe { OPEN_PREFIX.get(&p_key).is_some() } {
            matched = true;
            break;
        }
    }

    if matched {
        unsafe {
            BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }

    Ok(0)
}

fn process_bind(
    ctx: BtfTracePointContext,
    pt_regs: PtRegs,
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    let sock_addr: *const sockaddr = pt_regs.arg(1).ok_or(1u32)?;
    let sa_family: u16 = unsafe { bpf_probe_read(&(*sock_addr).sa_family).map_err(|_| 1u32)? };

    be.event_type = BlazrEventType::Bind;
    be.log_class = BlazrRuleClass::Socket;
    be.path[0] = 0u8;

    if sa_family == AF_INET {
        let sockaddr_in: sockaddr_in =
            unsafe { bpf_probe_read(pt_regs.arg(1).ok_or(1u32)?).map_err(|_| 1u32)? };
        be.port = sockaddr_in.sin_port.to_be();
    } else if sa_family == AF_INET6 {
        let sockaddr_in: sockaddr_in6 =
            unsafe { bpf_probe_read(pt_regs.arg(1).ok_or(1u32)?).map_err(|_| 1u32)? };

        be.port = sockaddr_in.sin6_port.to_be();
    } else {
        return Ok(1);
    }

    if be.port > 0 {
        unsafe {
            BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }
    Ok(0)
}

fn process_socket(
    ctx: BtfTracePointContext,
    pt_regs: PtRegs,
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    let family = pt_regs.arg::<i64>(0).ok_or(1u32)? as u16;
    be.protocol = pt_regs.arg::<i64>(2).ok_or(1u32)? as u16;

    be.event_type = BlazrEventType::Bind;
    be.log_class = BlazrRuleClass::Socket;

    if be.protocol > 0 && (family == AF_INET || family == AF_INET6) {
        unsafe {
            BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }

    Ok(0)
}

fn process_listen(
    ctx: BtfTracePointContext,
    _pt_regs: PtRegs,
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    be.event_type = BlazrEventType::Listen;
    be.log_class = BlazrRuleClass::Socket;
    be.path[0] = 0u8;

    unsafe {
        BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }
    Ok(0)
}

fn process_connect(
    ctx: BtfTracePointContext,
    pt_regs: PtRegs,
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    let sock_addr: *const sockaddr = pt_regs.arg(1).ok_or(1u32)?;
    let sa_family: u16 = unsafe { bpf_probe_read(&(*sock_addr).sa_family).map_err(|_| 1u32)? };

    be.event_type = BlazrEventType::Connect;
    be.log_class = BlazrRuleClass::Socket;

    if sa_family == AF_INET {
        let sockaddr_in: sockaddr_in =
            unsafe { bpf_probe_read(pt_regs.arg(1).ok_or(1u32)?).map_err(|_| 1u32)? };
        be.port = sockaddr_in.sin_port.to_be();
        let int_ip = sockaddr_in.sin_addr.to_be();
        let addr = Ipv4Addr::from(int_ip);
        be.ip_addr = IpAddr::V4(addr);
    } else if sa_family == AF_INET6 {
        let sockaddr_in: sockaddr_in6 =
            unsafe { bpf_probe_read(pt_regs.arg(1).ok_or(1u32)?).map_err(|_| 1u32)? };

        let addr6 = Ipv6Addr::from(sockaddr_in.sin6_addr);
        be.ip_addr = IpAddr::V6(addr6);
        be.port = sockaddr_in.sin6_port.to_be();
        // info!(&ctx, "Connection attempted to IPv6 port: {}", be.port);
    } else {
        return Ok(1);
    }

    if be.port == 0 {
        return Ok(0);
    }

    unsafe {
        BTP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}
