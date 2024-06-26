use aya_ebpf::EbpfContext;

use aya_ebpf::helpers::{
    bpf_get_current_task, bpf_probe_read, bpf_probe_read_kernel_buf,
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
};
use aya_ebpf::{macros::map, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::debug;

use crate::common::{
    read_list_u8, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, LOCAL_BUFFER, TP_SYSINFO,
};

use crate::vmlinux::vmlinux::{pid_t, sockaddr};
use crate::{get_offset, probe_read};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, LpmTrie, PerfEventByteArray};
use bitblazr_common::models::{BlazrArch, BlazrKernelVersion};
use bitblazr_common::rules::BlazrRuleClass;
use bitblazr_common::{BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType};
use core::ffi::c_void;
use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[map]
pub static mut TP_BUFFER: PerfEventByteArray = PerfEventByteArray::new(0);

#[repr(C)]
pub struct PrefixKey {
    pub buf: [u8; 27],
}

#[map]
pub(crate) static mut TP_OPEN_PREFIX: LpmTrie<PrefixKey, u32> = LpmTrie::with_max_entries(100, 0);

#[map]
pub(crate) static mut TP_OPEN_PREFIX_LEN: Array<u32> = Array::with_max_entries(100, 0);

#[tracepoint]
pub fn tracepoints(ctx: TracePointContext) -> u32 {
    match process_tps(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn init_be(ctx: &TracePointContext, be: &mut BlazrEvent) -> Result<(), u32> {
    let task: *const c_void = unsafe { bpf_get_current_task() as *const _ };
    let parent = probe_read!(task, task_struct, parent, *const c_void, 0u32);
    let ppid = probe_read!(parent, task_struct, pid, pid_t, 0u32);
    if get_parent_path(ctx, be).is_err() {
        let mut p_comm = ctx.command().map_err(|_| 0u32)?;
        unsafe {
            bpf_probe_read_kernel_str_bytes(p_comm.as_mut_ptr(), &mut be.p_path)
                .map_err(|_| 0u32)?
        };
    }

    be.class = BlazrEventClass::Tracepoint;
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

fn get_parent_path(_ctx: &TracePointContext, be: &mut BlazrEvent) -> Result<(), u32> {
    let task: *const c_void = unsafe { bpf_get_current_task() as *const _ };
    let mm = probe_read!(task, task_struct, mm, *const c_void, 0u32);
    let argv_p = probe_read!(mm, mm_struct, __bindgen_anon_1.arg_start, *const u8, 0u32);
    unsafe { bpf_probe_read_user_str_bytes(argv_p, &mut be.p_path).map_err(|_| 0u32)? };
    Ok(())
}

fn process_tps(ctx: TracePointContext) -> Result<u32, u32> {
    debug!(&ctx, "tracepoint called");

    let buf_ptr = unsafe { LOCAL_BUFFER.get_ptr_mut(0).ok_or(1u32)? };
    let mut be: &mut BlazrEvent = unsafe { &mut *buf_ptr };

    init_be(&ctx, &mut be).map_err(|_| 1u32)?;

    let sys_info = unsafe { TP_SYSINFO.get(0).ok_or(1u32)? };

    let call_id: i64 = unsafe { ctx.read_at::<i64>(8).map_err(|_| 1u32)? };
    let args: [u64; 6] = unsafe { ctx.read_at::<[u64; 6]>(16).map_err(|_| 1u32)? };

    match sys_info.arch {
        BlazrArch::X86_64 => match call_id {
            2 | 85 => process_open(ctx, args, be),
            41 => process_socket(ctx, args, be),
            42 => process_connect(ctx, args, be),
            49 => process_bind(ctx, args, be),
            50 => process_listen(ctx, args, be),
            59 => process_exec(ctx, args, be),
            60 | 231 => process_exit(ctx, args, be),
            257 | 437 => process_openat(ctx, args, be),
            _ => Ok(0),
        },
        BlazrArch::Aarch64 => match call_id {
            56 | 437 => process_openat(ctx, args, be),
            93 | 94 => process_exit(ctx, args, be),
            198 => process_socket(ctx, args, be),
            200 => process_bind(ctx, args, be),
            201 => process_listen(ctx, args, be),
            203 => process_connect(ctx, args, be),
            221 => process_exec(ctx, args, be),
            _ => Ok(0),
        },
        BlazrArch::Arm => match call_id {
            5 | 8 => process_open(ctx, args, be),
            322 | 437 => process_openat(ctx, args, be),
            1 | 248 => process_exit(ctx, args, be),
            281 => process_socket(ctx, args, be),
            282 => process_bind(ctx, args, be),
            284 => process_listen(ctx, args, be),
            283 => process_connect(ctx, args, be),
            11 => process_exec(ctx, args, be),
            _ => Ok(0),
        },
        _ => Ok(0),
    }
}

fn process_exec(ctx: TracePointContext, args: [u64; 6], be: &mut BlazrEvent) -> Result<u32, u32> {
    be.event_type = BlazrEventType::Exec;
    be.log_class = BlazrRuleClass::File;

    let f_name = args[0] as *const u8;
    unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

    let argv = args[1] as *const *const u8;

    be.argv_count = read_list_u8(argv, &mut be.argv)?;

    unsafe {
        TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

fn process_exit(ctx: TracePointContext, args: [u64; 6], be: &mut BlazrEvent) -> Result<u32, u32> {
    be.event_type = BlazrEventType::Exit;
    be.log_class = BlazrRuleClass::File;
    be.exit_code = args[0] as u8;
    unsafe {
        TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}

fn process_open(ctx: TracePointContext, args: [u64; 6], be: &mut BlazrEvent) -> Result<u32, u32> {
    be.event_type = BlazrEventType::Open;
    be.log_class = BlazrRuleClass::File;

    let f_name = args[0] as *const u8;
    unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

    let mut p_key = Key::new(25, PrefixKey { buf: [0; 27] });

    unsafe {
        bpf_probe_read_kernel_buf(be.path.as_ptr(), &mut p_key.data.buf).map_err(|_| 0u32)?;
    }

    let mut matched = false;
    for i in 0..100u32 {
        let len = unsafe { *TP_OPEN_PREFIX_LEN.get(i).unwrap_or(&27) };
        if len > 25 {
            break;
        }
        p_key.prefix_len = len * 8;
        if unsafe { TP_OPEN_PREFIX.get(&p_key).is_some() } {
            matched = true;
            break;
        }
    }

    if matched {
        unsafe {
            TP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }

    Ok(0)
}

fn process_openat(ctx: TracePointContext, args: [u64; 6], be: &mut BlazrEvent) -> Result<u32, u32> {
    be.event_type = BlazrEventType::Open;
    be.log_class = BlazrRuleClass::File;

    let f_name = args[1] as *const u8;
    unsafe { bpf_probe_read_user_str_bytes(f_name, &mut be.path).map_err(|_| 1u32)? };

    let mut p_key = Key::new(25, PrefixKey { buf: [0; 27] });

    unsafe {
        bpf_probe_read_kernel_buf(be.path.as_ptr(), &mut p_key.data.buf).map_err(|_| 0u32)?;
    }

    let mut matched = false;
    for i in 0..100u32 {
        let len = unsafe { *TP_OPEN_PREFIX_LEN.get(i).unwrap_or(&27) };
        if len > 25 {
            break;
        }
        p_key.prefix_len = len * 8;
        if unsafe { TP_OPEN_PREFIX.get(&p_key).is_some() } {
            matched = true;
            break;
        }
    }

    if matched {
        unsafe {
            TP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }

    Ok(0)
}

fn process_bind(ctx: TracePointContext, args: [u64; 6], be: &mut BlazrEvent) -> Result<u32, u32> {
    let sock_addr = args[1] as *const sockaddr;
    let sa_family: u16 = unsafe { bpf_probe_read(&(*sock_addr).sa_family).map_err(|_| 1u32)? };

    be.event_type = BlazrEventType::Bind;
    be.log_class = BlazrRuleClass::Socket;
    be.path[0] = 0u8;

    if sa_family == AF_INET {
        let sockaddr_in =
            unsafe { bpf_probe_read(args[1] as *const sockaddr_in).map_err(|_| 1u32)? };
        be.port = sockaddr_in.sin_port.to_be();
    } else if sa_family == AF_INET6 {
        let sockaddr_in =
            unsafe { bpf_probe_read(args[1] as *const sockaddr_in6).map_err(|_| 1u32)? };

        be.port = sockaddr_in.sin6_port.to_be();
    } else {
        return Ok(1);
    }

    if be.port > 0 {
        unsafe {
            TP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }
    Ok(0)
}

fn process_socket(ctx: TracePointContext, args: [u64; 6], be: &mut BlazrEvent) -> Result<u32, u32> {
    let family = args[0] as u16;
    be.protocol = args[2] as u16;

    be.event_type = BlazrEventType::Bind;
    be.log_class = BlazrRuleClass::Socket;

    if be.protocol > 0 && (family == AF_INET || family == AF_INET6) {
        unsafe {
            TP_BUFFER.output(&ctx, be.to_bytes(), 0);
        }
    }

    Ok(0)
}

fn process_listen(
    ctx: TracePointContext,
    _args: [u64; 6],
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    be.event_type = BlazrEventType::Listen;
    be.log_class = BlazrRuleClass::Socket;
    be.path[0] = 0u8;

    unsafe {
        TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }
    Ok(0)
}

fn process_connect(
    ctx: TracePointContext,
    args: [u64; 6],
    be: &mut BlazrEvent,
) -> Result<u32, u32> {
    let sock_addr = args[1] as *const sockaddr;
    let sa_family: u16 = unsafe { bpf_probe_read(&(*sock_addr).sa_family).map_err(|_| 1u32)? };

    be.event_type = BlazrEventType::Connect;
    be.log_class = BlazrRuleClass::Socket;

    if sa_family == AF_INET {
        let sockaddr_in =
            unsafe { bpf_probe_read(args[1] as *const sockaddr_in).map_err(|_| 1u32)? };
        be.port = sockaddr_in.sin_port.to_be();
        let int_ip = sockaddr_in.sin_addr.to_be();
        let addr = Ipv4Addr::from(int_ip);
        be.ip_addr = IpAddr::V4(addr);
    } else if sa_family == AF_INET6 {
        let sockaddr_in =
            unsafe { bpf_probe_read(args[1] as *const sockaddr_in6).map_err(|_| 1u32)? };

        let addr6 = Ipv6Addr::from(sockaddr_in.sin6_addr);
        be.ip_addr = IpAddr::V6(addr6);
        be.port = sockaddr_in.sin6_port.to_be();
    } else {
        return Ok(1);
    }

    if be.port == 0 {
        return Ok(0);
    }

    unsafe {
        TP_BUFFER.output(&ctx, be.to_bytes(), 0);
    }

    Ok(0)
}
