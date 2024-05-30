#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux6_9;

#[macro_export]
macro_rules! get_offset {
    ($($field:ident).+, $obj:ident, $err:expr) => {{
        use crate::vmlinux::{vmlinux, vmlinux6_9};
        let sys_info = unsafe { TP_SYSINFO.get(0).ok_or($err)? };
        match sys_info.kernel_ver {
            BlazrKernelVersion::SixNinePlus => {
                let st = core::ptr::null::<vmlinux6_9::$obj>();
                unsafe { &(*st).$($field).+ as *const _ as usize }
            }
            _ => {
                let st = core::ptr::null::<vmlinux::$obj>();
                unsafe { &(*st).$($field).+ as *const _ as usize }
            }
        }
    }};
}

#[macro_export]
macro_rules! probe_read {
    ($obj:ident, $obj_type:ident, $($field:ident).+, $field_type:ty, $err:expr) => {{
        let offset = get_offset!($($field).+, $obj_type, $err);
        unsafe {
            bpf_probe_read::<$field_type>($obj.add(offset) as *const $field_type)
                .map_err(|_| $err)?
        }
    }};
}
