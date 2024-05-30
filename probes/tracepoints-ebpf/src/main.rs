#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

mod btftracepoints;
mod common;
mod tracepoints;
#[macro_use]
mod vmlinux;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
