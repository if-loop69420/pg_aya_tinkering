#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_probe_write_user, generated::bpf_probe_read_user_str},
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe(path = "test_program", function = "print_user_message")]
pub fn simple_uprobe_backup(ctx: ProbeContext) -> u32 {
    match try_simple_uprobe_backup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_simple_uprobe_backup(ctx: ProbeContext) -> Result<u32, u32> {
    let arg_pointer: *const u8 = ctx.arg(0).unwrap();
    let mut buf = [0u8; 128];
    let _ = unsafe {
        bpf_probe_read_user_str(
            buf.as_mut_ptr() as *mut c_void,
            128,
            arg_pointer as *const c_void,
        )
    };

    if buf.starts_with(b"profanity") {
        let replacement = b"";
        let mut clean_buf = [b' '; 128];
        clean_buf[..replacement.len()].copy_from_slice(replacement);
        let _ = unsafe { bpf_probe_write_user(arg_pointer as *mut [u8; 128], &clean_buf) };
    }
    info!(&ctx, "function print_user_message called by test_program");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
