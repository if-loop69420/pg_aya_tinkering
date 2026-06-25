#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_probe_write_user,
        generated::{bpf_override_return, bpf_probe_read_user_str},
    },
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe]
pub fn postdrop(ctx: ProbeContext) -> u32 {
    match try_postdrop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_postdrop(ctx: ProbeContext) -> Result<u32, u32> {
    let query_ptr: *const u8 = ctx.arg(0).unwrap();

    let mut buf = [0u8; 128];
    let _ = unsafe {
        bpf_probe_read_user_str(
            buf.as_mut_ptr() as *mut c_void,
            128,
            query_ptr as *const c_void,
        )
    };

    if buf.starts_with(b"DROP TABLE") {
        let replacement = b"SELECT NULL;\0";
        let mut clean_buf = [b' '; 128];
        clean_buf[..replacement.len()].copy_from_slice(replacement);
        let _ = unsafe { bpf_probe_write_user(query_ptr as *mut [u8; 128], &clean_buf) };
    }

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
