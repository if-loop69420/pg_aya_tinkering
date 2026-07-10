#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::generated::bpf_probe_read_user_str,
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[map]
static MESSAGE_BUF: RingBuf = RingBuf::with_byte_size(1024 * 32, 0); // 32 KB buf

#[repr(C)]
struct Message {
    pub query: [u8; 1024], // 1KB of query
}

#[uprobe(path = "postgres", function = "pg_parse_query")]
pub fn kernel_user_ringbuf(ctx: ProbeContext) -> u32 {
    match try_kernel_user_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kernel_user_ringbuf(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function pg_parse_query called by postgres");
    let ptr: *const u8 = ctx.arg(0).unwrap();
    let Some(mut entry) = MESSAGE_BUF.reserve::<Message>(0) else {
        return Err(0);
    };
    let ev = entry.as_mut_ptr();

    let _ = unsafe {
        bpf_probe_read_user_str(
            (*ev).query.as_mut_ptr() as *mut c_void,
            1024,
            ptr as *const c_void,
        )
    };

    entry.submit(0);
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
