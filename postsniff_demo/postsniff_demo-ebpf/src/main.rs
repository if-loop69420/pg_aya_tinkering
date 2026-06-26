#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::generated::bpf_probe_read_user_str,
    macros::{map, uprobe},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[map]
static COUNTER_MAP: HashMap<u32, u64> = HashMap::with_max_entries(3, 0);

#[uprobe]
pub fn postsniff_demo(ctx: ProbeContext) -> u32 {
    match try_postsniff_demo(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_postsniff_demo(ctx: ProbeContext) -> Result<u32, u32> {
    let query_ptr: *const u8 = ctx.arg(0).unwrap();
    let mut buf = [0u8; 32];

    let _ = unsafe {
        bpf_probe_read_user_str(
            buf.as_mut_ptr() as *mut c_void,
            32,
            query_ptr as *const c_void,
        )
    };

    let key = if buf.starts_with(b"SELECT") {
        0u32
    } else if buf.starts_with(b"INSERT") {
        1u32
    } else {
        2u32
    };

    unsafe {
        let count = COUNTER_MAP.get(&key).copied().unwrap_or(0);
        let next_count = count + 1;

        // This is the critical change: capture the result
        let res = COUNTER_MAP.insert(&key, &next_count, 0);

        if res.is_err() {
            info!(&ctx, "Insert failed! Error: {}", res.err().unwrap());
        } else {
            info!(&ctx, "Success! Key {} is now {}", key, next_count);
        }
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
