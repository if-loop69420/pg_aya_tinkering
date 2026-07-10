use std::os::fd::AsRawFd;

use aya::maps::RingBuf;
use aya::programs::{UProbe, uprobe::UProbeScope};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<u32>,
}

#[repr(C)]
struct Message {
    query: [u8; 1024], // 1KB query string
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel_user_ringbuf"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { pid } = opt;
    let scope = match pid.map(std::num::NonZeroU32::new) {
        Some(Some(pid)) => UProbeScope::OneProcess(pid),
        Some(None) => UProbeScope::CallingProcess,
        None => UProbeScope::AllProcesses,
    };
    {
        let program: &mut UProbe = ebpf
            .program_mut("kernel_user_ringbuf")
            .unwrap()
            .try_into()?;
        program.load()?;
        let target_binary = match pid {
            Some(p) => format!("/proc/{}/exe", p),
            None => "/usr/bin/postgres".to_string(),
        };

        program.attach("pg_parse_query", &target_binary, scope)?;
    }
    let mut map = RingBuf::try_from(ebpf.map_mut("MESSAGE_BUF").unwrap()).unwrap();
    let fd = map.as_raw_fd();
    let async_ring = AsyncFd::with_interest(fd, Interest::READABLE)?;

    while let Some(x) = map.next() {
        let bytes = &*x;
        let msg: &Message = unsafe { &*(bytes.as_ptr() as *const Message) };
        println!(
            "Received {}",
            String::from_utf8(msg.query.to_vec()).unwrap()
        )
    }

    println!("Waiting for Ctrl-C...");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            },
            guard = async_ring.readable() => {
                let mut guard = guard.unwrap();
                while let Some(x) = map.next() {
                    let bytes = &*x;
                    let msg: &Message = unsafe { &*(bytes.as_ptr() as *const Message) };
                    println!(
                        "Received {}",
                        String::from_utf8(msg.query.to_vec()).unwrap()
                    )
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
