#import "@preview/typslides:1.3.4": *

// Project configuration
#show: typslides.with(
  ratio: "16-9",
  theme: "bluey",
  font: "Fira Sans",
  font-size: 20pt,
  link-style: "color",
  show-progress: true,
)

// The front slide is the first slide of your presentation
#front-slide(
  title: "Tinkering with Aya and Rust",
  subtitle: [for fun and profit],
  authors: "Jeremy Sztavinovszki",
  info: [Repo @ #link("https://github.com/if-loop69420/pg_aya_tinkering")],
)

#slide(title: "What is eBPF?")[
  - extended Berkley Packet Filters
  - Successor to BPF (Berkley Packet Filters)
  - Add kernel functionality without modules/source code changes
  #framed(title: "Basically")[
    It's a technology that can run programs in a privileged context.
  ]
]

#slide(title: "What's Aya?")[
  - A pure Rust library for eBPFs not relying on libbpf or bcc
  - Only uses the libc crate for syscalls
]
#slide(title: "So what can you do with that?")[
  - Aya has support for:
    - XDP
    - LSM
    - Probes
    - Tracepoints
]
// eXpress data Path (attaches to network interface, can filter out packets)
// Linux Security Module (allows security systems on top of the kernel. Like AppArmor)
// Probes (uprobes/kprobes) allows to connect to kernel or user functions
// Tracepoints Static Probing  inserted at specific locations in the kernel source code (syscalls, sched, net)

#title-slide[
  Let's get to demos!
]

