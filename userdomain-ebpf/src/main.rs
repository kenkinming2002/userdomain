#![no_std]
#![no_main]

#![feature(try_blocks)]

use core::{ffi::CStr, mem};

use aya_ebpf::{bindings::{BPF_F_MARK_MANGLED_0, TC_ACT_OK, TC_ACT_SHOT}, bpf_printk, macros::{classifier, map}, maps::HashMap, programs::TcContext};
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, tcp::TcpHdr, udp::UdpHdr};
use userdomain_common::{Addr, REDIR_MAX, Spec};

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Shot down packet because we have reached code that is supposed unreachable.
fn shot_unreachable(reason: &CStr) {
    unsafe { bpf_printk!(c"userdomain-postrouting: unreachable: %s: dropping packet", reason.as_ptr()); }
}

struct Loader<'a> {
    ctx: &'a TcContext,
    offset: usize,
}

impl<'a> Loader<'a> {
    fn new(ctx: &'a TcContext) -> Self {
        Self { ctx, offset: 0 }
    }
}
impl Loader<'_> {
    fn load<T>(&mut self, reason: &CStr) -> Result<T, ()> {
        let value = self.ctx.load(self.offset).map_err(|_| shot_unreachable(reason))?;
        self.offset += mem::size_of::<T>();
        Ok(value)
    }
}

fn spec_map_port(spec: &Spec, port: [u8; 2]) -> Option<[u8; 2]> {
    spec.redirs
        .iter()
        .take(REDIR_MAX as usize)
        .find(|redir| redir.port_from == port)
        .map(|redir| redir.port_to)
}

fn spec_unmap_port(spec: &Spec, port: [u8; 2]) -> Option<[u8; 2]> {
    spec.redirs
        .iter()
        .take(REDIR_MAX as usize)
        .find(|redir| redir.port_to == port)
        .map(|redir| redir.port_from)
}

fn fold_result(res: Result<i32, ()>) -> i32 {
    // Drop packet on error.
    //
    // TODO: Consider logging error
    res.unwrap_or_else(|_| TC_ACT_SHOT)
}

#[map]
static SPEC_MAP: HashMap<Addr, Spec> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn ingress(ctx: TcContext) -> i32 { fold_result(try {
    ///////////
    // Entry //
    ///////////
    let mut loader = Loader::new(&ctx);
    let ethhdr: EthHdr = loader.load(c"incomplete ethernet header")?;
    if ethhdr.ether_type() != Ok(EtherType::Ipv4) { return TC_ACT_OK }
    let iphdr: Ipv4Hdr = loader.load(c"incomplete internet header")?;

    ////////////////////////////
    // NAT - Rewrite Dst Port //
    ////////////////////////////
    {
        let addr = Addr(iphdr.dst_addr());
        if let Some(spec) = unsafe { SPEC_MAP.get(&addr)} {'rewrite:{
            let csum_offset;
            let port_offset;
            let old_port;
            let flags;
            match iphdr.proto() {
                Ok(IpProto::Tcp) => {
                    let tcphdr: TcpHdr = loader.load(c"incomplete tcp header")?;
                    csum_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(TcpHdr, check);
                    port_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(TcpHdr, dest);
                    old_port = tcphdr.dest;
                    flags = 0;
                },
                Ok(IpProto::Udp) => {
                    let udphdr: UdpHdr = loader.load(c"incomplete udp header")?;
                    csum_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(UdpHdr, check);
                    port_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(UdpHdr, dst);
                    old_port = udphdr.dst;
                    flags = BPF_F_MARK_MANGLED_0 as u64;
                },
                _ => break 'rewrite
            }

            if let Some(new_port) = spec_map_port(spec, old_port) {
                ctx.l4_csum_replace(csum_offset, u16::from_ne_bytes(old_port) as u64, u16::from_ne_bytes(new_port) as u64, flags | mem::size_of::<u16>() as u64).map_err(|_| ())?;
                ctx.store(port_offset, &new_port, 0).map_err(|_| ())?;
            }
        }}
    }

    /////////////
    // Default //
    /////////////
    TC_ACT_OK
})}

#[classifier]
pub fn egress(ctx: TcContext) -> i32 { fold_result(try {
    ///////////
    // Entry //
    ///////////
    let mut loader = Loader::new(&ctx);
    let ethhdr: EthHdr = loader.load(c"incomplete ethernet header")?;
    if ethhdr.ether_type() != Ok(EtherType::Ipv4) { return TC_ACT_OK }
    let iphdr: Ipv4Hdr = loader.load(c"incomplete internet header")?;

    //////////////
    // Firewall //
    //////////////
    {
        let addr = Addr(iphdr.dst_addr());
        if let Some(spec) = unsafe { SPEC_MAP.get(&addr)} {
            let uid = ctx.get_socket_uid();
            if spec.uid != uid {
                // NOTE: This is maybe suboptimal because we simply drop the packet
                //       without any response. For example, if a tcp connection is to be
                //       established, it will simply backoff exponentially until it
                //       timeout, which is less then efficient. A way to work around
                //       this is to use netfilter instead of tc.
                return TC_ACT_SHOT;
            }
        }
    }

    ////////////////////////////
    // NAT - Rewrite Src Port //
    ////////////////////////////
    {
        let addr = Addr(iphdr.src_addr());
        if let Some(spec) = unsafe { SPEC_MAP.get(&addr)} {'rewrite:{
            let csum_offset;
            let port_offset;
            let old_port;
            let flags;
            match iphdr.proto() {
                Ok(IpProto::Tcp) => {
                    let tcphdr: TcpHdr = loader.load(c"incomplete tcp header")?;
                    csum_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(TcpHdr, check);
                    port_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(TcpHdr, source);
                    old_port = tcphdr.source;
                    flags = 0;
                },
                Ok(IpProto::Udp) => {
                    let udphdr: UdpHdr = loader.load(c"incomplete udp header")?;
                    csum_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(UdpHdr, check);
                    port_offset = mem::size_of_val(&ethhdr) + mem::size_of_val(&iphdr) + mem::offset_of!(UdpHdr, src);
                    old_port = udphdr.src;
                    flags = BPF_F_MARK_MANGLED_0 as u64;
                },
                _ => break 'rewrite
            }

            if let Some(new_port) = spec_unmap_port(spec, old_port) {
                ctx.l4_csum_replace(csum_offset, u16::from_ne_bytes(old_port) as u64, u16::from_ne_bytes(new_port) as u64, flags | mem::size_of::<u16>() as u64).map_err(|_| ())?;
                ctx.store(port_offset, &new_port, 0).map_err(|_| ())?;
            }
        }}
    }

    /////////////
    // Default //
    /////////////
    TC_ACT_OK
})}

