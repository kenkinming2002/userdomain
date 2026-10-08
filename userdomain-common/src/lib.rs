#![no_std]

use core::net::Ipv4Addr;

pub const REDIR_MAX: u8 = 8;

#[derive(Clone, Copy, Debug)]
#[derive(PartialEq, Eq, Hash)]
pub struct Addr(pub Ipv4Addr);

#[derive(Clone, Copy, Debug)]
pub struct Redir {
    // Network bytes order
    pub port_from: [u8; 2],
    pub port_to: [u8; 2],
}

#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub uid: u32,
    pub redir_count: u8,
    pub redirs: [Redir; REDIR_MAX as usize],
}

#[cfg(feature="user")]
unsafe impl aya::Pod for Addr {}

#[cfg(feature="user")]
unsafe impl aya::Pod for Redir {}

#[cfg(feature="user")]
unsafe impl aya::Pod for Spec {}
