//! Unicast and Multicast DNS and DNS Service Discovery implementation.

mod num;
pub mod packet;
pub mod resolver;
pub mod service;
pub mod tap;

/// Size of unicast DNS message buffers.
///
/// Unicast DNS messages are limited to 512 Bytes.
pub const DNS_BUFFER_SIZE: usize = 512;

/// Size of multicast DNS message buffers.
///
/// DNS messages are limited to 512 Bytes, but mDNS works entirely within a local network, so it can
/// use larger messages.
///
/// This constant is the size of packet receive buffers and does not have to accomodate IP and UDP
/// headers. It still does, because I cannot be bothered.
pub const MDNS_BUFFER_SIZE: usize = 1500;
