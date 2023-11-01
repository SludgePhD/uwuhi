//! mDNS traffic tapping.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
};

use crate::{packet::decoder::MessageDecoder, Error};
use socket2::{Domain, Protocol, Socket, Type};

use crate::MDNS_BUFFER_SIZE;

/// An mDNS tap that will log every received mDNS packet.
pub struct SyncTap {
    sock: UdpSocket,
}

impl SyncTap {
    /// Creates a new mDNS tap listening on port 5353.
    pub fn new() -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.bind(&"0.0.0.0:5353".parse::<SocketAddr>().unwrap().into())?;

        let sock = UdpSocket::from(sock);
        sock.join_multicast_v4(&"224.0.0.251".parse().unwrap(), &Ipv4Addr::UNSPECIFIED)?;
        sock.set_multicast_loop_v4(true)?;
        Ok(Self { sock })
    }

    pub fn listen(self) -> io::Result<()> {
        loop {
            let mut buf = [0; MDNS_BUFFER_SIZE];
            let (len, addr) = self.sock.recv_from(&mut buf)?;

            let buf = &buf[..len];
            match self.process(addr, buf) {
                Ok(()) => {}
                Err(Error::Eof) if len == MDNS_BUFFER_SIZE => {
                    // The TC bit often does not seem to get set. Maybe I got the buffer size wrong?
                    log::debug!("error: unexpected EOF. However, the receive buffer is filled completely; message truncation is likely");
                }
                Err(e) => {
                    log::warn!("failed to process incoming message: {:?}", e);
                }
            }
        }
    }

    fn process(&self, addr: SocketAddr, msg: &[u8]) -> Result<(), Error> {
        log::trace!(
            "raw packet from {}: {} bytes {}",
            addr,
            msg.len(),
            msg.escape_ascii()
        );

        let mut msg = MessageDecoder::new(msg)?;
        let h = msg.header();
        log::trace!("header={:?}", h);
        let dir = if h.is_query() { "query" } else { "response" };
        let trunc = if h.is_truncated() { ", trunc" } else { "" };
        let ra = if h.is_recursion_available() {
            ", RA"
        } else {
            ""
        };
        let rd = if h.is_recursion_desired() { ", RD" } else { "" };
        let aa = if h.is_authority() { ", AA" } else { "" };
        log::info!(
            "{} from {} (id={}, op={}, rcode={}{trunc}{ra}{rd}{aa})",
            dir,
            addr,
            h.id(),
            h.opcode(),
            h.rcode(),
        );
        for q in msg.iter() {
            let q = q?;
            log::debug!("Q: {}", q);
        }
        let mut msg = msg.answers()?;
        for rr in msg.iter() {
            let rr = rr?;
            log::debug!("ANS: {}", rr);
        }
        let mut msg = msg.authority()?;
        for rr in msg.iter() {
            let rr = rr?;
            log::debug!("AUTH: {}", rr);
        }
        let mut msg = msg.additional()?;
        for rr in msg.iter() {
            let rr = rr?;
            log::debug!("ADDL: {}", rr);
        }
        Ok(())
    }
}
