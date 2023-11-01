//! mDNS traffic tapping.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
};

use crate::{hex::Hex, packet::decoder::MessageDecoder, Error};
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
        log::trace!("raw packet from {}: {} bytes {}", addr, msg.len(), Hex(msg));

        let msg = MessageDecoder::new(msg)?;
        msg.format(|args| log::debug!("{}", args))
    }
}
