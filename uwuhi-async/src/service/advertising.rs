//! Service advertising.

use std::{io, net::IpAddr};

use async_std::net::UdpSocket;
use uwuhi::{
    packet::name::Label,
    service::{advertising::Advertiser, InstanceDetails, ServiceInstance},
    MDNS_BUFFER_SIZE,
};

pub use uwuhi::service::advertising::*;

/// Asynchronous mDNS service advertiser and name server.
pub struct AsyncAdvertiser {
    adv: Advertiser,
    sock: UdpSocket,
}

impl AsyncAdvertiser {
    /// Creates a new service advertiser that uses the domain `hostname.local`.
    ///
    /// `hostname` should be different from the system host name, to avoid conflicts with other
    /// installed mDNS responders.
    pub fn new(hostname: Label, addr: IpAddr) -> io::Result<Self> {
        let adv = Advertiser::new(hostname, addr)?;
        Ok(Self {
            sock: adv.create_socket()?.into(),
            adv,
        })
    }

    /// Adds an additional hostname and IP address to resolve.
    pub fn add_name(&mut self, hostname: Label, addr: IpAddr) {
        self.adv.add_name(hostname, addr);
    }

    pub fn add_instance(&mut self, instance: ServiceInstance, details: InstanceDetails) {
        self.adv.add_instance(instance, details);
    }

    /// Listens for and replies to incoming DNS queries.
    pub async fn listen(&mut self) -> io::Result<()> {
        let mut recv_buf = [0; MDNS_BUFFER_SIZE];
        loop {
            let (len, addr) = self.sock.recv_from(&mut recv_buf).await?;
            let packet = &recv_buf[..len];

            log::trace!("raw recv from {}: {:x?}", addr, packet);

            match self.adv.handle_packet(packet) {
                Ok(Some(resp)) => {
                    self.sock.send_to(resp, addr).await?;
                }
                Ok(None) => {}
                Err(e) => {
                    log::debug!("failed to handle packet: {}", e);
                }
            }
        }
    }
}
