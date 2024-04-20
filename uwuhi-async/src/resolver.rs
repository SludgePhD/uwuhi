//! DNS name resolution.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use async_io::{Async, Timer};
use futures_lite::future;
pub use uwuhi::resolver::*;
use uwuhi::{name::DomainName, DNS_BUFFER_SIZE, MDNS_BUFFER_SIZE};

pub struct AsyncResolver {
    servers: Vec<SocketAddr>,
    sock: Async<UdpSocket>,
    ip_buf: Vec<IpAddr>,
    is_multicast: bool,
    timeout: Duration,
}

impl AsyncResolver {
    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

    /// Creates a new DNS resolver that will contact the given server.
    pub async fn new(server: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = if server.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        Ok(Self {
            servers: vec![server],
            sock: Async::<UdpSocket>::bind(bind_addr)?,
            ip_buf: Vec::new(),
            is_multicast: bind_addr.ip().is_multicast(),
            timeout: Self::DEFAULT_TIMEOUT,
        })
    }

    /// Creates a new mDNS resolver that will use IPv4.
    pub async fn new_multicast_v4() -> io::Result<Self> {
        Self::new("224.0.0.251:5353".parse().unwrap()).await
    }

    /// Creates a new mDNS resolver that will use IPv6.
    pub async fn new_multicast_v6() -> io::Result<Self> {
        Self::new("[ff02::fb]:5353".parse().unwrap()).await
    }

    /// Adds another server to be contacted by this resolver.
    ///
    /// Calling [`AsyncResolver::resolve`] or [`AsyncResolver::resolve_domain`] will send a query to
    /// every server in this list. The first response containing at least one resolved IP address
    /// will be returned.
    ///
    /// # Panics
    ///
    /// All servers added to the same [`AsyncResolver`] must match the family of the first server
    /// passed to [`AsyncResolver::new`], otherwise this method will panic.
    ///
    /// This method will also panic when called on a multicast resolver.
    pub fn add_server(&mut self, server: SocketAddr) {
        assert!(
            !self.is_multicast,
            "cannot add_server to a multicast DNS resolver",
        );
        assert_eq!(
            self.servers.last().unwrap().is_ipv4(),
            server.is_ipv4(),
            "server families must match",
        );
        self.servers.push(server);
    }

    /// Sets the timeout after which to abort a resolution attempt.
    ///
    /// This is the timeout for individual receive operations, not for the whole query. Packets that
    /// don't match the query that was sent will be ignored, but still reset the timeout.
    pub fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }

    /// Attempts to resolve `hostname` using the configured DNS servers.
    ///
    /// If the query times out, an error of type [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`] will be returned.
    ///
    /// The resolver does not perform recursive resolution (it is a "stub resolver"). It does set
    /// the `RD` bit in the query, which instructs the server to perform recursion.
    pub async fn resolve(
        &mut self,
        hostname: &str,
    ) -> io::Result<impl Iterator<Item = IpAddr> + '_> {
        let name = DomainName::from_str(&hostname)?;
        self.resolve_domain(&name).await
    }

    /// Attempts to resolve a [`DomainName`] using the configured DNS servers.
    ///
    /// If the query times out, an error of type [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`] will be returned.
    ///
    /// The resolver does not perform recursive resolution (it is a "stub resolver"). It does set
    /// the `RD` bit in the query, which instructs the server to perform recursion.
    pub async fn resolve_domain(
        &mut self,
        name: &DomainName,
    ) -> io::Result<impl Iterator<Item = IpAddr> + '_> {
        self.ip_buf.clear();

        let mut send_buf = [0; MDNS_BUFFER_SIZE];
        let data = encode_query(&mut send_buf, name);

        log::trace!("resolving '{}', raw query: {:x?}", name, data);

        // FIXME: retransmit
        for addr in &self.servers {
            self.sock.send_to(data, *addr).await?;
        }

        loop {
            let mut recv_buf = [0; DNS_BUFFER_SIZE];
            let timeout = async {
                Timer::after(self.timeout).await;
                Err(io::ErrorKind::TimedOut.into())
            };
            let (b, addr) = future::or(self.sock.recv_from(&mut recv_buf), timeout).await?;
            let recv = &recv_buf[..b];
            log::trace!("recv from {}: {:x?}", addr, recv);

            match decode_answer(recv, &mut self.ip_buf) {
                Ok(()) => {
                    if !self.ip_buf.is_empty() {
                        // We return once any answer contains IP addresses.
                        return Ok(self.ip_buf.iter().copied());
                    }
                }
                Err(e) => {
                    log::warn!("failed to decode response from {}: {:?}", addr, e);
                }
            }
        }
    }
}
