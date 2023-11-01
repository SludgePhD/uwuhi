//! DNS name resolution.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use crate::{
    name::DomainName,
    packet::{
        decoder::MessageDecoder,
        encoder::{MessageEncoder, Question},
        records::Record,
        Header, QType,
    },
    Error,
};

use crate::{DNS_BUFFER_SIZE, MDNS_BUFFER_SIZE};

/// A simple, synchronous, non-recursive (m)DNS stub resolver.
pub struct SyncResolver {
    servers: Vec<SocketAddr>,
    sock: UdpSocket,
    ip_buf: Vec<IpAddr>,
    is_multicast: bool,
}

impl SyncResolver {
    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

    /// Creates a new DNS resolver that will contact the given server.
    pub fn new(sock: SocketAddr) -> io::Result<Self> {
        let bind_addr: SocketAddr = if sock.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let mut this = Self {
            servers: vec![sock],
            sock: UdpSocket::bind(bind_addr)?,
            ip_buf: Vec::new(),
            is_multicast: bind_addr.ip().is_multicast(),
        };
        this.set_timeout(Self::DEFAULT_TIMEOUT)?;
        Ok(this)
    }

    /// Creates a new mDNS resolver that will use IPv4.
    pub fn new_multicast_v4() -> io::Result<Self> {
        Self::new("224.0.0.251:5353".parse().unwrap())
    }

    /// Creates a new mDNS resolver that will use IPv6.
    pub fn new_multicast_v6() -> io::Result<Self> {
        Self::new("[ff02::fb]:5353".parse().unwrap())
    }

    /// Adds another server to be contacted by this resolver.
    ///
    /// Calling [`SyncResolver::resolve`] or [`SyncResolver::resolve_domain`] will send a query to
    /// every server in this list. The first response containing at least one resolved IP address
    /// will be returned.
    ///
    /// # Panics
    ///
    /// All servers added to the same [`SyncResolver`] must match the family of the first server
    /// passed to [`SyncResolver::new`], otherwise this method will panic.
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
        self.sock.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    /// Attempts to resolve `hostname` using the configured DNS servers.
    ///
    /// If the query times out, an error of type [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`] will be returned.
    ///
    /// The resolver does not perform recursive resolution (it is a "stub resolver"). It does set
    /// the `RD` bit in the query, which instructs the server to perform recursion.
    pub fn resolve(&mut self, hostname: &str) -> io::Result<impl Iterator<Item = IpAddr> + '_> {
        let name = DomainName::from_str(&hostname)?;
        self.resolve_domain(&name)
    }

    /// Attempts to resolve a [`DomainName`] using the configured DNS servers.
    ///
    /// If the query times out, an error of type [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`] will be returned.
    ///
    /// The resolver does not perform recursive resolution (it is a "stub resolver"). It does set
    /// the `RD` bit in the query, which instructs the server to perform recursion.
    pub fn resolve_domain(
        &mut self,
        name: &DomainName,
    ) -> io::Result<impl Iterator<Item = IpAddr> + '_> {
        self.ip_buf.clear();

        let mut send_buf = [0; MDNS_BUFFER_SIZE];
        let data = encode_query(&mut send_buf, name);

        log::trace!("resolving '{}', raw query: {:x?}", name, data);

        // FIXME: retransmit
        for addr in &self.servers {
            self.sock.send_to(data, addr)?;
        }

        loop {
            let mut recv_buf = [0; DNS_BUFFER_SIZE];
            let (b, addr) = self.sock.recv_from(&mut recv_buf)?;
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

/// Writes a DNS query asking for IPv4 and IPv6 addresses of `name` into `buf`.
///
/// The given buffer must be large enough to fit the query, or this method will panic.
pub fn encode_query<'a>(buf: &'a mut [u8], name: &DomainName) -> &'a [u8] {
    let mut header = Header::default();
    header.set_recursion_desired(true);
    header.set_id(12345);
    let mut enc = MessageEncoder::new(buf);
    enc.set_header(header);
    enc.question(Question::new(&name).ty(QType::A));
    enc.question(Question::new(&name).ty(QType::AAAA));
    let bytes = enc.finish().unwrap();
    &buf[..bytes]
}

/// Decodes an answer packet from a DNS resolver, adding any contained IP addresses to `ip_buf`.
pub fn decode_answer(msg: &[u8], ip_buf: &mut Vec<IpAddr>) -> Result<(), Error> {
    let dec = MessageDecoder::new(msg)?;
    let h = dec.header();
    log::trace!("header: {:?}", h);
    if !h.is_response() {
        return Ok(());
    }

    for res in dec.answers()?.iter() {
        let ans = res?;
        log::debug!("ANS: {}", ans);
        match ans.as_enum() {
            Some(Ok(Record::A(a))) => ip_buf.push(IpAddr::V4(a.addr().octets().into())),
            Some(Ok(Record::AAAA(a))) => ip_buf.push(IpAddr::V6(a.addr().octets().into())),
            Some(Err(e)) => return Err(e),
            _ => {}
        }
    }

    Ok(())
}
