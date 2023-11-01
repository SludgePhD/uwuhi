//! DNS-based Service Discovery.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    ops::ControlFlow,
    time::{Duration, Instant},
};

use crate::{
    hex::Hex,
    name::DomainName,
    packet::{
        decoder::MessageDecoder,
        encoder::{self, MessageEncoder},
        records::Record,
        Header, QType,
    },
    Error,
};

use crate::MDNS_BUFFER_SIZE;

use super::{InstanceDetails, Service, ServiceInstance, TxtRecords};

/// A simple, synchronous DNS service discoverer.
pub struct SyncDiscoverer {
    sock: UdpSocket,
    server: SocketAddr,
    domain: DomainName,
    discovery_timeout: Duration,
}

impl SyncDiscoverer {
    const DEFAULT_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(300);
    const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1000);

    /// Creates a new service discoverer that will request services of `domain` from the given DNS
    /// server.
    pub fn new(server: SocketAddr, domain: DomainName) -> io::Result<Self> {
        let bind_addr: SocketAddr = if server.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let mut this = Self {
            sock: UdpSocket::bind(bind_addr)?,
            server,
            domain,
            discovery_timeout: Self::DEFAULT_DISCOVERY_TIMEOUT,
        };
        this.set_retransmit_timeout(Self::DEFAULT_RETRANSMIT_TIMEOUT)?;
        Ok(this)
    }

    /// Creates an mDNS service discoverer that will browse the `.local` service domain.
    pub fn new_multicast_v4() -> io::Result<Self> {
        Self::new(
            "224.0.0.251:5353".parse().unwrap(),
            DomainName::from_str("local").unwrap(),
        )
    }

    /// Sets the time after which a discovery query is retransmitted, if no responses have been
    /// received in this amount of time.
    pub fn set_retransmit_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.sock.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    /// Sets the total maximum time to run discovery for.
    ///
    /// Calling any service discovery method will block for this amount of time while it waits for
    /// responses.
    pub fn set_discovery_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.discovery_timeout = timeout;
        Ok(())
    }

    /// Requests the [`InstanceDetails`] associated with a specific [`ServiceInstance`] from the
    /// server.
    ///
    /// The [`InstanceDetails`] contain hostname and port where the [`ServiceInstance`] can be
    /// reached as well as service-specific metadata (which may be omitted).
    pub fn load_instance_details(
        &mut self,
        instance: &ServiceInstance,
    ) -> io::Result<InstanceDetails> {
        let mut domain = DomainName::from_iter([
            &instance.instance_name,
            instance.service.name(),
            &instance.service.transport().to_label(),
        ]);
        domain.extend(&self.domain);

        let mut details = None;
        let mut txt_records = None;
        self.send_query(&domain, &[QType::SRV, QType::TXT], &mut |record| {
            match record {
                Record::SRV(srv) => {
                    match InstanceDetails::from_srv(&srv) {
                        Ok(det) => {
                            // FIXME: respect SRV priority, as required by RFC 6763
                            details = Some(det);
                            // FIXME: breaking here ignores any subsequent TXT records!
                            ControlFlow::Break(())
                        }
                        Err(e) => {
                            log::debug!(
                                "failed to read instance details from SRV ({:?}): {}",
                                e,
                                srv
                            );
                            ControlFlow::Continue(())
                        }
                    }
                }
                Record::TXT(txt) => {
                    txt_records = Some(TxtRecords::from_txt(&txt));
                    ControlFlow::Continue(())
                }
                _ => ControlFlow::Continue(()),
            }
        })?;

        match details {
            Some(mut details) => {
                if let Some(txt) = txt_records {
                    // FIXME this can potentially combine a TXT from one machine with a SRV from
                    // another
                    details.txt = txt;
                }

                Ok(details)
            }

            // Didn't get a response in time.
            None => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    /// Starts service discovery and invokes `callback` with every discovered instance of `service`.
    ///
    /// The `callback` can control whether to keep discovering instances or to exit the discovery
    /// loop by returning a [`ControlFlow`] value.
    pub fn discover_instances<C>(&mut self, service: &Service, mut callback: C) -> io::Result<()>
    where
        C: FnMut(&ServiceInstance) -> ControlFlow<()>,
    {
        let mut domain = DomainName::from_iter([service.name(), &service.transport().to_label()]);
        domain.extend(&self.domain);

        let mut instances = BTreeMap::new();
        self.send_query(&domain, &[QType::PTR], &mut |record| {
            let ptr = match record {
                Record::PTR(ptr) => ptr,
                _ => return ControlFlow::Continue(()),
            };
            let instance = match ServiceInstance::from_ptr(ptr) {
                Ok(service) => service,
                Err(e) => {
                    log::trace!("failed to decode service instance: {:?}", e);
                    return ControlFlow::Continue(());
                }
            };

            // FIXME should probably check that the domain matches ours

            match instances.entry(instance) {
                Entry::Vacant(e) => {
                    let flow = callback(e.key());
                    e.insert(());
                    flow
                }
                Entry::Occupied(_) => {
                    // Already discovered this instance
                    ControlFlow::Continue(())
                }
            }
        })
    }

    /// Discovers the available *service types*.
    ///
    /// This function will request a list of available service types from the DNS server(s). This is
    /// mostly intended for maintenance and debugging, since applications typically know the service
    /// types they support already.
    ///
    /// To discover *service instances*, use [`SyncDiscoverer::discover_instances`] instead.
    pub fn discover_service_types<C>(&mut self, mut callback: C) -> io::Result<()>
    where
        C: FnMut(&Service) -> ControlFlow<()>,
    {
        let mut domain = DomainName::from_str("_services._dns-sd._udp").unwrap();
        domain.extend(&self.domain);
        let mut service_types = BTreeMap::new();
        self.send_query(&domain, &[QType::PTR], &mut |record| {
            let ptr = match record {
                Record::PTR(ptr) => ptr,
                _ => return ControlFlow::Continue(()),
            };
            let service = match Service::from_ptr(ptr) {
                Ok(service) => service,
                Err(e) => {
                    log::warn!("failed to decode service: {:?}", e);
                    return ControlFlow::Continue(());
                }
            };
            match service_types.entry(service) {
                Entry::Vacant(e) => {
                    let flow = callback(e.key());
                    e.insert(());
                    flow
                }
                Entry::Occupied(_) => {
                    // Already discovered this service
                    ControlFlow::Continue(())
                }
            }
        })
    }

    fn send_query(
        &mut self,
        domain: &DomainName,
        qtypes: &[QType],
        callback: &mut dyn FnMut(Record<'_>) -> ControlFlow<()>,
    ) -> io::Result<()> {
        let mut send_buf = [0; MDNS_BUFFER_SIZE];
        let data = encode_query(&mut send_buf, domain, qtypes);

        let discovery_start = Instant::now();
        'retransmit: loop {
            self.sock.send_to(data, self.server)?;

            loop {
                if discovery_start.elapsed() >= self.discovery_timeout {
                    // Max. discovery time exceeded.
                    return Ok(());
                }

                let mut recv_buf = [0; MDNS_BUFFER_SIZE];
                let (b, addr) = match self.sock.recv_from(&mut recv_buf) {
                    Ok(res) => res,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue 'retransmit;
                    }
                    Err(e) => return Err(e),
                };
                let recv = &recv_buf[..b];
                log::trace!("recv from {}: {}", addr, Hex(recv));

                let res = decode_answer(recv, callback);

                match res {
                    Ok(ControlFlow::Continue(())) => {}
                    Ok(ControlFlow::Break(())) => return Ok(()),
                    Err(err) => {
                        log::warn!("failed to decode response: {:?}", err);
                    }
                }
            }
        }
    }
}

pub fn encode_query<'a>(buf: &'a mut [u8], domain: &DomainName, qtypes: &[QType]) -> &'a [u8] {
    let mut header = Header::default();
    header.set_id(12345);
    let mut enc = MessageEncoder::new(buf);
    enc.set_header(header);
    for qtype in qtypes {
        enc.question(encoder::Question::new(domain).ty(*qtype));
    }
    let bytes = enc.finish().unwrap();
    let data = &buf[..bytes];

    log::trace!(
        "encode_query: domain={}, types={:?}, raw query={}",
        domain,
        qtypes,
        Hex(data),
    );

    data
}

/// Decodes `recv` and invokes `callback` with every ANS record inside.
pub fn decode_answer(
    recv: &[u8],
    callback: &mut dyn FnMut(Record<'_>) -> ControlFlow<()>,
) -> Result<ControlFlow<()>, Error> {
    let dec = MessageDecoder::new(recv)?;
    let h = dec.header();
    log::trace!("decode_answer: header={:?}", h);
    if !h.is_response() {
        return Ok(ControlFlow::Continue(()));
    }

    let mut dec = dec.answers()?;
    for res in dec.iter() {
        let ans = match res {
            Ok(ans) => ans,
            Err(e) => {
                log::warn!("failed to decode RR: {:?}", e);
                continue;
            }
        };
        log::debug!("ANS: {}", ans);
        match ans.as_enum() {
            Some(Ok(record)) => match callback(record) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(ControlFlow::Break(())),
            },
            Some(Err(e)) => {
                log::warn!("failed to decode RR: {:?}", e);
                continue;
            }
            None => {}
        }
    }

    Ok(ControlFlow::Continue(()))
}
