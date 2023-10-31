//! DNS-based Service Discovery.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::ControlFlow,
    time::{Duration, Instant},
};

use async_std::{future, net::UdpSocket};
use uwuhi::{
    packet::{name::DomainName, records::Record, QType},
    service::{InstanceDetails, Service, ServiceInstance, TxtRecords},
    MDNS_BUFFER_SIZE,
};

pub use uwuhi::service::discovery::*;

pub struct AsyncDiscoverer {
    sock: UdpSocket,
    server: SocketAddr,
    domain: DomainName,
    retransmit_timeout: Duration,
    discovery_timeout: Duration,
}

impl AsyncDiscoverer {
    const DEFAULT_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(300);
    const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1000);

    /// Creates a new service discoverer that will request services of `domain` from the given DNS
    /// server.
    pub async fn new(server: SocketAddr, domain: DomainName) -> io::Result<Self> {
        let bind_addr: SocketAddr = if server.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        Ok(Self {
            sock: UdpSocket::bind(bind_addr).await?,
            server,
            domain,
            retransmit_timeout: Self::DEFAULT_RETRANSMIT_TIMEOUT,
            discovery_timeout: Self::DEFAULT_DISCOVERY_TIMEOUT,
        })
    }

    /// Creates an mDNS service discoverer that will browse the `.local` service domain.
    pub async fn new_multicast_v4() -> io::Result<Self> {
        Self::new(
            "224.0.0.251:5353".parse().unwrap(),
            DomainName::from_str("local").unwrap(),
        )
        .await
    }

    /// Sets the time after which a discovery query is retransmitted, if no responses have been
    /// received in this amount of time.
    pub fn set_retransmit_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.retransmit_timeout = timeout;
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
    pub async fn load_instance_details(
        &mut self,
        instance: &ServiceInstance,
    ) -> io::Result<InstanceDetails> {
        let mut domain = DomainName::from_iter([
            instance.instance_name(),
            instance.service().name(),
            &instance.service().transport().to_label(),
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
        })
        .await?;

        match details {
            Some(mut details) => {
                if let Some(txt) = txt_records {
                    // FIXME this can potentially combine a TXT from one machine with a SRV from
                    // another
                    *details.txt_records_mut() = txt;
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
    pub async fn discover_instances<C>(
        &mut self,
        service: &Service,
        mut callback: C,
    ) -> io::Result<()>
    where
        C: FnMut(&ServiceInstance) -> ControlFlow<()> + Send,
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
        .await
    }

    /// Discovers the available *service types*.
    ///
    /// This function will request a list of available service types from the DNS server(s). This is
    /// mostly intended for maintenance and debugging, since applications typically know the service
    /// types they support already.
    ///
    /// To discover *service instances*, use [`AsyncDiscoverer::discover_instances`] instead.
    pub async fn discover_service_types<C>(&mut self, mut callback: C) -> io::Result<()>
    where
        C: FnMut(&Service) -> ControlFlow<()> + Send,
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
        .await
    }

    async fn send_query(
        &mut self,
        domain: &DomainName,
        qtypes: &[QType],
        callback: &mut (dyn FnMut(Record<'_>) -> ControlFlow<()> + Send),
    ) -> io::Result<()> {
        let mut send_buf = [0; MDNS_BUFFER_SIZE];
        let data = encode_query(&mut send_buf, domain, qtypes);

        let discovery_start = Instant::now();
        'retransmit: loop {
            self.sock.send_to(data, self.server).await?;

            loop {
                if discovery_start.elapsed() >= self.discovery_timeout {
                    // Max. discovery time exceeded.
                    return Ok(());
                }

                let mut recv_buf = [0; MDNS_BUFFER_SIZE];
                let (b, addr) = match future::timeout(
                    self.retransmit_timeout,
                    self.sock.recv_from(&mut recv_buf),
                )
                .await
                {
                    Ok(Ok(res)) => res,
                    Err(_) => continue 'retransmit,
                    Ok(Err(e)) => return Err(e),
                };
                let recv = &recv_buf[..b];
                log::trace!("recv from {}: {}", addr, recv.escape_ascii());

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
