//! Service advertising.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket},
};

use crate::{
    name::{DomainName, Label},
    packet::{
        decoder::MessageDecoder,
        encoder::{MessageEncoder, ResourceRecord},
        records::{Record, A, AAAA, PTR, SRV, TXT},
        Class, Header, Opcode, RCode,
    },
};
use socket2::{Domain, Protocol, Socket, Type};

use crate::MDNS_BUFFER_SIZE;

use super::{InstanceDetails, ServiceInstance, TxtRecordValue};

pub struct SyncAdvertiser {
    adv: Advertiser,
}

impl SyncAdvertiser {
    /// Creates a new service advertiser that uses the domain `hostname.local`.
    ///
    /// `hostname` should be different from the system host name, to avoid conflicts with other
    /// installed mDNS responders.
    pub fn new(hostname: Label, addr: IpAddr) -> io::Result<Self> {
        Ok(Self {
            adv: Advertiser::new(hostname, addr)?,
        })
    }

    pub fn add_name(&mut self, hostname: Label, addr: IpAddr) {
        self.adv.add_name(hostname, addr);
    }

    pub fn add_instance(&mut self, instance: ServiceInstance, details: InstanceDetails) {
        self.adv.add_instance(instance, details);
    }

    /// Starts listening for and responding to queries.
    ///
    /// This method will block forever and never return, except when an error occurs.
    pub fn listen_blocking(&mut self) -> io::Result<()> {
        let sock = self.adv.create_socket()?;
        let mut recv_buf = [0; MDNS_BUFFER_SIZE];
        loop {
            let (len, addr) = sock.recv_from(&mut recv_buf)?;
            let packet = &recv_buf[..len];

            log::trace!("raw recv from {}: {:x?}", addr, packet);

            match self.adv.handle_packet(packet) {
                Ok(Some(resp)) => {
                    sock.send_to(resp, addr)?;
                }
                Ok(None) => {}
                Err(e) => {
                    log::debug!("failed to handle packet: {}", e);
                }
            }
        }
    }
}

/// I/O-less advertising logic.
///
/// You probably want to use [`SyncAdvertiser`] instead.
pub struct Advertiser {
    discovery_domain: DomainName,
    db: RecordDb,
    response_buf: Vec<u8>,
}

impl Advertiser {
    /// Creates a new service advertiser that uses the domain `hostname.local`.
    ///
    /// `hostname` should be different from the system host name, to avoid conflicts with other
    /// installed mDNS responders.
    pub fn new(hostname: Label, addr: IpAddr) -> io::Result<Self> {
        let mut this = Self {
            discovery_domain: DomainName::from_str("_services._dns-sd._udp.local.").unwrap(),
            db: RecordDb::new(),
            response_buf: vec![0; MDNS_BUFFER_SIZE],
        };
        this.add_name(hostname, addr);
        Ok(this)
    }

    /// Adds an additional hostname and IP address to resolve.
    pub fn add_name(&mut self, hostname: Label, addr: IpAddr) {
        let mut host_and_domain = DomainName::from_iter([hostname]);
        host_and_domain.push_label(Label::new("local"));

        log::info!("{} <-> {}", addr, host_and_domain);

        let record = match addr {
            IpAddr::V4(addr) => Record::A(A::new(addr)),
            IpAddr::V6(addr) => Record::AAAA(AAAA::new(addr)),
        };

        self.db.entries.push(Entry::new(host_and_domain, record));
    }

    pub fn add_instance(&mut self, instance: ServiceInstance, details: InstanceDetails) {
        // Add SRV and TXT records for `$instance.$service.$transport.$domain`.
        // Add PTR record for `$service.$transport.$domain`.
        // Add PTR record for `_services._dns-sd._udp.$domain`.

        let service_domain = DomainName::from_iter([
            instance.service_name(),
            &instance.service_transport().to_label(),
            &Label::new("local"),
        ]);
        let instance_domain = DomainName::from_iter([
            instance.instance_name(),
            instance.service_name(),
            &instance.service_transport().to_label(),
            &Label::new("local"),
        ]);
        self.db.entries.push(Entry::new(
            instance_domain.clone(),
            Record::SRV(SRV::new(0, 0, details.port(), details.host().clone())),
        ));
        let txt = if details.txt_records().is_empty() {
            // A TXT record is required by RFC 6763, even if it just contains an empty entry.
            TXT::new([b""])
        } else {
            TXT::new(details.txt_records().iter().map(|(k, v)| match v {
                TxtRecordValue::NoValue => k.as_bytes().to_vec(),
                TxtRecordValue::Value(v) => {
                    let mut kv = k.as_bytes().to_vec();
                    kv.push(b'=');
                    kv.extend_from_slice(v);
                    kv
                }
            }))
        };
        self.db
            .entries
            .push(Entry::new(instance_domain.clone(), Record::TXT(txt)));

        self.db.entries.push(Entry::new(
            DomainName::from_iter([
                instance.service_name(),
                &instance.service_transport().to_label(),
                &Label::new("local"),
            ]),
            Record::PTR(PTR::new(instance_domain.clone())),
        ));

        self.db.entries.push(Entry::new(
            self.discovery_domain.clone(),
            Record::PTR(PTR::new(service_domain.clone())),
        ));
    }

    /// Creates a correctly configured [`UdpSocket`] to listen for mDNS queries to this advertiser.
    ///
    /// The returned socket will be in blocking mode, and can coexist with existing sockets
    /// listening on the same port.
    ///
    /// When receiving data using the returned [`UdpSocket`], a receive buffer with a size of at
    /// least [`MDNS_BUFFER_SIZE`] must be used, otherwise incoming mDNS queries may get truncated.
    pub fn create_socket(&self) -> io::Result<UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353).into())?;

        let sock = UdpSocket::from(sock);
        sock.join_multicast_v4(&"224.0.0.251".parse().unwrap(), &Ipv4Addr::UNSPECIFIED)?;

        Ok(sock)
    }

    /// Handles an incoming mDNS packet, and returns a response for it (if any).
    ///
    /// This method does not perform I/O by itself, so it can be used in a *sans-io* fashion to
    /// build an async mDNS advertiser. If that's not needed, [`SyncAdvertiser::listen_blocking`]
    /// can be called instead.
    pub fn handle_packet(&mut self, packet: &[u8]) -> io::Result<Option<&[u8]>> {
        let mut dec = MessageDecoder::new(packet)?;
        if !dec.header().is_query() {
            return Ok(None);
        }
        if dec.header().opcode() != Opcode::QUERY {
            return Ok(None);
        }
        if dec.header().rcode() != RCode::NO_ERROR {
            return Ok(None);
        }

        let mut header = Header::default();
        header.set_id(dec.header().id());
        header.set_response(true);
        header.set_authority(true);
        let mut enc = MessageEncoder::new(&mut *self.response_buf);
        enc.set_header(header);
        let mut enc = enc.answers();

        let mut have_relevant_answer = false;
        for res in dec.iter() {
            let q = res?;
            log::debug!("Q: {q}");

            for entry in &self.db.entries {
                if !q.qclass().matches(entry.class) {
                    continue;
                }
                if !q.qtype().matches(entry.record.record_type()) {
                    continue;
                }
                if q.qname() != &entry.name {
                    continue;
                }

                log::debug!("matches: {}", entry.record);
                have_relevant_answer = true;
                enc.add_answer(
                    ResourceRecord::new(&entry.name, &entry.record)
                        .class(entry.class)
                        .ttl(entry.ttl),
                );
            }
        }

        if have_relevant_answer {
            let len = enc.finish().ok().unwrap_or(self.response_buf.len()); // truncated replies should still get sent
            Ok(Some(&self.response_buf[..len]))
        } else {
            Ok(None)
        }
    }
}

struct RecordDb {
    // This could be, y'know, performant, by using literally any other data structure, but since
    // this is usually only gonna contain like 5 entries, it doesn't matter right now.
    entries: Vec<Entry>,
}

impl RecordDb {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

struct Entry {
    name: DomainName,
    class: Class,
    ttl: u32,
    record: Record<'static>,
}

impl Entry {
    fn new(name: DomainName, record: Record<'static>) -> Self {
        Self {
            name,
            class: Class::IN,
            ttl: TTL,
            record,
        }
    }
}

const TTL: u32 = 120;
