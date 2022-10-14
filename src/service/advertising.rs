use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
};

use crate::packet::{
    decoder::MessageDecoder,
    encoder::{MessageEncoder, ResourceRecord},
    name::{DomainName, Label},
    records::{Record, A, PTR, SRV, TXT},
    Class, Header, Opcode, RCode,
};
use socket2::{Domain, Protocol, Socket, Type};

use crate::MDNS_BUFFER_SIZE;

use super::{InstanceDetails, ServiceInstance, TxtRecordValue};

/// mDNS service advertiser and name server.
pub struct ServiceAdvertiser {
    discovery_domain: DomainName,
    sock: UdpSocket,
    db: RecordDb,
}

impl ServiceAdvertiser {
    /// Creates a new service advertiser that uses the domain `hostname.local`.
    ///
    /// `hostname` should be different from the system host name, to avoid conflicts with other
    /// installed mDNS responders.
    pub fn new(hostname: Label, addr: Ipv4Addr) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353).into())?;

        let sock = UdpSocket::from(sock);
        sock.join_multicast_v4(&"224.0.0.251".parse().unwrap(), &Ipv4Addr::UNSPECIFIED)?;

        let mut host_and_domain = DomainName::from_iter([hostname]);
        host_and_domain.push_label(Label::new("local"));

        log::info!("{} <-> {}", addr, host_and_domain);

        let mut db = RecordDb::new();
        db.entries
            .push(Entry::new(host_and_domain, Record::A(A::new(addr))));

        Ok(Self {
            discovery_domain: DomainName::from_str("_services._dns-sd._udp.local.").unwrap(),
            sock,
            db,
        })
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
        if !details.txt_records().is_empty() {
            self.db.entries.push(Entry::new(
                instance_domain.clone(),
                Record::TXT(TXT::new(details.txt_records().iter().map(
                    |(k, v)| match v {
                        TxtRecordValue::NoValue => k.as_bytes().to_vec(),
                        TxtRecordValue::Value(v) => {
                            let mut kv = k.as_bytes().to_vec();
                            kv.push(b'=');
                            kv.extend_from_slice(v);
                            kv
                        }
                    },
                ))),
            ));
        }

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

    pub fn socket(&self) -> &UdpSocket {
        &self.sock
    }

    /// Starts listening for and responding to queries.
    ///
    /// This method will not return, except when an error occurs.
    pub fn listen(&self) -> io::Result<()> {
        let mut recv_buf = [0; MDNS_BUFFER_SIZE];
        loop {
            let (len, addr) = self.sock.recv_from(&mut recv_buf)?;
            let packet = &recv_buf[..len];

            log::trace!("raw recv from {}: {:x?}", addr, packet);

            match self.handle_packet(addr, packet) {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("failed to handle packet: {}", e);
                }
            }
        }
    }

    fn handle_packet(&self, sender: SocketAddr, packet: &[u8]) -> io::Result<()> {
        let mut dec = MessageDecoder::new(packet)?;
        if !dec.header().is_query() {
            return Ok(());
        }
        if dec.header().opcode() != Opcode::QUERY {
            return Ok(());
        }
        if dec.header().rcode() != RCode::NO_ERROR {
            return Ok(());
        }

        let mut header = Header::default();
        header.set_id(dec.header().id());
        header.set_response(true);
        header.set_authority(true);
        let mut response_buf = [0; MDNS_BUFFER_SIZE];
        let mut enc = MessageEncoder::new(&mut response_buf);
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
            let len = enc.finish().ok().unwrap_or(response_buf.len()); // truncated replies should still get sent
            let resp = &response_buf[..len];
            self.sock.send_to(resp, sender)?;
        }

        Ok(())
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
