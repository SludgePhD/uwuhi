//! DNS resource records.
//!
//! This module contains types representing specific resource record types and their associated
//! record data. Also refer to [`encoder::ResourceRecord`] and [`decoder::ResourceRecord`].
//!
//! [`encoder::ResourceRecord`]: super::encoder::ResourceRecord
//! [`decoder::ResourceRecord`]: super::decoder::ResourceRecord

// TODO: move this module to the crate root

use std::{
    borrow::Cow,
    fmt::{self, Write},
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{name::DomainName, Error};

use super::{
    decoder::{self, Reader},
    encoder::Writer,
    Type,
};

/// Resource Record writer.
///
/// This is an opaque, internal type passed to [`RecordData::encode`].
pub struct Encoder<'a> {
    pub(crate) w: Writer<'a>,
}

/// Resource Record reader.
///
/// This is an opaque, internal type passed to [`RecordData::decode`].
pub struct Decoder<'a> {
    pub(crate) r: Reader<'a>,
}

/// Trait implemented by all resource record types.
pub trait RecordData<'a>: Sized {
    /// The associated resource record type.
    const TYPE: Type;

    /// Writes the data of this resource record to the given encoder.
    fn encode(&self, enc: &mut Encoder<'_>);

    /// Attempts to decode an instance of this resource record from an RDATA field.
    fn decode(r: &mut Decoder<'a>) -> Result<Self, Error>;
}

macro_rules! records {
    (
        $($record:ident),+ $(,)?
    ) => {
        /// Enumeration of all supported Resource Record types.
        #[non_exhaustive]
        #[derive(Debug)]
        pub enum Record<'a> {
            $( $record($record<'a>), )+
        }

        impl<'a> Record<'a> {
            pub(crate) fn from_rr(rr: &decoder::ResourceRecord<'a>) -> Option<Result<Self, Error>> {
                let r = &mut Decoder {
                    r: rr.rdata.clone(),
                };
                Some(match rr.type_() {
                    $( Type::$record => $record::decode(r).map(Self::$record), )+
                    _ => return None,
                })
            }

            pub(crate) fn encode(&self, enc: &mut Encoder<'_>) {
                match self {
                    $( Record::$record(rr) => rr.encode(enc), )+
                }
            }

            pub fn record_type(&self) -> Type {
                match self {
                    $( Record::$record(_) => Type::$record, )+
                }
            }
        }

        impl<'a> fmt::Display for Record<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $( Record::$record(r) => r.fmt(f), )+
                }
            }
        }
    };
}

records!(A, AAAA, CNAME, MX, NS, PTR, TXT, SRV, SOA);

/// A record storing an IPv4 address.
///
/// An [`A`] record is used to map a domain name to the IPv4 address(es) it can be reached under.
/// A domain name can have multiple [`A`] records (for DNS-based round-robin load balancing), or
/// none at all (instead making use of a [`CNAME`] record to point to another domain).
///
/// Also see [`AAAA`] for the IPv6 equivalent. Both [`A`] and [`AAAA`] records can be present for a
/// domain, making it reachable via both IPv4 and IPv6.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct A<'a> {
    addr: Ipv4Addr,
    _p: PhantomData<&'a [u8]>,
}

impl<'a> RecordData<'a> for A<'a> {
    const TYPE: Type = Type::A;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_slice(&self.addr.octets())
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            addr: Ipv4Addr::from(*dec.r.read_array()?),
            _p: PhantomData,
        })
    }
}

impl<'a> A<'a> {
    /// Creates a new [`A`] record storing the given [`Ipv4Addr`].
    #[inline]
    pub fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            _p: PhantomData,
        }
    }

    /// Returns the [`Ipv4Addr`] stored in this [`A`] record.
    #[inline]
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
}

impl<'a> fmt::Display for A<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

/// A record storing an IPv6 address.
///
/// An [`AAAA`] record is used to map a domain name to the IPv6 address(es) it can be reached under.
///
/// Also see [`A`] for the IPv4 equivalent. Both [`A`] and [`AAAA`] records can be present for a
/// domain, making it reachable via both IPv4 and IPv6.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AAAA<'a> {
    addr: Ipv6Addr,
    _p: PhantomData<&'a [u8]>,
}

impl<'a> RecordData<'a> for AAAA<'a> {
    const TYPE: Type = Type::AAAA;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_slice(&self.addr.octets());
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            addr: Ipv6Addr::from(*dec.r.read_array()?),
            _p: PhantomData,
        })
    }
}

impl<'a> AAAA<'a> {
    /// Creates a new [`AAAA`] record storing the given [`Ipv6Addr`].
    #[inline]
    pub fn new(addr: Ipv6Addr) -> Self {
        Self {
            addr,
            _p: PhantomData,
        }
    }

    /// Returns the [`Ipv6Addr`] stored in this [`AAAA`] record.
    #[inline]
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }
}

impl<'a> fmt::Display for AAAA<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

/// A record storing the *Canonical Name* of a domain.
///
/// [`CNAME`] records are used to map one domain name to another, instructing the DNS client to
/// instead use the address records of the target (canonical) domain. This is often used when a
/// single web server is hosting multiple subdomains.
///
/// A domain with a [`CNAME`] record should not have any other records except DNSSEC-related ones.
///
/// Domains with [`CNAME`] records are typically forbidden from being listed as the target of other
/// resource record types. For instace, a domain that has a [`CNAME`] record is not allowed to be
/// listed as a mail server in an [`MX`] record, nor as an authoritative name server in an [`NS`]
/// record. The canonical name should be used instead.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CNAME<'a> {
    name: Cow<'a, DomainName>,
    _p: PhantomData<&'a ()>,
}

impl<'a> RecordData<'a> for CNAME<'a> {
    const TYPE: Type = Type::CNAME;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_domain_name(&self.name);
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            name: dec.r.read_domain_name()?.into(),
            _p: PhantomData,
        })
    }
}

impl<'a> CNAME<'a> {
    /// Creates a new [`CNAME`] record from the *Canonical Name*.
    pub fn new(name: impl Into<Cow<'a, DomainName>>) -> Self {
        Self {
            name: name.into(),
            _p: PhantomData,
        }
    }

    /// Returns the canonical [`DomainName`] stored in this [`CNAME`] record.
    #[inline]
    pub fn cname(&self) -> &DomainName {
        &self.name
    }
}

impl<'a> fmt::Display for CNAME<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// A **M**ail e**X**changer record specifies the mail server in charge of a domain.
///
/// A domain can have multiple [`MX`] records pointing to different mail servers for load balancing.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MX<'a> {
    preference: u16,
    exchange: Cow<'a, DomainName>,
    _p: PhantomData<&'a ()>,
}

impl<'a> RecordData<'a> for MX<'a> {
    const TYPE: Type = Type::MX;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_u16(self.preference);
        enc.w.write_domain_name(&self.exchange);
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            preference: dec.r.read_u16()?,
            exchange: dec.r.read_domain_name()?.into(),
            _p: PhantomData,
        })
    }
}

impl<'a> MX<'a> {
    /// Creates a new [`MX`] record from its preference number and the mail server's [`DomainName`].
    #[inline]
    pub fn new(preference: u16, exchange: impl Into<Cow<'a, DomainName>>) -> Self {
        Self {
            preference,
            exchange: exchange.into(),
            _p: PhantomData,
        }
    }

    /// Returns the *preference number* of this [`MX`] record.
    ///
    /// The *preference number* tells the client which mail servers to prefer. Lower numbers are
    /// preferred over higher numbers, and multiple servers with equal preference numbers are
    /// contacted in random order by the MTA.
    #[inline]
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// Returns the [`DomainName`] of the mail server.
    #[inline]
    pub fn exchange(&self) -> &DomainName {
        &self.exchange
    }
}

impl<'a> fmt::Display for MX<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}

/// A record storing the authoritative **N**ame **S**erver for a domain.
///
/// This record type is used by recursive resolvers to locate the appropriate name servers to
/// contact.
///
/// Several [`NS`] records can be used by the same domain name to increase redundancy.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NS<'a> {
    nsdname: Cow<'a, DomainName>,
    _p: PhantomData<&'a ()>,
}

impl<'a> RecordData<'a> for NS<'a> {
    const TYPE: Type = Type::NS;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_domain_name(&self.nsdname);
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            nsdname: dec.r.read_domain_name()?.into(),
            _p: PhantomData,
        })
    }
}

impl<'a> NS<'a> {
    /// Creates an [`NS`] record from the [`DomainName`] of the authoritative name server.
    pub fn new(nsdname: impl Into<Cow<'a, DomainName>>) -> Self {
        Self {
            nsdname: nsdname.into(),
            _p: PhantomData,
        }
    }

    /// Returns the [`DomainName`] of the authoritative name server.
    pub fn nsdname(&self) -> &DomainName {
        &self.nsdname
    }
}

impl<'a> fmt::Display for NS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.nsdname.fmt(f)
    }
}

/// A record storing the [`DomainName`] associated with an IP address.
///
/// This record type is used by *reverse DNS*, in which [`PTR`] records are not associated with the
/// human-readable domain name, but with the `in-addr.arpa` namespace. It is also used for DNS-SD.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PTR<'a> {
    ptrdname: Cow<'a, DomainName>,
    _p: PhantomData<&'a ()>,
}

impl<'a> RecordData<'a> for PTR<'a> {
    const TYPE: Type = Type::PTR;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_domain_name(&self.ptrdname);
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            ptrdname: dec.r.read_domain_name()?.into(),
            _p: PhantomData,
        })
    }
}

impl<'a> PTR<'a> {
    /// Creates a [`PTR`] record from the [`DomainName`] of an IP address.
    pub fn new(ptrdname: impl Into<Cow<'a, DomainName>>) -> Self {
        Self {
            ptrdname: ptrdname.into(),
            _p: PhantomData,
        }
    }

    /// Returns the [`DomainName`] stored by this [`PTR`] record.
    pub fn ptrdname(&self) -> &DomainName {
        &self.ptrdname
    }
}

impl<'a> fmt::Display for PTR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ptrdname.fmt(f)
    }
}

/// A free-form data record.
///
/// A [`TXT`] record stores arbitrary data that is up for interpretation by a higher layer. It is
/// frequently used to convey information about an mDNS service without requiring a client
/// to connect to the service to obtain the information.
///
/// A domain may have multiple [`TXT`] records, and each [`TXT`] record can store multiple blobs of
/// data (but must contain at least one entry). Typically, information pertaining to a service must
/// be stored as several entries in a single [`TXT`] record.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TXT<'a> {
    entries: Vec<Cow<'a, [u8]>>,
}

impl<'a> RecordData<'a> for TXT<'a> {
    const TYPE: Type = Type::TXT;

    fn encode(&self, enc: &mut Encoder<'_>) {
        for entry in self.entries() {
            enc.w.write_character_string(entry);
        }
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        let mut entries = Vec::new();

        // Technically at least one is required, but we accept 0 too.
        while !dec.r.buf().is_empty() {
            entries.push(dec.r.read_character_string()?.into());
        }

        Ok(Self { entries })
    }
}

impl<'a> TXT<'a> {
    /// Creates a new [`TXT`] resource record containing one or more `entries`.
    ///
    /// # Panics
    ///
    /// This method will panic if `entries` is empty.
    pub fn new<I, T>(entries: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Cow<'a, [u8]>>,
    {
        let this = Self {
            entries: entries.into_iter().map(|t| t.into()).collect(),
        };
        assert!(!this.entries.is_empty());
        this
    }

    /// Returns an iterator over all *character string* values in this record.
    ///
    /// Each *character string* is an arbitrary sequence of bytes (empty sequences are allowed).
    /// Their interpretation is up to higher-level specifications.
    pub fn entries(&self) -> impl Iterator<Item = &'_ [u8]> {
        self.entries.iter().map(|cow| &**cow)
    }
}

impl<'a> fmt::Display for TXT<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries().enumerate() {
            if i != 0 {
                f.write_char('\t')?;
            }

            for &byte in entry {
                if byte.is_ascii_graphic() {
                    f.write_char(byte as char)?;
                } else {
                    f.write_char('�')?;
                }
            }
        }
        Ok(())
    }
}

/// A service record that defines the host and port number of a network service.
///
/// An [`SRV`] record is associated with a domain name of the form `_service._proto.name.`, where
/// `service` is an identifier of the service offered, `_proto` is either `_tcp` for services served
/// over TCP or `_udp` for all other services, and `name` is the domain name advertising the
/// service (which may be different from the domain name *hosting* the service).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SRV<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: Cow<'a, DomainName>,
    _p: PhantomData<&'a ()>,
}

impl<'a> RecordData<'a> for SRV<'a> {
    const TYPE: Type = Type::SRV;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_u16(self.priority);
        enc.w.write_u16(self.weight);
        enc.w.write_u16(self.port);
        enc.w.write_domain_name(&self.target);
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            priority: dec.r.read_u16()?,
            weight: dec.r.read_u16()?,
            port: dec.r.read_u16()?,
            target: dec.r.read_domain_name()?.into(),
            _p: PhantomData,
        })
    }
}

impl<'a> SRV<'a> {
    pub fn new(
        priority: u16,
        weight: u16,
        port: u16,
        target: impl Into<Cow<'a, DomainName>>,
    ) -> Self {
        Self {
            priority,
            weight,
            port,
            target: target.into(),
            _p: PhantomData,
        }
    }

    /// Returns the priority value of this service (lower values mean that the service should be
    /// preferred).
    #[inline]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the weight value of this service.
    ///
    /// For [`SRV`] records with the same [`SRV::priority()`] value, the relative weights determine
    /// the probability for the service getting picked by clients.
    #[inline]
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// Returns the port on which the service is hosted.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the [`DomainName`] where the service is hosted.
    #[inline]
    pub fn target(&self) -> &DomainName {
        &self.target
    }
}

impl<'a> fmt::Display for SRV<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}",
            self.priority, self.weight, self.port, self.target,
        )
    }
}

/// Record containing administrative information about a DNS zone.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SOA<'a> {
    mname: Cow<'a, DomainName>,
    rname: Cow<'a, DomainName>,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32,
    _p: PhantomData<&'a ()>,
}

impl<'a> RecordData<'a> for SOA<'a> {
    const TYPE: Type = Type::SOA;

    fn encode(&self, enc: &mut Encoder<'_>) {
        enc.w.write_domain_name(&self.mname);
        enc.w.write_domain_name(&self.rname);
        enc.w.write_u32(self.serial);
        enc.w.write_u32(self.refresh);
        enc.w.write_u32(self.retry);
        enc.w.write_u32(self.expire);
        enc.w.write_u32(self.minimum_ttl);
    }

    fn decode(dec: &mut Decoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            mname: dec.r.read_domain_name()?.into(),
            rname: dec.r.read_domain_name()?.into(),
            serial: dec.r.read_u32()?,
            refresh: dec.r.read_u32()?,
            retry: dec.r.read_u32()?,
            expire: dec.r.read_u32()?,
            minimum_ttl: dec.r.read_u32()?,
            _p: PhantomData,
        })
    }
}

impl<'a> SOA<'a> {
    /// Creates a new [`SOA`] record from all of its fields.
    pub fn new(
        mname: impl Into<Cow<'a, DomainName>>,
        rname: impl Into<Cow<'a, DomainName>>,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum_ttl: u32,
    ) -> Self {
        Self {
            mname: mname.into(),
            rname: rname.into(),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl,
            _p: PhantomData,
        }
    }

    /// Returns the primary master name server for the zone.
    #[inline]
    pub fn mname(&self) -> &DomainName {
        &self.mname
    }

    /// Returns the email address of the administrator responsible for this DNS zone.
    ///
    /// The email address is encoded as a [`DomainName`] where the first [`Label`] is the part
    /// before the `@` sign.
    ///
    /// [`Label`]: crate::name::Label
    #[inline]
    pub fn rname(&self) -> &DomainName {
        &self.rname
    }

    /// Returns the serial number of this zone.
    ///
    /// This is increased to signal a zone update to secondary name servers.
    #[inline]
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns the time in seconds after which the [`SOA`] record should be re-queried from the
    /// primary name server.
    #[inline]
    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    /// Returns the number of seconds after which the [`SOA`] record should be re-queried if the
    /// primary name server does not respond.
    #[inline]
    pub fn retry(&self) -> u32 {
        self.retry
    }

    /// Returns the number of seconds after which a secondary DNS server should stop answering
    /// requests for this zone if the primary server does not respond.
    #[inline]
    pub fn expire(&self) -> u32 {
        self.expire
    }

    /// Returns the `MINIMUM` field of the [`SOA`] record.
    ///
    /// The meaning of the result is defined by [RFC 2308].
    ///
    /// [RFC 2308]: https://datatracker.ietf.org/doc/html/rfc2308
    #[inline]
    pub fn minimum_ttl(&self) -> u32 {
        self.minimum_ttl
    }
}

impl<'a> fmt::Display for SOA<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum_ttl
        )
    }
}

#[cfg(test)]
#[allow(const_item_mutation)]
mod tests {
    use super::*;

    fn roundtrip<'a, R: RecordData<'a> + PartialEq + std::fmt::Debug>(rr: R, buf: &'a mut [u8]) {
        let mut enc = Encoder {
            w: Writer::new(buf),
        };
        rr.encode(&mut enc);
        let pos = enc.w.pos;
        let buf = &buf[..pos];
        let mut dec = Decoder {
            r: Reader::new(buf),
        };
        let decoded = R::decode(&mut dec).unwrap();
        assert_eq!(rr, decoded);
    }

    const BUF: [u8; 256] = [0; 256];

    fn domain(s: &str) -> DomainName {
        s.parse().unwrap()
    }

    #[test]
    fn test_roundtrip() {
        roundtrip(A::new(Ipv4Addr::new(9, 4, 78, 210)), &mut BUF);
        roundtrip(AAAA::new(Ipv6Addr::LOCALHOST), &mut BUF);
        roundtrip(CNAME::new(&domain("a.b.c")), &mut BUF);
        roundtrip(MX::new(123, &domain("a.b.c")), &mut BUF);
        roundtrip(NS::new(&domain("a.b.c")), &mut BUF);
        roundtrip(PTR::new(&domain("a.b.c")), &mut BUF);
        roundtrip(TXT::new([&b"abc"[..]]), &mut BUF);
        roundtrip(TXT::new([&b"abc"[..], &[], &b"def"[..]]), &mut BUF);
        roundtrip(SRV::new(123, 456, 8080, &domain("a.b.c")), &mut BUF);
        roundtrip(
            SOA::new(
                &domain("m.name"),
                &domain("r.name"),
                999999,
                888888,
                777777,
                666666,
                555555,
            ),
            &mut BUF,
        );
    }

    #[test]
    fn test_record_is_covariant() {
        fn _check<'short, 'long: 'short>(rec: Record<'long>) -> Record<'short> {
            rec
        }
    }
}
