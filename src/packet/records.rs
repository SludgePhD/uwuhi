//! DNS resource records.
//!
//! This module contains types representing specific resource record types and their associated
//! record data. Also refer to [`encoder::ResourceRecord`] and [`decoder::ResourceRecord`].
//!
//! [`encoder::ResourceRecord`]: super::encoder::ResourceRecord
//! [`decoder::ResourceRecord`]: super::decoder::ResourceRecord

use std::{
    borrow::Cow,
    fmt::{self, Write},
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::Error;

use super::{
    decoder::{self, Reader},
    encoder::Writer,
    name::DomainName,
    Type,
};

pub struct ResourceRecordEncoder<'a> {
    pub(crate) w: Writer<'a>,
}

pub struct ResourceRecordDecoder<'a> {
    pub(crate) r: Reader<'a>,
}

/// Trait implemented by all resource record types.
pub trait ResourceRecordData<'a>: Sized {
    /// The associated resource record type.
    const TYPE: Type;

    /// Writes the data of this resource record to the given encoder.
    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>);

    /// Attempts to decode an instance of this resource record from an RDATA field.
    fn decode(r: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error>;
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
                let r = &mut ResourceRecordDecoder {
                    r: rr.rdata.clone(),
                };
                Some(match rr.type_() {
                    $( Type::$record => $record::decode(r).map(Self::$record), )+
                    _ => return None,
                })
            }

            pub(crate) fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct A<'a> {
    addr: Ipv4Addr,
    _p: PhantomData<&'a [u8]>,
}

impl<'a> ResourceRecordData<'a> for A<'a> {
    const TYPE: Type = Type::A;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_slice(&self.addr.octets())
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            addr: Ipv4Addr::from(*dec.r.read_array()?),
            _p: PhantomData,
        })
    }
}

impl<'a> A<'a> {
    #[inline]
    pub fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            _p: PhantomData,
        }
    }

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AAAA<'a> {
    addr: Ipv6Addr,
    _p: PhantomData<&'a [u8]>,
}

impl<'a> ResourceRecordData<'a> for AAAA<'a> {
    const TYPE: Type = Type::AAAA;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_slice(&self.addr.octets());
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            addr: Ipv6Addr::from(*dec.r.read_array()?),
            _p: PhantomData,
        })
    }
}

impl<'a> AAAA<'a> {
    #[inline]
    pub fn new(addr: Ipv6Addr) -> Self {
        Self {
            addr,
            _p: PhantomData,
        }
    }

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CNAME<'a> {
    name: DomainName,
    _p: PhantomData<&'a ()>,
}

impl<'a> ResourceRecordData<'a> for CNAME<'a> {
    const TYPE: Type = Type::CNAME;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_domain_name(&self.name);
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            name: dec.r.read_domain_name()?,
            _p: PhantomData,
        })
    }
}

impl<'a> CNAME<'a> {
    pub fn new(name: DomainName) -> Self {
        Self {
            name,
            _p: PhantomData,
        }
    }

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MX<'a> {
    preference: u16,
    exchange: DomainName,
    _p: PhantomData<&'a ()>,
}

impl<'a> ResourceRecordData<'a> for MX<'a> {
    const TYPE: Type = Type::MX;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_u16(self.preference);
        enc.w.write_domain_name(&self.exchange);
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            preference: dec.r.read_u16()?,
            exchange: dec.r.read_domain_name()?,
            _p: PhantomData,
        })
    }
}

impl<'a> MX<'a> {
    pub fn new(preference: u16, exchange: DomainName) -> Self {
        Self {
            preference,
            exchange,
            _p: PhantomData,
        }
    }

    #[inline]
    pub fn preference(&self) -> u16 {
        self.preference
    }

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NS<'a> {
    nsdname: DomainName,
    _p: PhantomData<&'a ()>,
}

impl<'a> ResourceRecordData<'a> for NS<'a> {
    const TYPE: Type = Type::NS;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_domain_name(&self.nsdname);
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            nsdname: dec.r.read_domain_name()?,
            _p: PhantomData,
        })
    }
}

impl<'a> NS<'a> {
    pub fn new(nsdname: DomainName) -> Self {
        Self {
            nsdname,
            _p: PhantomData,
        }
    }

    pub fn nsdname(&self) -> &DomainName {
        &self.nsdname
    }
}

impl<'a> fmt::Display for NS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.nsdname.fmt(f)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PTR<'a> {
    ptrdname: DomainName,
    _p: PhantomData<&'a ()>,
}

impl<'a> ResourceRecordData<'a> for PTR<'a> {
    const TYPE: Type = Type::PTR;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_domain_name(&self.ptrdname);
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            ptrdname: dec.r.read_domain_name()?,
            _p: PhantomData,
        })
    }
}

impl<'a> PTR<'a> {
    pub fn new(ptrdname: DomainName) -> Self {
        Self {
            ptrdname,
            _p: PhantomData,
        }
    }

    pub fn ptrdname(&self) -> &DomainName {
        &self.ptrdname
    }
}

impl<'a> fmt::Display for PTR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ptrdname.fmt(f)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TXT<'a> {
    entries: Vec<Cow<'a, [u8]>>,
}

impl<'a> ResourceRecordData<'a> for TXT<'a> {
    const TYPE: Type = Type::TXT;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        for entry in self.entries() {
            enc.w.write_character_string(entry);
        }
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SRV<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: DomainName,
    _p: PhantomData<&'a ()>,
}

impl<'a> ResourceRecordData<'a> for SRV<'a> {
    const TYPE: Type = Type::SRV;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_u16(self.priority);
        enc.w.write_u16(self.weight);
        enc.w.write_u16(self.port);
        enc.w.write_domain_name(&self.target);
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            priority: dec.r.read_u16()?,
            weight: dec.r.read_u16()?,
            port: dec.r.read_u16()?,
            target: dec.r.read_domain_name()?,
            _p: PhantomData,
        })
    }
}

impl<'a> SRV<'a> {
    pub fn new(priority: u16, weight: u16, port: u16, target: DomainName) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
            _p: PhantomData,
        }
    }

    /// Returns the priority value of this service (lower values mean that the service should be
    /// preferred).
    #[inline]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    #[inline]
    pub fn weight(&self) -> u16 {
        self.weight
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SOA<'a> {
    mname: DomainName,
    rname: DomainName,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32,
    _p: PhantomData<&'a ()>,
}

impl<'a> ResourceRecordData<'a> for SOA<'a> {
    const TYPE: Type = Type::SOA;

    fn encode(&self, enc: &mut ResourceRecordEncoder<'_>) {
        enc.w.write_domain_name(&self.mname);
        enc.w.write_domain_name(&self.rname);
        enc.w.write_u32(self.serial);
        enc.w.write_u32(self.refresh);
        enc.w.write_u32(self.retry);
        enc.w.write_u32(self.expire);
        enc.w.write_u32(self.minimum_ttl);
    }

    fn decode(dec: &mut ResourceRecordDecoder<'a>) -> Result<Self, Error> {
        Ok(Self {
            mname: dec.r.read_domain_name()?,
            rname: dec.r.read_domain_name()?,
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
    pub fn new(
        mname: DomainName,
        rname: DomainName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum_ttl: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl,
            _p: PhantomData,
        }
    }

    #[inline]
    pub fn mname(&self) -> &DomainName {
        &self.mname
    }

    #[inline]
    pub fn rname(&self) -> &DomainName {
        &self.rname
    }

    #[inline]
    pub fn serial(&self) -> u32 {
        self.serial
    }

    #[inline]
    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    #[inline]
    pub fn retry(&self) -> u32 {
        self.retry
    }

    #[inline]
    pub fn expire(&self) -> u32 {
        self.expire
    }

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

    fn roundtrip<'a, R: ResourceRecordData<'a> + PartialEq + std::fmt::Debug>(
        rr: R,
        buf: &'a mut [u8],
    ) {
        let mut enc = ResourceRecordEncoder {
            w: Writer::new(buf),
        };
        rr.encode(&mut enc);
        let pos = enc.w.pos;
        let buf = &buf[..pos];
        let mut dec = ResourceRecordDecoder {
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
        roundtrip(CNAME::new(domain("a.b.c")), &mut BUF);
        roundtrip(MX::new(123, domain("a.b.c")), &mut BUF);
        roundtrip(NS::new(domain("a.b.c")), &mut BUF);
        roundtrip(PTR::new(domain("a.b.c")), &mut BUF);
        roundtrip(TXT::new([&b"abc"[..]]), &mut BUF);
        roundtrip(TXT::new([&b"abc"[..], &[], &b"def"[..]]), &mut BUF);
        roundtrip(SRV::new(123, 456, 8080, domain("a.b.c")), &mut BUF);
        roundtrip(
            SOA::new(
                domain("m.name"),
                domain("r.name"),
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
