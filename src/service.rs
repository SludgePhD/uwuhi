//! Service discovery and advertising.

use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt,
};

use crate::{
    name::{DomainName, Label},
    packet::records::{PTR, SRV, TXT},
    Error,
};

pub mod advertising;
pub mod discovery;

/// Transport protocol used by an advertised service (`_tcp` or `_udp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceTransport {
    /// Service uses TCP.
    TCP,
    /// Anything but TCP (UDP, SCTP, etc.).
    Other,
}

impl ServiceTransport {
    fn as_str(&self) -> &str {
        match self {
            ServiceTransport::TCP => "_tcp",
            ServiceTransport::Other => "_udp",
        }
    }

    pub fn to_label(&self) -> Label {
        Label::new(self.as_str())
    }
}

/// A service type identifier.
///
/// A service type is identified by a unique name ([`Label`]), and the [`ServiceTransport`] the
/// service can be reached with.
///
/// *Instances* of a service running on a specific machine are represented by [`ServiceInstance`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Service {
    /// The service name, starting with an underscore.
    name: Label,
    transport: ServiceTransport,
}

impl Service {
    /// Creates a new service.
    ///
    /// # Panics
    ///
    /// Panics if `name` does not start with an underscore (`_`).
    pub fn new(name: Label, transport: ServiceTransport) -> Self {
        assert!(name.as_bytes().starts_with(b"_"));
        Self { name, transport }
    }

    pub fn from_ptr(ptr: PTR<'_>) -> Result<Self, Error> {
        let mut labels = ptr.ptrdname().labels().iter();
        let service_name = labels.next().ok_or(Error::Eof)?;
        let transport = labels.next().ok_or(Error::Eof)?;
        if labels.next().is_none() {
            // Domain missing, this is probably not a valid service.
            return Err(Error::Eof);
        }
        Ok(Service {
            name: service_name.clone(),
            transport: match transport.as_bytes() {
                b"_tcp" => ServiceTransport::TCP,
                b"_udp" => ServiceTransport::Other,
                _ => return Err(Error::InvalidValue),
            },
        })
    }

    #[inline]
    pub fn name(&self) -> &Label {
        &self.name
    }

    #[inline]
    pub fn transport(&self) -> ServiceTransport {
        self.transport
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.transport.as_str())
    }
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A named instance of a [`Service`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceInstance {
    instance_name: Label,
    service: Service,
}

impl ServiceInstance {
    /// Creates a new [`ServiceInstance`] from its components.
    ///
    /// `instance_name` can be a free-form string, typically identifying the machine the service is
    /// running on.
    ///
    /// `service_name` must start with an underscore and is an agreed-upon identifier for the
    /// service being offered.
    pub fn new(instance_name: Label, service_name: Label, transport: ServiceTransport) -> Self {
        Self {
            instance_name,
            service: Service::new(service_name, transport),
        }
    }

    pub fn from_service(instance_name: Label, service: Service) -> Self {
        Self {
            instance_name,
            service,
        }
    }

    pub fn from_ptr(ptr: PTR<'_>) -> Result<Self, Error> {
        let mut labels = ptr.ptrdname().labels().iter();
        let instance_name = labels.next().ok_or(Error::Eof)?;
        let service_name = labels.next().ok_or(Error::Eof)?;
        let transport = labels.next().ok_or(Error::Eof)?;
        if labels.next().is_none() {
            // Domain missing, this is probably not a valid service.
            return Err(Error::Eof);
        }
        Ok(ServiceInstance {
            instance_name: instance_name.clone(),
            service: Service {
                name: service_name.clone(),
                transport: match transport.as_bytes() {
                    b"_tcp" => ServiceTransport::TCP,
                    b"_udp" => ServiceTransport::Other,
                    _ => return Err(Error::InvalidValue),
                },
            },
        })
    }

    #[inline]
    pub fn instance_name(&self) -> &Label {
        &self.instance_name
    }

    #[inline]
    pub fn service(&self) -> &Service {
        &self.service
    }

    #[inline]
    pub fn service_name(&self) -> &Label {
        self.service.name()
    }

    #[inline]
    pub fn service_transport(&self) -> ServiceTransport {
        self.service.transport
    }
}

impl fmt::Display for ServiceInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.instance_name, self.service,)
    }
}

impl fmt::Debug for ServiceInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Describes how a [`ServiceInstance`] can be reached, and supplies service metadata.
pub struct InstanceDetails {
    host: DomainName,
    port: u16,
    txt: TxtRecords,
}

impl InstanceDetails {
    pub fn new(host: DomainName, port: u16) -> Self {
        Self {
            host,
            port,
            txt: TxtRecords::new(),
        }
    }

    /// Parses an [`SRV`] record containing instance details.
    pub fn from_srv(srv: &SRV<'_>) -> Result<Self, Error> {
        Ok(Self {
            host: srv.target().clone(),
            port: srv.port(),
            txt: TxtRecords::new(),
        })
    }

    /// Returns the [`DomainName`] on which the service can be found.
    #[inline]
    pub fn host(&self) -> &DomainName {
        &self.host
    }

    /// Returns the port on which the service is listening.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[inline]
    pub fn txt_records(&self) -> &TxtRecords {
        &self.txt
    }

    #[inline]
    pub fn txt_records_mut(&mut self) -> &mut TxtRecords {
        &mut self.txt
    }
}

/// List of `key=value` records stored in a DNS-SD TXT record of a service instance.
#[derive(Debug)]
pub struct TxtRecords {
    // keys are lowercased
    // FIXME this should keep the original order
    map: BTreeMap<String, TxtRecord>,
}

#[derive(Debug)]
struct TxtRecord {
    key: String,
    value: Option<Vec<u8>>,
}

impl TxtRecords {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn from_txt(txt: &TXT<'_>) -> Self {
        let mut map = BTreeMap::new();

        for entry in txt.entries() {
            let mut split = entry.splitn(2, |&b| b == b'=');
            let key = split.next().unwrap();
            let key = match String::from_utf8(key.to_vec()) {
                Ok(key) => key,
                Err(e) => {
                    log::debug!("non-ASCII TXT key: {}", e);
                    continue;
                }
            };
            let entry = map.entry(key.to_ascii_lowercase());
            if let Entry::Occupied(_) = entry {
                log::debug!("TXT key '{}' already occupied, ignoring", entry.key());
            }

            match split.next() {
                Some(value) => {
                    entry.or_insert(TxtRecord {
                        key,
                        value: Some(value.to_vec()),
                    });
                }
                None => {
                    // boolean flag
                    entry.or_insert(TxtRecord { key, value: None });
                }
            }
        }

        Self { map }
    }

    /// Adds a TXT record with no value.
    pub fn add_flag(&mut self, key: String) {
        self.map
            .insert(key.to_ascii_lowercase(), TxtRecord { key, value: None });
    }

    /// Returns an iterator over all key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, TxtRecordValue<'_>)> {
        self.map.iter().map(|(_, rec)| match &rec.value {
            Some(v) => (rec.key.as_str(), TxtRecordValue::Value(&v)),
            None => (rec.key.as_str(), TxtRecordValue::NoValue),
        })
    }

    pub fn get(&self, key: &str) -> Option<TxtRecordValue<'_>> {
        self.map
            .get(&key.to_ascii_lowercase())
            .map(|rec| match &rec.value {
                Some(v) => TxtRecordValue::Value(v),
                None => TxtRecordValue::NoValue,
            })
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl fmt::Display for TxtRecords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, rec) in self.map.values().enumerate() {
            if i != 0 {
                f.write_str(" ")?;
            }

            f.write_str(&rec.key)?;
            match &rec.value {
                Some(v) => {
                    f.write_str("=")?;
                    v.escape_ascii().fmt(f)?;
                }
                None => {}
            }
        }
        Ok(())
    }
}

pub enum TxtRecordValue<'a> {
    NoValue,
    Value(&'a [u8]),
}

impl<'a> fmt::Debug for TxtRecordValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoValue => f.write_str("-"),
            Self::Value(v) => match std::str::from_utf8(v) {
                Ok(s) => s.fmt(f),
                Err(_) => {
                    for byte in *v {
                        byte.escape_ascii().fmt(f)?;
                    }
                    Ok(())
                }
            },
        }
    }
}
