//! (m)DNS packet decoder and encoder.

#[macro_use]
mod macros;
pub mod decoder;
pub mod encoder;
pub mod name;
pub mod records;
pub mod section;

use core::fmt;

use bitflags::bitflags;

use crate::num::U16;

ffi_enum! {
    /// DNS message operation codes.
    pub enum Opcode: u8 {
        /// Query (or response to a query).
        ///
        /// A client sends a message with this opcode and at least one entry in the *Question*
        /// section to retrieve information (resource records) associated with a domain name.
        /// The server will reply with a message with this opcode, a copy of the client's *Question*
        /// section, and an *Answer* section containing the requested resource records.
        QUERY = 0,

        /// Inverse Query (or response to an inverse query).
        ///
        /// This feature is optional and servers might not support it.
        ///
        /// A client sends a message with this opcode and at least one entry in the *Answer* section
        /// to retrieve the domain name associated with the resource record (typically an IP
        /// address). The server will reply with a message with this opcode, a copy of the client's
        /// *Answer* section, and a *Question* section containing the matching domain names.
        IQUERY = 1,

        /// Server status request.
        STATUS = 2,

        NOTIFY = 4,
        UPDATE = 5,
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

ffi_enum! {
    /// Server response codes.
    ///
    /// Note that only rcodes with a value of 15 or less can be represented in the packet's
    /// [`Header`].
    pub enum RCode: u8 {
        /// No error.
        NO_ERROR = 0,
        /// The query sent by the client was erroneous.
        FORM_ERR = 1,
        /// A server-side error prevented processing of the query.
        SERV_FAIL = 2,
        /// Signifies that the queried domain name does not exist.
        ///
        /// May only be sent by an authoritative name server.
        NX_DOMAIN = 3,
        /// The requested query type is not supported by the server.
        NOT_IMP = 4,
        /// The server refused to answer the query for policy reasons.
        REFUSED = 5,
        YX_DOMAIN = 6,
        YX_RR_SET = 7,
        NX_RR_SET = 8,
        NOT_AUTH = 9,
        NOT_ZONE = 10,
        DSO_TYPE_NI = 11,

        BAD_VERS = 16,
        BAD_SIG = 16,

        BAD_KEY = 17,
        BAD_TIME = 18,
        BAD_MODE = 19,
        BAD_NAME = 20,
        BAD_ALG = 21,
        BAD_TRUNC = 22,
        BAD_COOKIE = 23,
    }
}

impl fmt::Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

ffi_enum! {
    /// Resource Record types.
    ///
    /// These are mostly copied from [RFC 1035] and
    /// <https://en.wikipedia.org/wiki/List_of_DNS_record_types>.
    ///
    /// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
    pub enum Type: u16 {
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        SIG = 24,
        KEY = 25,
        AAAA = 28,
        LOC = 29,
        SRV = 33,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        DNAME = 39,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        SMIMEA = 53,
        HIP = 55,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        ZONEMD = 63,
        SVCB = 64,
        HTTPS = 65,
        EUI48 = 108,
        EUI64 = 109,
        TKEY = 249,
        TSIG = 250,
        URI = 256,
        CAA = 257,
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

ffi_enum! {
    /// The queried resource type that a client is interested in.
    pub enum QType: u16 {
        // Prefix is identical to `Type`.
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        SIG = 24,
        KEY = 25,
        AAAA = 28,
        LOC = 29,
        SRV = 33,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        DNAME = 39,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        SMIMEA = 53,
        HIP = 55,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        ZONEMD = 63,
        SVCB = 64,
        HTTPS = 65,
        EUI48 = 108,
        EUI64 = 109,
        TKEY = 249,
        TSIG = 250,
        URI = 256,
        CAA = 257,

        // QType-specific entries:
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        /// Query is for all record types.
        ALL = 255,
    }
}

impl QType {
    pub fn matches(&self, ty: Type) -> bool {
        match *self {
            Self::AXFR => {
                // Zone transfers need special handling and don't really request individual records.
                false
            }
            Self::MAILB => matches!(ty, Type::MB | Type::MG | Type::MR),
            Self::MAILA => false, // obsolete
            Self::ALL => true,
            _ => self.0 == ty.0,
        }
    }
}

impl fmt::Display for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

ffi_enum! {
    /// Resource Record classes.
    pub enum Class: u16 {
        /// The Internet.
        IN = 1,
        /// CSNET.
        CS = 2,
        /// Chaosnet.
        CH = 3,
        /// Hesiod (basically, an LDAP precursor).
        HS = 4,
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

ffi_enum! {
    /// The queried resource class.
    pub enum QClass: u16 {
        // Prefix is identical to `Class`.

        /// The Internet.
        IN = 1,
        /// CSNET.
        CS = 2,
        /// Chaosnet.
        CH = 3,
        /// Hesiod (basically, an LDAP precursor).
        HS = 4,

        /// Query is for all classes of resource.
        ANY = 255,
    }
}

impl QClass {
    pub fn matches(&self, class: Class) -> bool {
        if *self == Self::ANY {
            true
        } else {
            self.0 == class.0
        }
    }
}

impl fmt::Display for QClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// Bit positions in the header flags are inverted, because RFC 1035 starts counting at the MSb.
const fn be_pos(pos: u16) -> u16 {
    15 - pos
}

bitflags! {
    #[derive(Debug)]
    #[repr(transparent)]
    struct HeaderFlags: u16 {
        /// If set, the message is a response to a query. If unset, it is a query.
        const QR = 1 << be_pos(0);
        const OPCODE = Self::OPCODE_MASK;
        /// Set if this response was sent from a name server that is the authority for the queried
        /// domain name.
        const AA = 1 << be_pos(5);
        /// Set if the message was truncated because it is longer than the maximum allowed length of
        /// the transmission channel.
        const TC = 1 << be_pos(6);
        /// Recursion Desired: This bit can be set in a query to instruct recursive resolvers to
        /// perform a recursive query. The bit is copied to the response.
        const RD = 1 << be_pos(7);
        /// Recursion Available: This bit can be set in a response to indicate that the responding
        /// server support recursion.
        const RA = 1 << be_pos(8);
        const Z = 0b111 << be_pos(9);
        const RCODE = Self::RCODE_MASK;
    }
}

impl HeaderFlags {
    const OPCODE_POS: u16 = 11;
    const OPCODE_MASK: u16 = 0b1111 << Self::OPCODE_POS;

    const RCODE_POS: u16 = 0;
    const RCODE_MASK: u16 = 0b1111 << Self::RCODE_POS;

    fn opcode(&self) -> Opcode {
        Opcode(((self.bits() & Self::OPCODE_MASK) >> Self::OPCODE_POS) as u8)
    }

    fn rcode(&self) -> RCode {
        RCode(((self.bits() & Self::RCODE_MASK) >> Self::RCODE_POS) as u8)
    }
}

/// Packet header.
#[derive(Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C, packed)]
pub struct Header {
    id: U16,
    flags: U16,
    qdcount: U16,
    ancount: U16,
    nscount: U16,
    arcount: U16,
}

impl Header {
    fn flags(&self) -> HeaderFlags {
        HeaderFlags::from_bits_retain(self.flags.get())
    }

    fn modify_flags(&mut self, with: impl FnOnce(&mut HeaderFlags)) {
        let mut flags = self.flags();
        with(&mut flags);
        self.flags = flags.bits().into();
    }

    /// Returns the 16-bit packet ID.
    ///
    /// Servers will copy this ID to the corresponding response packet so that the client can
    /// identify responses to its queries.
    #[inline]
    pub fn id(&self) -> u16 {
        self.id.get()
    }

    #[inline]
    pub fn set_id(&mut self, id: u16) {
        self.id = id.into();
    }

    #[inline]
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }

    #[inline]
    pub fn is_response(&self) -> bool {
        self.flags().contains(HeaderFlags::QR)
    }

    pub fn set_response(&mut self, is_response: bool) {
        self.modify_flags(|f| f.set(HeaderFlags::QR, is_response));
    }

    /// Returns whether the truncation flag is set, indicating that the message was truncated to
    /// fit in the transport channel.
    pub fn is_truncated(&self) -> bool {
        self.flags().contains(HeaderFlags::TC)
    }

    pub fn set_truncated(&mut self, trunc: bool) {
        self.modify_flags(|f| f.set(HeaderFlags::TC, trunc));
    }

    pub fn is_recursion_desired(&self) -> bool {
        self.flags().contains(HeaderFlags::RD)
    }

    pub fn set_recursion_desired(&mut self, rd: bool) {
        self.modify_flags(|f| f.set(HeaderFlags::RD, rd));
    }

    pub fn is_recursion_available(&self) -> bool {
        self.flags().contains(HeaderFlags::RA)
    }

    pub fn set_recursion_available(&mut self, ra: bool) {
        self.modify_flags(|f| f.set(HeaderFlags::RA, ra));
    }

    pub fn is_authority(&self) -> bool {
        self.flags().contains(HeaderFlags::AA)
    }

    pub fn set_authority(&mut self, aa: bool) {
        self.modify_flags(|f| f.set(HeaderFlags::AA, aa));
    }

    pub fn opcode(&self) -> Opcode {
        self.flags().opcode()
    }

    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.modify_flags(|f| {
            f.remove(HeaderFlags::OPCODE);
            *f.0.bits_mut() |=
                (u16::from(opcode.0) << HeaderFlags::OPCODE_POS) & HeaderFlags::OPCODE_MASK;
        });
    }

    pub fn rcode(&self) -> RCode {
        self.flags().rcode()
    }

    pub fn set_rcode(&mut self, rcode: RCode) {
        self.modify_flags(|f| {
            f.remove(HeaderFlags::RCODE);
            *f.0.bits_mut() |=
                (u16::from(rcode.0) << HeaderFlags::RCODE_POS) & HeaderFlags::RCODE_MASK;
        });
    }

    pub fn question_count(&self) -> u16 {
        self.qdcount.get()
    }

    pub fn answer_count(&self) -> u16 {
        self.ancount.get()
    }

    pub fn authoritative_count(&self) -> u16 {
        self.nscount.get()
    }

    pub fn additional_count(&self) -> u16 {
        self.arcount.get()
    }

    fn set_qdcount(&mut self, qdcount: u16) {
        self.qdcount = qdcount.into();
    }

    fn set_ancount(&mut self, ancount: u16) {
        self.ancount = ancount.into();
    }

    fn set_nscount(&mut self, nscount: u16) {
        self.nscount = nscount.into();
    }

    fn set_arcount(&mut self, arcount: u16) {
        self.arcount = arcount.into();
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("id", &self.id())
            .field("flags", &self.flags())
            .field("qdcount", &self.qdcount.get())
            .field("ancount", &self.ancount.get())
            .field("nscount", &self.nscount.get())
            .field("arcount", &self.arcount.get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header() {
        let mut h = Header::default();
        assert!(h.is_query());
        assert!(!h.is_authority());
        assert!(!h.is_response());
        assert!(!h.is_recursion_available());
        assert!(!h.is_recursion_desired());

        assert_eq!(h.opcode(), Opcode::QUERY);
        h.set_opcode(Opcode::UPDATE);
        assert_eq!(h.opcode(), Opcode::UPDATE);
        h.set_opcode(Opcode::QUERY);
        assert_eq!(h.opcode(), Opcode::QUERY);

        assert_eq!(h.rcode(), RCode::NO_ERROR);
        h.set_rcode(RCode::REFUSED);
        assert_eq!(h.rcode(), RCode::REFUSED);
        h.set_rcode(RCode::NO_ERROR);
        assert_eq!(h.rcode(), RCode::NO_ERROR);
    }
}
