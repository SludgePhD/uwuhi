//! DNS packet decoder.

use core::mem;
use std::{any::TypeId, cmp, fmt, marker::PhantomData, mem::size_of};

use bytemuck::AnyBitPattern;

use crate::num::{U16, U32};

use super::{
    name::{DomainName, Label},
    records::Record,
    section::{self, Section},
    Class, Error, Header, QClass, QType, Type,
};

#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    /// The buffer containing the whole DNS message.
    full_buf: &'a [u8],
    /// The current reader position in the buffer.
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            full_buf: buf,
            pos: 0,
        }
    }

    pub(crate) fn buf(&self) -> &'a [u8] {
        &self.full_buf[self.pos..]
    }

    pub(crate) fn read_obj<T: AnyBitPattern>(&mut self) -> Result<T, Error> {
        let bytes = self.buf().get(..size_of::<T>()).ok_or(Error::Eof)?;
        self.pos += mem::size_of::<T>();
        Ok(bytemuck::pod_read_unaligned(bytes))
    }

    fn peek_u8(&self) -> Result<u8, Error> {
        self.full_buf.get(self.pos).copied().ok_or(Error::Eof)
    }

    pub(crate) fn read_slice(&mut self, len: usize) -> Result<&'a [u8], Error> {
        match self.full_buf.get(self.pos..self.pos + len) {
            Some(slice) => {
                self.pos += len;
                Ok(slice)
            }
            None => Err(Error::Eof),
        }
    }

    pub(crate) fn read_array<const LEN: usize>(&mut self) -> Result<&'a [u8; LEN], Error> {
        let slice = self.read_slice(LEN)?;
        Ok(slice.try_into().unwrap())
    }

    /// Splits off another `Reader` at the current position, with a backing store truncated to
    /// `self.pos + len`.
    ///
    /// This can be used when another object is created that might need to refer back to older data.
    fn split_off(&mut self, len: usize) -> Result<Reader<'a>, Error> {
        if self.buf().len() >= len {
            let mut copy = self.clone();
            copy.full_buf = &copy.full_buf[..self.pos + len];
            self.pos += len;
            Ok(copy)
        } else {
            Err(Error::Eof)
        }
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_obj::<u8>()?)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(self.read_obj::<U16>()?.get())
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(self.read_obj::<U32>()?.get())
    }

    /// Reads a `<character-string>` value.
    pub(crate) fn read_character_string(&mut self) -> Result<&'a [u8], Error> {
        let length = self.read_u8()?;
        self.read_slice(length.into())
    }

    /// Reads a `<domain-name>` value.
    pub(crate) fn read_domain_name(&mut self) -> Result<DomainName, Error> {
        let mut domain_name = DomainName::ROOT;
        let mut min_pos = self.pos;
        let mut copy = self.clone();
        loop {
            let length = copy.peek_u8()?;
            match length & 0b1100_0000 {
                0b1100_0000 => {
                    // 16-bit pointer to somewhere else in the UDP message.
                    let ptr = usize::from(copy.read_u16().unwrap() & 0b0011_1111_1111_1111);
                    if ptr >= min_pos {
                        // We require pointers to point to an earlier part of the message, to
                        // prevent loops. The specification is unclear about what exactly is
                        // allowed.
                        return Err(Error::PointerLoop);
                    } else {
                        self.pos = cmp::max(self.pos, copy.pos);
                        min_pos = ptr;
                        copy.pos = ptr;
                    }
                }
                0b0000_0000 => {
                    copy.pos += 1;

                    // Length byte followed by a label of that many bytes.
                    let length = usize::from(length);
                    if length == 0 {
                        break;
                    }
                    let label = copy.read_slice(length)?;
                    domain_name.push_label(Label::try_new(label)?);
                }
                _ => return Err(Error::InvalidValue), // anything but 00 and 11 in MSb is reserved
            }
        }

        self.pos = cmp::max(self.pos, copy.pos);
        Ok(domain_name)
    }

    fn read_question(&mut self) -> Result<Question, Error> {
        let qname = self.read_domain_name()?;
        let qtype = QType(self.read_u16()?);
        let qclass = QClass(self.read_u16()?);
        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    fn read_resource_record(&mut self) -> Result<ResourceRecord<'a>, Error> {
        let name = self.read_domain_name()?;
        let type_ = Type(self.read_u16()?);
        let mut cache_flush = false;
        let class = {
            let mut raw = self.read_u16()?;
            if raw & 0x8000 != 0 {
                cache_flush = true;
                raw &= !0x8000;
            }
            Class(raw)
        };
        let ttl = self.read_u32()?;
        let rdlength = self.read_u16()?;
        let rdata = self.split_off(usize::from(rdlength))?;
        Ok(ResourceRecord {
            name,
            type_,
            class,
            cache_flush,
            ttl,
            rdata,
        })
    }
}

/// Streaming decoder for DNS messages.
///
/// In DNS messages, sections are ordered as follows:
/// - *Question* section
/// - *Answer* section
/// - *Authority* section
/// - *Additional Records* section
///
/// To ensure efficient decoding and prevent misuse, the message decoder stores the section it is
/// currently decoding as the `S` type parameter. Initially (after calling [`MessageDecoder::new`]),
/// the decoder is in the [`section::Question`] state, and is advanced by calling the appropriate
/// methods.
pub struct MessageDecoder<'a, S: Section> {
    header: Header,
    q_remaining: u16,
    ans_remaining: u16,
    auth_remaining: u16,
    addl_remaining: u16,
    r: Reader<'a>,
    has_errored: bool,
    section: PhantomData<S>,
}

impl<'a> MessageDecoder<'a, section::Question> {
    /// Creates a streaming message decoder that will read from `buf`.
    pub fn new(buf: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let header = r.read_obj::<Header>()?;
        Ok(Self {
            header,
            q_remaining: header.question_count(),
            ans_remaining: header.answer_count(),
            auth_remaining: header.authoritative_count(),
            addl_remaining: header.additional_count(),
            r,
            has_errored: false,
            section: PhantomData,
        })
    }
}

impl<'a, S: Section> MessageDecoder<'a, S> {
    /// Returns the message header.
    #[inline]
    pub fn header(&self) -> &Header {
        &self.header
    }

    fn remaining(&mut self) -> &mut u16 {
        if TypeId::of::<S>() == TypeId::of::<section::Question>() {
            &mut self.q_remaining
        } else if TypeId::of::<S>() == TypeId::of::<section::Answer>() {
            &mut self.ans_remaining
        } else if TypeId::of::<S>() == TypeId::of::<section::Authority>() {
            &mut self.auth_remaining
        } else if TypeId::of::<S>() == TypeId::of::<section::Additional>() {
            &mut self.addl_remaining
        } else {
            unreachable!()
        }
    }

    fn change_section<N: Section>(self) -> MessageDecoder<'a, N> {
        MessageDecoder {
            header: self.header,
            q_remaining: self.q_remaining,
            ans_remaining: self.ans_remaining,
            auth_remaining: self.auth_remaining,
            addl_remaining: self.addl_remaining,
            r: self.r,
            has_errored: self.has_errored,
            section: PhantomData,
        }
    }

    fn next_rr(&mut self) -> Option<Result<ResourceRecord<'a>, Error>> {
        if self.has_errored || *self.remaining() == 0 {
            return None;
        }

        let rr = match self.r.read_resource_record() {
            Ok(q) => q,
            Err(e) => {
                self.has_errored = true;
                return Some(Err(e));
            }
        };

        *self.remaining() -= 1;

        Some(Ok(rr))
    }
}

impl<'a> MessageDecoder<'a, section::Question> {
    /// Reads the next [`Question`] from the *Question* section.
    pub fn next(&mut self) -> Option<Result<Question, Error>> {
        if self.has_errored || *self.remaining() == 0 {
            return None;
        }

        let question = match self.r.read_question() {
            Ok(q) => q,
            Err(e) => {
                self.has_errored = true;
                return Some(Err(e));
            }
        };

        *self.remaining() -= 1;

        Some(Ok(question))
    }

    /// Returns an iterator over all [`Question`]s in the *Question* section of the message.
    pub fn iter(&mut self) -> QuestionIter<'_, 'a> {
        QuestionIter { dec: self }
    }

    /// Skips the remaining entries in the *Question* section and advances the decoder to the
    /// *Answer* section.
    pub fn answers(mut self) -> Result<MessageDecoder<'a, section::Answer>, Error> {
        while let Some(res) = self.next() {
            res?;
        }

        Ok(self.change_section())
    }

    /// Skips the remaining entries in the *Question* section, as well as all entries in the
    /// *Answer* section, and advances the decoder to the *Authority* section.
    pub fn authority(self) -> Result<MessageDecoder<'a, section::Authority>, Error> {
        self.answers()?.authority()
    }

    /// Skips the remaining entries in the *Question* section, as well as all entries in the
    /// *Answer* and *Authority* sections, and advances the decoder to the *Additional Records*
    /// section.
    pub fn additional(self) -> Result<MessageDecoder<'a, section::Additional>, Error> {
        self.authority()?.additional()
    }
}

impl<'a> MessageDecoder<'a, section::Answer> {
    /// Reads the next [`ResourceRecord`] from the *Answer* section.
    pub fn next(&mut self) -> Option<Result<ResourceRecord<'_>, Error>> {
        self.next_rr()
    }

    /// Returns an iterator over all resource records in the *Answer* section.
    pub fn iter(&mut self) -> ResourceRecordIter<'_, 'a, section::Answer> {
        ResourceRecordIter { dec: self }
    }

    /// Skips the remaining entries in the *Answer* section, and advances the decoder to the
    /// *Additional Records* section.
    pub fn authority(mut self) -> Result<MessageDecoder<'a, section::Authority>, Error> {
        while let Some(res) = self.next() {
            res?;
        }

        Ok(self.change_section())
    }

    /// Skips the remaining entries in the *Answer* section, as well as all entries in the
    /// *Authority* section, and advances the decoder to the *Additional Records* section.
    pub fn additional(self) -> Result<MessageDecoder<'a, section::Additional>, Error> {
        self.authority()?.additional()
    }
}

impl<'a> MessageDecoder<'a, section::Authority> {
    /// Reads the next [`ResourceRecord`] from the *Authority* section.
    pub fn next(&mut self) -> Option<Result<ResourceRecord<'_>, Error>> {
        self.next_rr()
    }

    /// Returns an iterator over all resource records in the *Authority* section.
    pub fn iter(&mut self) -> ResourceRecordIter<'_, 'a, section::Authority> {
        ResourceRecordIter { dec: self }
    }

    pub fn additional(mut self) -> Result<MessageDecoder<'a, section::Additional>, Error> {
        while let Some(res) = self.next() {
            res?;
        }

        Ok(self.change_section())
    }
}

impl<'a> MessageDecoder<'a, section::Additional> {
    /// Reads the next [`ResourceRecord`] from the *Additional Records* section.
    pub fn next(&mut self) -> Option<Result<ResourceRecord<'_>, Error>> {
        self.next_rr()
    }

    /// Returns an iterator over all resource records in the *Additional Record* section.
    pub fn iter(&mut self) -> ResourceRecordIter<'_, 'a, section::Additional> {
        ResourceRecordIter { dec: self }
    }
}

/// Iterator over Resource Records in a DNS message.
pub struct ResourceRecordIter<'dec, 'data, S: Section> {
    dec: &'dec mut MessageDecoder<'data, S>,
}

impl<'dec, 'data, S: Section> Iterator for ResourceRecordIter<'dec, 'data, S> {
    type Item = Result<ResourceRecord<'data>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.dec.next_rr()
    }
}

/// A Resource Record from the *Answer*, *Authority*, or *Additional Records* section.
pub struct ResourceRecord<'a> {
    name: DomainName,
    type_: Type,
    class: Class,
    cache_flush: bool,
    ttl: u32,
    /// Record data, as a [`Reader`] pointing at the RDATA.
    pub(crate) rdata: Reader<'a>,
}

impl<'a> ResourceRecord<'a> {
    #[inline]
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    #[inline]
    pub fn type_(&self) -> Type {
        self.type_
    }

    #[inline]
    pub fn class(&self) -> Class {
        self.class
    }

    /// Returns whether the record's mDNS cache-flush bit is set.
    #[inline]
    pub fn cache_flush(&self) -> bool {
        self.cache_flush
    }

    /// Returns the entry's Time To Live, in seconds.
    #[inline]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns the raw record data.
    #[inline]
    pub fn rdata(&self) -> &[u8] {
        self.rdata.buf()
    }

    /// If this is a supported record type, decodes it and returns the corresponding [`Record`].
    ///
    /// Returns `None` if the record type is unsupported by this library.
    pub fn as_enum(&self) -> Option<Result<Record<'a>, Error>> {
        Record::from_rr(self)
    }
}

impl<'a> fmt::Debug for ResourceRecord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("ResourceRecord");
        dbg.field("name", &self.name)
            .field("type_", &self.type_)
            .field("class", &self.class)
            .field("cache_flush", &self.cache_flush)
            .field("ttl", &self.ttl);
        match self.as_enum() {
            Some(Ok(rec)) => dbg.field("rdata", &rec),
            Some(res @ Err(_)) => dbg.field("rdata", &res),
            None => dbg.field("rdata", &self.rdata),
        };
        dbg.finish()
    }
}

impl<'a> fmt::Display for ResourceRecord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t",
            self.name(),
            self.ttl(),
            self.class(),
            self.type_()
        )?;
        match self.as_enum() {
            Some(Ok(rr)) => {
                write!(f, "{}", rr)?;
            }
            Some(Err(e)) => {
                write!(f, "{}", e)?;
            }
            None => {
                write!(f, "{:02x?}", self.rdata())?;
            }
        }

        Ok(())
    }
}

/// An iterator over [`Question`]s in the *Question* section of a DNS message.
pub struct QuestionIter<'dec, 'data> {
    dec: &'dec mut MessageDecoder<'data, section::Question>,
}

impl<'dec, 'data> Iterator for QuestionIter<'dec, 'data> {
    type Item = Result<Question, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.dec.next()
    }
}

/// A question from a DNS query message.
#[derive(Debug)]
pub struct Question {
    qname: DomainName,
    qtype: QType,
    qclass: QClass,
}

impl Question {
    /// Returns the domain name that is being queried.
    #[inline]
    pub fn qname(&self) -> &DomainName {
        &self.qname
    }

    /// Returns the resource record types the client is interested in.
    #[inline]
    pub fn qtype(&self) -> QType {
        self.qtype
    }

    /// Returns the record class that the client is interested in.
    #[inline]
    pub fn qclass(&self) -> QClass {
        self.qclass
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}\t{}", self.qname(), self.qclass(), self.qtype())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(nope)]
    fn decode_msg(msg: &[u8]) {
        let mut msg = MessageDecoder::new(msg).unwrap();
        eprintln!("{:?}", msg.header());
        for q in msg.iter() {
            let q = q.unwrap();
            log::debug!("Q: {}", q);
        }
        let mut msg = msg.answers().unwrap();
        for rr in msg.iter() {
            let rr = rr.unwrap();
            log::debug!("ANS: {}", rr);
        }
        let mut msg = msg.authority().unwrap();
        for rr in msg.iter() {
            let rr = rr.unwrap();
            log::debug!("AUTH: {}", rr);
        }
        let mut msg = msg.additional().unwrap();
        eprintln!("{:?}", msg.r.buf());
        for rr in msg.iter() {
            let rr = rr.unwrap();
            log::debug!("ADDL: {}", rr);
        }
    }

    #[test]
    fn decode_domain_name() {
        let mut r = Reader::new(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        let name = r.read_domain_name().unwrap();
        assert_eq!(name.to_string(), "example.com.");

        let mut r = Reader::new(&[0]);
        let name = r.read_domain_name().unwrap();
        assert_eq!(name.to_string(), ".");
    }

    #[test]
    fn decode_domain_name_pointer() {
        let mut r = Reader::new(&[
            b'_', // never read
            3,
            b'c',
            b'o',
            b'm',
            0, // "com."
            7,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            // ptr to 1:
            0b1100_0000,
            1,
        ]);
        r.pos = 1;
        let name = r.read_domain_name().unwrap();
        assert_eq!(name.to_string(), "com.");
        let name = r.read_domain_name().unwrap();
        assert_eq!(name.to_string(), "example.com.");
        assert_eq!(r.read_u8(), Err(Error::Eof), "should be at EOF");
    }

    #[test]
    fn decode_domain_name_pointer_oob() {
        let mut r = Reader::new(&[0xff, 0xff]);
        assert_eq!(r.read_domain_name(), Err(Error::PointerLoop));
    }

    #[test]
    fn decode_domain_name_dos() {
        let mut r = Reader::new(&[
            // pointer to self:
            0b1100_0000,
            0,
        ]);
        assert_eq!(r.read_domain_name(), Err(Error::PointerLoop));

        let mut r = Reader::new(&[
            // fallthrough:
            1,
            b'a',
            // pointer to 0:
            0b1100_0000,
            0,
        ]);
        r.pos = 2;
        assert_eq!(r.read_domain_name(), Err(Error::PointerLoop));
    }
}
