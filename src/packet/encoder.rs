//! DNS packet encoder.

use core::marker::PhantomData;
use std::mem::{align_of, size_of};

use super::{
    name::DomainName,
    records::{Record, ResourceRecordEncoder},
    Class, Error, Header, QClass, QType,
};

pub(crate) struct Writer<'a> {
    buf: &'a mut [u8],
    pub(crate) pos: usize,
    trunc: bool,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            trunc: false,
        }
    }

    fn modify_header(&mut self, with: impl FnOnce(&mut Header)) {
        assert_eq!(align_of::<Header>(), 1);

        let h = bytemuck::from_bytes_mut(&mut self.buf[..size_of::<Header>()]);
        with(h);
    }

    pub(crate) fn write_slice(&mut self, data: &[u8]) {
        let buf = &mut self.buf[self.pos..];
        if data.len() > buf.len() {
            self.trunc = true;
            buf.copy_from_slice(&data[..buf.len()]);
            self.pos += buf.len();
        } else {
            buf[..data.len()].copy_from_slice(data);
            self.pos += data.len();
        }
    }

    pub(crate) fn write_obj<T: NoUninit>(&mut self, obj: T) {
        self.write_slice(bytemuck::bytes_of(&obj))
    }

    pub(crate) fn write_u8(&mut self, b: u8) {
        self.write_slice(&[b]);
    }

    pub(crate) fn write_u16(&mut self, v: u16) {
        self.write_slice(&v.to_be_bytes());
    }

    pub(crate) fn write_u32(&mut self, v: u32) {
        self.write_slice(&v.to_be_bytes());
    }

    pub(crate) fn write_domain_name(&mut self, name: &DomainName) {
        for label in name.labels() {
            self.write_u8(label.as_bytes().len() as u8);
            self.write_slice(label.as_bytes());
        }
        // Implicit root label at the end.
        self.write_u8(0);
    }

    pub(crate) fn write_character_string(&mut self, string: &[u8]) {
        assert!(string.len() <= 255);
        self.write_u8(string.len() as u8);
        self.write_slice(string);
    }
}

/// DNS message sections.
pub mod section {
    mod sealed {
        pub trait Sealed {}
    }
    pub trait Section: sealed::Sealed {}
    pub enum Question {}
    pub enum Answer {}
    pub enum Authority {}
    pub enum Additional {}
    impl sealed::Sealed for Question {}
    impl sealed::Sealed for Answer {}
    impl sealed::Sealed for Authority {}
    impl sealed::Sealed for Additional {}
    impl Section for Question {}
    impl Section for Answer {}
    impl Section for Authority {}
    impl Section for Additional {}
}
use bytemuck::{NoUninit, Zeroable};
use section::Section;

struct EncoderInner<'a> {
    w: Writer<'a>,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl<'a> Drop for EncoderInner<'a> {
    fn drop(&mut self) {
        let trunc = self.w.trunc;
        self.w.modify_header(|h| {
            h.set_qdcount(self.qdcount);
            h.set_ancount(self.ancount);
            h.set_nscount(self.nscount);
            h.set_arcount(self.arcount);
            h.set_truncated(trunc);
        });
    }
}

pub struct MessageEncoder<'a, S: Section> {
    inner: EncoderInner<'a>,
    _p: PhantomData<S>,
}

impl<'a, S: Section> MessageEncoder<'a, S> {
    /// Overrides the whole message header.
    ///
    /// Note that the [`MessageEncoder`] will modify some header fields on drop, to ensure that the
    /// message can be parsed correctly.
    pub fn set_header(&mut self, header: Header) {
        self.inner.w.modify_header(|h| *h = header);
    }

    /// Finishes encoding the packet, and returns the number of bytes that were written to the
    /// buffer.
    ///
    /// If the message was truncated because the provided buffer was too small, this will return
    /// [`Error::Truncated`], and the message's truncation bit will be set. In that case,
    /// the user can still decide to send the message.
    pub fn finish(self) -> Result<usize, Error> {
        let bytes_written = self.inner.w.pos;

        if self.inner.w.trunc {
            Err(Error::Truncated)
        } else {
            Ok(bytes_written)
        }
    }
}

impl<'a> MessageEncoder<'a, section::Question> {
    /// Creates a new message encoder that will write to `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        let mut w = Writer::new(buf);
        w.write_obj(Header::zeroed());
        Self {
            inner: EncoderInner {
                w,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            _p: PhantomData,
        }
    }

    /// Adds a question to the *Question* section.
    pub fn question<'l>(&mut self, question: Question<'l>) {
        self.inner.w.write_domain_name(question.name);
        self.inner.w.write_u16(question.ty.0);
        self.inner.w.write_u16(question.class.0);
        self.inner.qdcount += 1;
    }

    /// Moves the encoder to the *Answer* section.
    #[inline]
    pub fn answers(self) -> MessageEncoder<'a, section::Answer> {
        MessageEncoder {
            inner: self.inner,
            _p: PhantomData,
        }
    }
}

impl<'a, S: Section> MessageEncoder<'a, S> {
    fn write_rr(&mut self, rr: ResourceRecord<'_>) {
        let w = &mut self.inner.w;
        w.write_domain_name(rr.name);
        w.write_u16(rr.rdata.record_type().0);
        w.write_u16(rr.class.0);
        w.write_u32(rr.ttl);
        // a little inscrutable seek dance :3
        let lenpos = w.pos;
        w.write_u16(0); // dummy length
        let before_rdata = w.pos;
        let mut enc = ResourceRecordEncoder {
            w: Writer {
                buf: &mut *w.buf,
                pos: w.pos,
                trunc: w.trunc,
            },
        };
        rr.rdata.encode(&mut enc);
        w.pos = enc.w.pos;
        w.trunc = enc.w.trunc;
        let rdata_len = w.pos - before_rdata;
        let finished_pos = w.pos;
        w.pos = lenpos;
        w.write_u16(rdata_len.try_into().expect("RDATA length overflows u16"));
        w.pos = finished_pos;
    }
}

impl<'a> MessageEncoder<'a, section::Answer> {
    pub fn add_answer(&mut self, rr: ResourceRecord<'_>) {
        self.write_rr(rr);
        self.inner.ancount += 1;
    }

    /// Moves the encoder to the *Authority* section.
    #[inline]
    pub fn authority(self) -> MessageEncoder<'a, section::Authority> {
        MessageEncoder {
            inner: self.inner,
            _p: PhantomData,
        }
    }
}

impl<'a> MessageEncoder<'a, section::Authority> {
    pub fn add_authority(&mut self, rr: ResourceRecord<'_>) {
        self.write_rr(rr);
        self.inner.nscount += 1;
    }

    /// Moves the encoder to the *Additional Records* section.
    #[inline]
    pub fn additional(self) -> MessageEncoder<'a, section::Additional> {
        MessageEncoder {
            inner: self.inner,
            _p: PhantomData,
        }
    }
}

impl<'a> MessageEncoder<'a, section::Additional> {
    pub fn add_additional(&mut self, rr: ResourceRecord<'_>) {
        self.write_rr(rr);
        self.inner.arcount += 1;
    }
}

pub struct Question<'a> {
    name: &'a DomainName,
    class: QClass,
    ty: QType,
}

impl<'a> Question<'a> {
    /// Creates a question asking for all records ([`QType::ALL`]) in the internet class
    /// ([`QClass::IN`]) pertaining to `name`.
    #[inline]
    pub fn new(name: &'a DomainName) -> Self {
        Self {
            name,
            class: QClass::IN,
            ty: QType::ALL,
        }
    }

    /// Sets the record class to query.
    ///
    /// In almost all cases this can be left as the default value ([`QClass::IN`]), which queries
    /// records in the Internet class.
    #[inline]
    pub fn class(self, class: QClass) -> Self {
        Self { class, ..self }
    }

    /// Sets the resource type to query.
    #[inline]
    pub fn ty(self, ty: QType) -> Self {
        Self { ty, ..self }
    }
}

pub struct ResourceRecord<'a> {
    name: &'a DomainName,
    class: Class,
    ttl: u32,
    rdata: &'a Record<'a>,
}

impl<'a> ResourceRecord<'a> {
    pub fn new(name: &'a DomainName, rdata: &'a Record<'a>) -> Self {
        Self {
            name,
            class: Class::IN,
            ttl: 0,
            rdata,
        }
    }

    #[inline]
    pub fn class(self, class: Class) -> Self {
        Self { class, ..self }
    }

    #[inline]
    pub fn ttl(self, ttl: u32) -> Self {
        Self { ttl, ..self }
    }
}
