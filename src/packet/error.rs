use std::{fmt, io};

/// Non-I/O errors that may occur during message decoding.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    /// The end of the message was reached while more data was expected.
    Eof,
    /// A domain name pointer pointed into itself or further into the message.
    PointerLoop,
    /// A field was set to an invalid (reserved for future use or illegal) value.
    InvalidValue,
    /// Only returned from [`MessageEncoder::finish`], indicates that there was not enough space in
    /// the provided buffer to fit the entire message.
    ///
    /// [`MessageEncoder::finish`]: super::encoder::MessageEncoder::finish
    Truncated,
    /// An empty label was encountered where it is not allowed.
    InvalidEmptyLabel,
    /// A label exceeded the maximum allowable length of a label.
    LabelTooLong,
}

impl Error {
    fn description(&self) -> &str {
        match self {
            Error::Eof => "unexpected end of data",
            Error::PointerLoop => "encountered domain name pointer loop",
            Error::InvalidValue => "invalid value",
            Error::Truncated => "packet truncated",
            Error::InvalidEmptyLabel => "invalid empty label",
            Error::LabelTooLong => "label too long",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::Eof => io::ErrorKind::UnexpectedEof.into(),
            Error::PointerLoop => io::Error::new(
                io::ErrorKind::InvalidData,
                "a domain name pointer loop was encountered; this may indicate a malicious request",
            ),
            Error::InvalidValue => io::ErrorKind::InvalidData.into(),
            Error::InvalidEmptyLabel => io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid empty label in domain name",
            ),
            Error::LabelTooLong => io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain name label exceeds maximum label length",
            ),
            Error::Truncated => io::ErrorKind::OutOfMemory.into(),
        }
    }
}
