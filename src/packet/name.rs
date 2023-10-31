//! Domain names and labels.

use std::{
    fmt::{self, Write},
    hash::{Hash, Hasher},
    mem, slice,
    str::FromStr,
    vec,
};

use super::Error;

// 1 discr. byte + 2 usizes for the `Outline` variant (padded to 3 * usize)
// That means the inline variant can use `3 * usize - 1 byte` of total memory. One of those is used
// for the length.
const LABEL_MAX_INLINE_LEN: usize = mem::size_of::<usize>() * 3 - 1 - 1;
// (this is 22 bytes on 64-bit systems, which is quite a lot)

#[derive(Clone)]
enum LabelRepr {
    Inline {
        buf: [u8; LABEL_MAX_INLINE_LEN],
        len: u8,
    },
    Outline {
        data: Box<[u8]>,
    },
}

/// A `.`-separated component of a [`DomainName`].
///
/// Labels consist of arbitrary bytes and have a maximum length of 63 bytes. This type can only
/// represent non-empty labels, so the minimum length is 1 byte.
#[derive(Clone)]
pub struct Label {
    repr: LabelRepr,
}

impl Label {
    /// The maximum length of a domain label.
    pub const MAX_LEN: usize = 0b0011_1111;

    /// Creates a [`Label`] from raw bytes or a string slice, panicking if the bytes are an invalid
    /// label.
    ///
    /// # Panics
    ///
    /// This function will panic if `bytes` is empty, contains more than [`Self::MAX_LEN`] bytes, or
    /// contains bytes outside the ASCII range.
    pub fn new(label: impl AsRef<[u8]>) -> Self {
        Self::new_impl(label.as_ref())
    }

    fn new_impl(label: &[u8]) -> Self {
        Self::try_new(label)
            .unwrap_or_else(|_| panic!("`Label::new` called with invalid data: {:?}", label))
    }

    /// Creates a [`Label`] from raw bytes or a string slice, returning [`None`] if the bytes are an
    /// invalid label.
    pub fn try_new(label: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::try_new_impl(label.as_ref())
    }

    fn try_new_impl(label: &[u8]) -> Result<Self, Error> {
        if label.is_empty() {
            return Err(Error::InvalidEmptyLabel);
        }

        if label.len() > Self::MAX_LEN {
            return Err(Error::LabelTooLong);
        }

        Ok(Self {
            repr: if label.len() <= LABEL_MAX_INLINE_LEN {
                let mut buf = [0; LABEL_MAX_INLINE_LEN];
                buf[..label.len()].copy_from_slice(label);
                LabelRepr::Inline {
                    buf,
                    len: label.len() as u8,
                }
            } else {
                LabelRepr::Outline { data: label.into() }
            },
        })
    }

    /// Returns the raw bytes of this label.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match &self.repr {
            LabelRepr::Inline { buf, len } => &buf[..usize::from(*len)],
            LabelRepr::Outline { data } => data,
        }
    }
}

impl PartialEq for Label {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Label {}

impl PartialOrd for Label {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_bytes().partial_cmp(other.as_bytes())
    }
}

impl Ord for Label {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for Label {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#""{}""#, self.as_bytes().escape_ascii())
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_bytes().escape_ascii().fmt(f)
    }
}

impl FromStr for Label {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// A domain name, represented as a list of [`Label`]s.
///
/// In DNS queries, domain names are terminated by an empty label, but this type omits that label.
/// This allows downstream code to use [`DomainName::push_label`] to incrementally build a domain
/// name.
#[derive(PartialEq, Eq, Clone)]
pub struct DomainName {
    // Does not include the trailing empty label.
    labels: Vec<Label>,
}

impl DomainName {
    /// The empty root domain `.`.
    pub const ROOT: Self = Self { labels: Vec::new() };

    /// Parses a domain name as a string of `.`-separated labels.
    ///
    /// A trailing `.` is allowed but not required.
    ///
    /// The [`FromStr`] implementation performs the same operation. This method is just a
    /// convenience function so that you don't have to import that trait.
    pub fn from_str(s: &str) -> Result<Self, Error> {
        s.parse()
    }

    /// Returns the `.`-separated labels making up this domain name.
    ///
    /// The trailing empty label is not included.
    #[inline]
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Appends a [`Label`] to the end this domain name.
    #[inline]
    pub fn push_label(&mut self, label: Label) {
        self.labels.push(label);
    }
}

impl Extend<Label> for DomainName {
    fn extend<T: IntoIterator<Item = Label>>(&mut self, iter: T) {
        self.labels.extend(iter)
    }
}

impl<'a> Extend<&'a Label> for DomainName {
    fn extend<T: IntoIterator<Item = &'a Label>>(&mut self, iter: T) {
        self.labels.extend(iter.into_iter().cloned())
    }
}

impl FromIterator<Label> for DomainName {
    fn from_iter<T: IntoIterator<Item = Label>>(iter: T) -> Self {
        Self {
            labels: Vec::from_iter(iter),
        }
    }
}

impl<'a> FromIterator<&'a Label> for DomainName {
    fn from_iter<T: IntoIterator<Item = &'a Label>>(iter: T) -> Self {
        Self {
            labels: Vec::from_iter(iter.into_iter().cloned()),
        }
    }
}

impl IntoIterator for DomainName {
    type Item = Label;
    type IntoIter = IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.labels.into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a DomainName {
    type Item = &'a Label;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Iter {
            inner: self.labels.iter(),
        }
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_char('.');
        }
        for label in &self.labels {
            label.fmt(f)?;
            f.write_char('.')?;
        }
        Ok(())
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_char('.');
        }
        for label in &self.labels {
            label.fmt(f)?;
            f.write_char('.')?;
        }
        Ok(())
    }
}

impl FromStr for DomainName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "." {
            // `split_terminator` returns an empty label for this, so special-case it
            return Ok(Self::ROOT);
        }

        let mut name = DomainName { labels: Vec::new() };
        for label in s.split_terminator('.') {
            name.labels.push(label.parse()?);
        }
        Ok(name)
    }
}

/// A by-value iterator over the [`Label`]s of a [`DomainName`].
pub struct IntoIter {
    inner: vec::IntoIter<Label>,
}

impl Iterator for IntoIter {
    type Item = Label;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// A by-reference iterator over the [`Label`]s of a [`DomainName`].
pub struct Iter<'a> {
    inner: slice::Iter<'a, Label>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Label;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;

    #[test]
    fn label_size() {
        assert_eq!(mem::size_of::<Label>(), mem::size_of::<Vec<u8>>());
    }

    #[test]
    fn display_label() {
        assert_eq!(format!(" {} ", Label::new("\0")), r#" \x00 "#);
        assert_eq!(format!(" {} ", Label::new("\n")), r#" \n "#);
        assert_eq!(format!(" {} ", Label::new("a")), r#" a "#);
    }

    #[test]
    fn debug_label() {
        assert_eq!(format!(" {:?} ", Label::new("\0")), r#" "\x00" "#);
        assert_eq!(format!(" {:?} ", Label::new("\n")), r#" "\n" "#);
        assert_eq!(format!(" {:?} ", Label::new("a")), r#" "a" "#);
    }

    #[test]
    fn domain_name_string_conversion() {
        assert_eq!("..".parse::<DomainName>(), Err(Error::InvalidEmptyLabel));
        assert_eq!(".com".parse::<DomainName>(), Err(Error::InvalidEmptyLabel));
        assert_eq!(".".parse::<DomainName>(), Ok(DomainName::ROOT));
        assert_eq!("com.".parse::<DomainName>().unwrap().to_string(), "com.");
        assert_eq!("com.".parse::<DomainName>().unwrap().labels().len(), 1);
    }
}
