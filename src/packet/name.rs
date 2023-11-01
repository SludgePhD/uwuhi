//! Domain names and labels.

use std::{
    fmt::{self, Write},
    slice,
    str::FromStr,
    vec,
};

use crate::Error;

/// A `.`-separated component of a [`DomainName`].
///
/// Labels consist of arbitrary bytes and have a maximum length of 63 bytes. This type can only
/// represent non-empty labels, so the minimum length is 1 byte.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label {
    // Guaranteed to contain >0 and at most `Label::MAX_LEN` bytes.
    bytes: Box<[u8]>,
}

impl Label {
    /// The maximum length of a domain label.
    pub const MAX_LEN: usize = 0b0011_1111;

    /// Creates a [`Label`] from raw bytes or a string slice, panicking if the bytes are an invalid
    /// label.
    ///
    /// # Panics
    ///
    /// This function will panic if `bytes` is empty or contains more than [`Self::MAX_LEN`] bytes.
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
            bytes: label.into(),
        })
    }

    /// Returns the raw bytes of this label.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
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

    /// Appends a [`Label`] to the end of this domain name.
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
    use super::*;

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
        assert_eq!(DomainName::ROOT.labels().len(), 0);
    }
}
