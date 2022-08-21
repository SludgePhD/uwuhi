use core::fmt;
use std::ops::Deref;

/// A value that is held either by reference or by value.
///
/// This type is used throughout the [`super::records`] module to allow sharing record type
/// definitions between encoder and decoder, and to allow using them both with borrowed and owned
/// data. Normally, users do not need to interact with this type, and instead can just pass the
/// expected type or a reference to it to a function, since [`RefOrVal`] implements both [`From<T>`]
/// and [`From<&T>`].
#[derive(Clone, Copy)]
pub enum RefOrVal<'a, T> {
    Ref(&'a T),
    Val(T),
}

impl<'a, T: Clone> RefOrVal<'a, T> {
    /// Returns an owned version of `self`, by cloning the value if it is held by reference.
    pub fn make_owned(self) -> RefOrVal<'static, T> {
        match self {
            RefOrVal::Ref(r) => RefOrVal::Val(r.clone()),
            RefOrVal::Val(val) => RefOrVal::Val(val),
        }
    }
}

impl<'a, T: fmt::Debug> fmt::Debug for RefOrVal<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl<'a, T: fmt::Display> fmt::Display for RefOrVal<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl<'a, T: PartialEq> PartialEq for RefOrVal<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<'a, T: Eq> Eq for RefOrVal<'a, T> {}

impl<'a, T> Deref for RefOrVal<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            RefOrVal::Ref(r) => *r,
            RefOrVal::Val(val) => val,
        }
    }
}

impl<'a, T> From<T> for RefOrVal<'a, T> {
    fn from(val: T) -> Self {
        Self::Val(val)
    }
}

impl<'a, T> From<&'a T> for RefOrVal<'a, T> {
    fn from(r: &'a T) -> Self {
        Self::Ref(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ref_or_val_is_covariant() {
        fn _test<'short, 'long: 'short, T>(r: RefOrVal<'long, T>) -> RefOrVal<'short, T> {
            r
        }
    }
}
