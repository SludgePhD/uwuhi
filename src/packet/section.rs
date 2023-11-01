//! Types representing the different sections of a DNS message.

mod sealed {
    pub trait Sealed: 'static {}
}

/// Trait implemented by the DNS section types.
pub trait Section: sealed::Sealed {}

/// Represents the *Question* section of a DNS message.
pub enum Question {}

/// Represents the *Answer* section of a DNS message.
pub enum Answer {}

/// Represents the *Authority* section of a DNS message.
pub enum Authority {}

/// Represents the *Additional* section of a DNS message.
pub enum Additional {}

impl sealed::Sealed for Question {}
impl sealed::Sealed for Answer {}
impl sealed::Sealed for Authority {}
impl sealed::Sealed for Additional {}
impl Section for Question {}
impl Section for Answer {}
impl Section for Authority {}
impl Section for Additional {}
