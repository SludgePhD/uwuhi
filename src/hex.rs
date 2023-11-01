use std::fmt;

pub(crate) struct Hex<'a>(pub &'a [u8]);

impl<'a> fmt::Display for Hex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn parse(s: &str) -> Vec<u8> {
    assert!(s.is_ascii());

    let mut buf = Vec::new();
    for i in (0..s.len()).step_by(2) {
        let chs = &s[i..i + 2];
        assert!(!chs.contains('+'));

        buf.push(u8::from_str_radix(chs, 16).unwrap());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(parse("00abff"), &[0x00, 0xab, 0xff]);
    }
}
