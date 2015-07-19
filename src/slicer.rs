use std::fmt;
use std::result;

#[derive(Debug)]
pub enum SliceError {
    ExpectedToken(u8),
    UnexpectedTokens,
}

impl fmt::Display for SliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SliceError::ExpectedToken(token) => write!(f, "expected '{}'", token),
            SliceError::UnexpectedTokens => write!(f, "unexpected tokens"),
        }
    }
}

pub type Result<T> = result::Result<T, SliceError>;

pub struct Slicer<'a> {
    buffer: &'a [u8],
}

impl<'a> Slicer<'a> {
    pub fn new(s: &'a [u8]) -> Slicer<'a> {
        Slicer {
            buffer: s,
        }
    }

    pub fn slice_to(&mut self, delim: u8) -> Result<&'a [u8]> {
        // local benchmarks show this raw for loop is more performant in parsing whole haproxy log
        // lines (~290ns/iter) than .iter().position() (~340 ns/iter), or memchr (~320 ns/iter).
        for i in 0..self.buffer.len() {
            if self.buffer[i] == delim {
                let ret = &self.buffer[..i];
                self.buffer = &self.buffer[i+1..];
                return Ok(ret);
            }
        }

        Err(SliceError::ExpectedToken(delim))
    }

    pub fn slice_to_or_remainder(&mut self, delim: u8) -> &'a [u8] {
        match self.slice_to(delim) {
            Ok(slice) => slice,
            Err(_) => {
                let ret = self.buffer;
                self.buffer = b"";
                ret
            },
        }
    }

    pub fn discard(&mut self, s: &[u8]) -> Result<()> {
        if !self.buffer.starts_with(s) {
            return Err(SliceError::UnexpectedTokens)
        }

        self.buffer = &self.buffer[s.len()..];
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Slicer;

    #[test]
    fn slice_to() {
        let mut slicer = Slicer::new(b"first.second");
        let consumed = slicer.slice_to(b'.').unwrap();
        assert_eq!(consumed, b"first");
        assert_eq!(slicer.buffer, b"second");
    }

    #[test]
    fn slice_to_notfound() {
        let mut slicer = Slicer::new(b"first");
        let result = slicer.slice_to(b'.');
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn slice_to_or_remainder_found() {
        let mut slicer = Slicer::new(b"part\"\n");
        let part = slicer.slice_to_or_remainder(b'"');
        assert_eq!(part, b"part");
        assert_eq!(slicer.buffer, b"\n");
    }

    #[test]
    fn slice_to_or_remainder_notfound() {
        let mut slicer = Slicer::new(b"part");
        let part = slicer.slice_to_or_remainder(b'"');
        assert_eq!(part, b"part");
        assert_eq!(slicer.buffer, b"");
    }

    #[test]
    fn discard() {
        let mut slicer = Slicer::new(b"first.second");
        slicer.discard(b"first.").unwrap();
        assert_eq!(slicer.buffer, b"second");
    }

    #[test]
    fn discard_notfound() {
        let mut slicer = Slicer::new(b"second");
        let result = slicer.discard(b"first");
        assert_eq!(result.is_err(), true);
    }
}
