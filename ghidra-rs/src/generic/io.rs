use std::fmt;
use std::io;

/// A writer that silently discards all output.
///
/// Use this when an API requires a [`fmt::Write`] or [`io::Write`] but you want
/// to suppress all output without null-checking at every call site.
///
/// Mirrors `generic.io.NullWriter` from Ghidra.
pub struct NullWriter;

impl fmt::Write for NullWriter {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        Ok(())
    }
}

impl io::Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as FmtWrite;
    use std::io::Write as IoWrite;

    #[test]
    fn fmt_write_str_discards_output() {
        let mut w = NullWriter;
        assert!(w.write_str("hello").is_ok());
    }

    #[test]
    fn fmt_write_macro_discards_output() {
        let mut w = NullWriter;
        assert!(write!(w, "value={}", 42).is_ok());
    }

    #[test]
    fn io_write_returns_buf_len() {
        let mut w = NullWriter;
        let buf = b"some bytes";
        assert_eq!(w.write(buf).unwrap(), buf.len());
    }

    #[test]
    fn io_write_empty_buf() {
        let mut w = NullWriter;
        assert_eq!(w.write(&[]).unwrap(), 0);
    }

    #[test]
    fn io_flush_succeeds() {
        let mut w = NullWriter;
        assert!(w.flush().is_ok());
    }

    #[test]
    fn io_write_all_succeeds() {
        let mut w = NullWriter;
        assert!(w.write_all(b"discard this").is_ok());
    }
}
