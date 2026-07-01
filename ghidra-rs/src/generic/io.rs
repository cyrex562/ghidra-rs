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

/// A print writer that silently discards all output.
///
/// Mirrors `generic.io.NullPrintWriter` from Ghidra. Provides an `Option`-aware
/// constructor via [`dummy_if_null`] for ergonomic handling of nullable writer
/// parameters without null-checks at call sites.
pub struct NullPrintWriter(NullWriter);

impl NullPrintWriter {
    /// Creates a new null print writer.
    pub fn new() -> Self {
        Self(NullWriter)
    }

    /// Returns the provided writer if `Some`, otherwise creates a new `NullPrintWriter`.
    ///
    /// Mirrors the Java static method `dummyIfNull(PrintWriter pw)`.
    pub fn dummy_if_null<W: Default>(writer: Option<W>) -> DummyOrWriter<W> {
        match writer {
            Some(w) => DummyOrWriter::Writer(w),
            None => DummyOrWriter::Dummy(Self::new()),
        }
    }
}

impl Default for NullPrintWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for NullPrintWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_str(s)
    }
}

impl io::Write for NullPrintWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// An enum that holds either a user-provided writer or a `NullPrintWriter`.
///
/// Returned by [`NullPrintWriter::dummy_if_null`] to provide type-safe
/// null-coalescing behavior.
pub enum DummyOrWriter<W> {
    Writer(W),
    Dummy(NullPrintWriter),
}

impl<W: fmt::Write> fmt::Write for DummyOrWriter<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self {
            DummyOrWriter::Writer(w) => w.write_str(s),
            DummyOrWriter::Dummy(d) => d.write_str(s),
        }
    }
}

impl<W: io::Write> io::Write for DummyOrWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            DummyOrWriter::Writer(w) => w.write(buf),
            DummyOrWriter::Dummy(d) => d.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            DummyOrWriter::Writer(w) => w.flush(),
            DummyOrWriter::Dummy(d) => d.flush(),
        }
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

    #[test]
    fn null_print_writer_new() {
        let _pw = NullPrintWriter::new();
    }

    #[test]
    fn null_print_writer_default() {
        let _pw = NullPrintWriter::default();
    }

    #[test]
    fn null_print_writer_fmt_write() {
        let mut pw = NullPrintWriter::new();
        assert!(pw.write_str("test").is_ok());
        assert!(write!(pw, "value={}", 123).is_ok());
    }

    #[test]
    fn null_print_writer_io_write() {
        let mut pw = NullPrintWriter::new();
        assert_eq!(pw.write(b"bytes").unwrap(), 5);
        assert!(pw.write_all(b"more").is_ok());
        assert!(pw.flush().is_ok());
    }

    #[test]
    fn dummy_if_null_with_some() {
        let vec = Vec::new();
        let mut dw = NullPrintWriter::dummy_if_null::<std::io::Cursor<Vec<u8>>>(Some(
            std::io::Cursor::new(vec),
        ));
        let buf = b"test";
        if let DummyOrWriter::Writer(ref mut w) = dw {
            assert_eq!(w.write(buf).unwrap(), 4);
        } else {
            panic!("expected Writer variant");
        }
    }

    #[test]
    fn dummy_if_null_with_none() {
        let dw = NullPrintWriter::dummy_if_null::<std::io::Cursor<Vec<u8>>>(None);
        if let DummyOrWriter::Dummy(_) = dw {
            // expected
        } else {
            panic!("expected Dummy variant");
        }
    }

    #[test]
    fn dummy_or_writer_write_with_writer() {
        let vec = Vec::new();
        let cursor = std::io::Cursor::new(vec);
        let mut dw = DummyOrWriter::Writer(cursor);
        assert_eq!(dw.write(b"test").unwrap(), 4);
    }

    #[test]
    fn dummy_or_writer_write_with_dummy() {
        let mut dw = DummyOrWriter::<std::io::Cursor<Vec<u8>>>::Dummy(NullPrintWriter::new());
        assert_eq!(dw.write(b"discarded").unwrap(), 9);
    }

    #[test]
    fn dummy_or_writer_flush_with_writer() {
        let vec = Vec::new();
        let cursor = std::io::Cursor::new(vec);
        let mut dw = DummyOrWriter::Writer(cursor);
        assert!(dw.flush().is_ok());
    }

    #[test]
    fn dummy_or_writer_flush_with_dummy() {
        let mut dw = DummyOrWriter::<std::io::Cursor<Vec<u8>>>::Dummy(NullPrintWriter::new());
        assert!(dw.flush().is_ok());
    }

    #[test]
    fn dummy_or_writer_fmt_write_with_writer() {
        let mut buf = String::new();
        let mut dw = DummyOrWriter::Writer(&mut buf);
        assert!(dw.write_str("hello").is_ok());
        assert_eq!(buf, "hello");
    }

    #[test]
    fn dummy_or_writer_fmt_write_with_dummy() {
        let mut dw = DummyOrWriter::<String>::Dummy(NullPrintWriter::new());
        assert!(dw.write_str("ignored").is_ok());
    }
}
