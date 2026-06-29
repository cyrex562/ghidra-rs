use flate2::{Compression, write::ZlibEncoder};
use std::io::{self, Write};

/// A deflating output stream that ensures the compressor is finalized on close.
///
/// Wraps a writer with ZLIB-format deflate compression at a configurable
/// level. Mirrors Java's `RemoteDeflaterOutputStream`, which extends
/// `DeflaterOutputStream` and overrides `close()` to call `Deflater.end()` so
/// that the non-default `Deflater` releases its native resources exactly once.
///
/// In Rust this is handled automatically by `Drop`, but the explicit
/// [`close`](Self::close) method is provided for parity and early finalization.
pub struct RemoteDeflaterOutputStream<W: Write> {
    inner: Option<ZlibEncoder<W>>,
}

impl<W: Write> RemoteDeflaterOutputStream<W> {
    /// Creates a new deflating stream writing compressed output to `out`.
    ///
    /// `level` is the ZLIB compression level (0 = no compression, 9 = best
    /// compression), matching Java's `Deflater` level constants.
    pub fn new(out: W, level: u32) -> Self {
        Self {
            inner: Some(ZlibEncoder::new(out, Compression::new(level))),
        }
    }

    /// Finishes the ZLIB stream, flushes all compressed bytes, and closes the
    /// stream. Safe to call more than once; subsequent calls are no-ops.
    ///
    /// Mirrors Java's overridden `close()`, which calls `super.close()` and
    /// then `def.end()` while guarding against double-close via a `closed` flag.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(encoder) = self.inner.take() {
            encoder.finish().map(|_| ())?;
        }
        Ok(())
    }

    /// Finishes compression and returns the underlying writer.
    ///
    /// Consumes `self`; the ZLIB trailer is written before returning.
    pub fn finish(mut self) -> io::Result<W> {
        match self.inner.take() {
            Some(encoder) => encoder.finish(),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream already closed",
            )),
        }
    }
}

impl<W: Write> Write for RemoteDeflaterOutputStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            Some(enc) => enc.write(buf),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream is closed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            Some(enc) => enc.flush(),
            None => Ok(()),
        }
    }
}

impl<W: Write> Drop for RemoteDeflaterOutputStream<W> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn decompress_zlib(data: &[u8]) -> Vec<u8> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let mut decoder = ZlibDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("decompression failed");
        out
    }

    #[test]
    fn test_write_and_finish_produces_valid_zlib() {
        let mut stream = RemoteDeflaterOutputStream::new(Vec::new(), 6);
        stream.write_all(b"hello world").unwrap();
        let compressed = stream.finish().unwrap();
        // ZLIB streams start with a CMF byte; 0x78 is the most common value
        assert!(compressed.len() > 2);
        assert_eq!(compressed[0], 0x78);
        assert_eq!(decompress_zlib(&compressed), b"hello world");
    }

    #[test]
    fn test_close_is_idempotent() {
        let mut stream = RemoteDeflaterOutputStream::new(Vec::new(), 1);
        stream.write_all(b"data").unwrap();
        stream.close().unwrap();
        stream.close().unwrap();
    }

    #[test]
    fn test_write_after_close_returns_error() {
        let mut stream = RemoteDeflaterOutputStream::new(Vec::new(), 9);
        stream.close().unwrap();
        assert!(stream.write_all(b"more data").is_err());
    }

    #[test]
    fn test_level_zero_no_compression_still_valid_zlib() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut stream = RemoteDeflaterOutputStream::new(Vec::new(), 0);
        stream.write_all(data).unwrap();
        let compressed = stream.finish().unwrap();
        assert_eq!(decompress_zlib(&compressed), data);
    }

    #[test]
    fn test_level_nine_best_compression() {
        let data = b"hello world hello world hello world";
        let mut stream = RemoteDeflaterOutputStream::new(Vec::new(), 9);
        stream.write_all(data).unwrap();
        let compressed = stream.finish().unwrap();
        assert_eq!(decompress_zlib(&compressed), data);
    }

    #[test]
    fn test_drop_finalizes_without_panic() {
        let mut stream = RemoteDeflaterOutputStream::new(Cursor::new(Vec::new()), 6);
        stream.write_all(b"drop test").unwrap();
        drop(stream);
    }

    #[test]
    fn test_empty_stream_produces_valid_zlib() {
        let stream = RemoteDeflaterOutputStream::new(Vec::new(), 6);
        let compressed = stream.finish().unwrap();
        assert_eq!(decompress_zlib(&compressed), b"");
    }
}
