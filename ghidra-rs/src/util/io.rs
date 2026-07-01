use sha2::Digest;
use std::io::{self, Read, Write};

/// [`Read`] wrapper that limits itself to a portion of the wrapped stream.
pub struct BoundedInputStream<R: Read> {
    inner: R,
    limit: u64,
    position: u64,
}

impl<R: Read> BoundedInputStream<R> {
    /// Creates a new instance, wrapping `inner` (already positioned to the desired starting
    /// position) and allowing at most `size` bytes to be read from it.
    pub fn new(inner: R, size: u64) -> Self {
        Self {
            inner,
            limit: size,
            position: 0,
        }
    }

    /// Skips up to `n` bytes, limited to the number of bytes remaining within the bound.
    /// Returns the number of bytes actually skipped.
    pub fn skip(&mut self, n: u64) -> io::Result<u64> {
        let bytes_left = self.limit.saturating_sub(self.position);
        let to_skip = bytes_left.min(n);
        let mut limited = (&mut self.inner).take(to_skip);
        let skipped = io::copy(&mut limited, &mut io::sink())?;
        self.position += skipped;
        Ok(skipped)
    }
}

impl<R: Read> Read for BoundedInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.limit {
            return Ok(0);
        }
        let max_to_read = (self.limit - self.position).min(buf.len() as u64) as usize;
        let bytes_read = self.inner.read(&mut buf[..max_to_read])?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

pub struct NullOutputStream;

impl Write for NullOutputStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct HashingOutputStream<W: Write, D: Digest> {
    inner: W,
    digest: D,
}

impl<W: Write, D: Digest> HashingOutputStream<W, D> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            digest: D::new(),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        self.digest.finalize().to_vec()
    }
}

impl<W: Write, D: Digest> Write for HashingOutputStream<W, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.digest.update(buf);
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_bounded_input_stream() {
        let data = vec![1, 2, 3, 4, 5];
        let mut bounded = BoundedInputStream::new(Cursor::new(data), 3);
        let mut buf = Vec::new();
        bounded.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 3]);
    }

    #[test]
    fn test_bounded_input_stream_single_byte_reads() {
        let data = vec![10, 20, 30];
        let mut bounded = BoundedInputStream::new(Cursor::new(data), 2);
        let mut byte = [0u8; 1];
        assert_eq!(bounded.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 10);
        assert_eq!(bounded.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 20);
        assert_eq!(bounded.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn test_bounded_input_stream_skip_clamped_to_limit() {
        let data = vec![1, 2, 3, 4, 5];
        let mut bounded = BoundedInputStream::new(Cursor::new(data), 3);
        assert_eq!(bounded.skip(10).unwrap(), 3);
        let mut buf = Vec::new();
        assert_eq!(bounded.read_to_end(&mut buf).unwrap(), 0);
    }

    #[test]
    fn test_bounded_input_stream_skip_then_read() {
        let data = vec![1, 2, 3, 4, 5];
        let mut bounded = BoundedInputStream::new(Cursor::new(data), 4);
        assert_eq!(bounded.skip(2).unwrap(), 2);
        let mut buf = Vec::new();
        bounded.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, vec![3, 4]);
    }

    #[test]
    fn test_hashing_output_stream() {
        let mut out = Vec::new();
        let mut hashing = HashingOutputStream::<_, sha2::Sha256>::new(&mut out);
        hashing.write_all(b"hello").unwrap();
        let digest = hashing.finalize();
        assert_eq!(out, b"hello");
        assert!(digest.len() > 0);
    }
}
