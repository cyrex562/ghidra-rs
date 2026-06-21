use std::io;

/// Trait mirroring `org.catacombae.io.ReadableRandomAccessStream`.
///
/// Provides sequential read access and length query over a random-access
/// source. Implementations may wrap files, in-memory buffers, or any
/// seekable byte source.
pub trait ReadableRandomAccessStream: Send {
    /// Reads up to `buf.len()` bytes into `buf`.
    ///
    /// Returns `Ok(0)` to signal end-of-stream (equivalent to Java's -1 return).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Returns the total length of the underlying data source in bytes.
    fn length(&self) -> u64;
}

/// Wraps a [`ReadableRandomAccessStream`] as a standard [`io::Read`].
///
/// Mirrors `mobiledevices.dmg.reader.DmgInputStream`. The sole purpose is to
/// adapt a random-access source (which may also support seeking) so it can be
/// consumed by APIs expecting a conventional input stream.
pub struct DmgInputStream {
    stream: Box<dyn ReadableRandomAccessStream>,
}

impl DmgInputStream {
    /// Creates a new `DmgInputStream` wrapping `stream`.
    pub fn new(stream: Box<dyn ReadableRandomAccessStream>) -> Self {
        Self { stream }
    }

    /// Returns the total length of the underlying stream in bytes.
    ///
    /// Mirrors `DmgInputStream.getLength()`.
    pub fn get_length(&self) -> u64 {
        self.stream.length()
    }
}

impl io::Read for DmgInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct FakeStream {
        data: Vec<u8>,
        pos: usize,
    }

    impl FakeStream {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl ReadableRandomAccessStream for FakeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let available = self.data.len() - self.pos;
            let n = buf.len().min(available);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }

        fn length(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn get_length_returns_stream_length() {
        let stream = Box::new(FakeStream::new(vec![1, 2, 3, 4, 5]));
        let s = DmgInputStream::new(stream);
        assert_eq!(s.get_length(), 5);
    }

    #[test]
    fn read_single_byte() {
        let stream = Box::new(FakeStream::new(vec![0xAB]));
        let mut s = DmgInputStream::new(stream);
        let mut buf = [0u8; 1];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xAB);
    }

    #[test]
    fn read_full_buffer() {
        let data = vec![1u8, 2, 3, 4, 5];
        let stream = Box::new(FakeStream::new(data.clone()));
        let mut s = DmgInputStream::new(stream);
        let mut buf = vec![0u8; 5];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, data);
    }

    #[test]
    fn read_partial_buffer() {
        let stream = Box::new(FakeStream::new(vec![10, 20, 30]));
        let mut s = DmgInputStream::new(stream);
        let mut buf = [0u8; 2];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf, &[10, 20]);
    }

    #[test]
    fn read_buffer_with_offset_via_read_exact() {
        let data = vec![7u8, 8, 9];
        let stream = Box::new(FakeStream::new(data));
        let mut s = DmgInputStream::new(stream);
        let mut buf = [0u8; 5];
        let n = s.read(&mut buf[2..]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, &[0, 0, 7, 8, 9]);
    }

    #[test]
    fn read_at_eof_returns_zero() {
        let stream = Box::new(FakeStream::new(vec![]));
        let mut s = DmgInputStream::new(stream);
        let mut buf = [0u8; 4];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn sequential_reads_consume_stream() {
        let stream = Box::new(FakeStream::new(vec![1, 2, 3, 4]));
        let mut s = DmgInputStream::new(stream);
        let mut buf = [0u8; 2];

        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf, &[1, 2]);

        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf, &[3, 4]);

        let n = s.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn get_length_on_empty_stream() {
        let stream = Box::new(FakeStream::new(vec![]));
        let s = DmgInputStream::new(stream);
        assert_eq!(s.get_length(), 0);
    }
}
