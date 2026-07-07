use std::io;

/// Default buffer size for internal buffering.
///
/// Mirrors `CartV1StreamProcessor.DEFAULT_BUFFER_SIZE`.
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Trait for buffered CaRT v1 stream processors.
///
/// Implementors must provide chunk-state accessors and `read_next_chunk`.
/// The default method implementations handle the buffered-read protocol
/// shared by all CaRT v1 stream processors.
///
/// Mirrors `ghidra.file.formats.cart.CartV1StreamProcessor`.
pub trait CartV1StreamProcessor {
    /// Returns the current buffered chunk, if any.
    fn current_chunk(&self) -> Option<&[u8]>;

    /// Returns the current read position within [`current_chunk`].
    fn chunk_pos(&self) -> usize;

    /// Advances the chunk position by `n` bytes.
    fn advance_chunk_pos(&mut self, n: usize);

    /// Fetches and processes the next chunk from the underlying stream.
    ///
    /// Returns `true` if data is now available, `false` at EOF.
    fn read_next_chunk(&mut self) -> io::Result<bool>;

    /// Returns the next byte as an unsigned value, or `None` at EOF.
    ///
    /// Mirrors `CartV1StreamProcessor.read()`, mapping the Java `-1` EOF
    /// sentinel to `None`.
    fn read_byte(&mut self) -> io::Result<Option<u8>> {
        if !self.ensure_chunk_available()? {
            return Ok(None);
        }
        let pos = self.chunk_pos();
        let b = self.current_chunk().unwrap()[pos];
        self.advance_chunk_pos(1);
        Ok(Some(b))
    }

    /// Copies up to `len` bytes from the current chunk into `buf[off..]`.
    ///
    /// Returns the number of bytes copied, or `0` at EOF.
    /// Mirrors `CartV1StreamProcessor.read(byte[], int, int)`.
    fn read_buffered(&mut self, buf: &mut [u8], off: usize, len: usize) -> io::Result<usize> {
        if !self.ensure_chunk_available()? {
            return Ok(0);
        }
        let pos = self.chunk_pos();
        let to_copy = {
            let chunk = self.current_chunk().unwrap();
            let bytes_avail = chunk.len() - pos;
            let to_copy = len.min(bytes_avail);
            buf[off..off + to_copy].copy_from_slice(&chunk[pos..pos + to_copy]);
            to_copy
        };
        self.advance_chunk_pos(to_copy);
        Ok(to_copy)
    }

    /// Returns `true` if a non-exhausted chunk is available, fetching the
    /// next one via `read_next_chunk` if necessary.
    fn ensure_chunk_available(&mut self) -> io::Result<bool> {
        let needs_chunk = match self.current_chunk() {
            None => true,
            Some(chunk) => self.chunk_pos() >= chunk.len(),
        };
        if needs_chunk {
            self.read_next_chunk()
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestProcessor {
        data: Vec<u8>,
        read_pos: usize,
        chunk: Option<Vec<u8>>,
        pos: usize,
    }

    impl TestProcessor {
        fn new(data: Vec<u8>) -> Self {
            Self { data, read_pos: 0, chunk: None, pos: 0 }
        }
    }

    impl CartV1StreamProcessor for TestProcessor {
        fn current_chunk(&self) -> Option<&[u8]> {
            self.chunk.as_deref()
        }

        fn chunk_pos(&self) -> usize {
            self.pos
        }

        fn advance_chunk_pos(&mut self, n: usize) {
            self.pos += n;
        }

        fn read_next_chunk(&mut self) -> io::Result<bool> {
            if self.read_pos >= self.data.len() {
                self.chunk = None;
                return Ok(false);
            }
            let end = (self.read_pos + DEFAULT_BUFFER_SIZE).min(self.data.len());
            self.chunk = Some(self.data[self.read_pos..end].to_vec());
            self.pos = 0;
            self.read_pos = end;
            Ok(self.chunk.as_ref().map_or(false, |c| !c.is_empty()))
        }
    }

    #[test]
    fn read_single_byte_sequential() {
        let mut p = TestProcessor::new(vec![0x41, 0x42, 0x43]);
        assert_eq!(p.read_byte().unwrap(), Some(0x41));
        assert_eq!(p.read_byte().unwrap(), Some(0x42));
        assert_eq!(p.read_byte().unwrap(), Some(0x43));
        assert_eq!(p.read_byte().unwrap(), None);
    }

    #[test]
    fn read_buffered_partial() {
        let mut p = TestProcessor::new(vec![1, 2, 3, 4, 5]);
        let mut buf = [0u8; 10];
        let n = p.read_buffered(&mut buf, 0, 3).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);
    }

    #[test]
    fn read_buffered_more_than_available() {
        let mut p = TestProcessor::new(vec![7, 8, 9]);
        let mut buf = [0u8; 100];
        let n = p.read_buffered(&mut buf, 0, 100).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &[7, 8, 9]);
    }

    #[test]
    fn read_buffered_with_offset() {
        let mut p = TestProcessor::new(vec![10, 20, 30]);
        let mut buf = [0u8; 5];
        let n = p.read_buffered(&mut buf, 2, 3).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[2..5], &[10, 20, 30]);
    }

    #[test]
    fn eof_read_byte_returns_none() {
        let mut p = TestProcessor::new(vec![]);
        assert_eq!(p.read_byte().unwrap(), None);
    }

    #[test]
    fn eof_read_buffered_returns_zero() {
        let mut p = TestProcessor::new(vec![]);
        let mut buf = [0u8; 4];
        assert_eq!(p.read_buffered(&mut buf, 0, 4).unwrap(), 0);
    }

    #[test]
    fn default_buffer_size_is_64k() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 64 * 1024);
    }

    #[test]
    fn unsigned_high_bytes_preserved() {
        let mut p = TestProcessor::new(vec![0x00, 0x7F, 0x80, 0xFF]);
        assert_eq!(p.read_byte().unwrap(), Some(0x00));
        assert_eq!(p.read_byte().unwrap(), Some(0x7F));
        assert_eq!(p.read_byte().unwrap(), Some(0x80));
        assert_eq!(p.read_byte().unwrap(), Some(0xFF));
    }

    #[test]
    fn sequential_reads_advance_position() {
        let mut p = TestProcessor::new(vec![1, 2, 3, 4, 5, 6]);
        let mut buf = [0u8; 6];
        let n1 = p.read_buffered(&mut buf, 0, 3).unwrap();
        let n2 = p.read_buffered(&mut buf, 3, 3).unwrap();
        assert_eq!(n1, 3);
        assert_eq!(n2, 3);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
    }
}
