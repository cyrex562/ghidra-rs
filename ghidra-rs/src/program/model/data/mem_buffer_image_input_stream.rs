use crate::program::model::lang::sleigh::walker::MemBuffer;

/// ImageInputStream for reading images that wraps a MemBuffer to get the bytes.
/// Adds a method to find out how many bytes were read by the imageReader to read the image.
pub struct MemBufferImageInputStream<'a> {
    buf: &'a dyn MemBuffer,
    stream_pos: u64,
}

impl<'a> MemBufferImageInputStream<'a> {
    /// Constructs a new MemBufferImageInputStream that wraps the given MemBuffer.
    pub fn new(buf: &'a dyn MemBuffer) -> Self {
        Self {
            buf,
            stream_pos: 0,
        }
    }

    /// Returns the number of bytes consumed (read) from the stream.
    pub fn get_consumed_length(&self) -> usize {
        self.stream_pos as usize
    }

    /// Reads a single byte from the buffer at the current stream position.
    /// Returns -1 if the read fails due to a memory access exception.
    pub fn read(&mut self) -> i32 {
        match self.buf.get_byte(self.stream_pos as i32) {
            Ok(byte) => {
                self.stream_pos += 1;
                (byte as i32) & 0xff
            }
            Err(_) => -1,
        }
    }

    /// Reads up to `len` bytes from the buffer into the provided slice.
    /// Returns the number of bytes actually read.
    pub fn read_into(&mut self, b: &mut [u8]) -> usize {
        self.read_range(b, 0, b.len())
    }

    /// Reads up to `len` bytes from the buffer into the provided slice at offset `off`.
    /// Returns the number of bytes actually read.
    pub fn read_range(&mut self, b: &mut [u8], off: usize, len: usize) -> usize {
        for i in 0..len {
            let value = self.read();
            if value < 0 {
                return i;
            }
            if off + i < b.len() {
                b[off + i] = value as u8;
            }
        }
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::mem::MemoryAccessException;

    struct MockMemBuffer {
        data: Vec<u8>,
    }

    impl MockMemBuffer {
        fn new(data: Vec<u8>) -> Self {
            Self { data }
        }
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            todo!()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            if offset < 0 || offset >= self.data.len() as i32 {
                Err(MemoryAccessException::new("out of bounds"))
            } else {
                Ok(self.data[offset as usize])
            }
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 || offset >= self.data.len() as i32 {
                return 0;
            }
            let start = offset as usize;
            let available = self.data.len() - start;
            let to_read = std::cmp::min(available, buf.len());
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            to_read
        }

        fn is_big_endian(&self) -> bool {
            false
        }
    }

    #[test]
    fn read_single_byte() {
        let mock = MockMemBuffer::new(vec![0x42, 0x43, 0x44]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        assert_eq!(stream.read(), 0x42);
        assert_eq!(stream.get_consumed_length(), 1);
    }

    #[test]
    fn read_multiple_bytes_sequentially() {
        let mock = MockMemBuffer::new(vec![0x42, 0x43, 0x44, 0x45]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        assert_eq!(stream.read(), 0x42);
        assert_eq!(stream.read(), 0x43);
        assert_eq!(stream.read(), 0x44);
        assert_eq!(stream.get_consumed_length(), 3);
    }

    #[test]
    fn read_past_end_returns_negative_one() {
        let mock = MockMemBuffer::new(vec![0x42]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        assert_eq!(stream.read(), 0x42);
        assert_eq!(stream.read(), -1);
        assert_eq!(stream.get_consumed_length(), 1);
    }

    #[test]
    fn read_into_buffer() {
        let mock = MockMemBuffer::new(vec![0x42, 0x43, 0x44, 0x45]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        let mut buf = [0u8; 4];
        let bytes_read = stream.read_into(&mut buf);

        assert_eq!(bytes_read, 4);
        assert_eq!(&buf, &[0x42, 0x43, 0x44, 0x45]);
        assert_eq!(stream.get_consumed_length(), 4);
    }

    #[test]
    fn read_into_buffer_with_offset() {
        let mock = MockMemBuffer::new(vec![0x42, 0x43, 0x44, 0x45]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        let mut buf = [0u8; 6];
        let bytes_read = stream.read_range(&mut buf, 1, 3);

        assert_eq!(bytes_read, 3);
        assert_eq!(buf[0], 0);
        assert_eq!(&buf[1..4], &[0x42, 0x43, 0x44]);
        assert_eq!(stream.get_consumed_length(), 3);
    }

    #[test]
    fn read_into_buffer_partial() {
        let mock = MockMemBuffer::new(vec![0x42, 0x43]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        let mut buf = [0u8; 4];
        let bytes_read = stream.read_into(&mut buf);

        assert_eq!(bytes_read, 2);
        assert_eq!(&buf[..2], &[0x42, 0x43]);
        assert_eq!(stream.get_consumed_length(), 2);
    }

    #[test]
    fn read_returns_unsigned_byte() {
        let mock = MockMemBuffer::new(vec![0xff]);
        let mut stream = MemBufferImageInputStream::new(&mock);

        let value = stream.read();
        assert_eq!(value, 0xff);
    }
}
