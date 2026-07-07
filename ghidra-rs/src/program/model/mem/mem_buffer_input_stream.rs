use std::io;
use std::io::Read;

use crate::program::model::lang::sleigh::walker::MemBuffer;

/// Adapter between [`MemBuffer`] and [`Read`] streams.
pub struct MemBufferInputStream<'a> {
    membuf: &'a dyn MemBuffer,
    current_position: i32,
    max_position: i64, // exclusive
}

impl<'a> MemBufferInputStream<'a> {
    /// Creates a new instance, starting at offset 0 of the membuffer, limited to the
    /// first 2Gb of the membuffer.
    pub fn new(membuf: &'a dyn MemBuffer) -> Self {
        Self::with_range(membuf, 0, i32::MAX)
    }

    /// Creates a new instance, starting at `initial_position`, limited to `length` bytes.
    ///
    /// The sum of `initial_position` and `length` must not exceed `i32::MAX + 1`.
    ///
    /// # Panics
    ///
    /// Panics if `initial_position` or `length` is negative, or if their sum exceeds
    /// `i32::MAX + 1`.
    pub fn with_range(membuf: &'a dyn MemBuffer, initial_position: i32, length: i32) -> Self {
        let max_position = initial_position as i64 + length as i64;
        assert!(
            initial_position >= 0 && length >= 0 && max_position <= i32::MAX as i64 + 1,
            "illegal argument: initial_position={initial_position}, length={length}"
        );
        Self {
            membuf,
            current_position: initial_position,
            max_position,
        }
    }

    /// Closes this stream; subsequent reads report end-of-stream.
    pub fn close(&mut self) {
        self.max_position = 0;
    }

    /// Returns the number of bytes that can be read before reaching the end of the stream.
    pub fn available(&self) -> i32 {
        if self.current_position >= 0 && (self.current_position as i64) < self.max_position {
            (self.max_position - self.current_position as i64) as i32
        } else {
            0
        }
    }
}

impl<'a> Read for MemBufferInputStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.current_position < 0 || (self.current_position as i64) >= self.max_position {
            return Ok(0);
        }
        match self.membuf.get_byte(self.current_position) {
            Ok(byte) => {
                buf[0] = byte;
                self.current_position += 1;
                Ok(1)
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
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
        fn get_address(&self) -> Address {
            todo!()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 || offset as usize >= self.data.len() {
                return 0;
            }
            let start = offset as usize;
            let to_read = (self.data.len() - start).min(buf.len());
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            to_read
        }

        fn is_big_endian(&self) -> bool {
            false
        }
    }

    #[test]
    fn reads_single_bytes_sequentially() {
        let mock = MockMemBuffer::new(vec![0x41, 0x42, 0x43]);
        let mut stream = MemBufferInputStream::new(&mock);

        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x41);
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x42);
    }

    #[test]
    fn read_past_end_of_membuffer_errors() {
        let mock = MockMemBuffer::new(vec![0x41]);
        let mut stream = MemBufferInputStream::new(&mock);

        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        // MemBuffer has no more bytes, so the underlying get_byte errors -> io::Error.
        assert!(stream.read(&mut buf).is_err());
    }

    #[test]
    fn with_range_limits_stream_length() {
        let mock = MockMemBuffer::new(vec![0x10, 0x20, 0x30, 0x40, 0x50]);
        let mut stream = MemBufferInputStream::with_range(&mock, 1, 2);

        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x20);
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x30);
        // length exhausted -> EOF (0), even though the membuffer has more bytes.
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn available_reflects_remaining_length() {
        let mock = MockMemBuffer::new(vec![0x10, 0x20, 0x30, 0x40, 0x50]);
        let mut stream = MemBufferInputStream::with_range(&mock, 0, 3);

        assert_eq!(stream.available(), 3);
        let mut buf = [0u8; 1];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.available(), 2);
    }

    #[test]
    fn close_makes_stream_report_eof() {
        let mock = MockMemBuffer::new(vec![0x10, 0x20, 0x30]);
        let mut stream = MemBufferInputStream::new(&mock);

        stream.close();
        assert_eq!(stream.available(), 0);
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn empty_buffer_read_returns_zero_without_advancing() {
        let mock = MockMemBuffer::new(vec![0x10, 0x20]);
        let mut stream = MemBufferInputStream::new(&mock);

        assert_eq!(stream.read(&mut []).unwrap(), 0);
        assert_eq!(stream.available(), i32::MAX);
    }

    #[test]
    #[should_panic]
    fn negative_initial_position_panics() {
        let mock = MockMemBuffer::new(vec![0x10]);
        MemBufferInputStream::with_range(&mock, -1, 1);
    }

    #[test]
    #[should_panic]
    fn negative_length_panics() {
        let mock = MockMemBuffer::new(vec![0x10]);
        MemBufferInputStream::with_range(&mock, 0, -1);
    }

    #[test]
    #[should_panic]
    fn overflowing_range_panics() {
        let mock = MockMemBuffer::new(vec![0x10]);
        MemBufferInputStream::with_range(&mock, 2, i32::MAX);
    }

    #[test]
    fn max_range_at_int_max_plus_one_is_allowed() {
        let mock = MockMemBuffer::new(vec![0x10]);
        let stream = MemBufferInputStream::with_range(&mock, 1, i32::MAX);
        assert_eq!(stream.available(), i32::MAX);
    }
}
