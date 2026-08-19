use std::io;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::model::lang::sleigh::walker::MemBuffer;

/// A [`ByteProvider`] backed by a [`MemBuffer`].
///
/// Mirrors `ghidra.app.util.bin.MemBufferByteProvider` from the original Ghidra
/// source. The buffer's actual length is unknown, so `length()` reports
/// `i32::MAX` as the maximum possible length, matching the Java behaviour.
pub struct MemBufferByteProvider<'a> {
    buffer: &'a dyn MemBuffer,
}

impl<'a> MemBufferByteProvider<'a> {
    /// Creates a new provider backed by `buffer`.
    pub fn new(buffer: &'a dyn MemBuffer) -> Self {
        MemBufferByteProvider { buffer }
    }
}

impl<'a> ByteProvider for MemBufferByteProvider<'a> {
    fn length(&mut self) -> io::Result<u64> {
        Ok(i32::MAX as u64)
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        if index > i32::MAX as u64 {
            return false;
        }
        self.buffer.get_byte(index as i32).is_ok()
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        if index > i32::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "index out of range"));
        }
        self.buffer
            .get_byte(index as i32)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "index out of range"))
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let last = index as i128 + length as i128 - 1;
        if last > i32::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "index/length of range"));
        }
        let mut bytes = vec![0u8; length];
        if self.buffer.get_bytes(&mut bytes, index as i32) != length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "index/length of range"));
        }
        Ok(bytes)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MemBufferByteProvider does not support writes",
        ))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MemBufferByteProvider does not support writes",
        ))
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
            MockMemBuffer { data }
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
    fn length_is_i32_max() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        assert_eq!(p.length().unwrap(), i32::MAX as u64);
    }

    #[test]
    fn is_valid_index_true_within_buffer() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        assert!(p.is_valid_index(0));
        assert!(p.is_valid_index(2));
    }

    #[test]
    fn is_valid_index_false_past_buffer() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        assert!(!p.is_valid_index(3));
    }

    #[test]
    fn is_valid_index_false_beyond_i32_max() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        assert!(!p.is_valid_index(i32::MAX as u64 + 1));
    }

    #[test]
    fn read_byte_returns_value() {
        let mock = MockMemBuffer::new(vec![10, 20, 30]);
        let mut p = MemBufferByteProvider::new(&mock);
        assert_eq!(p.read_byte(0).unwrap(), 10);
        assert_eq!(p.read_byte(2).unwrap(), 30);
    }

    #[test]
    fn read_byte_out_of_buffer_errors() {
        let mock = MockMemBuffer::new(vec![10]);
        let mut p = MemBufferByteProvider::new(&mock);
        let err = p.read_byte(5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_byte_beyond_i32_max_errors() {
        let mock = MockMemBuffer::new(vec![10]);
        let mut p = MemBufferByteProvider::new(&mock);
        let err = p.read_byte(i32::MAX as u64 + 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_bytes_returns_slice() {
        let mock = MockMemBuffer::new(vec![1, 2, 3, 4, 5]);
        let mut p = MemBufferByteProvider::new(&mock);
        assert_eq!(p.read_bytes(1, 3).unwrap(), vec![2, 3, 4]);
    }

    #[test]
    fn read_bytes_short_read_errors() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        let err = p.read_bytes(1, 5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_bytes_beyond_i32_max_errors() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        let err = p.read_bytes(i32::MAX as u64, 2).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn write_byte_unsupported() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        let err = p.write_byte(0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn write_bytes_unsupported() {
        let mock = MockMemBuffer::new(vec![1, 2, 3]);
        let mut p = MemBufferByteProvider::new(&mock);
        let err = p.write_bytes(0, &[1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
