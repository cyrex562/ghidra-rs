use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::mem::MemoryAccessException;

/// Trait providing default implementations for integer reads from a memory buffer.
///
/// This is a mixin trait that extends [`MemBuffer`] and provides convenient methods for
/// reading multi-byte values. All methods use the underlying `get_bytes` implementation.
/// Byte order (endianness) is handled according to the buffer's `is_big_endian()` setting.
pub trait MemBufferMixin: MemBuffer {
    /// Reads the specified number of bytes into a newly allocated buffer.
    ///
    /// # Errors
    /// Returns an error if the requested number of bytes cannot be read at the specified offset.
    fn get_bytes_in_full(&self, offset: i32, len: usize) -> Result<Vec<u8>, MemoryAccessException> {
        let mut buf = vec![0u8; len];
        let bytes_read = self.get_bytes(&mut buf, offset);
        if bytes_read != len {
            return Err(MemoryAccessException::new("Could not read enough bytes"));
        }
        if !self.is_big_endian() {
            buf.reverse();
        }
        Ok(buf)
    }

    /// Reads a 16-bit signed integer (short) from the specified offset.
    ///
    /// Respects the buffer's endianness setting.
    ///
    /// # Errors
    /// Returns an error if 2 bytes cannot be read at the specified offset.
    fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
        let buf = self.get_bytes_in_full(offset, 2)?;
        let bytes = [buf[0], buf[1]];
        Ok(i16::from_be_bytes(bytes))
    }

    /// Reads a 32-bit signed integer from the specified offset.
    ///
    /// Respects the buffer's endianness setting.
    ///
    /// # Errors
    /// Returns an error if 4 bytes cannot be read at the specified offset.
    fn get_int(&self, offset: i32) -> Result<i32, MemoryAccessException> {
        let buf = self.get_bytes_in_full(offset, 4)?;
        let bytes = [buf[0], buf[1], buf[2], buf[3]];
        Ok(i32::from_be_bytes(bytes))
    }

    /// Reads a 64-bit signed integer from the specified offset.
    ///
    /// Respects the buffer's endianness setting.
    ///
    /// # Errors
    /// Returns an error if 8 bytes cannot be read at the specified offset.
    fn get_long(&self, offset: i32) -> Result<i64, MemoryAccessException> {
        let buf = self.get_bytes_in_full(offset, 8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[..8]);
        Ok(i64::from_be_bytes(bytes))
    }

    /// Reads a variable-length big integer from the specified offset.
    ///
    /// The integer is constructed from `size` bytes. If `signed` is true, the bytes are
    /// interpreted as a two's complement signed integer; otherwise, they are interpreted
    /// as an unsigned integer.
    ///
    /// The returned bytes are in big-endian order regardless of the buffer's endianness,
    /// making them suitable for constructing arbitrary-precision integers.
    ///
    /// # Errors
    /// Returns an error if the requested `size` bytes cannot be read at the specified offset.
    fn get_big_integer(
        &self,
        offset: i32,
        size: usize,
        signed: bool,
    ) -> Result<Vec<u8>, MemoryAccessException> {
        let mut buf = vec![0u8; size];
        let bytes_read = self.get_bytes(&mut buf, offset);
        if bytes_read != size {
            return Err(MemoryAccessException::new("Could not read enough bytes"));
        }

        if !self.is_big_endian() {
            buf.reverse();
        }

        if signed {
            Ok(buf)
        } else {
            Ok(buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;

    struct MockMemBuffer {
        data: Vec<u8>,
        big_endian: bool,
    }

    impl MockMemBuffer {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                big_endian: true,
            }
        }

        fn little_endian(data: Vec<u8>) -> Self {
            Self {
                data,
                big_endian: false,
            }
        }
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let start = offset as usize;
            if start >= self.data.len() {
                return 0;
            }
            let available = self.data.len() - start;
            let to_read = std::cmp::min(buf.len(), available);
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            to_read
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    impl MemBufferMixin for MockMemBuffer {}

    #[test]
    fn get_bytes_in_full_reads_full_buffer() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_bytes_in_full(0, 4).unwrap();
        assert_eq!(result, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn get_bytes_in_full_reverses_for_little_endian() {
        let mock = MockMemBuffer::little_endian(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_bytes_in_full(0, 4).unwrap();
        assert_eq!(result, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn get_bytes_in_full_fails_if_not_enough_data() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34]);
        let result = mock.get_bytes_in_full(0, 4);
        assert!(result.is_err());
    }

    #[test]
    fn get_short_big_endian() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34]);
        let result = mock.get_short(0).unwrap();
        assert_eq!(result, 0x1234i16);
    }

    #[test]
    fn get_short_little_endian() {
        let mock = MockMemBuffer::little_endian(vec![0x12, 0x34]);
        let result = mock.get_short(0).unwrap();
        assert_eq!(result, 0x1234i16);
    }

    #[test]
    fn get_int_big_endian() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_int(0).unwrap();
        assert_eq!(result, 0x12345678i32);
    }

    #[test]
    fn get_int_little_endian() {
        let mock = MockMemBuffer::little_endian(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_int(0).unwrap();
        assert_eq!(result, 0x12345678i32);
    }

    #[test]
    fn get_long_big_endian() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        let result = mock.get_long(0).unwrap();
        assert_eq!(result, 0x123456789abcdef0i64);
    }

    #[test]
    fn get_long_little_endian() {
        let mock = MockMemBuffer::little_endian(vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ]);
        let result = mock.get_long(0).unwrap();
        assert_eq!(result, 0x123456789abcdef0i64);
    }

    #[test]
    fn get_big_integer_unsigned() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_big_integer(0, 4, false).unwrap();
        assert_eq!(result, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn get_big_integer_signed() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_big_integer(0, 4, true).unwrap();
        assert_eq!(result, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn get_big_integer_with_offset() {
        let mock = MockMemBuffer::new(vec![0xff, 0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_big_integer(1, 4, false).unwrap();
        assert_eq!(result, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn get_big_integer_little_endian() {
        let mock = MockMemBuffer::little_endian(vec![0x12, 0x34, 0x56, 0x78]);
        let result = mock.get_big_integer(0, 4, false).unwrap();
        assert_eq!(result, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn get_short_fails_if_not_enough_data() {
        let mock = MockMemBuffer::new(vec![0x12]);
        let result = mock.get_short(0);
        assert!(result.is_err());
    }

    #[test]
    fn get_int_fails_if_not_enough_data() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34]);
        let result = mock.get_int(0);
        assert!(result.is_err());
    }

    #[test]
    fn get_long_fails_if_not_enough_data() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34, 0x56]);
        let result = mock.get_long(0);
        assert!(result.is_err());
    }

    #[test]
    fn get_big_integer_fails_if_not_enough_data() {
        let mock = MockMemBuffer::new(vec![0x12, 0x34]);
        let result = mock.get_big_integer(0, 4, false);
        assert!(result.is_err());
    }
}
