use crate::program::model::mem::MemBuffer;
use crate::program::model::mem::MemoryAccessException;

/// Trait providing default implementations for integer reads from a memory buffer.
///
/// This is a mixin trait that extends [`MemBuffer`] and provides convenient methods for
/// reading multi-byte values. All methods use the underlying `get_bytes` implementation.
/// Byte order (endianness) is handled according to the buffer's `is_big_endian()` setting.
/// Extension trait for reads that are not part of [`MemBuffer`] itself.
///
/// Java splits `MemBuffer` (the interface) from `MemBufferMixin` (default bodies for the derived
/// reads). The port cannot: nearly every caller here holds a `&dyn MemBuffer`, and a trait object
/// cannot reach methods on a separate extension trait -- `get_int` alone has 96 call sites. So
/// the derived reads are defaulted on [`MemBuffer`] directly and this trait keeps only what is
/// genuinely additional. Duplicating them here as well produced `E0034: multiple applicable
/// items in scope` at every call site that had both traits imported.
pub trait MemBufferMixin: MemBuffer {
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
        // Little-endian: least-significant byte first, so [0x12, 0x34] -> 0x3412.
        assert_eq!(result, 0x3412i16);
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
        // Little-endian: [0x12, 0x34, 0x56, 0x78] -> 0x78563412.
        assert_eq!(result, 0x78563412i32);
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
        // Little-endian: byte order reversed -> 0xf0debc9a78563412.
        assert_eq!(result, 0xf0debc9a78563412u64 as i64);
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
