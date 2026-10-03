//! Big-endian data converter with MemBuffer support.
//!
//! Port of `ghidra.util.GhidraBigEndianDataConverter`.

use super::big_endian_data_converter::BigEndianDataConverter;
use super::data_converter::DataConverter;
use super::ghidra_data_converter::GhidraDataConverter;

/// Shared singleton, mirroring `GhidraBigEndianDataConverter.INSTANCE` in the original Java source.
pub static INSTANCE: GhidraBigEndianDataConverter = GhidraBigEndianDataConverter;

/// A big-endian data converter that can read directly from a [`MemBuffer`](crate::program::model::lang::sleigh::walker::MemBuffer).
///
/// Extends [`BigEndianDataConverter`] with methods that read from a `MemBuffer`, throwing
/// [`MemoryAccessException`](crate::program::model::mem::MemoryAccessException) if the requested bytes
/// cannot be read. A shared singleton is available via [`INSTANCE`]; prefer it over constructing new instances.
pub struct GhidraBigEndianDataConverter;

impl DataConverter for GhidraBigEndianDataConverter {
    fn is_big_endian(&self) -> bool {
        true
    }

    fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
        BigEndianDataConverter.get_short_at(b, offset)
    }

    fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
        BigEndianDataConverter.get_int_at(b, offset)
    }

    fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
        BigEndianDataConverter.get_long_at(b, offset)
    }

    fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64 {
        BigEndianDataConverter.get_value_at(b, offset, size)
    }

    fn get_big_integer_at(&self, b: &[u8], offset: usize, size: usize, signed: bool) -> i128 {
        BigEndianDataConverter.get_big_integer_at(b, offset, size, signed)
    }

    fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
        BigEndianDataConverter.put_short_at(b, offset, value)
    }

    fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
        BigEndianDataConverter.put_int_at(b, offset, value)
    }

    fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize) {
        BigEndianDataConverter.put_value_at(value, size, b, offset)
    }

    fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128) {
        BigEndianDataConverter.put_big_integer_at(b, offset, size, value)
    }
}

impl GhidraDataConverter for GhidraBigEndianDataConverter {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::sleigh::walker::MemBuffer;
    use crate::program::model::mem::MemoryAccessException;

    /// Fixed byte-array-backed `MemBuffer`, just enough to exercise the `_buf` reads.
    struct FixedMemBuffer {
        bytes: Vec<u8>,
    }

    impl MemBuffer for FixedMemBuffer {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            Address::new(space, 0)
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("offset out of range"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let offset = offset as usize;
            let available = self.bytes.len().saturating_sub(offset);
            let n = buf.len().min(available);
            buf[..n].copy_from_slice(&self.bytes[offset..offset + n]);
            n
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    #[test]
    fn get_short_buf_reads_big_endian() {
        let buf = FixedMemBuffer {
            bytes: vec![0x01, 0x02],
        };
        assert_eq!(INSTANCE.get_short_buf(&buf, 0).unwrap(), 0x0102);
    }

    #[test]
    fn get_short_buf_at_offset() {
        let buf = FixedMemBuffer {
            bytes: vec![0xFF, 0x00, 0x01, 0x02],
        };
        assert_eq!(INSTANCE.get_short_buf(&buf, 2).unwrap(), 0x0102);
    }

    #[test]
    fn get_short_buf_errors_on_short_read() {
        let buf = FixedMemBuffer {
            bytes: vec![0x01],
        };
        assert!(INSTANCE.get_short_buf(&buf, 0).is_err());
    }

    #[test]
    fn get_int_buf_reads_big_endian() {
        let buf = FixedMemBuffer {
            bytes: vec![0x00, 0x00, 0x00, 0x07],
        };
        assert_eq!(INSTANCE.get_int_buf(&buf, 0).unwrap(), 7);
    }

    #[test]
    fn get_int_buf_at_offset() {
        let buf = FixedMemBuffer {
            bytes: vec![0xFF, 0x00, 0x00, 0x00, 0x0A],
        };
        assert_eq!(INSTANCE.get_int_buf(&buf, 1).unwrap(), 10);
    }

    #[test]
    fn get_int_buf_errors_on_short_read() {
        let buf = FixedMemBuffer {
            bytes: vec![0u8; 3],
        };
        assert!(INSTANCE.get_int_buf(&buf, 0).is_err());
    }

    #[test]
    fn get_long_buf_reads_big_endian() {
        let mut bytes = vec![0u8; 8];
        bytes[7] = 1;
        let buf = FixedMemBuffer { bytes };
        assert_eq!(INSTANCE.get_long_buf(&buf, 0).unwrap(), 1);
    }

    #[test]
    fn get_long_buf_at_offset() {
        let buf = FixedMemBuffer {
            bytes: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        };
        assert_eq!(INSTANCE.get_long_buf(&buf, 1).unwrap(), 1);
    }

    #[test]
    fn get_long_buf_errors_on_short_read() {
        let buf = FixedMemBuffer {
            bytes: vec![0u8; 4],
        };
        assert!(INSTANCE.get_long_buf(&buf, 0).is_err());
    }

    #[test]
    fn get_big_integer_buf_unsigned() {
        let buf = FixedMemBuffer {
            bytes: vec![0xFF, 0xFF],
        };
        assert_eq!(
            INSTANCE.get_big_integer_buf(&buf, 0, 2, false).unwrap(),
            0xFFFF
        );
    }

    #[test]
    fn get_big_integer_buf_signed() {
        let buf = FixedMemBuffer {
            bytes: vec![0xFF, 0xFF],
        };
        assert_eq!(
            INSTANCE.get_big_integer_buf(&buf, 0, 2, true).unwrap(),
            -1
        );
    }

    #[test]
    fn get_big_integer_buf_signed_positive() {
        let buf = FixedMemBuffer {
            bytes: vec![0x7F, 0xFF],
        };
        assert_eq!(
            INSTANCE.get_big_integer_buf(&buf, 0, 2, true).unwrap(),
            0x7FFF
        );
    }

    #[test]
    fn get_big_integer_buf_at_offset() {
        let buf = FixedMemBuffer {
            bytes: vec![0xFF, 0xFF, 0xFF, 0xFF],
        };
        assert_eq!(
            INSTANCE.get_big_integer_buf(&buf, 1, 3, true).unwrap(),
            -1
        );
    }

    #[test]
    fn get_big_integer_buf_errors_on_short_read() {
        let buf = FixedMemBuffer {
            bytes: vec![0u8; 2],
        };
        assert!(INSTANCE.get_big_integer_buf(&buf, 0, 4, false).is_err());
    }
}
