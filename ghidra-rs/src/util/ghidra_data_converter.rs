//! Port of `ghidra.util.GhidraDataConverter`.
//!
//! Extends [`DataConverter`] with overloads that read directly from a [`MemBuffer`] instead of
//! a raw byte slice, throwing [`MemoryAccessException`] if the requested bytes cannot be read.
//! Java overloads `getShort`/`getInt`/`getLong`/`getBigInteger` on parameter type; Rust has no
//! method overloading, so each is suffixed `_buf` here to distinguish it from the byte-slice
//! version inherited from `DataConverter`.
//!
//! In the Java source, `GhidraBigEndianDataConverter` and `GhidraLittleEndianDataConverter` are
//! the only two implementors, and both give these methods identical bodies (read the requested
//! number of bytes from the buffer, then delegate to the `DataConverter` byte-array method of
//! the same size). That logic is lifted into default trait methods here so implementors get it
//! for free, mirroring how [`DataConverter`]'s default methods are structured.
//!
//! The Java interface also declares a static factory, `getInstance(boolean)`, that dispatches to
//! the `GhidraBigEndianDataConverter` / `GhidraLittleEndianDataConverter` singletons; those types
//! are not yet ported (see `PORT_MANIFEST.tsv`), so — matching the convention set by
//! `DataConverter::getInstance` — that factory is deferred until they land rather than stubbed
//! out here.

use super::data_converter::DataConverter;
use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::mem::MemoryAccessException;

/// Converts Java-style numeric types to and from their raw form as read from a [`MemBuffer`].
pub trait GhidraDataConverter: DataConverter {
    /// Reads a short value from `buf` at `offset`.
    ///
    /// # Errors
    /// Returns an error if 2 bytes cannot be read at the specified offset.
    fn get_short_buf(&self, buf: &dyn MemBuffer, offset: i32) -> Result<i16, MemoryAccessException> {
        let mut bytes = [0u8; 2];
        if buf.get_bytes(&mut bytes, offset) != 2 {
            return Err(MemoryAccessException::default());
        }
        Ok(self.get_short_at(&bytes, 0))
    }

    /// Reads an int value from `buf` at `offset`.
    ///
    /// # Errors
    /// Returns an error if 4 bytes cannot be read at the specified offset.
    fn get_int_buf(&self, buf: &dyn MemBuffer, offset: i32) -> Result<i32, MemoryAccessException> {
        let mut bytes = [0u8; 4];
        if buf.get_bytes(&mut bytes, offset) != 4 {
            return Err(MemoryAccessException::default());
        }
        Ok(self.get_int_at(&bytes, 0))
    }

    /// Reads a long value from `buf` at `offset`.
    ///
    /// # Errors
    /// Returns an error if 8 bytes cannot be read at the specified offset.
    fn get_long_buf(&self, buf: &dyn MemBuffer, offset: i32) -> Result<i64, MemoryAccessException> {
        let mut bytes = [0u8; 8];
        if buf.get_bytes(&mut bytes, offset) != 8 {
            return Err(MemoryAccessException::default());
        }
        Ok(self.get_long_at(&bytes, 0))
    }

    /// Reads a `size`-byte value from `buf` at `offset`, treating it as signed or unsigned.
    ///
    /// # Errors
    /// Returns an error if `size` bytes cannot be read at the specified offset.
    fn get_big_integer_buf(
        &self,
        buf: &dyn MemBuffer,
        offset: i32,
        size: i32,
        signed: bool,
    ) -> Result<i128, MemoryAccessException> {
        let size = size as usize;
        let mut bytes = vec![0u8; size];
        if buf.get_bytes(&mut bytes, offset) != size {
            return Err(MemoryAccessException::default());
        }
        Ok(self.get_big_integer(&bytes, size, signed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    /// Minimal big-endian mock, enough to prove the trait is object-safe and that its default
    /// `_buf` methods correctly delegate to the byte-slice methods.
    struct MockBigEndianConverter;

    impl DataConverter for MockBigEndianConverter {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
            i16::from_be_bytes([b[offset], b[offset + 1]])
        }

        fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
            i32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
        }

        fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&b[offset..offset + 8]);
            i64::from_be_bytes(buf)
        }

        fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64 {
            let mut val: u64 = 0;
            for i in 0..size {
                val = (val << 8) | b[offset + i] as u64;
            }
            val
        }

        fn get_big_integer_at(&self, b: &[u8], offset: usize, size: usize, signed: bool) -> i128 {
            let unsigned = self.get_value_at(b, offset, size) as i128;
            if signed && size < 16 && size > 0 {
                let shift_bits = (16 - size) * 8;
                (unsigned << shift_bits) >> shift_bits
            }
            else {
                unsigned
            }
        }

        fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
            b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }

        fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
            b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }

        fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize) {
            for i in 0..size {
                b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
            }
        }

        fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128) {
            for i in 0..size {
                b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
            }
        }
    }

    impl GhidraDataConverter for MockBigEndianConverter {}

    /// Fixed byte-array-backed `MemBuffer`, just enough to exercise the `_buf` reads.
    struct FixedMemBuffer {
        bytes: Vec<u8>,
        big_endian: bool,
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
            self.big_endian
        }
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let converter: Box<dyn GhidraDataConverter> = Box::new(MockBigEndianConverter);
        assert!(converter.is_big_endian());
    }

    #[test]
    fn get_short_buf_reads_big_endian() {
        let converter = MockBigEndianConverter;
        let buf = FixedMemBuffer { bytes: vec![0x01, 0x02], big_endian: true };
        assert_eq!(converter.get_short_buf(&buf, 0).unwrap(), 0x0102);
    }

    #[test]
    fn get_int_buf_reads_at_offset() {
        let converter = MockBigEndianConverter;
        let buf = FixedMemBuffer { bytes: vec![0xff, 0x00, 0x00, 0x00, 0x01], big_endian: true };
        assert_eq!(converter.get_int_buf(&buf, 1).unwrap(), 1);
    }

    #[test]
    fn get_long_buf_errors_on_short_read() {
        let converter = MockBigEndianConverter;
        let buf = FixedMemBuffer { bytes: vec![0u8; 4], big_endian: true };
        assert!(converter.get_long_buf(&buf, 0).is_err());
    }

    #[test]
    fn get_big_integer_buf_round_trips_signed() {
        let converter = MockBigEndianConverter;
        let buf = FixedMemBuffer { bytes: vec![0xff, 0xff, 0xff, 0xff], big_endian: true };
        assert_eq!(converter.get_big_integer_buf(&buf, 0, 4, true).unwrap(), -1);
        assert_eq!(converter.get_big_integer_buf(&buf, 0, 4, false).unwrap(), 0xffff_ffff);
    }
}
