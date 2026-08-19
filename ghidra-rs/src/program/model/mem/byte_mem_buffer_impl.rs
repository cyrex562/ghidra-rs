//! Port of `ghidra.program.model.mem.ByteMemBufferImpl`.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::mem::{Memory, MemoryAccessException};
use crate::util::ghidra_big_endian_data_converter::INSTANCE as BIG_ENDIAN_INSTANCE;
use crate::util::ghidra_little_endian_data_converter::INSTANCE as LITTLE_ENDIAN_INSTANCE;
use crate::util::GhidraDataConverter;

/// Simple byte buffer implementation of [`MemBuffer`]. Even if a [`Memory`] is provided, the
/// available bytes are limited to the bytes supplied during construction.
pub struct ByteMemBufferImpl {
    converter: &'static (dyn GhidraDataConverter + Send + Sync),
    bytes: Vec<u8>,
    addr: Address,
    mem: Option<Arc<dyn Memory>>,
}

impl ByteMemBufferImpl {
    /// Construct a `ByteMemBufferImpl` with no associated [`Memory`].
    pub fn new(addr: Address, bytes: Vec<u8>, is_big_endian: bool) -> Self {
        Self::with_memory(None, addr, bytes, is_big_endian)
    }

    /// Construct a `ByteMemBufferImpl` associated with `memory`, used when `get_memory()` is
    /// called to obtain related things like address spaces.
    pub fn with_memory(
        memory: Option<Arc<dyn Memory>>,
        addr: Address,
        bytes: Vec<u8>,
        is_big_endian: bool,
    ) -> Self {
        let converter: &'static (dyn GhidraDataConverter + Send + Sync) = if is_big_endian {
            &BIG_ENDIAN_INSTANCE
        } else {
            &LITTLE_ENDIAN_INSTANCE
        };
        Self {
            converter,
            bytes,
            addr,
            mem: memory,
        }
    }

    /// Get number of bytes contained within the buffer.
    pub fn get_length(&self) -> usize {
        self.bytes.len()
    }

    /// Get the [`Memory`] used by this buffer, or `None` if not available.
    pub fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.mem.clone()
    }

    /// Returns the short at the given offset, taking into account the endianness.
    ///
    /// # Errors
    /// Returns an error if 2 bytes cannot be read at the specified offset.
    pub fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
        self.converter.get_short_buf(self, offset)
    }

    /// Returns the int at the given offset, taking into account the endianness.
    ///
    /// # Errors
    /// Returns an error if 4 bytes cannot be read at the specified offset.
    pub fn get_int(&self, offset: i32) -> Result<i32, MemoryAccessException> {
        self.converter.get_int_buf(self, offset)
    }

    /// Returns the long at the given offset, taking into account the endianness.
    ///
    /// # Errors
    /// Returns an error if 8 bytes cannot be read at the specified offset.
    pub fn get_long(&self, offset: i32) -> Result<i64, MemoryAccessException> {
        self.converter.get_long_buf(self, offset)
    }

    /// Returns the value at the given offset, taking into account the endianness.
    ///
    /// # Errors
    /// Returns an error if `size` bytes cannot be read at the specified offset.
    pub fn get_big_integer(
        &self,
        offset: i32,
        size: i32,
        signed: bool,
    ) -> Result<i128, MemoryAccessException> {
        self.converter.get_big_integer_buf(self, offset, size, signed)
    }
}

impl MemBuffer for ByteMemBufferImpl {
    fn get_address(&self) -> Address {
        self.addr.clone()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        if offset < 0 || offset as usize >= self.bytes.len() {
            return Err(MemoryAccessException::new(format!(
                "Offset {offset} is not in range"
            )));
        }
        Ok(self.bytes[offset as usize])
    }

    fn get_bytes(&self, b: &mut [u8], offset: i32) -> usize {
        if offset < 0 || offset as usize >= self.bytes.len() {
            return 0;
        }
        let offset = offset as usize;
        let len = b.len().min(self.bytes.len() - offset);
        b[..len].copy_from_slice(&self.bytes[offset..offset + len]);
        len
    }

    fn is_big_endian(&self) -> bool {
        self.converter.is_big_endian()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn get_length_returns_byte_count() {
        let buf = ByteMemBufferImpl::new(addr(0x100), vec![1, 2, 3, 4], true);
        assert_eq!(buf.get_length(), 4);
    }

    #[test]
    fn get_address_returns_constructed_address() {
        let a = addr(0x1000);
        let buf = ByteMemBufferImpl::new(a.clone(), vec![1, 2, 3], true);
        assert_eq!(buf.get_address(), a);
    }

    #[test]
    fn get_byte_reads_in_range() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![0x12, 0x34, 0x56], true);
        assert_eq!(buf.get_byte(0).unwrap(), 0x12);
        assert_eq!(buf.get_byte(2).unwrap(), 0x56);
    }

    #[test]
    fn get_byte_out_of_range_errors() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![0x12, 0x34], true);
        assert!(buf.get_byte(-1).is_err());
        assert!(buf.get_byte(2).is_err());
    }

    #[test]
    fn get_bytes_copies_available_range() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![1, 2, 3, 4, 5], true);
        let mut dest = [0u8; 3];
        let n = buf.get_bytes(&mut dest, 1);
        assert_eq!(n, 3);
        assert_eq!(dest, [2, 3, 4]);
    }

    #[test]
    fn get_bytes_truncates_when_short_of_full_request() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![1, 2, 3], true);
        let mut dest = [0u8; 5];
        let n = buf.get_bytes(&mut dest, 1);
        assert_eq!(n, 2);
        assert_eq!(&dest[..2], &[2, 3]);
    }

    #[test]
    fn get_bytes_out_of_range_returns_zero() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![1, 2, 3], true);
        let mut dest = [0u8; 2];
        assert_eq!(buf.get_bytes(&mut dest, -1), 0);
        assert_eq!(buf.get_bytes(&mut dest, 3), 0);
    }

    #[test]
    fn is_big_endian_reflects_constructor_argument() {
        let big = ByteMemBufferImpl::new(addr(0), vec![1], true);
        let little = ByteMemBufferImpl::new(addr(0), vec![1], false);
        assert!(big.is_big_endian());
        assert!(!little.is_big_endian());
    }

    #[test]
    fn get_short_respects_endianness() {
        let big = ByteMemBufferImpl::new(addr(0), vec![0x01, 0x02], true);
        let little = ByteMemBufferImpl::new(addr(0), vec![0x01, 0x02], false);
        assert_eq!(big.get_short(0).unwrap(), 0x0102);
        assert_eq!(little.get_short(0).unwrap(), 0x0201);
    }

    #[test]
    fn get_int_respects_endianness() {
        let big = ByteMemBufferImpl::new(addr(0), vec![0x00, 0x00, 0x00, 0x07], true);
        assert_eq!(big.get_int(0).unwrap(), 7);
    }

    #[test]
    fn get_long_respects_endianness() {
        let mut bytes = vec![0u8; 8];
        bytes[7] = 1;
        let big = ByteMemBufferImpl::new(addr(0), bytes, true);
        assert_eq!(big.get_long(0).unwrap(), 1);
    }

    #[test]
    fn get_big_integer_signed_and_unsigned() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![0xff, 0xff], true);
        assert_eq!(buf.get_big_integer(0, 2, true).unwrap(), -1);
        assert_eq!(buf.get_big_integer(0, 2, false).unwrap(), 0xffff);
    }

    #[test]
    fn get_short_errors_on_insufficient_bytes() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![0x01], true);
        assert!(buf.get_short(0).is_err());
    }

    #[test]
    fn get_memory_defaults_to_none() {
        let buf = ByteMemBufferImpl::new(addr(0), vec![1, 2], true);
        assert!(buf.get_memory().is_none());
    }
}
