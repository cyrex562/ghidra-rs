//! Port of `ghidra.program.model.mem.DumbMemBufferImpl`.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::mem::mem_buffer_mixin::MemBufferMixin;
use crate::program::model::mem::memory::Memory;
use crate::program::model::mem::memory_access_exception::MemoryAccessException;
use crate::program::model::mem::memory_buffer_impl::MemoryBufferImpl;
use crate::program::model::mem::mutable_mem_buffer::MutableMemBuffer;

/// `DumbMemBufferImpl`'s internal cache buffer size, in bytes.
///
/// Port of `DumbMemBufferImpl.BUF_SIZE`.
const BUF_SIZE: usize = 16;

/// A [`MemBuffer`] with an internal cache buffer size of 16 bytes but that will use the
/// underlying memory if needed.
///
/// Port of `ghidra.program.model.mem.DumbMemBufferImpl`. Java extends `MemoryBufferImpl`; per
/// this crate's composition-over-inheritance convention, this type wraps a
/// [`MemoryBufferImpl`] constructed with the fixed 16-byte cache size instead, and forwards every
/// trait method to it.
pub struct DumbMemBufferImpl {
    inner: MemoryBufferImpl,
}

impl DumbMemBufferImpl {
    /// Construct a new `DumbMemBufferImpl`.
    ///
    /// # Arguments
    /// * `mem` - memory associated with the given address
    /// * `addr` - starting address
    ///
    /// Port of `DumbMemBufferImpl(Memory, Address)`.
    pub fn new(mem: Arc<dyn Memory>, addr: Address) -> Self {
        Self { inner: MemoryBufferImpl::with_buf_size(mem, addr, BUF_SIZE) }
    }
}

impl MemBuffer for DumbMemBufferImpl {
    fn get_address(&self) -> Address {
        self.inner.get_address()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.inner.get_byte(offset)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.inner.get_bytes(buf, offset)
    }

    fn is_big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.inner.get_memory()
    }
}

impl MemBufferMixin for DumbMemBufferImpl {}

impl MutableMemBuffer for DumbMemBufferImpl {
    fn advance(&mut self, displacement: i32) -> Result<(), AddressOverflowException> {
        self.inner.advance(displacement)
    }

    fn set_position(&mut self, addr: Address) {
        self.inner.set_position(addr)
    }

    fn clone_mutable(&self) -> Box<dyn MutableMemBuffer> {
        self.inner.clone_mutable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Mutex;

    struct MockMemory {
        bytes: Mutex<Vec<u8>>,
        big_endian: bool,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let idx = addr.offset() as usize;
            self.bytes
                .lock()
                .unwrap()
                .get(idx)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let bytes = self.bytes.lock().unwrap();
            let start = addr.offset() as usize;
            if start >= bytes.len() {
                return 0;
            }
            let available = bytes.len() - start;
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&bytes[start..start + n]);
            n
        }

        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let mut bytes = self.bytes.lock().unwrap();
            let start = addr.offset() as usize;
            if start + source.len() > bytes.len() {
                bytes.resize(start + source.len(), 0);
            }
            bytes[start..start + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn mock_mem(data: Vec<u8>) -> Arc<dyn Memory> {
        Arc::new(MockMemory { bytes: Mutex::new(data), big_endian: true })
    }

    #[test]
    fn get_address_reflects_construction_address() {
        let buf = DumbMemBufferImpl::new(mock_mem(vec![1, 2, 3, 4]), addr(0x100));
        assert_eq!(buf.get_address(), addr(0x100));
    }

    #[test]
    fn get_byte_reads_from_the_underlying_memory() {
        let buf = DumbMemBufferImpl::new(mock_mem(vec![0xAA, 0xBB, 0xCC]), addr(0));
        assert_eq!(buf.get_byte(0).unwrap(), 0xAA);
        assert_eq!(buf.get_byte(2).unwrap(), 0xCC);
    }

    /// The cache is only 16 bytes, but reads past that limit must still work by falling back to
    /// the underlying `Memory` -- this is the entire point of `DumbMemBufferImpl` per its Java
    /// doc comment ("...but will use the underlying memory if needed").
    #[test]
    fn reads_beyond_the_16_byte_cache_still_succeed() {
        let mut data = vec![0u8; 32];
        data[20] = 0x42;
        let buf = DumbMemBufferImpl::new(mock_mem(data), addr(0));
        assert_eq!(buf.get_byte(20).unwrap(), 0x42);
    }

    #[test]
    fn get_bytes_reads_across_the_cache_boundary() {
        let data: Vec<u8> = (0..32).collect();
        let buf = DumbMemBufferImpl::new(mock_mem(data), addr(0));
        let mut out = [0u8; 8];
        // offset 12..20 straddles the 16-byte cache boundary.
        assert_eq!(buf.get_bytes(&mut out, 12), 8);
        assert_eq!(out, [12, 13, 14, 15, 16, 17, 18, 19]);
    }

    #[test]
    fn is_big_endian_reflects_memory() {
        let buf = DumbMemBufferImpl::new(mock_mem(vec![1]), addr(0));
        assert!(buf.is_big_endian());
    }

    #[test]
    fn get_memory_returns_the_backing_memory() {
        let buf = DumbMemBufferImpl::new(mock_mem(vec![1]), addr(0));
        assert!(MemBuffer::get_memory(&buf).is_some());
    }

    #[test]
    fn advance_moves_the_address() {
        let mut buf = DumbMemBufferImpl::new(mock_mem(vec![1, 2, 3, 4, 5]), addr(0));
        buf.advance(2).unwrap();
        assert_eq!(MemBuffer::get_address(&buf), addr(2));
        assert_eq!(buf.get_byte(0).unwrap(), 3);
    }

    #[test]
    fn set_position_moves_the_address() {
        let mut buf = DumbMemBufferImpl::new(mock_mem(vec![1, 2, 3, 4, 5, 6, 7, 8]), addr(0));
        buf.set_position(addr(4));
        assert_eq!(MemBuffer::get_address(&buf), addr(4));
        assert_eq!(buf.get_byte(0).unwrap(), 5);
    }

    #[test]
    fn clone_mutable_produces_an_independent_buffer() {
        let buf = DumbMemBufferImpl::new(mock_mem(vec![1, 2, 3, 4]), addr(0));
        let mut cloned = buf.clone_mutable();
        cloned.advance(1).unwrap();
        assert_eq!(MemBuffer::get_address(cloned.as_ref()), addr(1));
        assert_eq!(MemBuffer::get_address(&buf), addr(0));
    }

    #[test]
    fn usable_as_a_mem_buffer_trait_object() {
        let buf: Box<dyn MemBuffer> = Box::new(DumbMemBufferImpl::new(mock_mem(vec![7]), addr(0)));
        assert_eq!(buf.get_byte(0).unwrap(), 7);
    }
}
