//! Port of `ghidra.program.model.mem.WrappedMemBuffer`.

use std::sync::Mutex;

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::mem::MemoryAccessException;
use crate::util::ghidra_big_endian_data_converter::INSTANCE as BIG_ENDIAN_INSTANCE;
use crate::util::ghidra_little_endian_data_converter::INSTANCE as LITTLE_ENDIAN_INSTANCE;
use crate::util::GhidraDataConverter;

const DEFAULT_BUFSIZE: usize = 0; // default no buffer

struct Cache {
    buffer: Vec<u8>,
    min_offset: i32,
    max_offset: i32,
}

/// Provides a zero based index on top of an underlying [`MemBuffer`] at a given address.
///
/// It can buffer N bytes at a time using [`WrappedMemBuffer::with_buffer_size`]. However the
/// default (via [`WrappedMemBuffer::new`]) is to provide no buffering. Use of the buffer can
/// reduce the overall number of calls to the underlying buffer, greatly reducing the overhead of
/// various error checks. This implementation will not wrap if the end of the memory space is
/// encountered.
///
/// [`get_byte`][MemBuffer::get_byte] and [`get_bytes`][MemBuffer::get_bytes] can cause the bytes
/// in the buffer to be cached if the request is outside of the current cached bytes.
///
/// WARNING: The underlying [`MemBuffer`] should not change its base address. Using a mutable
/// [`MemBuffer`] can cause problematic behavior if not controlled carefully.
///
/// WARNING: Not thread-safe; the cache is guarded by a `Mutex` only to satisfy the `Sync`
/// supertrait required by [`MemBuffer`], not to provide any real concurrency guarantees.
pub struct WrappedMemBuffer {
    mem_buffer: Box<dyn MemBuffer>,
    converter: &'static (dyn GhidraDataConverter + Send + Sync),
    base_offset: i32,
    address: Address,
    cache: Mutex<Cache>,
}

impl WrappedMemBuffer {
    /// Construct a wrapped `MemBuffer` with an adjustable base offset and no buffering.
    ///
    /// `base_offset` is relative to the underlying buffer's start address: `(addr + base_offset)`
    /// will be the 0 index into this buffer.
    ///
    /// # Errors
    /// Returns an error if `base_offset` moves the resulting address out of bounds.
    pub fn new(buf: Box<dyn MemBuffer>, base_offset: i32) -> Result<Self, AddressOverflowException> {
        Self::with_buffer_size(buf, DEFAULT_BUFSIZE, base_offset)
    }

    /// Construct a wrapped `MemBuffer` with an adjustable base offset and a cache of
    /// `buffer_size` bytes. Specify 0 for no buffering.
    ///
    /// # Errors
    /// Returns an error if `base_offset` moves the resulting address out of bounds.
    pub fn with_buffer_size(
        buf: Box<dyn MemBuffer>,
        buffer_size: usize,
        base_offset: i32,
    ) -> Result<Self, AddressOverflowException> {
        let converter: &'static (dyn GhidraDataConverter + Send + Sync) = if buf.is_big_endian() {
            &BIG_ENDIAN_INSTANCE
        } else {
            &LITTLE_ENDIAN_INSTANCE
        };

        let address = buf.get_address().add(base_offset as i64)?;

        let mut buffer = vec![0u8; buffer_size];
        let mut max_offset = -1i32;
        if !buffer.is_empty() {
            let n_read = buf.get_bytes(&mut buffer, base_offset) as i32;
            max_offset = n_read - 1;
        }

        Ok(Self {
            mem_buffer: buf,
            converter,
            base_offset,
            address,
            cache: Mutex::new(Cache {
                buffer,
                min_offset: 0,
                max_offset,
            }),
        })
    }

    /// Compute offset into the original `MemBuffer`, making sure the offset doesn't wrap.
    fn compute_offset(&self, offset: i32) -> Result<i32, MemoryAccessException> {
        let buf_offset = self.base_offset.wrapping_add(offset);
        if offset > 0 && buf_offset < self.base_offset {
            return Err(MemoryAccessException::new(
                "Invalid WrappedMemBuffer, offset would wrap underlying memory buffer",
            ));
        }
        if offset < 0 && buf_offset > self.base_offset {
            return Err(MemoryAccessException::new(
                "Invalid WrappedMemBuffer offset, offset would wrap underlying memory buffer",
            ));
        }
        Ok(buf_offset)
    }

    fn fill_buffer(&self, cache: &mut Cache, offset: i32) -> Result<(), MemoryAccessException> {
        let buf_offset = self.compute_offset(offset)?;
        let n_read = self.mem_buffer.get_bytes(&mut cache.buffer, buf_offset) as i32;

        if n_read == 0 {
            return Err(MemoryAccessException::new("No bytes available in memory to cache"));
        }

        cache.min_offset = offset;
        cache.max_offset = offset + n_read - 1;
        Ok(())
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

impl MemBuffer for WrappedMemBuffer {
    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        let mut cache = self.cache.lock().unwrap();

        // no buffering, just get the byte
        if cache.buffer.is_empty() {
            let buf_offset = self.compute_offset(offset)?;
            return self.mem_buffer.get_byte(buf_offset);
        }

        // byte found in buffer
        if offset >= cache.min_offset && offset <= cache.max_offset {
            return Ok(cache.buffer[(offset - cache.min_offset) as usize]);
        }

        self.fill_buffer(&mut cache, offset)?;
        Ok(cache.buffer[0])
    }

    fn get_bytes(&self, b: &mut [u8], offset: i32) -> usize {
        let mut cache = self.cache.lock().unwrap();

        let result: Result<usize, MemoryAccessException> = (|| {
            // if there is a buffer, and the number of bytes requested will fit in the buffer
            if !cache.buffer.is_empty() && b.len() <= cache.buffer.len() {
                // bytes not in buffer
                if offset < cache.min_offset || (b.len() as i32 + offset - 1) > cache.max_offset {
                    self.fill_buffer(&mut cache, offset)?;
                }
                // bytes are contained in the buffer
                if offset >= cache.min_offset && (b.len() as i32 + offset - 1) <= cache.max_offset {
                    let start = (offset - cache.min_offset) as usize;
                    b.copy_from_slice(&cache.buffer[start..start + b.len()]);
                    return Ok(b.len());
                }
            }

            // grab from wrapped buffer, too many bytes, or no buffer
            let buf_offset = self.compute_offset(offset)?;
            Ok(self.mem_buffer.get_bytes(b, buf_offset))
        })();

        result.unwrap_or(0)
    }

    fn is_big_endian(&self) -> bool {
        self.mem_buffer.is_big_endian()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// `MemBuffer` mock that counts calls to `get_bytes`, used to assert caching behavior.
    /// The call counter is a shared handle so it stays inspectable after the mock is boxed.
    struct CountingMemBuffer {
        address: Address,
        data: Vec<u8>,
        big_endian: bool,
        calls: Arc<AtomicUsize>,
    }

    impl CountingMemBuffer {
        fn new(address: Address, data: Vec<u8>, big_endian: bool) -> Self {
            Self::with_counter(address, data, big_endian, Arc::new(AtomicUsize::new(0)))
        }

        fn with_counter(
            address: Address,
            data: Vec<u8>,
            big_endian: bool,
            calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                address,
                data,
                big_endian,
                calls,
            }
        }
    }

    impl MemBuffer for CountingMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("offset out of range"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if offset < 0 || offset as usize >= self.data.len() {
                return 0;
            }
            let start = offset as usize;
            let n = buf.len().min(self.data.len() - start);
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            n
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    #[test]
    fn get_address_applies_base_offset() {
        let mem = CountingMemBuffer::new(addr(0x1000), vec![1, 2, 3, 4], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 4).unwrap();
        assert_eq!(wrapped.get_address(), addr(0x1004));
    }

    #[test]
    fn unbuffered_get_byte_delegates_with_base_offset() {
        let mem = CountingMemBuffer::new(addr(0), vec![0x10, 0x20, 0x30, 0x40], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 1).unwrap();
        assert_eq!(wrapped.get_byte(0).unwrap(), 0x20);
        assert_eq!(wrapped.get_byte(2).unwrap(), 0x40);
    }

    #[test]
    fn unbuffered_get_byte_out_of_range_errors() {
        let mem = CountingMemBuffer::new(addr(0), vec![0x10, 0x20], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 0).unwrap();
        assert!(wrapped.get_byte(5).is_err());
    }

    #[test]
    fn unbuffered_get_bytes_delegates() {
        let mem = CountingMemBuffer::new(addr(0), vec![1, 2, 3, 4, 5], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 1).unwrap();
        let mut dest = [0u8; 3];
        let n = wrapped.get_bytes(&mut dest, 0);
        assert_eq!(n, 3);
        assert_eq!(dest, [2, 3, 4]);
    }

    #[test]
    fn buffered_construction_prefills_cache() {
        let mem = CountingMemBuffer::new(addr(0), (0..10).collect(), true);
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(mem), 4, 0).unwrap();
        // Constructor should have already filled the cache once.
        assert_eq!(wrapped.get_byte(0).unwrap(), 0);
        assert_eq!(wrapped.get_byte(3).unwrap(), 3);
    }

    #[test]
    fn buffered_get_byte_within_cache_avoids_refill() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mem = CountingMemBuffer::with_counter(addr(0), (0..10).collect(), true, calls.clone());
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(mem), 4, 0).unwrap();
        // Constructor already performed the initial fill.
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Reads within the cached [0, 3] range should not trigger another fill.
        assert_eq!(wrapped.get_byte(0).unwrap(), 0);
        assert_eq!(wrapped.get_byte(3).unwrap(), 3);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn buffered_get_byte_outside_cache_triggers_refill() {
        let calls = Arc::new(AtomicUsize::new(0));
        let data: Vec<u8> = (0..10).collect();
        let mem = CountingMemBuffer::with_counter(addr(0), data, true, calls.clone());
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(mem), 4, 0).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Offset 4 is outside the initial [0, 3] cache window; must refill.
        assert_eq!(wrapped.get_byte(4).unwrap(), 4);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(wrapped.get_byte(7).unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn buffered_get_bytes_within_cache() {
        let data: Vec<u8> = (0..10).collect();
        let mem = CountingMemBuffer::new(addr(0), data, true);
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(mem), 4, 0).unwrap();

        let mut dest = [0u8; 2];
        let n = wrapped.get_bytes(&mut dest, 1);
        assert_eq!(n, 2);
        assert_eq!(dest, [1, 2]);
    }

    #[test]
    fn get_bytes_larger_than_buffer_bypasses_cache() {
        let data: Vec<u8> = (0..10).collect();
        let mem = CountingMemBuffer::new(addr(0), data, true);
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(mem), 2, 0).unwrap();

        let mut dest = [0u8; 5];
        let n = wrapped.get_bytes(&mut dest, 0);
        assert_eq!(n, 5);
        assert_eq!(dest, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn get_bytes_out_of_range_returns_zero() {
        let mem = CountingMemBuffer::new(addr(0), vec![1, 2, 3], true);
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(mem), 4, 0).unwrap();
        let mut dest = [0u8; 2];
        assert_eq!(wrapped.get_bytes(&mut dest, 10), 0);
    }

    #[test]
    fn is_big_endian_delegates_to_wrapped_buffer() {
        let big = CountingMemBuffer::new(addr(0), vec![1], true);
        let little = CountingMemBuffer::new(addr(0), vec![1], false);
        assert!(WrappedMemBuffer::new(Box::new(big), 0).unwrap().is_big_endian());
        assert!(!WrappedMemBuffer::new(Box::new(little), 0).unwrap().is_big_endian());
    }

    #[test]
    fn get_short_respects_endianness() {
        let big = CountingMemBuffer::new(addr(0), vec![0x01, 0x02], true);
        let little = CountingMemBuffer::new(addr(0), vec![0x01, 0x02], false);
        let big = WrappedMemBuffer::new(Box::new(big), 0).unwrap();
        let little = WrappedMemBuffer::new(Box::new(little), 0).unwrap();
        assert_eq!(big.get_short(0).unwrap(), 0x0102);
        assert_eq!(little.get_short(0).unwrap(), 0x0201);
    }

    #[test]
    fn get_int_respects_endianness() {
        let mem = CountingMemBuffer::new(addr(0), vec![0x00, 0x00, 0x00, 0x07], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 0).unwrap();
        assert_eq!(wrapped.get_int(0).unwrap(), 7);
    }

    #[test]
    fn get_long_respects_endianness() {
        let mut bytes = vec![0u8; 8];
        bytes[7] = 1;
        let mem = CountingMemBuffer::new(addr(0), bytes, true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 0).unwrap();
        assert_eq!(wrapped.get_long(0).unwrap(), 1);
    }

    #[test]
    fn get_big_integer_signed_and_unsigned() {
        let mem = CountingMemBuffer::new(addr(0), vec![0xff, 0xff], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), 0).unwrap();
        assert_eq!(wrapped.get_big_integer(0, 2, true).unwrap(), -1);
        assert_eq!(wrapped.get_big_integer(0, 2, false).unwrap(), 0xffff);
    }

    #[test]
    fn construction_fails_when_base_offset_overflows_address() {
        // 8-bit address space: max address offset is 0xff.
        let space = AddressSpace::new("ram", 8, 1, AddressSpaceType::Ram, 1);
        let start = Address::new(space, 0xf0);
        let mem = CountingMemBuffer::new(start, vec![1, 2, 3], true);
        let result = WrappedMemBuffer::new(Box::new(mem), 0x20);
        assert!(result.is_err());
    }

    #[test]
    fn compute_offset_positive_wrap_errors() {
        // 64-bit space so the address itself never overflows; base_offset near i32::MAX
        // exercises the 32-bit wraparound check inside compute_offset.
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
        let start = Address::new(space, 0);
        let mem = CountingMemBuffer::new(start, vec![0u8; 4], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), i32::MAX).unwrap();

        assert!(wrapped.get_byte(1).is_err());
    }

    #[test]
    fn compute_offset_negative_wrap_errors() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
        // Start high enough that (start + i32::MIN) is still a valid, non-negative offset.
        let start = Address::new(space, 0x1_0000_0000);
        let mem = CountingMemBuffer::new(start, vec![0u8; 4], true);
        let wrapped = WrappedMemBuffer::new(Box::new(mem), i32::MIN).unwrap();

        assert!(wrapped.get_byte(-1).is_err());
    }
}
