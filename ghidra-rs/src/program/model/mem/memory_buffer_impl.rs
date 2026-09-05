//! Port of `ghidra.program.model.mem.MemoryBufferImpl`.
//!
//! `MemBufferImpl` implements the `MemBuffer` interface. It buffers up N bytes at a time,
//! reducing the overall number of calls to `Memory`, greatly reducing the overhead of various
//! error checks. This implementation will not wrap if the end of the memory space is encountered.
//!
//! The `getByte(int)` method can cause the buffer cache to adjust if outside the current cache
//! range. This is not the case for other methods, which will simply defer to the underlying
//! memory if outside the cache range.
//!
//! # Fidelity notes
//!
//! Java's `getByte`/`getBytes`/`clone`/`advance`/`setPosition` are declared on `MemBuffer`/
//! `MutableMemBuffer`, both of whose Java originals are ordinary (non-`final`) instance methods
//! free to mutate `this`. This crate's ported [`MemBuffer`] trait, however, declares `get_byte`/
//! `get_bytes` (and [`MutableMemBuffer`] declares `clone_mutable`) as taking `&self` rather than
//! `&mut self` -- unavoidable, since 96+ call sites elsewhere hold only a `&dyn MemBuffer` and
//! Java's own cache-adjusting `getByte` still needs to mutate the cache through that borrow. All
//! cache state therefore lives behind a [`std::sync::Mutex`] (needed anyway to keep this type
//! `Send + Sync`, as [`MemBuffer`] requires) rather than as plain fields.
//!
//! `getShort`/`getInt`/`getLong`/`getBigInteger` are not overridden here at all: Java implements
//! them via a `GhidraDataConverter` field precisely because `MemBuffer`/`MemBufferMixin` supply no
//! defaults for them in Java. This crate's [`MemBuffer`] trait (see its own docs) already defaults
//! `get_short`/`get_int`/`get_long` in terms of [`MemBuffer::get_bytes`], and
//! [`MemBufferMixin::get_big_integer`] does likewise -- both already respect
//! [`MemBuffer::is_big_endian`], so inheriting those defaults reproduces the same behavior without
//! needing a converter field at all.
//!
//! `getByte`'s fallback branch has a notable quirk, preserved here rather than "fixed": if the
//! underlying `Memory.getBytes` read comes back short (including a full failure, `nRead == 0`),
//! Java still unconditionally executes `return buffer[0];` -- returning a stale (or, on the very
//! first read, zero-initialized) byte rather than surfacing an error, even though the resulting
//! `minOffset > maxOffset` marks the cache as invalid for next time. This looks like a bug, but
//! porting is not the place to fix upstream behavior nobody asked to change.

use std::sync::{Arc, Mutex};

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::mem::mem_buffer_mixin::MemBufferMixin;
use crate::program::model::mem::memory::Memory;
use crate::program::model::mem::memory_access_exception::MemoryAccessException;
use crate::program::model::mem::mutable_mem_buffer::MutableMemBuffer;

/// Port of `MemoryBufferImpl.DEFAULT_BUFSIZE`.
pub const DEFAULT_BUFSIZE: usize = 1024;

/// The mutable cache state, guarded by [`MemoryBufferImpl`]'s mutex -- see the module docs for
/// why this needs interior mutability at all.
struct CacheState {
    start_addr: Address,
    buffer: Vec<u8>,
    start_addr_index: i64,
    min_offset: i64,
    max_offset: i64,
}

/// Buffers up bytes from a [`Memory`] at a time, reducing the number of calls into it.
///
/// Port of `ghidra.program.model.mem.MemoryBufferImpl`. See the module docs for what was ported
/// and the one behavioral quirk preserved verbatim.
pub struct MemoryBufferImpl {
    mem: Arc<dyn Memory>,
    threshold: i64,
    state: Mutex<CacheState>,
}

impl MemoryBufferImpl {
    /// Construct a new `MemoryBufferImpl` using the default buffer size.
    pub fn new(mem: Arc<dyn Memory>, addr: Address) -> Self {
        Self::with_buf_size(mem, addr, DEFAULT_BUFSIZE)
    }

    /// Construct a new `MemoryBufferImpl` with the given buffer size.
    pub fn with_buf_size(mem: Arc<dyn Memory>, addr: Address, buf_size: usize) -> Self {
        let threshold = (buf_size / 100) as i64;
        let this = MemoryBufferImpl {
            mem,
            threshold,
            state: Mutex::new(CacheState {
                start_addr: addr.clone(),
                buffer: vec![0u8; buf_size],
                start_addr_index: 0,
                min_offset: 0,
                max_offset: -1,
            }),
        };
        this.set_position_locked(addr);
        this
    }

    /// Shared implementation of `setPosition`, usable from both the `&mut self`
    /// [`MutableMemBuffer::set_position`] entry point and this type's own constructors (which only
    /// have `&self` available before construction finishes).
    fn set_position_locked(&self, addr: Address) {
        let mut state = self.state.lock().unwrap();
        if state.min_offset <= state.max_offset && addr.space() == state.start_addr.space() {
            let diff = addr.subtract(&state.start_addr);
            if diff >= state.min_offset && diff < state.max_offset - self.threshold {
                state.start_addr = addr;
                state.min_offset -= diff;
                state.max_offset -= diff;
                state.start_addr_index += diff;
                return;
            }
        }
        state.start_addr = addr.clone();
        state.start_addr_index = 0;
        state.min_offset = 0;
        state.max_offset = -1;

        let n = self.mem.get_bytes(&addr, &mut state.buffer);
        state.max_offset = n as i64 - 1;
    }
}

impl MemBuffer for MemoryBufferImpl {
    fn get_address(&self) -> Address {
        self.state.lock().unwrap().start_addr.clone()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        let mut state = self.state.lock().unwrap();
        let offset = offset as i64;
        if offset >= state.min_offset && offset <= state.max_offset {
            let idx = (state.start_addr_index + offset) as usize;
            return Ok(state.buffer[idx]);
        }

        let addr = state
            .start_addr
            .add_no_wrap(offset)
            .map_err(|e| MemoryAccessException::new(e.to_string()))?;
        let n = self.mem.get_bytes(&addr, &mut state.buffer);
        state.start_addr_index = -offset;
        state.min_offset = offset;
        state.max_offset = offset + n as i64 - 1;
        // See the module docs: this returns `buffer[0]` even when `n == 0`, matching Java.
        Ok(state.buffer[0])
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        let state = self.state.lock().unwrap();
        let offset = offset as i64;
        if offset >= state.min_offset && (buf.len() as i64 + offset) <= state.max_offset {
            let start = (state.start_addr_index + offset) as usize;
            buf.copy_from_slice(&state.buffer[start..start + buf.len()]);
            return buf.len();
        }
        match state.start_addr.add_no_wrap(offset) {
            Ok(addr) => {
                drop(state);
                self.mem.get_bytes(&addr, buf)
            }
            Err(_) => 0,
        }
    }

    fn is_big_endian(&self) -> bool {
        self.mem.is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        Some(self.mem.clone())
    }
}

impl MemBufferMixin for MemoryBufferImpl {}

impl MutableMemBuffer for MemoryBufferImpl {
    fn advance(&mut self, displacement: i32) -> Result<(), AddressOverflowException> {
        let current = self.state.lock().unwrap().start_addr.clone();
        let addr = current.add_no_wrap(displacement as i64)?;
        self.set_position_locked(addr);
        Ok(())
    }

    fn set_position(&mut self, addr: Address) {
        self.set_position_locked(addr);
    }

    fn clone_mutable(&self) -> Box<dyn MutableMemBuffer> {
        let (addr, buf_len) = {
            let state = self.state.lock().unwrap();
            (state.start_addr.clone(), state.buffer.len())
        };
        Box::new(MemoryBufferImpl::with_buf_size(self.mem.clone(), addr, buf_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Mutex as StdMutex;

    /// A simple in-memory [`Memory`] test double backed by a flat byte vector starting at
    /// offset 0 in its address space.
    struct MockMemory {
        bytes: StdMutex<Vec<u8>>,
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
        Arc::new(MockMemory { bytes: StdMutex::new(data), big_endian: true })
    }

    #[test]
    fn get_address_reflects_construction_address() {
        let buf = MemoryBufferImpl::new(mock_mem(vec![1, 2, 3, 4]), addr(0x100));
        assert_eq!(buf.get_address(), addr(0x100));
    }

    #[test]
    fn get_byte_reads_from_the_cached_buffer() {
        let buf = MemoryBufferImpl::new(mock_mem(vec![0xAA, 0xBB, 0xCC]), addr(0));
        assert_eq!(buf.get_byte(0).unwrap(), 0xAA);
        assert_eq!(buf.get_byte(1).unwrap(), 0xBB);
        assert_eq!(buf.get_byte(2).unwrap(), 0xCC);
    }

    #[test]
    fn get_byte_beyond_cache_refills_and_reads() {
        // A tiny buffer so reading past its end forces a refill from a fresh position.
        let buf = MemoryBufferImpl::with_buf_size(mock_mem(vec![1, 2, 3, 4, 5, 6]), addr(0), 2);
        assert_eq!(buf.get_byte(0).unwrap(), 1);
        assert_eq!(buf.get_byte(4).unwrap(), 5);
    }

    #[test]
    fn get_bytes_reads_from_the_cached_buffer() {
        let buf = MemoryBufferImpl::new(mock_mem(vec![10, 20, 30, 40]), addr(0));
        let mut out = [0u8; 2];
        assert_eq!(buf.get_bytes(&mut out, 1), 2);
        assert_eq!(out, [20, 30]);
    }

    #[test]
    fn get_bytes_beyond_cache_defers_to_memory() {
        let buf = MemoryBufferImpl::with_buf_size(mock_mem(vec![1, 2, 3, 4, 5, 6]), addr(0), 2);
        let mut out = [0u8; 3];
        assert_eq!(buf.get_bytes(&mut out, 3), 3);
        assert_eq!(out, [4, 5, 6]);
    }

    #[test]
    fn is_big_endian_reflects_memory() {
        let buf_be = MemoryBufferImpl::new(mock_mem(vec![1]), addr(0));
        assert!(buf_be.is_big_endian());
    }

    #[test]
    fn get_memory_returns_the_backing_memory() {
        let buf = MemoryBufferImpl::new(mock_mem(vec![1]), addr(0));
        assert!(buf.get_memory().is_some());
    }

    #[test]
    fn advance_moves_the_address_and_reads_from_the_new_position() {
        let mut buf = MemoryBufferImpl::new(mock_mem(vec![1, 2, 3, 4, 5]), addr(0));
        buf.advance(2).unwrap();
        assert_eq!(buf.get_address(), addr(2));
        assert_eq!(buf.get_byte(0).unwrap(), 3);
    }

    #[test]
    fn advance_overflow_returns_error() {
        let byte_space = AddressSpace::new("tiny", 8, 1, AddressSpaceType::Ram, 0);
        let max_addr = byte_space.max_address();
        let mem: Arc<dyn Memory> = mock_mem(vec![0; 256]);
        let mut buf = MemoryBufferImpl::new(mem, max_addr.clone());
        assert!(buf.advance(1).is_err());
        // A failed advance must not move the buffer's reported address.
        assert_eq!(buf.get_address(), max_addr);
    }

    #[test]
    fn set_position_moves_within_the_cache_without_refilling() {
        let buf_impl = MemoryBufferImpl::with_buf_size(mock_mem(vec![1, 2, 3, 4, 5, 6, 7, 8]), addr(0), 8);
        let mut buf: Box<dyn MutableMemBuffer> = Box::new(buf_impl);
        buf.set_position(addr(2));
        assert_eq!(buf.get_address(), addr(2));
        assert_eq!(buf.get_byte(0).unwrap(), 3);
    }

    #[test]
    fn set_position_far_away_triggers_a_fresh_read() {
        let buf_impl = MemoryBufferImpl::with_buf_size(mock_mem(vec![1, 2, 3, 4, 5, 6, 7, 8]), addr(0), 2);
        let mut buf: Box<dyn MutableMemBuffer> = Box::new(buf_impl);
        buf.set_position(addr(6));
        assert_eq!(buf.get_address(), addr(6));
        assert_eq!(buf.get_byte(0).unwrap(), 7);
    }

    #[test]
    fn clone_mutable_produces_an_independent_buffer_at_the_same_address() {
        let buf = MemoryBufferImpl::new(mock_mem(vec![1, 2, 3, 4]), addr(0));
        let mut cloned = buf.clone_mutable();
        assert_eq!(cloned.get_address(), addr(0));

        cloned.advance(1).unwrap();
        assert_eq!(cloned.get_address(), addr(1));
        // The original is unaffected by mutating the clone.
        assert_eq!(buf.get_address(), addr(0));
    }

    #[test]
    fn get_short_and_get_int_use_the_inherited_mem_buffer_defaults() {
        // Big-endian: 0x0102 as a short, 0x01020304 as an int.
        let buf = MemoryBufferImpl::new(mock_mem(vec![0x01, 0x02, 0x03, 0x04]), addr(0));
        assert_eq!(MemBuffer::get_short(&buf, 0).unwrap(), 0x0102);
        assert_eq!(MemBuffer::get_int(&buf, 0).unwrap(), 0x0102_0304);
    }

    #[test]
    fn get_big_integer_uses_the_inherited_mem_buffer_mixin_default() {
        let buf = MemoryBufferImpl::new(mock_mem(vec![0x00, 0x2A]), addr(0));
        let raw = buf.get_big_integer(0, 2, false).unwrap();
        assert_eq!(raw, vec![0x00, 0x2A]);
    }

    #[test]
    fn usable_as_a_mem_buffer_trait_object() {
        let buf: Box<dyn MemBuffer> = Box::new(MemoryBufferImpl::new(mock_mem(vec![7]), addr(0)));
        assert_eq!(buf.get_byte(0).unwrap(), 7);
    }
}
