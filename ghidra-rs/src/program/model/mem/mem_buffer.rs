//! Port of `ghidra.program.model.mem.MemBuffer`.
//!
//! # Why this file exists, when `MemBuffer.java` was already marked DONE
//!
//! It was marked DONE against a definition in
//! [`sleigh::walker`](crate::program::model::lang::sleigh::walker) -- the wrong module (Java puts
//! it in `ghidra.program.model.mem`), carrying four of the interface's methods. A *second*,
//! unrelated definition lived in `program/seam_stubs.rs` requiring only `get_address`, and 116
//! files referenced one or the other. `program/model/mem/` held only this type's dependents
//! ([`MemBufferMixin`](super::mem_buffer_mixin::MemBufferMixin),
//! [`ByteMemBufferImpl`](super::byte_mem_buffer_impl::ByteMemBufferImpl),
//! [`WrappedMemBuffer`](super::wrapped_mem_buffer::WrappedMemBuffer)) and not the type itself.
//!
//! Two types with one name, one of them empty, is the shadowing that `scripts/stub_audit.py`
//! ranks; `MemBuffer` was its worst case. This module is the single canonical definition, in the
//! module Java uses, and both former homes now re-export it.
//!
//! # The split with `MemBufferMixin`
//!
//! Ghidra splits the interface the same way, and the port already had the second half: this
//! trait carries what an implementation must supply (address, bytes, endianness), while
//! [`MemBufferMixin`](super::mem_buffer_mixin::MemBufferMixin) derives `get_short`/`get_int`/
//! `get_long`/`get_big_integer` from them.

use crate::program::model::address::Address;
use crate::program::model::mem::{Memory, MemoryAccessException};

/// Provides a buffer of bytes at some address, the basic read interface used throughout
/// disassembly and data typing.
///
/// Port of `ghidra.program.model.mem.MemBuffer`.
pub trait MemBuffer: Send + Sync {
    /// The address of this buffer's byte at offset 0.
    ///
    /// Stands in for `MemBuffer.getAddress()`.
    fn get_address(&self) -> Address;

    /// Reads the byte at `offset` from this buffer's address.
    ///
    /// Stands in for `MemBuffer.getByte(int)`, whose `MemoryAccessException` becomes an `Err`.
    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException>;

    /// Fills `buf` from `offset`, returning how many bytes were actually read.
    ///
    /// Stands in for `MemBuffer.getBytes(byte[], int)`, which likewise reports a short read by
    /// its return value rather than by failing.
    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize;

    /// Whether multi-byte values in this buffer are big-endian.
    ///
    /// Stands in for `MemBuffer.isBigEndian()`.
    fn is_big_endian(&self) -> bool;

    /// The memory this buffer reads from, when it has one.
    ///
    /// Stands in for `MemBuffer.getMemory()`, which is documented as possibly `null` -- hence
    /// `Option` rather than a required method. Buffers over a plain byte array have no memory.
    fn get_memory(&self) -> Option<&dyn Memory> {
        None
    }

    /// Whether this buffer's address is in initialized memory.
    ///
    /// Mirrors `MemBuffer.isInitializedMemory()`'s default exactly: Java probes with `getByte(0)`
    /// and reports whether it threw. Overriding with a cheaper check is fine where the
    /// implementation can answer directly.
    fn is_initialized_memory(&self) -> bool {
        self.get_byte(0).is_ok()
    }

    /// Whether the buffer's own address is initialized.
    ///
    /// Stands in for `buf.getMemory().getAllInitializedAddressSet().contains(buf.getAddress())`,
    /// which callers used before `Memory`'s address-set queries were ported. Kept as a defaulted
    /// method so those call sites survive the consolidation unchanged.
    fn is_at_initialized_memory_address(&self) -> bool {
        self.is_initialized_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct ArrayBuffer {
        bytes: Vec<u8>,
    }

    fn addr(offset: i64) -> Address {
        Address::new(
            AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1),
            offset,
        )
    }

    impl MemBuffer for ArrayBuffer {
        fn get_address(&self) -> Address {
            addr(0x1000)
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let n = buf.len().min(self.bytes.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    #[test]
    fn reads_bytes_and_reports_short_reads() {
        let b = ArrayBuffer { bytes: vec![1, 2, 3] };
        assert_eq!(b.get_byte(1).unwrap(), 2);
        let mut out = [0u8; 5];
        assert_eq!(b.get_bytes(&mut out, 1), 2, "a short read reports its length");
        assert_eq!(&out[..2], &[2, 3]);
    }

    #[test]
    fn get_byte_past_the_end_is_an_error_not_a_panic() {
        let b = ArrayBuffer { bytes: vec![1] };
        assert!(b.get_byte(9).is_err());
    }

    /// Java's default probes with `getByte(0)`; an empty buffer must therefore report
    /// uninitialized rather than claiming success.
    #[test]
    fn is_initialized_memory_follows_the_java_default() {
        assert!(ArrayBuffer { bytes: vec![7] }.is_initialized_memory());
        assert!(!ArrayBuffer { bytes: vec![] }.is_initialized_memory());
    }

    #[test]
    fn a_buffer_without_backing_memory_reports_none() {
        assert!(ArrayBuffer { bytes: vec![1] }.get_memory().is_none());
    }

    #[test]
    fn usable_as_a_trait_object() {
        let b: Arc<dyn MemBuffer> = Arc::new(ArrayBuffer { bytes: vec![9] });
        assert_eq!(b.get_address(), addr(0x1000));
        assert!(b.is_big_endian());
    }
}
