//! Trait ported from the abstract class `ghidra.program.database.mem.SubMemoryBlock`.
//!
//! In Java, `SubMemoryBlock` is a package-private abstract base class used by `MemoryBlockDB` to
//! store and fetch the bytes making up a `MemoryBlock`; concrete subclasses (buffer-backed,
//! bit-mapped, byte-mapped, uninitialized, file-bytes-backed) each hold their own
//! `MemoryMapDBAdapter`/`DBRecord` state and implement the byte-access primitives. That
//! constructor-injected state is an implementation detail of each concrete sub block, not part of
//! the public contract, so it is not represented on this trait: implementors own whatever storage
//! (adapter/record, in-memory buffer, etc.) they need internally.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::io;
use std::sync::Arc;

use crate::program::model::mem::{MemoryAccessException, MemoryBlock, MemoryBlockSourceInfo, MemoryBlockType};
use crate::program::database::mem::file_bytes::FileBytes;

/// Error type aggregating the checked exceptions thrown by Java's `SubMemoryBlock` byte-access
/// and mutation methods (`IndexOutOfBoundsException`, `IllegalArgumentException`,
/// `MemoryAccessException`, `IOException`).
#[derive(Debug)]
pub enum SubMemoryBlockError {
    /// Mirrors `IndexOutOfBoundsException`: the requested offset is outside this sub block.
    IndexOutOfBounds(String),
    /// Mirrors `IllegalArgumentException`: the requested offset is not in this block.
    IllegalArgument(String),
    /// Mirrors `MemoryAccessException`: the block (or requested bytes) is uninitialized.
    MemoryAccess(MemoryAccessException),
    /// Mirrors `IOException`: a database error occurred.
    Io(io::Error),
}

impl fmt::Display for SubMemoryBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds(msg) => write!(f, "index out of bounds: {msg}"),
            Self::IllegalArgument(msg) => write!(f, "illegal argument: {msg}"),
            Self::MemoryAccess(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl Error for SubMemoryBlockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::MemoryAccess(err) => Some(err),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<MemoryAccessException> for SubMemoryBlockError {
    fn from(err: MemoryAccessException) -> Self {
        Self::MemoryAccess(err)
    }
}

impl From<io::Error> for SubMemoryBlockError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Interface for the various types of memory block sections. They are used by a `MemoryBlockDB`
/// to do the actual storing and fetching of the bytes that make up a `MemoryBlock`.
pub trait SubMemoryBlock: Send + Sync {
    /// Returns whether this block has been initialized (has byte values).
    fn is_initialized(&self) -> bool;

    /// Returns the id of the `MemoryBlockDB` object that owns this sub block.
    fn get_parent_block_id(&self) -> i64;

    /// Returns the starting offset for this sub block. In other words, the first byte in this
    /// sub block is at this starting offset relative to the containing `MemoryBlockDB`.
    fn get_starting_offset(&self) -> i64;

    /// Returns the length of this sub block.
    fn get_length(&self) -> i64;

    /// Returns true if the given `MemoryBlockDB` offset is in this sub block.
    fn contains(&self, mem_block_offset: i64) -> bool {
        let start = self.get_starting_offset();
        mem_block_offset >= start && mem_block_offset < start + self.get_length()
    }

    /// Returns the byte in this sub block corresponding to the given offset relative to the
    /// containing `MemoryBlockDB`.
    fn get_byte(&self, mem_block_offset: i64) -> Result<u8, SubMemoryBlockError>;

    /// Tries to get `len` bytes from this block at the given offset (relative to the containing
    /// `MemoryBlockDB`) and put them into the given byte array at the specified offset. May
    /// return fewer bytes if the requested length is beyond the end of the block. Returns the
    /// number of bytes actually populated.
    fn get_bytes(
        &self,
        mem_block_offset: i64,
        b: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, SubMemoryBlockError>;

    /// Stores the byte in this sub block at the given offset relative to the containing
    /// `MemoryBlockDB`.
    fn put_byte(&mut self, mem_block_offset: i64, b: u8) -> Result<(), SubMemoryBlockError>;

    /// Tries to write `len` bytes to this block at the given offset (relative to the containing
    /// `MemoryBlockDB`) using the bytes contained in the given byte array at the specified byte
    /// array offset. May write fewer bytes if the requested length is beyond the end of the
    /// block. Returns the number of bytes actually written.
    fn put_bytes(
        &mut self,
        mem_block_offset: i64,
        b: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, SubMemoryBlockError>;

    /// Deletes this sub memory block.
    fn delete(&mut self) -> io::Result<()>;

    /// Sets the length of a sub-block (used by the split command).
    fn set_length(&mut self, length: i64) -> io::Result<()>;

    /// Attempts to join the given `SubMemoryBlock` with this block if possible. Returns true if
    /// the given block was successfully merged into this one.
    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> io::Result<bool>;

    /// Returns true if this is either a bit-mapped or byte-mapped block.
    fn is_mapped(&self) -> bool {
        false
    }

    /// Get the `MemoryBlockType` for this block: `Default`, `BitMapped`, or `ByteMapped`.
    fn get_type(&self) -> MemoryBlockType {
        MemoryBlockType::Default
    }

    /// Returns the `MemoryBlockSourceInfo` object for this sub block.
    ///
    /// `block` is the `MemoryBlock` that this sub block belongs to.
    fn get_source_info(&self, block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo>;

    /// Splits this sub block into two memory blocks. `mem_block_offset` is the offset relative to
    /// the owning `MemoryBlock` (not this sub block); to get the offset relative to this sub
    /// block, subtract this sub block's starting offset. Returns the new sub block that contains
    /// the back half of this block.
    fn split(&mut self, mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError>;

    /// Updates this sub block to have a new owning `MemoryBlock` id and offset within that block.
    /// This is used when splitting a block and entire sub blocks have to be moved to the new
    /// split block.
    fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()>;

    /// Returns a description of this sub block suitable to be displayed to the user.
    fn get_description(&self) -> String;

    /// Returns true if this sub block uses the given `FileBytes` as its byte source.
    fn uses(&self, file_bytes: &dyn FileBytes) -> bool {
        let _ = file_bytes;
        false
    }

    /// Mirrors `Comparable<SubMemoryBlock>.compareTo`, ordering by starting offset.
    fn compare_to(&self, other: &dyn SubMemoryBlock) -> Ordering {
        self.get_starting_offset().cmp(&other.get_starting_offset())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal in-memory `SubMemoryBlock` used to prove the trait is object-safe and that its
    /// default methods behave correctly against real (non-trivial) state.
    struct MockSubMemoryBlock {
        offset: i64,
        bytes: Vec<u8>,
        initialized: bool,
    }

    impl MockSubMemoryBlock {
        fn new(offset: i64, len: usize) -> Self {
            Self {
                offset,
                bytes: vec![0u8; len],
                initialized: true,
            }
        }
    }

    impl SubMemoryBlock for MockSubMemoryBlock {
        fn is_initialized(&self) -> bool {
            self.initialized
        }

        fn get_parent_block_id(&self) -> i64 {
            0
        }

        fn get_starting_offset(&self) -> i64 {
            self.offset
        }

        fn get_length(&self) -> i64 {
            self.bytes.len() as i64
        }

        fn get_byte(&self, mem_block_offset: i64) -> Result<u8, SubMemoryBlockError> {
            if !self.contains(mem_block_offset) {
                return Err(SubMemoryBlockError::IndexOutOfBounds(format!(
                    "{mem_block_offset} not in block"
                )));
            }
            if !self.initialized {
                return Err(MemoryAccessException::new("uninitialized").into());
            }
            Ok(self.bytes[(mem_block_offset - self.offset) as usize])
        }

        fn get_bytes(
            &self,
            mem_block_offset: i64,
            b: &mut [u8],
            off: usize,
            len: usize,
        ) -> Result<usize, SubMemoryBlockError> {
            if !self.contains(mem_block_offset) {
                return Err(SubMemoryBlockError::IllegalArgument(format!(
                    "{mem_block_offset} not in block"
                )));
            }
            let start = (mem_block_offset - self.offset) as usize;
            let available = self.bytes.len() - start;
            let n = len.min(available);
            b[off..off + n].copy_from_slice(&self.bytes[start..start + n]);
            Ok(n)
        }

        fn put_byte(&mut self, mem_block_offset: i64, b: u8) -> Result<(), SubMemoryBlockError> {
            if !self.contains(mem_block_offset) {
                return Err(SubMemoryBlockError::IndexOutOfBounds(format!(
                    "{mem_block_offset} not in block"
                )));
            }
            self.bytes[(mem_block_offset - self.offset) as usize] = b;
            Ok(())
        }

        fn put_bytes(
            &mut self,
            mem_block_offset: i64,
            b: &[u8],
            off: usize,
            len: usize,
        ) -> Result<usize, SubMemoryBlockError> {
            if !self.contains(mem_block_offset) {
                return Err(SubMemoryBlockError::IllegalArgument(format!(
                    "{mem_block_offset} not in block"
                )));
            }
            let start = (mem_block_offset - self.offset) as usize;
            let available = self.bytes.len() - start;
            let n = len.min(available);
            self.bytes[start..start + n].copy_from_slice(&b[off..off + n]);
            Ok(n)
        }

        fn delete(&mut self) -> io::Result<()> {
            self.bytes.clear();
            Ok(())
        }

        fn set_length(&mut self, length: i64) -> io::Result<()> {
            self.bytes.resize(length as usize, 0);
            Ok(())
        }

        fn join(&mut self, other: &mut dyn SubMemoryBlock) -> io::Result<bool> {
            if other.get_starting_offset() != self.offset + self.get_length() {
                return Ok(false);
            }
            let other_len = other.get_length() as usize;
            let mut merged = vec![0u8; other_len];
            other
                .get_bytes(other.get_starting_offset(), &mut merged, 0, other_len)
                .expect("mock join read should succeed");
            self.bytes.extend_from_slice(&merged);
            Ok(true)
        }

        fn get_source_info(&self, block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
            // Not exercised by these smoke tests; MemoryBlockSourceInfoDB is not yet ported.
            let _ = block;
            unimplemented!("source info construction requires MemoryBlockSourceInfoDB")
        }

        fn split(&mut self, mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
            if !self.contains(mem_block_offset) {
                return Err(SubMemoryBlockError::IndexOutOfBounds(format!(
                    "{mem_block_offset} not in block"
                )));
            }
            let split_at = (mem_block_offset - self.offset) as usize;
            let back = self.bytes.split_off(split_at);
            let new_block = MockSubMemoryBlock {
                offset: mem_block_offset,
                bytes: back,
                initialized: self.initialized,
            };
            Ok(Box::new(new_block))
        }

        fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
            let _ = key;
            self.offset = starting_offset;
            Ok(())
        }

        fn get_description(&self) -> String {
            "mock sub memory block".to_string()
        }
    }

    #[test]
    fn contains_uses_offset_and_length() {
        let block = MockSubMemoryBlock::new(10, 5);
        assert!(!block.contains(9));
        assert!(block.contains(10));
        assert!(block.contains(14));
        assert!(!block.contains(15));
    }

    #[test]
    fn put_and_get_byte_round_trip() {
        let mut block = MockSubMemoryBlock::new(0, 4);
        block.put_byte(2, 0xAB).unwrap();
        assert_eq!(block.get_byte(2).unwrap(), 0xAB);
        assert_eq!(block.get_byte(0).unwrap(), 0);
    }

    #[test]
    fn get_byte_out_of_bounds_is_index_error() {
        let block = MockSubMemoryBlock::new(0, 4);
        let err = block.get_byte(100).unwrap_err();
        assert!(matches!(err, SubMemoryBlockError::IndexOutOfBounds(_)));
    }

    #[test]
    fn get_bytes_clamps_to_available_length() {
        let mut block = MockSubMemoryBlock::new(0, 4);
        block.put_bytes(0, &[1, 2, 3, 4], 0, 4).unwrap();
        let mut dest = [0u8; 10];
        let n = block.get_bytes(2, &mut dest, 0, 10).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&dest[..2], &[3, 4]);
    }

    #[test]
    fn split_moves_back_half_into_new_block() {
        let mut block = MockSubMemoryBlock::new(0, 4);
        block.put_bytes(0, &[10, 20, 30, 40], 0, 4).unwrap();
        let mut back = block.split(2).unwrap();

        assert_eq!(block.get_length(), 2);
        assert_eq!(back.get_length(), 2);
        assert_eq!(back.get_starting_offset(), 2);
        assert_eq!(back.get_byte(2).unwrap(), 30);
        assert_eq!(back.get_byte(3).unwrap(), 40);

        // exercise as a trait object to prove object-safety end to end
        let dyn_back: &mut dyn SubMemoryBlock = back.as_mut();
        assert_eq!(dyn_back.get_description(), "mock sub memory block");
    }

    #[test]
    fn join_merges_adjacent_block_and_rejects_non_adjacent() {
        let mut a = MockSubMemoryBlock::new(0, 2);
        a.put_bytes(0, &[1, 2], 0, 2).unwrap();
        let mut b = MockSubMemoryBlock::new(2, 2);
        b.put_bytes(2, &[3, 4], 0, 2).unwrap();

        assert!(a.join(&mut b).unwrap());
        assert_eq!(a.get_length(), 4);
        assert_eq!(a.get_byte(3).unwrap(), 4);

        let mut c = MockSubMemoryBlock::new(0, 2);
        let mut not_adjacent = MockSubMemoryBlock::new(99, 2);
        assert!(!c.join(&mut not_adjacent).unwrap());
    }

    #[test]
    fn compare_to_orders_by_starting_offset() {
        let low = MockSubMemoryBlock::new(0, 1);
        let high = MockSubMemoryBlock::new(10, 1);
        assert_eq!(low.compare_to(&high), Ordering::Less);
        assert_eq!(high.compare_to(&low), Ordering::Greater);
        assert_eq!(low.compare_to(&low), Ordering::Equal);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let boxed: Box<dyn SubMemoryBlock> = Box::new(MockSubMemoryBlock::new(0, 3));
        assert!(boxed.is_initialized());
        assert!(!boxed.is_mapped());
        assert_eq!(boxed.get_type(), MemoryBlockType::Default);
    }
}
