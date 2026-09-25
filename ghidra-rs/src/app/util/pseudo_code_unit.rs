//! Port of `ghidra.app.util.PseudoCodeUnit`.
//!
//! Java's `PseudoCodeUnit` is the abstract base of the "fake" code units the pseudo-disassembler
//! and the emulator produce: code units that act like listing code units but are backed by a
//! private copy of their bytes rather than by a program's listing. Per `shape_rules.py` (an
//! abstract class with instance fields) the shared state is a struct; the class's only abstract
//! member is `equals(Object)`, so there is no abstract behaviour left for a trait to declare.
//! [`PseudoInstruction`](crate::app::util::pseudo_instruction::PseudoInstruction) composes it.
//!
//! # A snapshot, not a cache
//!
//! In the arena design (`OWNERSHIP_MIGRATION.md`, "Instruction/CodeUnit arena (2026-09-25)") a
//! pseudo code unit *owns* its snapshot: the bytes are copied from the source buffer at
//! construction and never re-read. Java's `invalidate()`/`isValid()`/`refreshIfNeeded()` exist to
//! re-read those bytes from a program's memory after an edit; that is the staleness scaffolding
//! convention 3 retires, and it is not ported. A caller that wants current bytes decodes again.
//!
//! # Program-attached code units are not ported here
//!
//! Java's constructors that take a `Program` route labels, symbols, references, block names and
//! out-of-cache byte reads through that program. The ported `Program` reaches its
//! `ReferenceManager` and `Listing` only through `&mut self`, which a code unit holding a shared
//! handle cannot call; those queries land with the program arena, where they become lookups
//! against a program snapshot by address. Every method here is the `program == null` path of the
//! Java class, which is the path the emulator and `Disassembler.pseudoDisassembleBlock` use.

use std::collections::HashMap;

use thiserror::Error;

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};

/// Why a pseudo code unit could not be built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PseudoCodeUnitError {
    /// Java's `IllegalArgumentException("non-zero positive length required")`.
    #[error("non-zero positive length required")]
    NonPositiveLength,
    /// The code unit's last byte would fall outside its address space.
    #[error("{0}")]
    AddressOverflow(AddressOverflowException),
}

impl From<AddressOverflowException> for PseudoCodeUnitError {
    fn from(e: AddressOverflowException) -> Self {
        PseudoCodeUnitError::AddressOverflow(e)
    }
}

/// The state shared by pseudo code units: an address range, a private copy of the bytes at and
/// after it, the byte order, and comments.
///
/// Port of the fields and concrete methods of `ghidra.app.util.PseudoCodeUnit`, for a code unit
/// with no program (see the module docs).
#[derive(Debug, Clone)]
pub struct PseudoCodeUnit {
    address: Address,
    max_address: Address,
    length: i32,
    /// The byte cache, which may be longer than `length` (an instruction caches its delay slots
    /// and the bytes sleigh may read past its end). Bytes the source could not supply are 0.
    bytes: Vec<u8>,
    is_big_endian: bool,
    comments: HashMap<CommentType, String>,
}

impl PseudoCodeUnit {
    /// Port of `PseudoCodeUnit(Address, int, MemBuffer)`: caches exactly `length` bytes.
    ///
    /// # Errors
    /// [`PseudoCodeUnitError::NonPositiveLength`] if `length <= 0`;
    /// [`PseudoCodeUnitError::AddressOverflow`] if the unit would run off its address space.
    pub fn new(addr: Address, length: i32, mem_buffer: &dyn MemBuffer) -> Result<Self, PseudoCodeUnitError> {
        Self::with_cache_length(addr, length, length, mem_buffer)
    }

    /// Port of `PseudoCodeUnit(Address, int, int, MemBuffer)`: a unit of `length` bytes caching
    /// `cache_length` bytes from `mem_buffer` (which is positioned at `addr`). Bytes the buffer
    /// cannot supply read as 0, as in Java.
    ///
    /// # Errors
    /// As [`PseudoCodeUnit::new`].
    pub fn with_cache_length(
        addr: Address,
        length: i32,
        cache_length: i32,
        mem_buffer: &dyn MemBuffer,
    ) -> Result<Self, PseudoCodeUnitError> {
        if length <= 0 {
            return Err(PseudoCodeUnitError::NonPositiveLength);
        }
        let max_address = addr.add_no_wrap(i64::from(length - 1))?;
        let mut bytes = vec![0u8; cache_length.max(0) as usize];
        mem_buffer.get_bytes(&mut bytes, 0); // unavailable bytes will be 0
        Ok(Self {
            address: addr,
            max_address,
            length,
            bytes,
            is_big_endian: mem_buffer.is_big_endian(),
            comments: HashMap::new(),
        })
    }

    /// Port of `getMinAddress()` / `getAddress()`.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Port of `getMaxAddress()`.
    pub fn max_address(&self) -> &Address {
        &self.max_address
    }

    /// Port of the final `getLength()`.
    pub fn length(&self) -> i32 {
        self.length
    }

    /// The whole byte cache, including any bytes past [`length`](Self::length).
    pub fn cached_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Port of `isBigEndian()`.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// Port of `getAddressString(boolean, boolean)` without a program: there is no memory block
    /// to name, so `show_block_name` has no effect.
    pub fn address_string(&self, _show_block_name: bool, pad: bool) -> String {
        // Java: `address.toString(false, pad)`. `Address::format` clamps the digit count to the
        // space's own width, so an oversized request means "pad fully".
        self.address.format(false, if pad { 64 } else { 1 })
    }

    /// Port of `getBytes()`: the unit's `length` bytes.
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes[..(self.length as usize).min(self.bytes.len())].to_vec()
    }

    /// Port of `getBytes(byte[], int)` without a program: copies what the cache holds from
    /// `offset` and returns the count (0 for an offset outside the cache).
    ///
    /// Java computes that count but then copies `b.length` bytes, throwing
    /// `ArrayIndexOutOfBoundsException` when `b` extends past the cache; this copies the count it
    /// reports, which is the partial fill the Java comment describes.
    pub fn read_bytes(&self, b: &mut [u8], offset: i32) -> usize {
        if offset < 0 || offset as usize >= self.bytes.len() {
            return 0;
        }
        let offset = offset as usize;
        let len = b.len().min(self.bytes.len() - offset);
        b[..len].copy_from_slice(&self.bytes[offset..offset + len]);
        len
    }

    /// Port of `getByte(int)` without a program.
    ///
    /// # Errors
    /// A [`MemoryAccessException`] for an offset outside the cache, with Java's message.
    pub fn byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        if offset < 0 || offset as usize >= self.bytes.len() {
            return Err(MemoryAccessException::new(
                "Pseduo code unit has null program - memory request out of range",
            ));
        }
        Ok(self.bytes[offset as usize])
    }

    /// Port of `getBytesInCodeUnit(byte[], int)`: copies `min(buffer.len(), length)` bytes of
    /// the unit into `buffer` at `buffer_offset`.
    ///
    /// # Errors
    /// A [`MemoryAccessException`] where Java's `System.arraycopy` would throw
    /// `IndexOutOfBoundsException`: the copy does not fit in `buffer` at `buffer_offset`.
    pub fn bytes_in_code_unit(&self, buffer: &mut [u8], buffer_offset: i32) -> Result<(), MemoryAccessException> {
        let count = buffer.len().min(self.length as usize).min(self.bytes.len());
        let start = usize::try_from(buffer_offset)
            .ok()
            .filter(|start| start + count <= buffer.len())
            .ok_or_else(|| {
                MemoryAccessException::new(format!(
                    "{count} bytes do not fit in a buffer of {} at offset {buffer_offset}",
                    buffer.len()
                ))
            })?;
        buffer[start..start + count].copy_from_slice(&self.bytes[..count]);
        Ok(())
    }

    /// Port of `contains(Address)`: whether `test_addr` lies in `[address, address + length - 1]`
    /// (the end computed with wrap-around, as Java's `addWrap`).
    pub fn contains(&self, test_addr: &Address) -> bool {
        let end_addr = self.address.add_wrap(i64::from(self.length - 1));
        self.address <= *test_addr && *test_addr <= end_addr
    }

    /// Port of `compareTo(Address)`: 0 inside the unit, else the start address compared with
    /// `addr` (`-1`/`1`).
    pub fn compare_to(&self, addr: &Address) -> i32 {
        if self.contains(addr) {
            return 0;
        }
        match self.address.cmp(addr) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// Port of `getComment(CommentType)`.
    pub fn comment(&self, comment_type: CommentType) -> Option<String> {
        self.comments.get(&comment_type).cloned()
    }

    /// Port of `getCommentAsArray(CommentType)`: the comment as a one-element array, or empty.
    pub fn comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        self.comment(comment_type).into_iter().collect()
    }

    /// Port of `setComment(CommentType, String)`. Java stores `null` as a value, which reads back
    /// as no comment; here `None` removes the entry.
    pub fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        match comment {
            Some(c) => {
                self.comments.insert(comment_type, c);
            }
            None => {
                self.comments.remove(&comment_type);
            }
        }
    }

    /// Port of `setCommentAsArray(CommentType, String[])`: only the first element is kept. An
    /// empty array clears the comment (Java would throw `ArrayIndexOutOfBoundsException`).
    pub fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
        self.set_comment(comment_type, comment.first().cloned());
    }
}

impl MemBuffer for PseudoCodeUnit {
    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.byte(offset)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.read_bytes(buf, offset)
    }

    fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::ByteMemBufferImpl;

    fn addr(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    fn unit(offset: i64, length: i32, cache: i32, bytes: &[u8]) -> PseudoCodeUnit {
        let mem = ByteMemBufferImpl::new(addr(offset), bytes.to_vec(), true);
        PseudoCodeUnit::with_cache_length(addr(offset), length, cache, &mem).unwrap()
    }

    #[test]
    fn caches_bytes_zero_filling_what_the_source_lacks() {
        let cu = unit(0x100, 2, 5, &[0xde, 0xad, 0xbe]);
        assert_eq!(cu.cached_bytes(), &[0xde, 0xad, 0xbe, 0, 0]);
        assert_eq!(cu.bytes(), vec![0xde, 0xad]);
        assert_eq!(cu.length(), 2);
        assert_eq!(cu.max_address().offset(), 0x101);
        assert!(cu.is_big_endian());
        assert_eq!(cu.get_short(0).unwrap(), 0xdeadu16 as i16);
    }

    #[test]
    fn rejects_empty_and_overflowing_units() {
        let mem = ByteMemBufferImpl::new(addr(0), vec![1], true);
        assert_eq!(
            PseudoCodeUnit::new(addr(0), 0, &mem).unwrap_err(),
            PseudoCodeUnitError::NonPositiveLength
        );
        let top = addr(0xffff_ffff);
        let mem = ByteMemBufferImpl::new(top.clone(), vec![1, 2], true);
        assert!(matches!(
            PseudoCodeUnit::new(top, 2, &mem),
            Err(PseudoCodeUnitError::AddressOverflow(_))
        ));
    }

    #[test]
    fn byte_reads_are_limited_to_the_cache() {
        let cu = unit(0x100, 2, 3, &[1, 2, 3, 4]);
        assert_eq!(cu.get_byte(2).unwrap(), 3);
        assert!(cu.get_byte(3).is_err());
        assert!(cu.get_byte(-1).is_err());
        let mut b = [0u8; 8];
        assert_eq!(cu.get_bytes(&mut b, 1), 2);
        assert_eq!(&b[..2], &[2, 3]);
        assert_eq!(cu.get_bytes(&mut b, 3), 0);
        let mut into = [9u8; 4];
        cu.bytes_in_code_unit(&mut into, 1).unwrap();
        assert_eq!(into, [9, 1, 2, 9]);
        assert!(cu.bytes_in_code_unit(&mut into, 3).is_err());
    }

    #[test]
    fn contains_and_compare_to_use_the_unit_range() {
        let cu = unit(0x100, 4, 4, &[0; 4]);
        assert!(cu.contains(&addr(0x100)));
        assert!(cu.contains(&addr(0x103)));
        assert!(!cu.contains(&addr(0x104)));
        assert_eq!(cu.compare_to(&addr(0x102)), 0);
        assert_eq!(cu.compare_to(&addr(0x200)), -1);
        assert_eq!(cu.compare_to(&addr(0x10)), 1);
        assert_eq!(cu.address_string(false, false), "100");
        assert_eq!(cu.address_string(false, true), "00000100");
    }

    #[test]
    fn comments_are_kept_per_type() {
        let mut cu = unit(0, 1, 1, &[0]);
        assert_eq!(cu.comment(CommentType::Eol), None);
        cu.set_comment(CommentType::Eol, Some("hi".into()));
        cu.set_comment_as_array(CommentType::Pre, &["a".into(), "b".into()]);
        assert_eq!(cu.comment(CommentType::Eol).as_deref(), Some("hi"));
        assert_eq!(cu.comment_as_array(CommentType::Pre), vec!["a".to_string()]);
        cu.set_comment(CommentType::Eol, None);
        assert!(cu.comment_as_array(CommentType::Eol).is_empty());
    }
}
