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
//! # With and without a program
//!
//! Java's constructors that take a `Program` route labels, symbols, references, block names and
//! out-of-cache byte reads through that program; without one (the path the emulator and
//! `Disassembler.pseudoDisassembleBlock` take) those answer "nothing" or throw
//! `UnsupportedOperationException`. Both paths are ported: [`PseudoCodeUnit::with_program`] keeps
//! a shared `Arc<dyn Program>` and asks it for its managers per call (Java caches the reference
//! manager at construction; the program's manager handles are short-lived locks, see
//! `OWNERSHIP_MIGRATION.md`, "Program manager access (2026-09-26)"). Java's `UnsupportedOperation`
//! and `IllegalArgument` exceptions are unchecked, so they panic here with Java's reason.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::lang::register::Register;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException};
use crate::program::model::symbol::{
    ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
};

/// `Reference.MNEMONIC`: the operand index of a mnemonic reference.
const MNEMONIC: i32 = -1;

/// Java's `UnsupportedOperationException` for an operation that needs the code unit's program
/// (or its reference manager) when it has none.
pub(crate) fn unsupported(operation: &str) -> ! {
    panic!("UnsupportedOperationException: {operation} is not supported by a pseudo code unit without a program")
}

/// Java's `UnsupportedOperationException` for an operation no pseudo code unit supports.
pub(crate) fn unsupported_always(operation: &str) -> ! {
    panic!("UnsupportedOperationException: {operation} is not supported by a pseudo code unit")
}

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
/// Port of the fields and concrete methods of `ghidra.app.util.PseudoCodeUnit` (see the module
/// docs for the program-attached path).
#[derive(Clone)]
pub struct PseudoCodeUnit {
    program: Option<Arc<dyn Program>>,
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
            program: None,
            address: addr,
            max_address,
            length,
            bytes,
            is_big_endian: mem_buffer.is_big_endian(),
            comments: HashMap::new(),
        })
    }

    /// Port of `PseudoCodeUnit(Program, Address, int, int, MemBuffer)`: as
    /// [`with_cache_length`](Self::with_cache_length), within `program` (Java accepts a `null`
    /// program, which is the program-less unit).
    ///
    /// # Errors
    /// As [`PseudoCodeUnit::new`].
    pub fn with_program(
        program: Option<Arc<dyn Program>>,
        addr: Address,
        length: i32,
        cache_length: i32,
        mem_buffer: &dyn MemBuffer,
    ) -> Result<Self, PseudoCodeUnitError> {
        let mut unit = Self::with_cache_length(addr, length, cache_length, mem_buffer)?;
        unit.program = program;
        Ok(unit)
    }

    /// Port of `getProgram()`: the program this unit is in, if any.
    pub fn program(&self) -> Option<&Arc<dyn Program>> {
        self.program.as_ref()
    }

    /// Port of `getMemory()`: the program's memory, if there is a program.
    pub fn memory(&self) -> Option<Arc<dyn Memory>> {
        self.program.as_ref()?.get_memory()
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

    /// Port of `getAddressString(boolean, boolean)`: with `show_block_name` and a program, the
    /// address is prefixed with the name of the memory block containing it.
    pub fn address_string(&self, show_block_name: bool, pad: bool) -> String {
        // Java: `address.toString(false, pad)`. `Address::format` clamps the digit count to the
        // space's own width, so an oversized request means "pad fully".
        let address_string = self.address.format(false, if pad { 64 } else { 1 });
        if show_block_name {
            if let Some(block) = self.memory().and_then(|memory| memory.get_block(&self.address)) {
                return format!("{}:{address_string}", block.get_name());
            }
        }
        address_string
    }

    /// Port of `getBytes()`: the unit's `length` bytes.
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes[..(self.length as usize).min(self.bytes.len())].to_vec()
    }

    /// Port of `getBytes(byte[], int)`.
    ///
    /// Without a program: copies what the cache holds from `offset` and returns the count (0 for
    /// an offset outside the cache). Java computes that count but then copies `b.length` bytes,
    /// throwing `ArrayIndexOutOfBoundsException` when `b` extends past the cache; this copies the
    /// count it reports, which is the partial fill the Java comment describes.
    ///
    /// With a program, a request the cache cannot satisfy completely is read from the program's
    /// memory instead (0 if that fails), as in Java.
    pub fn read_bytes(&self, b: &mut [u8], offset: i32) -> usize {
        if let Some(program) = &self.program {
            if offset < 0 || offset as usize + b.len() > self.bytes.len() {
                let Some(memory) = program.get_memory() else {
                    return 0;
                };
                return match self.address.add(i64::from(offset)) {
                    Ok(start) => memory.get_bytes(&start, b),
                    Err(_) => 0,
                };
            }
            let offset = offset as usize;
            let len = b.len();
            b.copy_from_slice(&self.bytes[offset..offset + len]);
            return len;
        }
        if offset < 0 || offset as usize >= self.bytes.len() {
            return 0;
        }
        let offset = offset as usize;
        let len = b.len().min(self.bytes.len() - offset);
        b[..len].copy_from_slice(&self.bytes[offset..offset + len]);
        len
    }

    /// Port of `getByte(int)`: a byte from the cache, or -- for an offset outside it -- from the
    /// program's memory.
    ///
    /// # Errors
    /// A [`MemoryAccessException`] for an offset outside the cache when there is no program (with
    /// Java's message), or when the program's memory cannot supply the byte.
    pub fn byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        if offset < 0 || offset as usize >= self.bytes.len() {
            let Some(program) = &self.program else {
                return Err(MemoryAccessException::new(
                    "Pseduo code unit has null program - memory request out of range",
                ));
            };
            let memory = program
                .get_memory()
                .ok_or_else(|| MemoryAccessException::new("program has no memory"))?;
            let addr = self
                .address
                .add(i64::from(offset))
                .map_err(|e| MemoryAccessException::new(e.to_string()))?;
            return memory.get_byte(&addr);
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

    // ----- symbols and neighbours, through the program -----

    /// Port of the deprecated `getLabel()`: the name of the primary symbol at this address, or
    /// `None` without a program.
    pub fn label(&self) -> Option<String> {
        self.primary_symbol().map(|symbol| symbol.get_name().to_string())
    }

    /// Port of `getSymbols()`: the symbols at this address (Java returns `null`, here empty,
    /// without a program).
    pub fn symbols(&self) -> Vec<Arc<dyn Symbol>> {
        let Some(program) = &self.program else {
            return Vec::new();
        };
        let symbols = program
            .get_symbol_table()
            .and_then(|table| table.get_symbols(&self.address).ok())
            .unwrap_or_default();
        symbols
    }

    /// Port of `getPrimarySymbol()`.
    pub fn primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        let program = self.program.as_ref()?;
        let symbol = program.get_symbol_table()?.get_primary_symbol(&self.address).ok().flatten();
        symbol
    }

    /// Port of `getNextCodeUnit()`: the program listing's code unit after this address.
    pub fn next_code_unit(&self) -> Option<Arc<dyn CodeUnit>> {
        let program = self.program.as_ref()?;
        let code_unit = program.get_listing()?.get_code_unit_after(&self.address);
        code_unit
    }

    /// Port of `getPreviousCodeUnit()`: the program listing's code unit before this address.
    pub fn previous_code_unit(&self) -> Option<Arc<dyn CodeUnit>> {
        let program = self.program.as_ref()?;
        let code_unit = program.get_listing()?.get_code_unit_before(&self.address);
        code_unit
    }

    // ----- references, through the program's reference manager -----

    /// Whether Java's `refMgr` would be non-null: there is a program, and it has a reference
    /// manager.
    fn has_reference_manager(&self) -> bool {
        self.program.as_ref().is_some_and(|program| program.get_reference_manager().is_some())
    }

    /// Runs `f` against the program's reference manager, or reports Java's
    /// `UnsupportedOperationException` for `operation` when there is none.
    fn with_reference_manager<T>(
        &self,
        operation: &str,
        f: impl FnOnce(&mut dyn crate::program::model::symbol::ReferenceManager) -> T,
    ) -> T {
        let Some(program) = &self.program else {
            unsupported(operation)
        };
        let Some(mut ref_mgr) = program.get_reference_manager() else {
            unsupported(operation)
        };
        f(&mut *ref_mgr)
    }

    /// Port of `addMnemonicReference(Address, RefType, SourceType)`.
    ///
    /// # Panics
    /// Without a reference manager (Java's `UnsupportedOperationException`).
    pub fn add_mnemonic_reference(&self, ref_addr: Address, ref_type: RefType, source_type: SourceType) {
        self.with_reference_manager("addMnemonicReference", |ref_mgr| {
            ref_mgr.add_memory_reference(self.address.clone(), ref_addr, ref_type, source_type, MNEMONIC);
        });
    }

    /// Port of `getMnemonicReferences()`: empty without a reference manager.
    pub fn mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        self.operand_references(MNEMONIC)
    }

    /// Port of `removeMnemonicReference(Address)`.
    ///
    /// # Panics
    /// Without a reference manager (Java's `UnsupportedOperationException`).
    pub fn remove_mnemonic_reference(&self, ref_addr: &Address) {
        self.remove_reference("removeMnemonicReference", MNEMONIC, ref_addr);
    }

    /// Port of `addOperandReference(int, Address, RefType, SourceType)`.
    ///
    /// # Panics
    /// Without a reference manager (Java's `UnsupportedOperationException`).
    pub fn add_operand_reference(&self, op_index: i32, ref_addr: Address, ref_type: RefType, source_type: SourceType) {
        self.with_reference_manager("addOperandReference", |ref_mgr| {
            ref_mgr.add_memory_reference(self.address.clone(), ref_addr, ref_type, source_type, op_index);
        });
    }

    /// Port of `PseudoCodeUnit.getOperandReferences(int)`: the reference manager's references from
    /// the operand, empty without one. (`PseudoInstruction` overrides this with references computed
    /// from its prototype.)
    pub fn operand_references(&self, op_index: i32) -> Vec<Arc<dyn Reference>> {
        let Some(program) = &self.program else {
            return Vec::new();
        };
        let references = program
            .get_reference_manager()
            .map(|ref_mgr| ref_mgr.get_references_from_operand(self.address.clone(), op_index))
            .unwrap_or_default();
        references
    }

    /// Port of `removeOperandReference(int, Address)`.
    ///
    /// # Panics
    /// Without a reference manager (Java's `UnsupportedOperationException`).
    pub fn remove_operand_reference(&self, op_index: i32, ref_addr: &Address) {
        self.remove_reference("removeOperandReference", op_index, ref_addr);
    }

    fn remove_reference(&self, operation: &str, op_index: i32, ref_addr: &Address) {
        self.with_reference_manager(operation, |ref_mgr| {
            if let Some(reference) = ref_mgr.get_reference(self.address.clone(), ref_addr.clone(), op_index) {
                ref_mgr.delete(reference);
            }
        });
    }

    /// The reference-manager half of `getReferencesFrom()`: every reference from this address, or
    /// `None` without a reference manager (the caller then collects its operands' references, as
    /// Java does).
    pub fn references_from(&self) -> Option<Vec<Arc<dyn Reference>>> {
        let program = self.program.as_ref()?;
        let references = program.get_reference_manager()?.get_references_from(self.address.clone());
        Some(references)
    }

    /// Java's private `validateOpIndex(int)`.
    fn validate_op_index(op_index: i32, num_operands: i32) {
        if op_index >= num_operands {
            panic!("IllegalArgumentException: Invalid operand index [{op_index}] specified");
        }
    }

    /// Port of `setStackReference(int, int, SourceType, RefType)`; `num_operands` is the
    /// instruction's operand count (Java's virtual `getNumOperands()`).
    ///
    /// # Panics
    /// Without a reference manager (`UnsupportedOperationException`), or for an operand index
    /// past the last operand (`IllegalArgumentException`).
    pub fn set_stack_reference(
        &self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: RefType,
        num_operands: i32,
    ) {
        if !self.has_reference_manager() {
            unsupported("setStackReference")
        }
        Self::validate_op_index(op_index, num_operands);
        self.with_reference_manager("setStackReference", |ref_mgr| {
            ref_mgr.add_stack_reference(self.address.clone(), op_index, offset, ref_type, source_type);
        });
    }

    /// Port of `setRegisterReference(int, Register, SourceType, RefType)`; see
    /// [`set_stack_reference`](Self::set_stack_reference) for `num_operands` and the panics.
    pub fn set_register_reference(
        &self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: RefType,
        num_operands: i32,
    ) {
        if !self.has_reference_manager() {
            unsupported("setRegisterReference")
        }
        Self::validate_op_index(op_index, num_operands);
        self.with_reference_manager("setRegisterReference", |ref_mgr| {
            ref_mgr.add_register_reference(self.address.clone(), op_index, reg, ref_type, source_type);
        });
    }

    /// Port of `getPrimaryReference(int)`.
    pub fn primary_reference(&self, index: i32) -> Option<Arc<dyn Reference>> {
        let program = self.program.as_ref()?;
        let reference = program.get_reference_manager()?.get_primary_reference_from(self.address.clone(), index);
        reference
    }

    /// Port of `setPrimaryMemoryReference(Reference)`.
    ///
    /// # Panics
    /// Without a reference manager (Java's `UnsupportedOperationException`).
    pub fn set_primary_memory_reference(&self, reference: Arc<dyn Reference>) {
        self.with_reference_manager("setPrimaryMemoryReference", |ref_mgr| ref_mgr.set_primary(reference, true));
    }

    /// Port of `getExternalReference(int)`: the first external reference from the operand.
    pub fn external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        let program = self.program.as_ref()?;
        let references = program
            .get_reference_manager()?
            .get_references_from_operand(self.address.clone(), op_index);
        references
            .into_iter()
            .find(|reference| reference.is_external_reference())
            .and_then(|reference| reference.to_external_reference())
    }

    /// Port of `getReferenceIteratorTo()`: the references to this address, or `None` (Java's
    /// `null`) without a reference manager.
    pub fn reference_iterator_to(&self) -> Option<Box<dyn ReferenceIterator>> {
        let program = self.program.as_ref()?;
        let references = program.get_reference_manager()?.get_references_to(self.address.clone());
        Some(references)
    }

    /// Port of `setExternalReference(Reference)`, which always throws.
    pub fn set_external_reference(&self, _reference: Arc<dyn Reference>) {
        unsupported_always("setExternalReference")
    }

    /// Port of `setMemoryReference(int, Address, RefType)`, which always throws.
    pub fn set_memory_reference(&self, _op_index: i32, _ref_addr: Address, _ref_type: RefType) {
        unsupported_always("setMemoryReference")
    }

    /// Port of `getStackReference(int)`, which always answers `null`.
    pub fn stack_reference(&self, _op_index: i32) -> Option<Arc<dyn Reference>> {
        None
    }

    /// Port of `removeStackReference(int)`, which always throws.
    pub fn remove_stack_reference(&self, _op_index: i32) {
        unsupported_always("removeStackReference")
    }

    /// Port of `removeExternalReference(int)`, which always throws.
    pub fn remove_external_reference(&self, _op_index: i32) {
        unsupported_always("removeExternalReference")
    }
}

impl fmt::Debug for PseudoCodeUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PseudoCodeUnit")
            .field("has_program", &self.program.is_some())
            .field("address", &self.address)
            .field("max_address", &self.max_address)
            .field("length", &self.length)
            .field("bytes", &self.bytes)
            .field("is_big_endian", &self.is_big_endian)
            .field("comments", &self.comments)
            .finish()
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
    fn a_unit_without_a_program_answers_program_queries_with_nothing() {
        let cu = unit(0x100, 2, 2, &[1, 2]);
        assert!(cu.program().is_none());
        assert!(cu.memory().is_none());
        assert_eq!(cu.label(), None);
        assert!(cu.symbols().is_empty());
        assert!(cu.primary_symbol().is_none());
        assert!(cu.next_code_unit().is_none());
        assert!(cu.previous_code_unit().is_none());
        assert!(cu.mnemonic_references().is_empty());
        assert!(cu.operand_references(0).is_empty());
        assert!(cu.references_from().is_none());
        assert!(cu.primary_reference(0).is_none());
        assert!(cu.external_reference(0).is_none());
        assert!(cu.reference_iterator_to().is_none());
        assert!(cu.stack_reference(0).is_none());
        // `with_program(None, ..)` is the same unit
        let mem = ByteMemBufferImpl::new(addr(0x100), vec![1, 2], true);
        let same = PseudoCodeUnit::with_program(None, addr(0x100), 2, 2, &mem).unwrap();
        assert!(same.program().is_none());
        assert_eq!(same.bytes(), cu.bytes());
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException: removeStackReference is not supported by a pseudo code unit")]
    fn remove_stack_reference_always_throws() {
        unit(0, 1, 1, &[0]).remove_stack_reference(0);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException: setPrimaryMemoryReference")]
    fn setting_a_primary_reference_needs_a_program() {
        let cu = unit(0x100, 1, 1, &[0]);
        let reference: Arc<dyn Reference> = Arc::new(crate::program::model::symbol::MemReferenceImpl::new(
            addr(0x100),
            addr(0x200),
            RefType::Data,
            SourceType::UserDefined,
            0,
            true,
        ));
        cu.set_primary_memory_reference(reference);
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
