use std::io::Read;
use std::sync::{Arc, RwLock};

use thiserror::Error;

use crate::framework::store::lock_exception::LockException;
use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::database::mem::byte_mapping_scheme::ByteMappingScheme;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView, AddressSetViewAdapter};
use crate::program::model::listing::Program;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock, MemoryConflictException};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Validate the given block name: cannot be empty and cannot contain a control character
/// (`< 0x20`).
///
/// Port of the static `Memory.isValidMemoryBlockName(String)`; `None` stands in for Java's `null`
/// argument at call sites that have one.
pub fn is_valid_memory_block_name(name: &str) -> bool {
    !name.is_empty() && name.encode_utf16().all(|c| c >= 0x20)
}

pub trait Memory: Send + Sync {
    fn is_big_endian(&self) -> bool;
    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException>;
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize;
    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException>;

    /// Get the memory block which contains the given address, or `None` if the address is not
    /// contained within any memory block.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities)'s ports of
    /// `getMaxAddressOfUndefinedRange`/`isUndefinedRange`.
    fn get_block(&self, addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
        let _ = addr;
        None
    }

    /// True if the given address lies within one of this memory's blocks.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DemangledObject`](crate::demangler::demangled_object::DemangledObject)'s port of
    /// `applyPlateCommentOnly`, which skips symbols outside program memory. Stands in for
    /// `Memory.contains(Address)`, which Java inherits from `AddressSetView`; this port's
    /// [`Memory`] has no such supertrait, so containment is answered from
    /// [`get_block`](Self::get_block).
    fn contains(&self, addr: &Address) -> bool {
        self.get_block(addr).is_some()
    }

    /// Get the program this memory belongs to, if any.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType)'s
    /// port of `PointerDataType.getAddressValue`, which needs it to resolve a named address
    /// space and an image-base-relative pointer's image base.
    fn get_program(&self) -> Option<Arc<dyn Program>> {
        None
    }

    /// Locate the address(es) within this memory that correspond to the given offset into the
    /// underlying file bytes, if any.
    ///
    /// Grown (defaulted) alongside [`get_program`](Self::get_program) for the same
    /// `PointerDataType.getAddressValue` port, which needs it to resolve a file-offset-relative
    /// pointer.
    fn locate_addresses_for_file_offset(&self, offset: i64) -> Vec<Address> {
        let _ = offset;
        Vec::new()
    }

    /// True if this memory has any backing file bytes.
    ///
    /// Grown (defaulted) alongside [`get_program`](Self::get_program) for the same
    /// `PointerDataType.getAddressValue` port, standing in for `!mem.getAllFileBytes().isEmpty()`.
    fn has_file_bytes(&self) -> bool {
        false
    }

    /// Get the memory block with the given name, or `None` if no block has that name.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`ElfInfoItem::read_item_from_section`](crate::format::elf::info::elf_info_item::read_item_from_section)'s
    /// port of `Memory.getBlock(String)`, used to locate a named section before reading an ELF
    /// info item out of it.
    fn get_block_by_name(&self, name: &str) -> Option<Arc<dyn MemoryBlock>> {
        let _ = name;
        None
    }

    /// Create an initialized memory block of `size` bytes at `start`, filled with
    /// `initial_value`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DecompileDebugFormatManager`](crate::app::util::opinion::decompile_debug_format_manager::DecompileDebugFormatManager)'s
    /// port of `parseSymbol`, which backs an unmapped data symbol with a zero-filled block so
    /// the Listing has bytes to show. Stands in for
    /// `Memory.createInitializedBlock(String, Address, long, byte, TaskMonitor, boolean)`.
    ///
    /// Defaults to refusing the request, so a memory that has not implemented block creation
    /// cannot silently report a block it did not create -- the same choice
    /// [`SymbolTable::get_or_create_name_space`](crate::program::model::symbol::SymbolTable::get_or_create_name_space)
    /// makes.
    fn create_initialized_block(
        &mut self,
        name: &str,
        start: &Address,
        size: u64,
        initial_value: u8,
        monitor: &dyn TaskMonitor,
        overlay: bool,
    ) -> Result<Arc<dyn MemoryBlock>, CreateBlockError> {
        let _ = (name, start, size, initial_value, monitor, overlay);
        Err(CreateBlockError::IllegalArgument(
            "block creation is not supported by this memory".to_string(),
        ))
    }

    /// Get all memory blocks that make up this memory.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`ProgramMemorySearcher`](crate::util::bytesearch::program_memory_searcher::ProgramMemorySearcher)'s
    /// port of `Memory.getBlocks()`, which searches each block independently.
    fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
        Vec::new()
    }

    /// Get the set of addresses that comprise the loaded, initialized memory (excludes `OTHER`
    /// space and any non-loaded overlay blocks).
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`ProgramMemorySearcher`](crate::util::bytesearch::program_memory_searcher::ProgramMemorySearcher)'s
    /// port of `Memory.getLoadedAndInitializedAddressSet()`.
    fn get_loaded_and_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(AddressSetViewAdapter::empty())
    }

    /// Get the set of addresses that comprise all initialized memory.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`ProgramMemorySearcher`](crate::util::bytesearch::program_memory_searcher::ProgramMemorySearcher)'s
    /// port of `Memory.getAllInitializedAddressSet()`.
    fn get_all_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(AddressSetViewAdapter::empty())
    }

    /// Set the write permission of the block starting at `block_start`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for the same `parseSymbol`
    /// port, which marks a generated block read-only when the symbol carried the `readonly`
    /// attribute. Stands in for `MemoryBlock.setWrite(boolean)`, keyed by the block's start
    /// address like [`SymbolTable::set_primary_symbol`](crate::program::model::symbol::SymbolTable::set_primary_symbol)
    /// is keyed by ID, since an `Arc<dyn MemoryBlock>` handed out by this trait cannot be
    /// mutated through.
    ///
    /// Defaults to doing nothing, matching a memory that does not model block permissions.
    fn set_block_write(&mut self, block_start: &Address, write: bool) {
        let _ = (block_start, write);
    }

    /// Create an initialized block of `length` bytes at `start` whose bytes are read from `is`
    /// (zero-filled once `is` runs out, or entirely when `is` is `None`).
    ///
    /// Stands in for `Memory.createInitializedBlock(String, Address, InputStream, long,
    /// TaskMonitor, boolean)`. Unlike [`create_initialized_block`](Self::create_initialized_block),
    /// the new block comes back as a shared, lockable [`MemoryBlockHandle`] -- the form a
    /// database-backed memory (`MemoryMapDB`) keeps its blocks in -- so a loader can set the
    /// block's permissions/comment afterwards, as Java's `MemoryBlockUtils` does.
    ///
    /// Defaults to refusing the request (see [`create_initialized_block`](Self::create_initialized_block)).
    fn create_initialized_block_from_stream(
        &mut self,
        name: &str,
        start: &Address,
        is: Option<&mut dyn Read>,
        length: i64,
        monitor: Option<&dyn TaskMonitor>,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (name, start, is, length, monitor, overlay);
        Err(unsupported())
    }

    /// Create an initialized block of `length` bytes at `start` backed by `file_bytes` starting
    /// at `offset`. Stands in for `Memory.createInitializedBlock(String, Address, FileBytes,
    /// long, long, boolean)`. Defaults to refusing the request.
    fn create_initialized_block_from_file_bytes(
        &mut self,
        name: &str,
        start: &Address,
        file_bytes: Arc<dyn FileBytes>,
        offset: i64,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (name, start, file_bytes, offset, length, overlay);
        Err(unsupported())
    }

    /// Create an uninitialized block of `length` bytes at `start`. Stands in for
    /// `Memory.createUninitializedBlock(String, Address, long, boolean)`. Defaults to refusing
    /// the request.
    fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: &Address,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (name, start, length, overlay);
        Err(unsupported())
    }

    /// Store `size` bytes read from `is` as the original bytes of the imported file `filename`
    /// (which started at `offset` within its container). Stands in for
    /// `Memory.createFileBytes(String, long, long, InputStream, TaskMonitor)`, whose
    /// `IOException`/`CancelledException` map to [`CreateBlockError::Io`]/
    /// [`CreateBlockError::Cancelled`]. Defaults to refusing the request.
    fn create_file_bytes(
        &mut self,
        filename: &str,
        offset: i64,
        size: i64,
        is: &mut dyn Read,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn FileBytes>, CreateBlockError> {
        let _ = (filename, offset, size, is, monitor);
        Err(unsupported())
    }

    /// Create a bit-mapped block over the bits of the bytes at `mapped_address`. Stands in for
    /// `Memory.createBitMappedBlock(String, Address, Address, long, boolean)`. Defaults to
    /// refusing the request.
    fn create_bit_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (name, start, mapped_address, length, overlay);
        Err(unsupported())
    }

    /// Create a byte-mapped block over the bytes at `mapped_address` (`None` scheme: 1:1). Stands
    /// in for `Memory.createByteMappedBlock(String, Address, Address, long, ByteMappingScheme,
    /// boolean)`. Defaults to refusing the request.
    fn create_byte_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: i64,
        byte_mapping_scheme: Option<ByteMappingScheme>,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (name, start, mapped_address, length, byte_mapping_scheme, overlay);
        Err(unsupported())
    }

    /// Create a block like `block` (same type, initialization and permissions). Stands in for
    /// `Memory.createBlock(MemoryBlock, String, Address, long)`. Defaults to refusing the
    /// request.
    fn create_block(
        &mut self,
        block: &MemoryBlockHandle,
        name: &str,
        start: &Address,
        length: i64,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (block, name, start, length);
        Err(unsupported())
    }

    /// Join two contiguous blocks into one. Stands in for `Memory.join(MemoryBlock,
    /// MemoryBlock)` (its `MemoryBlockException` is [`CreateBlockError::IllegalArgument`]).
    /// Defaults to refusing the request.
    fn join(
        &mut self,
        block_one: &MemoryBlockHandle,
        block_two: &MemoryBlockHandle,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        let _ = (block_one, block_two);
        Err(unsupported())
    }

    /// All stored file bytes. Stands in for `Memory.getAllFileBytes()`; defaults to none.
    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        Vec::new()
    }

    /// All blocks as shared handles, sorted on start address. Stands in for
    /// `Memory.getBlocks()` for a memory that keeps its blocks as [`MemoryBlockHandle`]s (where
    /// [`get_blocks`](Self::get_blocks) cannot hand them out). Defaults to none.
    fn get_block_handles(&self) -> Vec<MemoryBlockHandle> {
        Vec::new()
    }

    /// The block containing `addr` as a shared handle, or `None`. Stands in for
    /// `Memory.getBlock(Address)`; see [`get_block_handles`](Self::get_block_handles).
    fn get_block_handle(&self, addr: &Address) -> Option<MemoryBlockHandle> {
        self.get_block_handles().into_iter().find(|b| b.read().unwrap().contains(addr))
    }

    /// True if this memory has no blocks. Stands in for `Memory.isEmpty()` (inherited from
    /// `AddressSetView`).
    fn is_empty(&self) -> bool {
        self.get_block_handles().is_empty() && self.get_blocks().is_empty()
    }

    /// The addresses of `[start, end]` that lie within a block. Stands in for
    /// `Memory.intersectRange(Address, Address)` (inherited from `AddressSetView`).
    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        let mut set = AddressSet::new();
        for block in self.get_block_handles() {
            let b = block.read().unwrap();
            if let Some(r) = AddressRange::new(b.get_start(), b.get_end()).intersect_range(start, end) {
                set.add_range(r.min_address(), r.max_address());
            }
        }
        for b in self.get_blocks() {
            if let Some(r) = AddressRange::new(b.get_start(), b.get_end()).intersect_range(start, end) {
                set.add_range(r.min_address(), r.max_address());
            }
        }
        set
    }
}

/// A block shared by its owning memory map: [`MemoryBlock`] mutators (`set_read`, `set_comment`,
/// ...) take `&mut self`, so a block a loader may still need to adjust is handed out behind a
/// lock, which the memory map keeps the other `Arc` of.
pub type MemoryBlockHandle = Arc<RwLock<dyn MemoryBlock>>;

fn unsupported() -> CreateBlockError {
    CreateBlockError::IllegalArgument("block creation is not supported by this memory".to_string())
}

/// The failure modes of [`Memory::create_initialized_block`], collecting the exceptions Java's
/// `Memory.createInitializedBlock` declares (`LockException`, `MemoryConflictException`,
/// `AddressOverflowException`, `CancelledException`) plus its unchecked
/// `IllegalArgumentException`.
#[derive(Debug, Error)]
pub enum CreateBlockError {
    /// The program was not exclusively checked out / the memory could not be locked.
    #[error(transparent)]
    Lock(#[from] LockException),
    /// The new block would overlap an existing one.
    #[error(transparent)]
    Conflict(#[from] MemoryConflictException),
    /// `start + size` runs off the end of the address space.
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    /// The task monitor was cancelled while the block was being filled.
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    /// The request was rejected outright (Java's `IllegalArgumentException`).
    #[error("{0}")]
    IllegalArgument(String),
    /// The memory is in a state that forbids the request (Java's `IllegalStateException`, e.g.
    /// a size limit, or overlay creation where no overlay support exists).
    #[error("{0}")]
    IllegalState(String),
    /// A file-bytes range is out of bounds (Java's `IndexOutOfBoundsException`).
    #[error("{0}")]
    IndexOutOfBounds(String),
    /// A database / input error (Java's `IOException`).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::is_valid_memory_block_name;

    #[test]
    fn valid_memory_block_names_match_java() {
        assert!(is_valid_memory_block_name("__TEXT"));
        assert!(is_valid_memory_block_name(" "));
        assert!(!is_valid_memory_block_name(""));
        assert!(!is_valid_memory_block_name("a\0b"));
        assert!(!is_valid_memory_block_name("tab\there"));
        assert!(is_valid_memory_block_name("\u{7f}"));
    }
}
