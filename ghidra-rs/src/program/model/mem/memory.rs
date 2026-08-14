use std::sync::Arc;

use thiserror::Error;

use crate::framework::store::lock_exception::LockException;
use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::address::{Address, AddressSetView, AddressSetViewAdapter};
use crate::program::model::listing::Program;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock, MemoryConflictException};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

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
}
