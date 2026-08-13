use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock};

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
}
