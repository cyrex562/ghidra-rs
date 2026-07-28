use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryAccessException;

pub trait Memory: Send + Sync {
    fn is_big_endian(&self) -> bool;
    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException>;
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize;
    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException>;

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
}
