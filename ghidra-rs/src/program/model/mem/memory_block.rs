use crate::program::model::address::Address;
use crate::program::model::mem::{MemoryAccessException, MemoryBlockType, MemoryBlockSourceInfo};
use std::sync::Arc;

pub trait MemoryBlock: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_start(&self) -> Address;
    fn get_end(&self) -> Address;
    fn get_size(&self) -> u64;
    fn is_initialized(&self) -> bool;

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException>;
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize;
    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException>;

    /// Returns the read permission state of this block.
    fn is_read(&self) -> bool {
        false
    }

    /// Returns the write permission state of this block.
    fn is_write(&self) -> bool {
        false
    }

    /// Returns the execute permission state of this block.
    fn is_execute(&self) -> bool {
        false
    }

    /// Returns the comment associated with this block, if any.
    fn get_comment(&self) -> Option<&str> {
        None
    }

    /// Returns whether this block is marked as volatile.
    fn is_volatile(&self) -> bool {
        false
    }

    /// Returns whether this block is marked as artificial.
    fn is_artificial(&self) -> bool {
        false
    }

    /// Returns the type of this memory block.
    fn get_type(&self) -> MemoryBlockType {
        MemoryBlockType::Default
    }

    /// Returns the source infos for this memory block.
    fn get_source_infos(&self) -> Vec<Arc<dyn MemoryBlockSourceInfo>> {
        Vec::new()
    }
}
