use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::{MemoryAccessException, MemoryBlockType, MemoryBlockSourceInfo};
use std::sync::Arc;

/// Name of the block a loader creates to hold otherwise-unresolved external symbols.
///
/// Stands in for `MemoryBlock.EXTERNAL_BLOCK_NAME`.
pub const EXTERNAL_BLOCK_NAME: &str = "EXTERNAL";

pub trait MemoryBlock: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_start(&self) -> Address;
    fn get_end(&self) -> Address;
    fn get_size(&self) -> u64;
    fn is_initialized(&self) -> bool;

    /// Returns true if the given address is contained in this block.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities)'s port of
    /// `DataUtilities.isUndefinedRange`.
    fn contains(&self, addr: &Address) -> bool {
        AddressRange::new(self.get_start(), self.get_end()).contains(addr)
    }

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

    /// Marks this block as artificial (or not). Stands in for `MemoryBlock.setArtificial(boolean)`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`UnixAoutProgramLoader`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader),
    /// which marks the block it synthesizes for undefined symbols artificial. The default
    /// discards the request, matching [`is_artificial`](Self::is_artificial)'s constant `false`.
    fn set_artificial(&mut self, artificial: bool) {
        let _ = artificial;
    }

    /// Marks this block as volatile (or not). Stands in for `MemoryBlock.setVolatile(boolean)`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`MemoryMapSarifMgr`](crate::sarif::managers::memory_map_sarif_mgr::MemoryMapSarifMgr)'s
    /// port of `MemoryMapSarifMgr.processMemoryBlock`, which restores the `isVolatile` flag SARIF
    /// recorded for a block onto the block it (re)creates. The default discards the request,
    /// matching [`is_volatile`](Self::is_volatile)'s constant `false`.
    fn set_volatile(&mut self, volatile: bool) {
        let _ = volatile;
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
