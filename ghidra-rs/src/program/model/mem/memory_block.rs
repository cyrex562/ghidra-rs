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

    /// Sets the read permission. Stands in for `MemoryBlock.setRead(boolean)`; the default
    /// discards the request, matching [`is_read`](Self::is_read)'s constant `false`.
    fn set_read(&mut self, read: bool) {
        let _ = read;
    }

    /// Sets the write permission. Stands in for `MemoryBlock.setWrite(boolean)`; the default
    /// discards the request, matching [`is_write`](Self::is_write)'s constant `false`.
    fn set_write(&mut self, write: bool) {
        let _ = write;
    }

    /// Sets the execute permission. Stands in for `MemoryBlock.setExecute(boolean)`; the default
    /// discards the request, matching [`is_execute`](Self::is_execute)'s constant `false`.
    fn set_execute(&mut self, execute: bool) {
        let _ = execute;
    }

    /// Sets the comment associated with this block. Stands in for
    /// `MemoryBlock.setComment(String)`; the default discards the request, matching
    /// [`get_comment`](Self::get_comment)'s constant `None`.
    fn set_comment(&mut self, comment: Option<&str>) {
        let _ = comment;
    }

    /// Returns the name of the source of this block (e.g. the loader that created it), if any.
    /// Stands in for `MemoryBlock.getSourceName()`.
    fn get_source_name(&self) -> Option<&str> {
        None
    }

    /// Sets the name of the source of this block. Stands in for
    /// `MemoryBlock.setSourceName(String)`; the default discards the request, matching
    /// [`get_source_name`](Self::get_source_name)'s constant `None`.
    fn set_source_name(&mut self, source_name: Option<&str>) {
        let _ = source_name;
    }

    /// Returns whether this block lives in an overlay address space. Stands in for
    /// `MemoryBlock.isOverlay()`, which is `getStart().getAddressSpace().isOverlaySpace()`; this
    /// port's [`AddressSpace`](crate::program::model::address::AddressSpace) has no overlay
    /// variant yet, so the default is `false`.
    fn is_overlay(&self) -> bool {
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
