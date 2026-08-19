//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor`.
//!
//! Holds information about a call frame: the exception-handling memory block it lives in, the
//! instruction-pointer range it protects, its LSDA table, and the FDE that describes it.
//!
//! # Divergences from the Java
//!
//! * **No `Address.NO_ADDRESS` sentinel.** The Java field defaults to `new
//!   AddressRangeImpl(Address.NO_ADDRESS, Address.NO_ADDRESS)`; the ported [`Address`] has no such
//!   sentinel (see the same divergence in
//!   [`GccExceptionAnalyzer`](crate::app::plugin::exceptionhandlers::gcc::GccExceptionAnalyzer)),
//!   so `ip_range` defaults to `None` instead, and [`RegionDescriptor::get_range_start`]/
//!   [`RegionDescriptor::get_range_size`] answer `None`/`0` for the unset case rather than
//!   reporting a meaningless sentinel range.
//! * **`getLSDAAddress(Address)` keeps its unused parameter.** The Java getter declares an
//!   `Address addr` parameter it never reads -- every other getter on this class is zero-argument,
//!   so this is almost certainly a copy/paste mistake -- but this port preserves the signature
//!   faithfully rather than silently "fixing" the public API.
//! * **`getFrameDescriptorEntry()`/`getLSDATable()` return `Option`.** Java returns `null` when
//!   the field was never set (both start unset); the ported accessors return `Option` for that
//!   case instead of a bare, possibly-absent reference.
//! * **`LSDATable` is a stub.** It is not ported yet; [`seam_stubs::LSDATable`] models only the
//!   three accessors this type delegates to.

use std::sync::Arc;

use crate::app::seam_stubs::{
    FrameDescriptionEntry, LSDAActionTable, LSDACallSiteTable, LSDATable, LSDATypeTable,
};
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::mem::MemoryBlock;

/// RegionDescriptor holds information about a call frame.
///
/// Port of `class RegionDescriptor`.
pub struct RegionDescriptor {
    lsda_address: Option<Address>,
    lsda_table: Option<Arc<dyn LSDATable>>,
    fde: Option<Arc<dyn FrameDescriptionEntry>>,
    ip_range: Option<AddressRange>,
    eh_memory: Arc<dyn MemoryBlock>,
}

impl RegionDescriptor {
    /// Constructor for a region descriptor.
    ///
    /// Port of `RegionDescriptor(MemoryBlock ehblock)`.
    pub fn new(eh_block: Arc<dyn MemoryBlock>) -> Self {
        RegionDescriptor {
            lsda_address: None,
            lsda_table: None,
            fde: None,
            ip_range: None,
            eh_memory: eh_block,
        }
    }

    /// Gets the exception handling memory block associated with this region.
    ///
    /// Port of `getEHMemoryBlock()`.
    pub fn get_eh_memory_block(&self) -> Arc<dyn MemoryBlock> {
        Arc::clone(&self.eh_memory)
    }

    /// Sets the address range of the IP (instructions) for this region.
    ///
    /// Port of `setIPRange(AddressRange)`.
    pub fn set_ip_range(&mut self, range: AddressRange) {
        self.ip_range = Some(range);
    }

    /// Gets the address range of the IP (instructions) for this region.
    ///
    /// Port of `getRange()`.
    pub fn get_range(&self) -> Option<AddressRange> {
        self.ip_range.clone()
    }

    /// Gets the start (minimum address) of the IP range for this region.
    ///
    /// Port of `getRangeStart()`.
    pub fn get_range_start(&self) -> Option<Address> {
        self.ip_range.as_ref().map(|range| range.min_address().clone())
    }

    /// Gets the size of the address range for the IP.
    ///
    /// Port of `getRangeSize()`.
    pub fn get_range_size(&self) -> u64 {
        self.ip_range.as_ref().map(|range| range.length()).unwrap_or(0)
    }

    /// Sets the address of the start of the LSDA.
    ///
    /// Port of `setLSDAAddress(Address)`.
    pub fn set_lsda_address(&mut self, addr: Address) {
        self.lsda_address = Some(addr);
    }

    /// Gets the address of the start of the LSDA. `addr` is unused, matching the Java signature
    /// -- see the module docs.
    ///
    /// Port of `getLSDAAddress(Address)`.
    pub fn get_lsda_address(&self, addr: &Address) -> Option<Address> {
        let _ = addr;
        self.lsda_address.clone()
    }

    /// Sets the LSDA table for this frame region.
    ///
    /// Port of `setLSDATable(LSDATable)`.
    pub fn set_lsda_table(&mut self, lsda_table: Arc<dyn LSDATable>) {
        self.lsda_table = Some(lsda_table);
    }

    /// Gets the LSDA table for this frame region.
    ///
    /// Port of `getLSDATable()`.
    pub fn get_lsda_table(&self) -> Option<Arc<dyn LSDATable>> {
        self.lsda_table.clone()
    }

    /// Gets the call site table for this region's frame.
    ///
    /// Port of `getCallSiteTable()`.
    pub fn get_call_site_table(&self) -> Option<Arc<LSDACallSiteTable>> {
        self.lsda_table.as_ref().and_then(|table| table.get_call_site_table())
    }

    /// Gets the action table for this region's frame, or `None` if it hasn't been set for this
    /// region.
    ///
    /// Port of `getActionTable()`.
    pub fn get_action_table(&self) -> Option<Arc<LSDAActionTable>> {
        self.lsda_table.as_ref().and_then(|table| table.get_action_table())
    }

    /// Gets the type table for this region's frame, or `None` if it hasn't been set for this
    /// region.
    ///
    /// Port of `getTypeTable()`.
    pub fn get_type_table(&self) -> Option<Arc<LSDATypeTable>> {
        self.lsda_table.as_ref().and_then(|table| table.get_type_table())
    }

    /// Sets the FDE associated with the region.
    ///
    /// Port of `setFrameDescriptorEntry(FrameDescriptionEntry)`.
    pub fn set_frame_descriptor_entry(&mut self, fde: Arc<dyn FrameDescriptionEntry>) {
        self.fde = Some(fde);
    }

    /// Gets the FDE associated with this region.
    ///
    /// Port of `getFrameDescriptorEntry()`.
    pub fn get_frame_descriptor_entry(&self) -> Option<Arc<dyn FrameDescriptionEntry>> {
        self.fde.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn ram_address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct StubBlock {
        name: &'static str,
    }
    impl MemoryBlock for StubBlock {
        fn get_name(&self) -> &str {
            self.name
        }
        fn get_start(&self) -> Address {
            ram_address(0)
        }
        fn get_end(&self) -> Address {
            ram_address(0)
        }
        fn get_size(&self) -> u64 {
            0
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn contains(&self, _addr: &Address) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Err(MemoryAccessException::new("no bytes"))
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only"))
        }
    }

    fn region() -> RegionDescriptor {
        RegionDescriptor::new(Arc::new(StubBlock { name: ".eh_frame" }))
    }

    #[test]
    fn constructor_stores_the_eh_memory_block() {
        let region = region();
        assert_eq!(region.get_eh_memory_block().get_name(), ".eh_frame");
    }

    #[test]
    fn range_accessors_default_to_the_unset_state() {
        let region = region();

        // Java defaults ipRange to a NO_ADDRESS/NO_ADDRESS sentinel range; the ported Address has
        // no such sentinel, so this port reports the unset state as None/0 instead.
        assert!(region.get_range().is_none());
        assert!(region.get_range_start().is_none());
        assert_eq!(region.get_range_size(), 0);
    }

    #[test]
    fn set_ip_range_round_trips_start_and_size() {
        let mut region = region();
        let range = AddressRange::new(ram_address(0x1000), ram_address(0x100f));

        region.set_ip_range(range.clone());

        assert_eq!(region.get_range(), Some(range.clone()));
        assert_eq!(region.get_range_start(), Some(ram_address(0x1000)));
        assert_eq!(region.get_range_size(), 0x10);
    }

    #[test]
    fn lsda_address_getter_ignores_its_argument() {
        let mut region = region();
        region.set_lsda_address(ram_address(0x2000));

        // Java's getLSDAAddress(Address) never reads its parameter; any address passed in must
        // still get back the stored lsdaAddress.
        assert_eq!(region.get_lsda_address(&ram_address(0x9999)), Some(ram_address(0x2000)));
    }

    #[test]
    fn lsda_address_defaults_to_none() {
        let region = region();
        assert!(region.get_lsda_address(&ram_address(0)).is_none());
    }

    #[test]
    fn table_accessors_are_none_without_an_lsda_table() {
        let region = region();

        assert!(region.get_lsda_table().is_none());
        assert!(region.get_call_site_table().is_none());
        assert!(region.get_action_table().is_none());
        assert!(region.get_type_table().is_none());
    }

    #[test]
    fn table_accessors_delegate_to_the_lsda_table() {
        struct StubTable {
            call_site_table: Arc<LSDACallSiteTable>,
            action_table: Arc<LSDAActionTable>,
            type_table: Arc<LSDATypeTable>,
        }
        impl LSDATable for StubTable {
            fn get_call_site_table(&self) -> Option<Arc<LSDACallSiteTable>> {
                Some(Arc::clone(&self.call_site_table))
            }
            fn get_action_table(&self) -> Option<Arc<LSDAActionTable>> {
                Some(Arc::clone(&self.action_table))
            }
            fn get_type_table(&self) -> Option<Arc<LSDATypeTable>> {
                Some(Arc::clone(&self.type_table))
            }
        }

        let mut region = region();
        let table = Arc::new(StubTable {
            call_site_table: Arc::new(LSDACallSiteTable::new(Vec::new())),
            action_table: Arc::new(LSDAActionTable::new(None, Vec::new())),
            type_table: Arc::new(LSDATypeTable::new(Vec::new())),
        });
        region.set_lsda_table(table);

        assert!(region.get_lsda_table().is_some());
        assert!(region.get_call_site_table().is_some());
        assert!(region.get_action_table().is_some());
        assert!(region.get_type_table().is_some());
    }

    #[test]
    fn frame_descriptor_entry_round_trips() {
        struct StubFde;
        impl FrameDescriptionEntry for StubFde {
            fn get_augmentation_ex_data_address(&self) -> Option<Address> {
                None
            }
        }

        let mut region = region();
        assert!(region.get_frame_descriptor_entry().is_none());

        region.set_frame_descriptor_entry(Arc::new(StubFde));
        assert!(region.get_frame_descriptor_entry().is_some());
    }
}
