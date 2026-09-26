//! A proposed mapping of trace regions to program memory blocks.
//!
//! Port of `ghidra.debug.api.modules.RegionMapProposal`, including its nested
//! `RegionMapProposal.RegionMapEntry` interface.

use std::sync::Arc;

use super::map_entry::MapEntry;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlock;
use crate::trace::model::memory::trace_memory_region::{SetLengthError, TraceMemoryRegion};
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;

/// A single entry of a [`RegionMapProposal`], mapping one trace region to one program memory block.
///
/// Port of `ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry`.
///
/// Note: In the Java API, `RegionMapProposal` is a marker interface that extends
/// `MapProposal<TraceMemoryRegion, MemoryBlock, RegionMapEntry>`. In Rust, since `RegionMapProposal`
/// adds no methods, we just use `MapProposal` directly and expose `RegionMapEntry` as the specialized
/// entry type for region mappings.
pub trait RegionMapEntry: MapEntry {
    /// Get the region for this entry.
    fn get_region(&self) -> Box<dyn TraceMemoryRegion>;

    /// Get the region's name (may depend on the snap).
    fn get_region_name(&self) -> String;

    /// Get the region's minimum address (may depend on the snap).
    fn get_region_min_address(&self) -> Address;

    /// Get the matched memory block.
    fn get_block(&self) -> Arc<dyn MemoryBlock>;

    /// Set the matched memory block.
    fn set_block(&mut self, program: Arc<dyn Program>, block: Arc<dyn MemoryBlock>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::util::ProgramLocation;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_location::TraceLocation;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "static.exe".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockProgramLocation;
    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> Address {
            addr(0x1000)
        }
        fn get_byte_address(&self) -> Address {
            addr(0x1000)
        }
    }

    struct MockTraceLocation;
    impl TraceLocation for MockTraceLocation {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn crate::trace::model::thread::trace_thread::TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::ALL
        }
        fn get_address(&self) -> Address {
            addr(0x2000)
        }
    }

    struct MockTraceMemoryRegion;
    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockTraceMemoryRegion {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::trace::model::target::iface::TraceObjectInterface for MockTraceMemoryRegion {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl TraceMemoryRegion for MockTraceMemoryRegion {
        fn trace_object_info() -> TraceObjectInfo
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name_at(&mut self, _snap: i64, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            ".text".to_string()
        }
        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_range_at(
            &mut self,
            _snap: i64,
            _range: AddressRange,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self, _snap: i64) -> AddressRange {
            AddressRange::new(addr(0x1000), addr(0x1fff))
        }
        fn set_min_address(
            &mut self,
            _snap: i64,
            _min: Address,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_min_address(&self, _snap: i64) -> Address {
            addr(0x1000)
        }
        fn set_max_address(
            &mut self,
            _snap: i64,
            _max: Address,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_address(&self, _snap: i64) -> Address {
            addr(0x1fff)
        }
        fn set_length(
            &mut self,
            _snap: i64,
            _length: u64,
        ) -> Result<(), SetLengthError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_length(&self, _snap: i64) -> u64 {
            0x1000
        }
        fn set_flags(&mut self, _lifespan: Lifespan, _flags: &[crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_flags_at(&mut self, _snap: i64, _flags: &[crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_flags(&mut self, _lifespan: Lifespan, _flags: &[crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_flags_at(&mut self, _snap: i64, _flags: &[crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_flags(&mut self, _lifespan: Lifespan, _flags: &[crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_flags_at(&mut self, _snap: i64, _flags: &[crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_flags(&self, _snap: i64) -> std::collections::HashSet<crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_read(&mut self, _snap: i64, _read: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_read(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_write(&mut self, _snap: i64, _write: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_write(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_execute(&mut self, _snap: i64, _execute: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_execute(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_volatile(&mut self, _snap: i64, _vol: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_volatile(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn delete(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove(&mut self, _snap: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_valid(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockMemoryBlock;
    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            ".text"
        }
        fn get_start(&self) -> Address {
            addr(0x1000)
        }
        fn get_end(&self) -> Address {
            addr(0x1fff)
        }
        fn get_size(&self) -> u64 {
            0x1000
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn contains(&self, addr: &Address) -> bool {
            addr.offset() >= 0x1000 && addr.offset() <= 0x1fff
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_read(&self) -> bool {
            true
        }
        fn is_write(&self) -> bool {
            true
        }
        fn is_execute(&self) -> bool {
            true
        }
        fn get_comment(&self) -> Option<&str> {
            None
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_artificial(&self) -> bool {
            false
        }
        fn set_artificial(&mut self, _artificial: bool) {}
        fn get_type(&self) -> crate::program::model::mem::MemoryBlockType {
            crate::program::model::mem::MemoryBlockType::Default
        }
        fn get_source_infos(&self) -> Vec<Arc<dyn crate::program::model::mem::MemoryBlockSourceInfo>> {
            vec![]
        }
    }

    struct MockRegionMapEntry {
        region_name: String,
        region_range: AddressRange,
    }
    impl MapEntry for MockRegionMapEntry {
        fn get_from_trace(&self) -> &dyn Trace {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_from_object(&self) -> Box<dyn Any> {
            Box::new(MockTraceMemoryRegion)
        }
        fn get_from_range(&self) -> &AddressRange {
            &self.region_range
        }
        fn get_from_lifespan(&self) -> Lifespan {
            Lifespan::ALL
        }
        fn get_from_trace_location(&self) -> Box<dyn TraceLocation> {
            Box::new(MockTraceLocation)
        }
        fn get_to_program(&self) -> &dyn Program {
            &MockProgram
        }
        fn get_to_object(&self) -> Box<dyn Any> {
            Box::new(MockMemoryBlock)
        }
        fn get_to_range(&self) -> &AddressRange {
            &self.region_range
        }
        fn get_to_program_location(&self) -> &dyn ProgramLocation {
            &MockProgramLocation
        }
        fn get_mapping_length(&self) -> i64 {
            self.region_range.length() as i64
        }
    }
    impl RegionMapEntry for MockRegionMapEntry {
        fn get_region(&self) -> Box<dyn TraceMemoryRegion> {
            Box::new(MockTraceMemoryRegion)
        }
        fn get_region_name(&self) -> String {
            self.region_name.clone()
        }
        fn get_region_min_address(&self) -> Address {
            self.region_range.min_address().clone()
        }
        fn get_block(&self) -> Arc<dyn MemoryBlock> {
            Arc::new(MockMemoryBlock)
        }
        fn set_block(&mut self, _program: Arc<dyn Program>, _block: Arc<dyn MemoryBlock>) {}
    }

    #[test]
    fn region_map_entry_exposes_region_name_and_address() {
        let entry = MockRegionMapEntry {
            region_name: ".text".to_string(),
            region_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
        };

        assert_eq!(entry.get_region_name(), ".text");
        assert_eq!(entry.get_region_min_address(), addr(0x1000));
        assert_eq!(entry.get_mapping_length(), 0x1000);
    }

    #[test]
    fn region_map_entry_reflects_block() {
        let entry = MockRegionMapEntry {
            region_name: ".text".to_string(),
            region_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
        };

        assert_eq!(entry.get_block().get_name(), ".text");
        assert_eq!(entry.get_region_name(), ".text");
    }
}
