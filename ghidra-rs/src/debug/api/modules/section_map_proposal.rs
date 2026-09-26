//! A proposed mapping of trace sections to program memory blocks.
//!
//! Port of `ghidra.debug.api.modules.SectionMapProposal`, including its nested
//! `SectionMapProposal.SectionMapEntry` interface.

use std::sync::Arc;

use super::map_entry::MapEntry;
use super::map_proposal::MapProposal;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlock;
use crate::trace::model::modules::trace_module::TraceModule;
use crate::trace::model::modules::trace_section::TraceSection;

/// A single entry of a [`SectionMapProposal`], mapping one trace section to one program memory
/// block.
///
/// Port of `ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry`.
pub trait SectionMapEntry: MapEntry {
    /// Get the section for this entry.
    fn get_section(&self) -> Box<dyn TraceSection>;

    /// Get the section name for this entry (may depend on the snap).
    fn get_section_name(&self) -> String;

    /// Get the start address of the section (may depend on the snap).
    fn get_section_start(&self) -> Address;

    /// Get the module containing the section.
    fn get_module(&self) -> Box<dyn TraceModule>;

    /// Get the name of the module containing the section (may depend on the snap).
    fn get_module_name(&self) -> String;

    /// Get the matched memory block.
    fn get_block(&self) -> Arc<dyn MemoryBlock>;

    /// Set the matched memory block.
    fn set_block(&mut self, program: Arc<dyn Program>, block: Arc<dyn MemoryBlock>);
}

/// A proposed mapping of trace sections to program memory blocks.
///
/// Port of `ghidra.debug.api.modules.SectionMapProposal`.
pub trait SectionMapProposal: MapProposal {
    /// Get the trace module of this proposal.
    fn get_module(&self) -> Box<dyn TraceModule>;
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

    struct MockTraceModule;
    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockTraceModule {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::trace::model::target::iface::TraceObjectInterface for MockTraceModule {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl TraceModule for MockTraceModule {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_section(
            &mut self,
            _snap: i64,
            _section_path: &str,
            _section_name: Option<&str>,
            _range: AddressRange,
        ) -> Result<
            Box<dyn TraceSection>,
            crate::util::exception::DuplicateNameException,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_section_default_name(
            &mut self,
            _snap: i64,
            _section_path: &str,
            _range: AddressRange,
        ) -> Result<
            Box<dyn TraceSection>,
            crate::util::exception::DuplicateNameException,
        > {
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
            "libc.so.6".to_string()
        }
        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_range_at(&mut self, _snap: i64, _range: AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self, _snap: i64) -> AddressRange {
            AddressRange::new(addr(0x1000), addr(0x1fff))
        }
        fn set_base(&mut self, _snap: i64, _base: Address) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_max_address(&mut self, _snap: i64, _max: Address) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_address(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_length(
            &mut self,
            _snap: i64,
            _length: i64,
        ) -> Result<(), crate::program::model::address::AddressOverflowException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_length(&self, _snap: i64) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_sections(&self, _snap: i64) -> Vec<Box<dyn TraceSection>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_section_by_name(
            &self,
            _snap: i64,
            _section_name: &str,
        ) -> Option<Box<dyn TraceSection>> {
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
        fn is_alive(&self, _span: Lifespan) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockTraceSection;
    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockTraceSection {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::trace::model::target::iface::TraceObjectInterface for MockTraceSection {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl TraceSection for MockTraceSection {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module(&self) -> Box<dyn TraceModule> {
            Box::new(MockTraceModule)
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name_at(
            &mut self,
            _snap: i64,
            _name: &str,
        ) -> Result<(), crate::util::exception::DuplicateNameException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            ".text".to_string()
        }
        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self, _snap: i64) -> Option<AddressRange> {
            Some(AddressRange::new(addr(0x1000), addr(0x1fff)))
        }
        fn get_start(&self, _snap: i64) -> Option<Address> {
            Some(addr(0x1000))
        }
        fn get_end(&self, _snap: i64) -> Option<Address> {
            Some(addr(0x1fff))
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

    struct MockSectionMapEntry {
        section_range: AddressRange,
    }
    impl MapEntry for MockSectionMapEntry {
        fn get_from_trace(&self) -> &dyn Trace {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_from_object(&self) -> Box<dyn Any> {
            Box::new(MockTraceSection)
        }
        fn get_from_range(&self) -> &AddressRange {
            &self.section_range
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
            &self.section_range
        }
        fn get_to_program_location(&self) -> &dyn ProgramLocation {
            &MockProgramLocation
        }
        fn get_mapping_length(&self) -> i64 {
            self.section_range.length() as i64
        }
    }
    impl SectionMapEntry for MockSectionMapEntry {
        fn get_section(&self) -> Box<dyn TraceSection> {
            Box::new(MockTraceSection)
        }
        fn get_section_name(&self) -> String {
            MockTraceSection.get_name(0)
        }
        fn get_section_start(&self) -> Address {
            self.section_range.min_address().clone()
        }
        fn get_module(&self) -> Box<dyn TraceModule> {
            Box::new(MockTraceModule)
        }
        fn get_module_name(&self) -> String {
            MockTraceModule.get_name(0)
        }
        fn get_block(&self) -> Arc<dyn MemoryBlock> {
            Arc::new(MockMemoryBlock)
        }
        fn set_block(&mut self, _program: Arc<dyn Program>, _block: Arc<dyn MemoryBlock>) {}
    }

    struct MockSectionMapProposal {
        score: f64,
    }
    impl MapProposal for MockSectionMapProposal {
        fn get_trace(&self) -> &dyn Trace {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program(&self) -> &dyn Program {
            &MockProgram
        }
        fn get_to_object(&self, _from: &dyn Any) -> Box<dyn Any> {
            Box::new(())
        }
        fn compute_score(&self) -> f64 {
            self.score
        }
        fn compute_map(&self) -> Vec<(Box<dyn Any>, Box<dyn MapEntry>)> {
            vec![]
        }
    }
    impl SectionMapProposal for MockSectionMapProposal {
        fn get_module(&self) -> Box<dyn TraceModule> {
            Box::new(MockTraceModule)
        }
    }

    #[test]
    fn section_map_proposal_is_object_safe() {
        let proposals: Vec<Box<dyn SectionMapProposal>> = vec![];
        assert_eq!(proposals.len(), 0);
    }

    #[test]
    fn section_map_proposal_exposes_score_and_module() {
        let proposal: Box<dyn SectionMapProposal> = Box::new(MockSectionMapProposal { score: 0.75 });

        assert_eq!(proposal.compute_score(), 0.75);
        assert_eq!(proposal.get_module().get_name(0), "libc.so.6");
    }

    #[test]
    fn section_map_entry_reflects_section_and_module() {
        let mut entry = MockSectionMapEntry {
            section_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
        };

        assert_eq!(entry.get_section_name(), ".text");
        assert_eq!(entry.get_section_start(), addr(0x1000));
        assert_eq!(entry.get_module_name(), "libc.so.6");
        assert_eq!(entry.get_mapping_length(), 0x1000);

        entry.set_block(Arc::new(MockProgram), Arc::new(MockMemoryBlock));
        assert_eq!(entry.get_block().get_name(), ".text");
    }
}
