//! A proposed mapping of a trace module to a program.
//!
//! Port of `ghidra.debug.api.modules.ModuleMapProposal`, including its nested
//! `ModuleMapProposal.ModuleMapEntry` interface.

use std::sync::Arc;

use super::map_entry::MapEntry;
use super::map_proposal::MapProposal;
use crate::program::model::address::AddressRange;
use crate::program::model::listing::Program;
use crate::trace::model::modules::trace_module::TraceModule;

/// A single entry of a [`ModuleMapProposal`], mapping one trace module to one program.
///
/// Port of `ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry`.
pub trait ModuleMapEntry: MapEntry {
    /// Get the module for this entry.
    fn get_module(&self) -> Box<dyn TraceModule>;

    /// Get the module name for this entry (may depend on the snap).
    fn get_module_name(&self) -> String;

    /// Get the address range of the module in the trace, as computed from the matched
    /// program's image size.
    fn get_module_range(&self) -> AddressRange;

    /// Set the matched program.
    ///
    /// This is generally used in UIs to let the user tweak and reassign, if desired. This will
    /// also re-compute the module range based on the new program's image size.
    fn set_program(&mut self, program: Arc<dyn Program>);

    /// Check if the user would like to memorize this mapping for future traces.
    fn is_memorize(&self) -> bool;

    /// Set whether this mapping should be memorized for future traces.
    fn set_memorize(&mut self, memorize: bool);
}

/// A proposed mapping of a trace module to a program.
///
/// Port of `ghidra.debug.api.modules.ModuleMapProposal`.
pub trait ModuleMapProposal: MapProposal {
    /// Get the trace module of this proposal.
    fn get_module(&self) -> Box<dyn TraceModule>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
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
            Box<dyn crate::trace::model::modules::trace_section::TraceSection>,
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
            Box<dyn crate::trace::model::modules::trace_section::TraceSection>,
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
        fn get_sections(
            &self,
            _snap: i64,
        ) -> Vec<Box<dyn crate::trace::model::modules::trace_section::TraceSection>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_sections(
            &self,
        ) -> Vec<Box<dyn crate::trace::model::modules::trace_section::TraceSection>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_section_by_name(
            &self,
            _snap: i64,
            _section_name: &str,
        ) -> Option<Box<dyn crate::trace::model::modules::trace_section::TraceSection>> {
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

    struct MockModuleMapEntry {
        module_range: AddressRange,
        memorize: bool,
    }
    impl MapEntry for MockModuleMapEntry {
        fn get_from_trace(&self) -> &dyn Trace {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_from_object(&self) -> Box<dyn Any> {
            Box::new(MockTraceModule)
        }
        fn get_from_range(&self) -> &AddressRange {
            &self.module_range
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
            Box::new(())
        }
        fn get_to_range(&self) -> &AddressRange {
            &self.module_range
        }
        fn get_to_program_location(&self) -> &dyn ProgramLocation {
            &MockProgramLocation
        }
        fn get_mapping_length(&self) -> i64 {
            self.module_range.length() as i64
        }
    }
    impl ModuleMapEntry for MockModuleMapEntry {
        fn get_module(&self) -> Box<dyn TraceModule> {
            Box::new(MockTraceModule)
        }
        fn get_module_name(&self) -> String {
            MockTraceModule.get_name(0)
        }
        fn get_module_range(&self) -> AddressRange {
            self.module_range.clone()
        }
        fn set_program(&mut self, _program: Arc<dyn Program>) {}
        fn is_memorize(&self) -> bool {
            self.memorize
        }
        fn set_memorize(&mut self, memorize: bool) {
            self.memorize = memorize;
        }
    }

    struct MockModuleMapProposal {
        score: f64,
    }
    impl MapProposal for MockModuleMapProposal {
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
    impl ModuleMapProposal for MockModuleMapProposal {
        fn get_module(&self) -> Box<dyn TraceModule> {
            Box::new(MockTraceModule)
        }
    }

    #[test]
    fn module_map_proposal_is_object_safe() {
        let proposals: Vec<Box<dyn ModuleMapProposal>> = vec![];
        assert_eq!(proposals.len(), 0);
    }

    #[test]
    fn module_map_proposal_exposes_score_and_module() {
        let proposal: Box<dyn ModuleMapProposal> = Box::new(MockModuleMapProposal { score: 0.75 });

        assert_eq!(proposal.compute_score(), 0.75);
        assert_eq!(proposal.get_module().get_name(0), "libc.so.6");
    }

    #[test]
    fn module_map_entry_reflects_memorize_and_range() {
        let mut entry = MockModuleMapEntry {
            module_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            memorize: false,
        };

        assert!(!entry.is_memorize());
        entry.set_memorize(true);
        assert!(entry.is_memorize());

        assert_eq!(entry.get_module_range(), entry.module_range);
        assert_eq!(entry.get_module_name(), "libc.so.6");
        assert_eq!(entry.get_mapping_length(), 0x1000);
    }
}
