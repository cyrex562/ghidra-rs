//! A proposed mapping from objects in a trace into a program.
//!
//! Port of `ghidra.debug.api.modules.MapProposal<T, P, E extends MapEntry<T, P>>`.
//!
//! The Java interface is generic over the trace-side object type `T`, the program-side object
//! type `P`, and the [`MapEntry`] type `E`. As with [`MapEntry`] itself, `T` and `P` are erased
//! to `Box<dyn Any>` here so the trait stays object-safe (`&dyn MapProposal` /
//! `Box<dyn MapProposal>`), matching how [`MapEntry::get_from_object`] and
//! [`MapEntry::get_to_object`] already erase `T`/`P`.
//!
//! `computeMap()` returns `Map<T, E>` in Java. Since the erased key type `Box<dyn Any>` does not
//! implement `Hash`/`Eq`, this is represented as `Vec<(Box<dyn Any>, Box<dyn MapEntry>)>` rather
//! than a `HashMap`.
//!
//! The two `static` helper methods, `flatten` and `removeOverlapping`, become free functions
//! [`flatten`] and [`remove_overlapping`] since Rust traits cannot declare generic static
//! methods and stay object-safe. `flatten` collects into a `LinkedHashSet<E>` in Java to
//! deduplicate identical entries across proposals; since [`MapEntry`] trait objects don't
//! support `Eq`/`Hash`, [`flatten`] returns a `Vec` without deduplication.

use std::any::Any;

use super::map_entry::MapEntry;
use crate::program::model::listing::Program;
use crate::trace::model::trace::Trace;

/// A proposed mapping from objects of a trace into a program.
///
/// Port of `ghidra.debug.api.modules.MapProposal`.
pub trait MapProposal: Send + Sync {
    /// Get the trace containing the trace objects in this proposal.
    fn get_trace(&self) -> &dyn Trace;

    /// Get the corresponding program image of this proposal.
    fn get_program(&self) -> &dyn Program;

    /// Get the destination (program) object for a given source (trace) object.
    fn get_to_object(&self, from: &dyn Any) -> Box<dyn Any>;

    /// Compute a notional "score" of the proposal.
    ///
    /// This may examine attributes of the "from" and "to" objects, in order to determine the
    /// likelihood of the match based on this proposal. The implementation need not assign
    /// meaning to any particular score, but a higher score must imply a more likely match.
    fn compute_score(&self) -> f64;

    /// Compute the overall map given by this proposal, as trace-object/entry pairs.
    fn compute_map(&self) -> Vec<(Box<dyn Any>, Box<dyn MapEntry>)>;
}

/// Flatten proposals into a single collection of entries.
///
/// The output is suitable for use with
/// [`DebuggerStaticMappingService::add_mappings`](crate::app::services::DebuggerStaticMappingService::add_mappings).
/// In some contexts, the user should be permitted to see and optionally adjust the collection
/// first.
///
/// Note, it is advisable to filter the returned collection using [`remove_overlapping`] to avoid
/// errors from adding overlapped mappings. Alternatively, `truncate_existing` can be set to
/// `true` when calling `add_mappings`.
///
/// Port of `MapProposal.flatten(Collection)`.
pub fn flatten(proposals: &[Box<dyn MapProposal>]) -> Vec<Box<dyn MapEntry>> {
    proposals
        .iter()
        .flat_map(|proposal| proposal.compute_map())
        .map(|(_from, entry)| entry)
        .collect()
}

/// Remove entries from a collection which overlap existing entries in the trace.
///
/// Port of `MapProposal.removeOverlapping(Collection)`.
pub fn remove_overlapping(entries: Vec<Box<dyn MapEntry>>) -> Vec<Box<dyn MapEntry>> {
    entries
        .into_iter()
        .filter(|entry| {
            let manager = entry.get_from_trace().get_static_mapping_manager();
            manager
                .find_all_overlapping(entry.get_from_range(), entry.get_from_lifespan())
                .is_empty()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::util::ProgramLocation;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::modules::trace_conflicted_mapping_exception::TraceConflictedMappingException;
    use crate::trace::model::modules::trace_static_mapping::TraceStaticMapping;
    use crate::trace::model::modules::TraceStaticMappingManager;
    use crate::trace::model::trace_location::TraceLocation;
    use std::sync::Arc;

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

    /// A static mapping manager whose `find_all_overlapping` reports an overlap for any range
    /// that starts at or after `0x3000`, and no overlap otherwise.
    struct MockStaticMappingManager;
    impl TraceStaticMappingManager for MockStaticMappingManager {
        fn add(
            &mut self,
            _range: AddressRange,
            _lifespan: Lifespan,
            _to_program_url: &str,
            _to_address: &str,
        ) -> Result<Box<dyn TraceStaticMapping>, Box<dyn TraceConflictedMappingException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_entries(&self) -> Vec<Box<dyn TraceStaticMapping>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_containing(&self, _address: &Address, _snap: i64) -> Option<Box<dyn TraceStaticMapping>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_any_conflicting(
            &self,
            _range: &AddressRange,
            _lifespan: Lifespan,
            _to_program_url: &str,
            _to_address: &str,
        ) -> Option<Box<dyn TraceStaticMapping>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_all_overlapping(
            &self,
            range: &AddressRange,
            _lifespan: Lifespan,
        ) -> Vec<Box<dyn TraceStaticMapping>> {
            if *range.min_address() >= addr(0x3000) {
                vec![]
            } else {
                vec![Box::new(MockOverlappingMapping)]
            }
        }
    }

    /// A dummy [`TraceStaticMapping`], used only as a non-empty marker: `find_all_overlapping`
    /// never invokes any of its methods, only checks the returned `Vec`'s length.
    struct MockOverlappingMapping;
    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockOverlappingMapping {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl TraceStaticMapping for MockOverlappingMapping {
        fn get_trace(&self) -> Arc<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_trace_address_range(&self) -> AddressRange {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_min_trace_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_trace_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_length(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_shift(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start_snap(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_end_snap(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_program_url(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_address(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn delete(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
        fn conflicts_with(
            &self,
            _range: &AddressRange,
            _lifespan: Lifespan,
            _to_program_url: &str,
            _to_address: &str,
        ) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockTrace;
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::model::property::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(
            &self,
        ) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(
            &self,
        ) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(
            &self,
        ) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            Box::new(MockStaticMappingManager)
        }
        fn get_symbol_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(
            &self,
        ) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(
            &self,
        ) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(
            &self,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A [`MapEntry`] whose `from_range` determines whether the mock manager reports an overlap.
    struct MockMapEntry {
        from_range: AddressRange,
    }
    impl MapEntry for MockMapEntry {
        fn get_from_trace(&self) -> &dyn Trace {
            &MockTrace
        }
        fn get_from_object(&self) -> Box<dyn Any> {
            Box::new(())
        }
        fn get_from_range(&self) -> &AddressRange {
            &self.from_range
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
            &self.from_range
        }
        fn get_to_program_location(&self) -> &dyn ProgramLocation {
            &MockProgramLocation
        }
        fn get_mapping_length(&self) -> i64 {
            self.from_range.length() as i64
        }
    }

    struct MockMapProposal {
        entries: Vec<AddressRange>,
    }
    impl MapProposal for MockMapProposal {
        fn get_trace(&self) -> &dyn Trace {
            &MockTrace
        }
        fn get_program(&self) -> &dyn Program {
            &MockProgram
        }
        fn get_to_object(&self, _from: &dyn Any) -> Box<dyn Any> {
            Box::new(())
        }
        fn compute_score(&self) -> f64 {
            1.0
        }
        fn compute_map(&self) -> Vec<(Box<dyn Any>, Box<dyn MapEntry>)> {
            self.entries
                .iter()
                .cloned()
                .map(|range| {
                    (
                        Box::new(()) as Box<dyn Any>,
                        Box::new(MockMapEntry { from_range: range }) as Box<dyn MapEntry>,
                    )
                })
                .collect()
        }
    }

    #[test]
    fn map_proposal_is_object_safe() {
        let proposals: Vec<Box<dyn MapProposal>> = vec![];
        assert_eq!(proposals.len(), 0);
    }

    #[test]
    fn flatten_collects_entries_from_all_proposals() {
        let proposals: Vec<Box<dyn MapProposal>> = vec![
            Box::new(MockMapProposal {
                entries: vec![AddressRange::new(addr(0x1000), addr(0x1fff))],
            }),
            Box::new(MockMapProposal {
                entries: vec![
                    AddressRange::new(addr(0x2000), addr(0x2fff)),
                    AddressRange::new(addr(0x4000), addr(0x4fff)),
                ],
            }),
        ];

        let flattened = flatten(&proposals);

        assert_eq!(flattened.len(), 3);
        assert_eq!(flattened[0].get_mapping_length(), 0x1000);
        assert_eq!(flattened[1].get_mapping_length(), 0x1000);
        assert_eq!(flattened[2].get_mapping_length(), 0x1000);
    }

    #[test]
    fn remove_overlapping_keeps_only_non_overlapping_entries() {
        // Below 0x3000, the mock manager reports an overlap; at or above, it reports none.
        let entries: Vec<Box<dyn MapEntry>> = vec![
            Box::new(MockMapEntry {
                from_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            }),
            Box::new(MockMapEntry {
                from_range: AddressRange::new(addr(0x4000), addr(0x4fff)),
            }),
            Box::new(MockMapEntry {
                from_range: AddressRange::new(addr(0x5000), addr(0x5fff)),
            }),
        ];

        let kept = remove_overlapping(entries);

        assert_eq!(kept.len(), 2);
        assert_eq!(*kept[0].get_from_range().min_address(), addr(0x4000));
        assert_eq!(*kept[1].get_from_range().min_address(), addr(0x5000));
    }
}
