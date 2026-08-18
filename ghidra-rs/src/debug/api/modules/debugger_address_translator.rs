//! Translates addresses/locations between a trace's dynamic (recorded) view and a program's
//! static view, with respect to each trace's "Static Mappings" table.
//!
//! Port of `ghidra.debug.api.modules.DebuggerAddressTranslator`.
//!
//! Several Java methods are overloaded on parameter type/arity alone, which Rust traits cannot
//! express; each overload is given a distinct name:
//! - `getOpenMappedLocation(TraceLocation)` stays [`get_open_mapped_location`](DebuggerAddressTranslator::get_open_mapped_location);
//!   `getOpenMappedLocation(Trace, ProgramLocation, long)` becomes
//!   [`get_open_mapped_trace_location`](DebuggerAddressTranslator::get_open_mapped_trace_location).
//! - `getOpenMappedViews(Trace, AddressSetView, long)` stays [`get_open_mapped_views`](DebuggerAddressTranslator::get_open_mapped_views);
//!   `getOpenMappedViews(Program, AddressSetView)` becomes
//!   [`get_open_mapped_views_for_program`](DebuggerAddressTranslator::get_open_mapped_views_for_program).
//!
//! Java's `Set<Program>`, `Set<TraceLocation>`, and `Set<URL>` become `Vec` since the underlying
//! model traits (`Program`, `TraceLocation`) don't support `Hash`/`Eq`. `java.net.URL` is
//! represented as `String`, matching how this crate already represents Java URLs elsewhere (e.g.
//! [`crate::trace::model::modules::trace_static_mapping`]). Java's `Map<K, Collection<V>>` return
//! types become `Vec<(K, Vec<V>)>` for the same reason `Set` becomes `Vec`.
//!
//! `TraceSpan` is represented by its sole in-repo implementation,
//! [`DefaultTraceSpan`](crate::trace::model::default_trace_span::DefaultTraceSpan), since the
//! `TraceSpan` trait itself uses associated types and so is not `dyn`-compatible.
//!
//! `MappedAddressRange` is not yet ported, so it is represented by a placeholder struct in
//! [`crate::debug::seam_stubs`]. See `STUBS.tsv` for provenance.

use crate::debug::seam_stubs::MappedAddressRange;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;
use crate::trace::model::default_trace_span::DefaultTraceSpan;
use crate::trace::model::program::TraceProgramView;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_location::TraceLocation;

/// Translates addresses/locations between a trace's dynamic view and a program's static view.
///
/// Port of `ghidra.debug.api.modules.DebuggerAddressTranslator`.
pub trait DebuggerAddressTranslator {
    /// Collect all the open destination programs relevant for the given trace and snap.
    ///
    /// Port of `DebuggerAddressTranslator.getOpenMappedProgramsAtSnap(Trace, long)`.
    fn get_open_mapped_programs_at_snap(&self, trace: &dyn Trace, snap: i64)
        -> Vec<Box<dyn Program>>;

    /// Map the given trace location to a program location, if the destination is open.
    ///
    /// Returns `None` if not mapped, or not open.
    ///
    /// Port of `DebuggerAddressTranslator.getOpenMappedLocation(TraceLocation)`.
    fn get_open_mapped_location(
        &self,
        loc: &dyn TraceLocation,
    ) -> Option<Box<dyn ProgramLocation>>;

    /// Similar to [`get_open_mapped_location`](Self::get_open_mapped_location), but preserves
    /// details.
    ///
    /// The given location's `get_program()` must return a
    /// [`TraceProgramView`](crate::trace::model::program::TraceProgramView). It derives the trace
    /// and snap from that view. Additionally, this will attempt to map over other "location"
    /// details, e.g., field, row, column.
    ///
    /// Port of `DebuggerAddressTranslator.getStaticLocationFromDynamic(ProgramLocation)`.
    fn get_static_location_from_dynamic(
        &self,
        loc: &dyn ProgramLocation,
    ) -> Option<Box<dyn ProgramLocation>>;

    /// Map the given program location back to open source trace locations.
    ///
    /// Port of `DebuggerAddressTranslator.getOpenMappedLocations(ProgramLocation)`.
    fn get_open_mapped_locations(&self, loc: &dyn ProgramLocation) -> Vec<Box<dyn TraceLocation>>;

    /// Map the given program location back to a source trace and snap.
    ///
    /// Returns `None` if not mapped.
    ///
    /// Port of `DebuggerAddressTranslator.getOpenMappedLocation(Trace, ProgramLocation, long)`.
    fn get_open_mapped_trace_location(
        &self,
        trace: &dyn Trace,
        loc: &dyn ProgramLocation,
        snap: i64,
    ) -> Option<Box<dyn TraceLocation>>;

    /// Similar to
    /// [`get_open_mapped_trace_location`](Self::get_open_mapped_trace_location), but preserves
    /// details.
    ///
    /// This derives the source trace and snap from the given view. Additionally, this will
    /// attempt to map over other "location" details, e.g., field, row, column.
    ///
    /// Port of `DebuggerAddressTranslator.getDynamicLocationFromStatic(TraceProgramView,
    /// ProgramLocation)`.
    fn get_dynamic_location_from_static(
        &self,
        view: &dyn TraceProgramView,
        loc: &dyn ProgramLocation,
    ) -> Option<Box<dyn ProgramLocation>>;

    /// Find/compute all destination address sets given a source trace address set.
    ///
    /// Returns a map (as key-value pairs) of destination programs to corresponding computed
    /// destination address ranges.
    ///
    /// Port of `DebuggerAddressTranslator.getOpenMappedViews(Trace, AddressSetView, long)`.
    fn get_open_mapped_views(
        &self,
        trace: &dyn Trace,
        set: &dyn AddressSetView,
        snap: i64,
    ) -> Vec<(Box<dyn Program>, Vec<MappedAddressRange>)>;

    /// Find/compute all source address sets given a destination program address set.
    ///
    /// Returns a map (as key-value pairs) of source traces to corresponding computed source
    /// address ranges.
    ///
    /// Port of `DebuggerAddressTranslator.getOpenMappedViews(Program, AddressSetView)`.
    fn get_open_mapped_views_for_program(
        &self,
        program: &dyn Program,
        set: &dyn AddressSetView,
    ) -> Vec<(DefaultTraceSpan, Vec<MappedAddressRange>)>;

    /// Get all destination program URLs in mappings intersecting the given source trace, address
    /// set, and snap.
    ///
    /// Port of `DebuggerAddressTranslator.getMappedProgramUrlsInView(Trace, AddressSetView,
    /// long)`.
    fn get_mapped_program_urls_in_view(
        &self,
        trace: &dyn Trace,
        set: &dyn AddressSetView,
        snap: i64,
    ) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressSet, AddressSpace, AddressSpaceType, BoxedAddressIterator, EmptyAddressIterator, EmptyAddressRangeIterator};
    use crate::trace::model::lifespan::Lifespan;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct MockProgramA;
    impl crate::framework::model::DomainObject for MockProgramA {}
    impl Program for MockProgramA {
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
            Arc::new(MockProgramA)
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

    struct MockAddressSetView;
    impl AddressSetView for MockAddressSetView {
        fn contains(&self, _address: &Address) -> bool {
            false
        }
        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }
        fn is_empty(&self) -> bool {
            true
        }
        fn min_address(&self) -> Option<Address> {
            None
        }
        fn max_address(&self) -> Option<Address> {
            None
        }
        fn num_address_ranges(&self) -> usize {
            0
        }
        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn address_ranges_ordered(&self, _forward: bool) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn address_ranges_from(&self, _start: &Address, _forward: bool) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn num_addresses(&self) -> u64 {
            0
        }
        fn addresses(&self, _forward: bool) -> BoxedAddressIterator {
            Box::new(EmptyAddressIterator)
        }
        fn addresses_from(&self, _start: &Address, _forward: bool) -> BoxedAddressIterator {
            Box::new(EmptyAddressIterator)
        }
        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }
        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }
        fn intersect(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }
        fn intersect_range(&self, _start: &Address, _end: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn union(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }
        fn subtract(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }
        fn xor(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }
        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            true
        }
        fn first_range(&self) -> Option<AddressRange> {
            None
        }
        fn last_range(&self) -> Option<AddressRange> {
            None
        }
        fn range_containing(&self, _address: &Address) -> Option<AddressRange> {
            None
        }
        fn find_first_address_in_common(&self, _set: &dyn AddressSetView) -> Option<Address> {
            None
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
        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
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
        fn get_equate_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(&self) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
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

    /// Identity translator: static and dynamic addresses coincide, and every location/set maps
    /// to itself. Mirrors the trivial (but real) behavior of an "identity" static mapping, as
    /// exercised by `DebuggerStaticMappingService.addIdentityMapping`.
    struct IdentityTranslator;

    impl DebuggerAddressTranslator for IdentityTranslator {
        fn get_open_mapped_programs_at_snap(
            &self,
            _trace: &dyn Trace,
            _snap: i64,
        ) -> Vec<Box<dyn Program>> {
            vec![Box::new(MockProgramA)]
        }

        fn get_open_mapped_location(
            &self,
            _loc: &dyn TraceLocation,
        ) -> Option<Box<dyn ProgramLocation>> {
            Some(Box::new(MockProgramLocation))
        }

        fn get_static_location_from_dynamic(
            &self,
            loc: &dyn ProgramLocation,
        ) -> Option<Box<dyn ProgramLocation>> {
            let _ = loc.get_address();
            Some(Box::new(MockProgramLocation))
        }

        fn get_open_mapped_locations(
            &self,
            _loc: &dyn ProgramLocation,
        ) -> Vec<Box<dyn TraceLocation>> {
            vec![Box::new(MockTraceLocation)]
        }

        fn get_open_mapped_trace_location(
            &self,
            _trace: &dyn Trace,
            _loc: &dyn ProgramLocation,
            _snap: i64,
        ) -> Option<Box<dyn TraceLocation>> {
            Some(Box::new(MockTraceLocation))
        }

        fn get_dynamic_location_from_static(
            &self,
            _view: &dyn TraceProgramView,
            _loc: &dyn ProgramLocation,
        ) -> Option<Box<dyn ProgramLocation>> {
            Some(Box::new(MockProgramLocation))
        }

        fn get_open_mapped_views(
            &self,
            _trace: &dyn Trace,
            _set: &dyn AddressSetView,
            _snap: i64,
        ) -> Vec<(Box<dyn Program>, Vec<MappedAddressRange>)> {
            vec![(Box::new(MockProgramA), Vec::new())]
        }

        fn get_open_mapped_views_for_program(
            &self,
            _program: &dyn Program,
            _set: &dyn AddressSetView,
        ) -> Vec<(DefaultTraceSpan, Vec<MappedAddressRange>)> {
            let trace: Arc<dyn Trace> = Arc::new(MockTrace);
            vec![(
                DefaultTraceSpan::new(trace, Lifespan::ALL),
                Vec::new(),
            )]
        }

        fn get_mapped_program_urls_in_view(
            &self,
            _trace: &dyn Trace,
            _set: &dyn AddressSetView,
            _snap: i64,
        ) -> Vec<String> {
            vec!["ghidra://localhost/repo/static.exe".to_string()]
        }
    }

    #[test]
    fn resolves_open_mapped_programs_at_snap() {
        let translator = IdentityTranslator;
        let programs = translator.get_open_mapped_programs_at_snap(&MockTrace, 0);
        assert_eq!(programs.len(), 1);
        assert_eq!(Program::get_name(programs[0].as_ref()), "static.exe");
    }

    #[test]
    fn resolves_open_mapped_location_round_trip() {
        let translator = IdentityTranslator;
        let dst = translator
            .get_open_mapped_location(&MockTraceLocation)
            .expect("mapped");
        assert_eq!(dst.get_address(), addr(0x1000));

        let src = translator
            .get_open_mapped_trace_location(&MockTrace, &MockProgramLocation, 0)
            .expect("mapped back");
        assert_eq!(src.get_address(), addr(0x2000));
    }

    #[test]
    fn resolves_static_and_dynamic_location_conversions() {
        let translator = IdentityTranslator;
        assert!(translator
            .get_static_location_from_dynamic(&MockProgramLocation)
            .is_some());

        struct MockView;
        impl crate::framework::model::DomainObject for MockView {}
        impl crate::program::model::listing::Program for MockView {
            fn get_name(&self) -> String {
                "view".to_string()
            }
            fn get_language_id(&self) -> String {
                "mock:LE:32:default".to_string()
            }
        }
        impl TraceProgramView for MockView {
            fn get_trace_program_view_memory(
                &self,
            ) -> Box<dyn crate::trace::model::program::TraceProgramViewMemory> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_trace(&self) -> Box<dyn Trace> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_snap(&self) -> i64 {
                0
            }
            fn get_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_max_snap(&self) -> Option<i64> {
                None
            }
        }
        let view = MockView;
        assert!(translator
            .get_dynamic_location_from_static(&view, &MockProgramLocation)
            .is_some());
    }

    #[test]
    fn resolves_open_mapped_locations_and_views() {
        let translator = IdentityTranslator;
        assert_eq!(
            translator.get_open_mapped_locations(&MockProgramLocation).len(),
            1
        );

        let views = translator.get_open_mapped_views(&MockTrace, &MockAddressSetView, 0);
        assert_eq!(views.len(), 1);
        assert_eq!(Program::get_name(views[0].0.as_ref()), "static.exe");

        let program = MockProgramA;
        let by_span = translator.get_open_mapped_views_for_program(&program, &MockAddressSetView);
        assert_eq!(by_span.len(), 1);
    }

    #[test]
    fn resolves_mapped_program_urls_in_view() {
        let translator = IdentityTranslator;
        let urls = translator.get_mapped_program_urls_in_view(&MockTrace, &MockAddressSetView, 0);
        assert_eq!(urls, vec!["ghidra://localhost/repo/static.exe".to_string()]);
    }

    #[test]
    fn trait_is_usable_as_boxed_trait_object() {
        let translator: Box<dyn DebuggerAddressTranslator> = Box::new(IdentityTranslator);
        assert_eq!(
            translator
                .get_open_mapped_programs_at_snap(&MockTrace, 0)
                .len(),
            1
        );
    }
}
