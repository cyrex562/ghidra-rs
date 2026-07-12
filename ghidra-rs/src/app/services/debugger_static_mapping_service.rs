//! A service for consuming and mutating trace static mappings, i.e., relocations.
//!
//! Port of `ghidra.app.services.DebuggerStaticMappingService`. This service consumes and tracks
//! all open traces' mappings, tracks when the destination programs are opened and closed,
//! notifies listeners of changes in the tool's overall mapping picture, and provides for addition
//! and validation of new mappings. It also provides methods for proposing and adding mappings.
//!
//! The Java interface extends `DebuggerAddressTranslator`; that interface is not yet ported, so it
//! is represented here by the empty [`DebuggerAddressTranslator`](crate::app::seam_stubs::DebuggerAddressTranslator)
//! placeholder trait, mirroring how [`ViewManagerService`](crate::app::services::ViewManagerService)
//! extends the unported `ViewService`.
//!
//! Several Java methods are overloaded on parameter type/arity alone, which Rust traits cannot
//! express; each overload is given a distinct name:
//! - `addMapping(TraceLocation, ProgramLocation, long, boolean)` stays [`add_mapping`](DebuggerStaticMappingService::add_mapping);
//!   `addMapping(MapEntry, boolean)` becomes [`add_mapping_entry`](DebuggerStaticMappingService::add_mapping_entry).
//! - `proposeModuleMap(TraceModule, long, Program)` stays [`propose_module_map`](DebuggerStaticMappingService::propose_module_map);
//!   `proposeModuleMap(TraceModule, long, Collection<Program>)` becomes
//!   [`propose_module_map_from_programs`](DebuggerStaticMappingService::propose_module_map_from_programs).
//! - `proposeSectionMap(TraceSection, long, Program, MemoryBlock)` becomes
//!   [`propose_section_map_for_section`](DebuggerStaticMappingService::propose_section_map_for_section);
//!   `proposeSectionMap(TraceModule, long, Program)` stays [`propose_section_map`](DebuggerStaticMappingService::propose_section_map);
//!   `proposeSectionMap(TraceModule, long, Collection<Program>)` becomes
//!   [`propose_section_map_from_programs`](DebuggerStaticMappingService::propose_section_map_from_programs).
//! - `proposeRegionMap(TraceMemoryRegion, long, Program, MemoryBlock)` stays [`propose_region_map`](DebuggerStaticMappingService::propose_region_map);
//!   `proposeRegionMap(Collection<TraceMemoryRegion>, long, Program)` becomes
//!   [`propose_region_map_for_regions`](DebuggerStaticMappingService::propose_region_map_for_regions).
//!
//! Java's `Map<TraceModule, ModuleMapProposal>` (and the analogous section/region map return
//! types) key a `HashMap` by trait-object-like model types. Since none of `TraceModule`,
//! `TraceMemoryRegion`, or the map entry/proposal types (all unported, and represented here by
//! placeholder traits in [`crate::app::seam_stubs`]) support `Hash`/`Eq`, those return types
//! become `Vec` of key-value pairs instead. Likewise, `Set<Program>` and `Set<Exception>`
//! (the latter an output parameter of [`open_mapped_programs_in_view`](DebuggerStaticMappingService::open_mapped_programs_in_view))
//! become `Vec`/`&mut Vec` for the same reason.
//!
//! `TraceLocation`, `TraceConflictedMappingException`, `MapEntry`, `ModuleMapEntry`,
//! `SectionMapEntry`, `RegionMapEntry`, `ModuleMapProposal`, `SectionMapProposal`,
//! `RegionMapProposal`, `TraceModule`, `TraceSection`, and `TraceMemoryRegion` are not yet
//! ported, so they are represented by placeholder traits in [`crate::app::seam_stubs`]. See
//! `STUBS.tsv` for provenance.

use std::future::Future;
use std::pin::Pin;

use crate::app::seam_stubs::{
    DebuggerAddressTranslator, MapEntry, ModuleMapEntry, ModuleMapProposal, ProgramLocation,
    RegionMapEntry, RegionMapProposal, SectionMapEntry, SectionMapProposal,
    TraceConflictedMappingException, TraceLocation, TraceMemoryRegion, TraceModule, TraceSection,
};
use crate::debug::api::modules::DebuggerStaticMappingChangeListener;
use crate::framework::model::DomainFile;
use crate::program::model::address::{AddressSetView, AddressSpace};
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlock;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A future representing an asynchronous operation that produces no value.
///
/// Port of Java's `CompletableFuture<Void>` return type used by
/// [`DebuggerStaticMappingService::changes_settled`].
pub type ChangesSettledFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A service for consuming and mutating trace static mappings, i.e., relocations.
///
/// Port of `ghidra.app.services.DebuggerStaticMappingService`.
pub trait DebuggerStaticMappingService: DebuggerAddressTranslator {
    /// Add a static mapping (relocation) from the given trace to the given program.
    ///
    /// `length` is the length of the mapped region, where `0` indicates `1 << 64`.
    /// `truncate_existing`: true to delete or truncate the lifespan of overlapping entries.
    ///
    /// # Errors
    ///
    /// Returns a `TraceConflictedMappingException` if a conflicting mapping overlaps the source
    /// and `truncate_existing` is false.
    fn add_mapping(
        &mut self,
        from: &dyn TraceLocation,
        to: &dyn ProgramLocation,
        length: i64,
        truncate_existing: bool,
    ) -> Result<(), Box<dyn TraceConflictedMappingException>>;

    /// Add a static mapping from the given trace to the given program, using identical addresses.
    ///
    /// `truncate_existing`: true to delete or truncate the lifespan of overlapping entries; if
    /// false, overlapping entries are omitted.
    fn add_identity_mapping(
        &mut self,
        from: &dyn Trace,
        to_program: &dyn Program,
        lifespan: &dyn Lifespan,
        truncate_existing: bool,
    );

    /// Add a static mapping (relocation) described by the given map entry.
    ///
    /// Port of `DebuggerStaticMappingService.addMapping(MapEntry, boolean)`.
    ///
    /// # Errors
    ///
    /// Returns a `TraceConflictedMappingException` if a conflicting mapping overlaps the source
    /// and `truncate_existing` is false.
    fn add_mapping_entry(
        &mut self,
        entry: &dyn MapEntry,
        truncate_existing: bool,
    ) -> Result<(), Box<dyn TraceConflictedMappingException>>;

    /// Add several static mappings (relocations).
    ///
    /// This will group the entries by trace and add each's entries in a single transaction. If
    /// any entry fails, including due to conflicts, that failure is logged but ignored, and the
    /// remaining entries are processed.
    ///
    /// # Errors
    ///
    /// Returns a `CancelledException` if the user cancels.
    fn add_mappings(
        &mut self,
        entries: &[&dyn MapEntry],
        monitor: &dyn TaskMonitor,
        truncate_existing: bool,
        description: &str,
    ) -> Result<(), CancelledException>;

    /// Add several module static mappings (relocations).
    ///
    /// This will group the entries by trace and add each's entries in a single transaction. If
    /// any entry fails, including due to conflicts, that failure is logged but ignored, and the
    /// remaining entries are processed. Any entries indicated for memorization will have their
    /// module paths added to the destination program's metadata.
    ///
    /// # Errors
    ///
    /// Returns a `CancelledException` if the user cancels.
    fn add_module_mappings(
        &mut self,
        entries: &[&dyn ModuleMapEntry],
        monitor: &dyn TaskMonitor,
        truncate_existing: bool,
    ) -> Result<(), CancelledException>;

    /// Add several section static mappings (relocations).
    ///
    /// See [`add_module_mappings`](Self::add_module_mappings) for the grouping/failure semantics.
    ///
    /// # Errors
    ///
    /// Returns a `CancelledException` if the user cancels.
    fn add_section_mappings(
        &mut self,
        entries: &[&dyn SectionMapEntry],
        monitor: &dyn TaskMonitor,
        truncate_existing: bool,
    ) -> Result<(), CancelledException>;

    /// Add several region static mappings (relocations).
    ///
    /// See [`add_module_mappings`](Self::add_module_mappings) for the grouping/failure semantics.
    ///
    /// # Errors
    ///
    /// Returns a `CancelledException` if the user cancels.
    fn add_region_mappings(
        &mut self,
        entries: &[&dyn RegionMapEntry],
        monitor: &dyn TaskMonitor,
        truncate_existing: bool,
    ) -> Result<(), CancelledException>;

    /// Open all destination programs in mappings intersecting the given source trace, address
    /// set, and snap.
    ///
    /// This essentially computes the mapped program URLs in view and then tries to open each one.
    /// Because the trace's mapping table contains program URLs, it's possible the destination
    /// program(s) do not exist, and/or that there may be errors opening the destination
    /// program(s); those errors are appended to `failures` (standing in for Java's `Set<Exception>`
    /// output parameter, since the unported error types here have no `Hash`/`Eq`).
    ///
    /// The caller should not expect the relevant mappings to be immediately loaded by the manager
    /// implementation. Instead, it should listen for the expected changes in mappings before
    /// proceeding.
    ///
    /// Returns the destination programs in the relevant mappings, including those already open.
    fn open_mapped_programs_in_view(
        &self,
        trace: &dyn Trace,
        set: &dyn AddressSetView,
        snap: i64,
        failures: &mut Vec<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Vec<Box<dyn Program>>;

    /// Add a listener for changes in mappings.
    ///
    /// The caller must ensure a strong reference to the listener is maintained, or it will be
    /// removed automatically.
    fn add_change_listener(&mut self, l: Box<dyn DebuggerStaticMappingChangeListener>);

    /// Remove a listener for changes in mappings.
    fn remove_change_listener(&mut self, l: &dyn DebuggerStaticMappingChangeListener);

    /// Get a future which completes when pending changes have all settled.
    ///
    /// The returned future completes after all change listeners have been invoked.
    fn changes_settled(&self) -> ChangesSettledFuture;

    /// Find the best match among programs in the project for the given trace module.
    ///
    /// The service maintains an index of likely module names to domain files in the active
    /// project. This will search that index for the module's full file path. Failing that, it
    /// will search just for the module's file name. Among the programs found, it first prefers
    /// those whose module name list includes the sought module. Then, it prefers those whose
    /// executable path matches the sought module. Finally, it prefers matches on the program name
    /// and the domain file name. Ties in name matching are broken by looking for domain files in
    /// the same folders as those programs already mapped into the trace in the given address
    /// space.
    ///
    /// `space` is the fallback address space if the module is missing its base.
    ///
    /// Returns the best probable match, or `None` if no program is found.
    fn find_best_module_program(
        &self,
        space: &AddressSpace,
        module: &dyn TraceModule,
        snap: i64,
    ) -> Option<Box<dyn DomainFile>>;

    /// Propose a module map for the given module to the given program.
    ///
    /// No sanity check is performed on the given parameters. This will simply propose the given
    /// module-program pair. It is strongly advised to assess the proposal's score. Alternatively,
    /// use [`propose_module_map_from_programs`](Self::propose_module_map_from_programs) to have
    /// the service select the best-scored mapping from a collection of proposed programs.
    fn propose_module_map(
        &self,
        module: &dyn TraceModule,
        snap: i64,
        program: &dyn Program,
    ) -> Box<dyn ModuleMapProposal>;

    /// Compute the best-scored module map for the given module and programs.
    ///
    /// No sanity check is performed on any given module-program pair. Instead, the
    /// highest-scoring proposal is selected from the possible module-program pairs.
    ///
    /// Returns the best-scored proposal, or `None` if no program is proposed.
    fn propose_module_map_from_programs(
        &self,
        module: &dyn TraceModule,
        snap: i64,
        programs: &[&dyn Program],
    ) -> Option<Box<dyn ModuleMapProposal>>;

    /// Compute the "best" map of trace module to program for each given module given a
    /// collection of proposed programs.
    ///
    /// This will first examine module and program names in order to cull unlikely pairs. It then
    /// takes the best-scored proposal for each module. If a module has no likely paired program,
    /// then it is omitted from the result.
    fn propose_module_maps(
        &self,
        modules: &[&dyn TraceModule],
        snap: i64,
        programs: &[&dyn Program],
    ) -> Vec<(Box<dyn TraceModule>, Box<dyn ModuleMapProposal>)>;

    /// Propose a singleton section map from the given section to the given program memory block.
    ///
    /// Port of `DebuggerStaticMappingService.proposeSectionMap(TraceSection, long, Program,
    /// MemoryBlock)`. No sanity check is performed on the given parameters. This will simply give
    /// a singleton map of the given entry.
    fn propose_section_map_for_section(
        &self,
        section: &dyn TraceSection,
        snap: i64,
        program: &dyn Program,
        block: &dyn MemoryBlock,
    ) -> Box<dyn SectionMapProposal>;

    /// Propose a section map for the given module to the given program.
    ///
    /// Port of `DebuggerStaticMappingService.proposeSectionMap(TraceModule, long, Program)`. No
    /// sanity check is performed on the given parameters. This will do its best to map sections
    /// from the given module to memory blocks in the given program.
    fn propose_section_map(
        &self,
        module: &dyn TraceModule,
        snap: i64,
        program: &dyn Program,
    ) -> Box<dyn SectionMapProposal>;

    /// Propose the best-scored section map for the given module and programs.
    ///
    /// Port of `DebuggerStaticMappingService.proposeSectionMap(TraceModule, long,
    /// Collection<Program>)`. No sanity check is performed on any given module-program pair.
    ///
    /// Returns the best-scored map, or `None` if no program is proposed.
    fn propose_section_map_from_programs(
        &self,
        module: &dyn TraceModule,
        snap: i64,
        programs: &[&dyn Program],
    ) -> Option<Box<dyn SectionMapProposal>>;

    /// Propose the best-scored maps of trace sections to program memory blocks for each given
    /// module given a collection of proposed programs.
    ///
    /// This will first examine module and program names in order to cull unlikely pairs. It then
    /// takes the best-scored proposal for each module. If a module has no likely paired program,
    /// then it is omitted from the result.
    fn propose_section_maps(
        &self,
        modules: &[&dyn TraceModule],
        snap: i64,
        programs: &[&dyn Program],
    ) -> Vec<(Box<dyn TraceModule>, Box<dyn SectionMapProposal>)>;

    /// Propose a singleton region map from the given region to the given program memory block.
    ///
    /// Port of `DebuggerStaticMappingService.proposeRegionMap(TraceMemoryRegion, long, Program,
    /// MemoryBlock)`. No sanity check is performed on the given parameters. This will simply give
    /// a singleton map of the given entry.
    fn propose_region_map(
        &self,
        region: &dyn TraceMemoryRegion,
        snap: i64,
        program: &dyn Program,
        block: &dyn MemoryBlock,
    ) -> Box<dyn RegionMapProposal>;

    /// Propose a region map for the given regions to the given program.
    ///
    /// Port of `DebuggerStaticMappingService.proposeRegionMap(Collection<TraceMemoryRegion>,
    /// long, Program)`. No sanity check is performed on the given parameters. This will do its
    /// best to map regions to memory blocks in the given program. For the best results, regions
    /// should all comprise the same module, and the minimum address among the regions should be
    /// the module's base address.
    fn propose_region_map_for_regions(
        &self,
        regions: &[&dyn TraceMemoryRegion],
        snap: i64,
        program: &dyn Program,
    ) -> Box<dyn RegionMapProposal>;

    /// Propose the best-scored maps of trace regions to program memory blocks for each given
    /// "module" given a collection of proposed programs.
    ///
    /// This will first group regions into likely modules by parsing their names, then compare to
    /// program names in order to cull unlikely pairs. It then takes the best-scored proposal for
    /// each module. If a module has no likely paired program, then it is omitted from the result.
    /// For informational purposes, the keys in the returned collection reflect the grouping of
    /// regions into likely modules. For the best results, the minimum address of each module
    /// should be among the regions.
    fn propose_region_maps(
        &self,
        regions: &[&dyn TraceMemoryRegion],
        snap: i64,
        programs: &[&dyn Program],
    ) -> Vec<(Vec<Box<dyn TraceMemoryRegion>>, Box<dyn RegionMapProposal>)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct MockConflictError;

    impl fmt::Display for MockConflictError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "mock conflicted mapping")
        }
    }

    impl std::error::Error for MockConflictError {}
    impl TraceConflictedMappingException for MockConflictError {}

    struct MockTraceLocation;
    impl TraceLocation for MockTraceLocation {}

    struct MockProgramLocation;
    impl ProgramLocation for MockProgramLocation {}

    struct MockMapEntry;
    impl MapEntry for MockMapEntry {}

    struct MockModuleMapEntry;
    impl ModuleMapEntry for MockModuleMapEntry {}

    struct MockSectionMapEntry;
    impl SectionMapEntry for MockSectionMapEntry {}

    struct MockRegionMapEntry;
    impl RegionMapEntry for MockRegionMapEntry {}

    struct MockModuleMapProposal;
    impl ModuleMapProposal for MockModuleMapProposal {}

    struct MockSectionMapProposal;
    impl SectionMapProposal for MockSectionMapProposal {}

    struct MockRegionMapProposal;
    impl RegionMapProposal for MockRegionMapProposal {}

    struct MockTraceModule;
    impl TraceModule for MockTraceModule {}

    struct MockTraceSection;
    impl TraceSection for MockTraceSection {}

    struct MockTraceMemoryRegion;
    impl TraceMemoryRegion for MockTraceMemoryRegion {}

    struct MockTrace;
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl crate::program::seam_stubs::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    // `Trace` declares no default methods, so every method needs a body even though none of
    // them are exercised by this smoke test (MockTrace is only ever passed through as an opaque
    // `&dyn Trace` parameter).
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
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn crate::trace::seam_stubs::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::seam_stubs::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::seam_stubs::TraceTimeViewport> {
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
        fn lock_read(
            &self,
        ) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(
            &self,
        ) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockLifespan;
    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            0
        }
        fn lmax(&self) -> i64 {
            0
        }
        fn contains(&self, _n: i64) -> bool {
            false
        }
        fn with_min(&self, _min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan)
        }
        fn with_max(&self, _max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan)
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(std::iter::empty())
        }
    }

    struct MockAddressSetView;
    impl AddressSetView for MockAddressSetView {
        fn contains(&self, _address: &crate::program::model::address::Address) -> bool {
            false
        }
        fn contains_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }
        fn is_empty(&self) -> bool {
            true
        }
        fn min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn max_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn num_address_ranges(&self) -> usize {
            0
        }
        fn address_ranges(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn address_ranges_ordered(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn address_ranges_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn num_addresses(&self) -> u64 {
            0
        }
        fn addresses(&self, _forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }
        fn addresses_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }
        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }
        fn intersects_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }
        fn intersect(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn intersect_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn union(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn subtract(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn xor(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            true
        }
        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }
        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }
        fn range_containing(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Option<crate::program::model::address::AddressRange> {
            None
        }
        fn find_first_address_in_common(
            &self,
            _set: &dyn AddressSetView,
        ) -> Option<crate::program::model::address::Address> {
            None
        }
    }

    struct MockDomainFile;
    impl DomainFile for MockDomainFile {}

    struct MockMemoryBlock;
    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_end(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_size(&self) -> u64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_initialized(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_byte(
            &self,
            _addr: &crate::program::model::address::Address,
        ) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bytes(
            &self,
            _addr: &crate::program::model::address::Address,
            _dest: &mut [u8],
        ) -> usize {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_bytes(
            &mut self,
            _addr: &crate::program::model::address::Address,
            _source: &[u8],
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockListener;
    impl DebuggerStaticMappingChangeListener for MockListener {
        fn mappings_changed(
            &self,
            _affected_traces: &std::collections::HashSet<std::sync::Arc<dyn Trace>>,
            _affected_programs: &std::collections::HashSet<std::sync::Arc<dyn Program>>,
        ) {
        }
    }

    struct MockService {
        listener_count: usize,
    }

    impl DebuggerAddressTranslator for MockService {}

    impl DebuggerStaticMappingService for MockService {
        fn add_mapping(
            &mut self,
            _from: &dyn TraceLocation,
            _to: &dyn ProgramLocation,
            _length: i64,
            _truncate_existing: bool,
        ) -> Result<(), Box<dyn TraceConflictedMappingException>> {
            Err(Box::new(MockConflictError))
        }

        fn add_identity_mapping(
            &mut self,
            _from: &dyn Trace,
            _to_program: &dyn Program,
            _lifespan: &dyn Lifespan,
            _truncate_existing: bool,
        ) {
        }

        fn add_mapping_entry(
            &mut self,
            _entry: &dyn MapEntry,
            _truncate_existing: bool,
        ) -> Result<(), Box<dyn TraceConflictedMappingException>> {
            Ok(())
        }

        fn add_mappings(
            &mut self,
            _entries: &[&dyn MapEntry],
            _monitor: &dyn TaskMonitor,
            _truncate_existing: bool,
            _description: &str,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn add_module_mappings(
            &mut self,
            _entries: &[&dyn ModuleMapEntry],
            _monitor: &dyn TaskMonitor,
            _truncate_existing: bool,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn add_section_mappings(
            &mut self,
            _entries: &[&dyn SectionMapEntry],
            _monitor: &dyn TaskMonitor,
            _truncate_existing: bool,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn add_region_mappings(
            &mut self,
            _entries: &[&dyn RegionMapEntry],
            _monitor: &dyn TaskMonitor,
            _truncate_existing: bool,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn open_mapped_programs_in_view(
            &self,
            _trace: &dyn Trace,
            _set: &dyn AddressSetView,
            _snap: i64,
            failures: &mut Vec<Box<dyn std::error::Error + Send + Sync>>,
        ) -> Vec<Box<dyn Program>> {
            failures.push(Box::new(MockConflictError));
            vec![Box::new(MockProgram)]
        }

        fn add_change_listener(&mut self, _l: Box<dyn DebuggerStaticMappingChangeListener>) {
            self.listener_count += 1;
        }

        fn remove_change_listener(&mut self, _l: &dyn DebuggerStaticMappingChangeListener) {
            self.listener_count -= 1;
        }

        fn changes_settled(&self) -> ChangesSettledFuture {
            Box::pin(async {})
        }

        fn find_best_module_program(
            &self,
            _space: &AddressSpace,
            _module: &dyn TraceModule,
            _snap: i64,
        ) -> Option<Box<dyn DomainFile>> {
            Some(Box::new(MockDomainFile))
        }

        fn propose_module_map(
            &self,
            _module: &dyn TraceModule,
            _snap: i64,
            _program: &dyn Program,
        ) -> Box<dyn ModuleMapProposal> {
            Box::new(MockModuleMapProposal)
        }

        fn propose_module_map_from_programs(
            &self,
            _module: &dyn TraceModule,
            _snap: i64,
            programs: &[&dyn Program],
        ) -> Option<Box<dyn ModuleMapProposal>> {
            if programs.is_empty() {
                None
            } else {
                Some(Box::new(MockModuleMapProposal))
            }
        }

        fn propose_module_maps(
            &self,
            modules: &[&dyn TraceModule],
            _snap: i64,
            _programs: &[&dyn Program],
        ) -> Vec<(Box<dyn TraceModule>, Box<dyn ModuleMapProposal>)> {
            modules
                .iter()
                .map(|_| {
                    (
                        Box::new(MockTraceModule) as Box<dyn TraceModule>,
                        Box::new(MockModuleMapProposal) as Box<dyn ModuleMapProposal>,
                    )
                })
                .collect()
        }

        fn propose_section_map_for_section(
            &self,
            _section: &dyn TraceSection,
            _snap: i64,
            _program: &dyn Program,
            _block: &dyn MemoryBlock,
        ) -> Box<dyn SectionMapProposal> {
            Box::new(MockSectionMapProposal)
        }

        fn propose_section_map(
            &self,
            _module: &dyn TraceModule,
            _snap: i64,
            _program: &dyn Program,
        ) -> Box<dyn SectionMapProposal> {
            Box::new(MockSectionMapProposal)
        }

        fn propose_section_map_from_programs(
            &self,
            _module: &dyn TraceModule,
            _snap: i64,
            programs: &[&dyn Program],
        ) -> Option<Box<dyn SectionMapProposal>> {
            if programs.is_empty() {
                None
            } else {
                Some(Box::new(MockSectionMapProposal))
            }
        }

        fn propose_section_maps(
            &self,
            modules: &[&dyn TraceModule],
            _snap: i64,
            _programs: &[&dyn Program],
        ) -> Vec<(Box<dyn TraceModule>, Box<dyn SectionMapProposal>)> {
            modules
                .iter()
                .map(|_| {
                    (
                        Box::new(MockTraceModule) as Box<dyn TraceModule>,
                        Box::new(MockSectionMapProposal) as Box<dyn SectionMapProposal>,
                    )
                })
                .collect()
        }

        fn propose_region_map(
            &self,
            _region: &dyn TraceMemoryRegion,
            _snap: i64,
            _program: &dyn Program,
            _block: &dyn MemoryBlock,
        ) -> Box<dyn RegionMapProposal> {
            Box::new(MockRegionMapProposal)
        }

        fn propose_region_map_for_regions(
            &self,
            _regions: &[&dyn TraceMemoryRegion],
            _snap: i64,
            _program: &dyn Program,
        ) -> Box<dyn RegionMapProposal> {
            Box::new(MockRegionMapProposal)
        }

        fn propose_region_maps(
            &self,
            regions: &[&dyn TraceMemoryRegion],
            _snap: i64,
            _programs: &[&dyn Program],
        ) -> Vec<(Vec<Box<dyn TraceMemoryRegion>>, Box<dyn RegionMapProposal>)> {
            if regions.is_empty() {
                Vec::new()
            } else {
                vec![(
                    vec![Box::new(MockTraceMemoryRegion) as Box<dyn TraceMemoryRegion>],
                    Box::new(MockRegionMapProposal) as Box<dyn RegionMapProposal>,
                )]
            }
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerStaticMappingService> =
            Box::new(MockService { listener_count: 0 });

        assert!(service
            .add_mapping(&MockTraceLocation, &MockProgramLocation, 0, false)
            .is_err());
        assert!(service.add_mapping_entry(&MockMapEntry, false).is_ok());

        service.add_identity_mapping(&MockTrace, &MockProgram, &MockLifespan, true);

        service.add_change_listener(Box::new(MockListener));
        service.remove_change_listener(&MockListener);

        let mut failures: Vec<Box<dyn std::error::Error + Send + Sync>> = Vec::new();
        let programs = service.open_mapped_programs_in_view(
            &MockTrace,
            &MockAddressSetView,
            0,
            &mut failures,
        );
        assert_eq!(programs.len(), 1);
        assert_eq!(failures.len(), 1);

        assert!(service
            .find_best_module_program(
                &AddressSpace::new(
                    "ram",
                    32,
                    1,
                    crate::program::model::address::AddressSpaceType::Ram,
                    1
                ),
                &MockTraceModule,
                0
            )
            .is_some());

        let module_map = service.propose_module_map(&MockTraceModule, 0, &MockProgram);
        let _ = module_map;
        assert!(service
            .propose_module_map_from_programs(&MockTraceModule, 0, &[])
            .is_none());
        assert_eq!(
            service
                .propose_module_maps(&[&MockTraceModule], 0, &[&MockProgram])
                .len(),
            1
        );

        let _section_map = service.propose_section_map_for_section(
            &MockTraceSection,
            0,
            &MockProgram,
            &MockMemoryBlock,
        );
        let _section_map = service.propose_section_map(&MockTraceModule, 0, &MockProgram);
        assert!(service
            .propose_section_map_from_programs(&MockTraceModule, 0, &[&MockProgram])
            .is_some());
        assert_eq!(
            service
                .propose_section_maps(&[&MockTraceModule], 0, &[&MockProgram])
                .len(),
            1
        );

        let _region_map =
            service.propose_region_map(&MockTraceMemoryRegion, 0, &MockProgram, &MockMemoryBlock);
        let _region_map = service.propose_region_map_for_regions(
            &[&MockTraceMemoryRegion],
            0,
            &MockProgram,
        );
        assert_eq!(
            service
                .propose_region_maps(&[&MockTraceMemoryRegion], 0, &[&MockProgram])
                .len(),
            1
        );

        let _future = service.changes_settled();
    }
}
