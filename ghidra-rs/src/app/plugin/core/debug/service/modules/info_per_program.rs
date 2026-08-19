//! Per-program bookkeeping for
//! [`DebuggerStaticMappingContext`](super::DebuggerStaticMappingContext).
//!
//! Port of `ghidra.app.plugin.core.debug.service.modules.InfoPerProgram`.
//!
//! # Divergences from the Java
//!
//! * Java's nested `NavMultiMap<K, V>` (a `TreeMap<K, Set<V>>`) is specialized here to
//!   `NavMultiMap`, keyed by [`Address`] with `Arc<Mutex<dyn MappingEntry>>` values, since this is
//!   the only instantiation the Java class uses. `MappingEntry` trait objects have no `Hash`/`Eq`,
//!   so set membership is emulated with `Vec` + `Arc::ptr_eq`, matching the Java field's use of
//!   reference identity (`MappingEntry` never overrides `equals`/`hashCode` in a way this
//!   collection depends on).
//! * `program.addListener(this)` from the Java constructor is not performed here: `Program`'s
//!   ported `add_listener` takes an owned `Box<dyn DomainObjectListener>`, which requires a
//!   registration adapter over shared (`Arc<Mutex<_>>`) ownership of `self`.
//! * Java's `ctx` back-reference is dropped: the context owns these infos, so
//!   pointing back at it would make ownership cyclic. What that field was used for is passed in
//!   instead -- the open traces' infos for [`clear_entries`](InfoPerProgram::clear_entries) and
//!   [`fill_entries`](InfoPerProgram::fill_entries) -- and Java's `domainObjectChanged` handler,
//!   which re-registers a renamed program with its context, moves onto the context itself as
//!   `DebuggerStaticMappingContext::program_object_changed`.
//! * Java's `Set<TraceLocation>` return values become `Vec`, since `TraceLocation` trait objects
//!   have no `Hash`/`Eq` (same rationale used elsewhere in this crate, e.g.
//!   `DebuggerStaticMappingService`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use crate::app::plugin::core::debug::service::modules::ChangeCollector;
use crate::app::plugin::core::debug::utils::ProgramURLUtils;
use crate::app::seam_stubs::{InfoPerTrace, MappingEntry};
use crate::debug::seam_stubs::MappedAddressRange;
use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::listing::Program;
use crate::trace::model::default_trace_span::DefaultTraceSpan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_location::TraceLocation;
use crate::util::Msg;

/// A multi-map from [`Address`] to a set of [`MappingEntry`]s, ordered by key.
///
/// Port of the Java nested class `InfoPerProgram.NavMultiMap<K, V>`, specialized to this type's
/// one instantiation (see the module-level divergence note).
#[derive(Default)]
struct NavMultiMap {
    map: BTreeMap<Address, Vec<Arc<Mutex<dyn MappingEntry>>>>,
}

impl NavMultiMap {
    fn new() -> Self {
        Self { map: BTreeMap::new() }
    }

    /// Port of `NavMultiMap.put`.
    fn put(&mut self, k: Address, v: Arc<Mutex<dyn MappingEntry>>) -> bool {
        let set = self.map.entry(k).or_default();
        if set.iter().any(|existing| Arc::ptr_eq(existing, &v)) {
            return false;
        }
        set.push(v);
        true
    }

    /// Port of `NavMultiMap.remove`.
    fn remove(&mut self, k: &Address, v: &Arc<Mutex<dyn MappingEntry>>) -> bool {
        let Some(set) = self.map.get_mut(k) else {
            return false;
        };
        let before = set.len();
        set.retain(|existing| !Arc::ptr_eq(existing, v));
        let removed = set.len() != before;
        if removed && set.is_empty() {
            self.map.remove(k);
        }
        removed
    }

    /// Port of `map.headMap(toKey, true).values()`: all entry-sets keyed at or below `to_key`.
    fn head_inclusive(&self, to_key: &Address) -> impl Iterator<Item = &Vec<Arc<Mutex<dyn MappingEntry>>>> {
        self.map.range(..=to_key.clone()).map(|(_, v)| v)
    }
}

/// Per-program bookkeeping tracked by
/// [`DebuggerStaticMappingContext`](super::DebuggerStaticMappingContext).
///
/// Port of `ghidra.app.plugin.core.debug.service.modules.InfoPerProgram`.
pub struct InfoPerProgram {
    /// The program this info tracks.
    pub program: Arc<dyn Program>,
    inbound_by_static_address: NavMultiMap,
    /// This program's Ghidra URL, computed once at construction, or `None` if the program does
    /// not belong to a project.
    pub url: Option<String>,
}

impl InfoPerProgram {
    /// Port of `InfoPerProgram(DebuggerStaticMappingContext, Program)`.
    ///
    /// See the module-level divergence notes: unlike the Java constructor, this does not register
    /// `self` as a listener on `program`, and it takes no back-reference to its context.
    pub fn new(program: Arc<dyn Program>) -> Self {
        let url = ProgramURLUtils::get_url_from_program(program.as_ref());
        InfoPerProgram {
            program,
            inbound_by_static_address: NavMultiMap::new(),
            url,
        }
    }

    /// Port of `InfoPerProgram.urlMatches()`.
    pub fn url_matches(&self) -> bool {
        self.url == ProgramURLUtils::get_url_from_program(self.program.as_ref())
    }

    /// Port of `InfoPerProgram.clearProgram(ChangeCollector, MappingEntry)`.
    pub fn clear_program(&mut self, cc: &mut ChangeCollector, me: Arc<Mutex<dyn MappingEntry>>) {
        let static_address = me.lock().unwrap().get_static_address();
        if let Some(addr) = static_address {
            self.inbound_by_static_address.remove(&addr, &me);
        }
        me.lock().unwrap().clear_program(cc, self.program.as_ref());
    }

    /// Port of `InfoPerProgram.fillProgram(ChangeCollector, MappingEntry)`.
    pub fn fill_program(&mut self, cc: &mut ChangeCollector, me: Arc<Mutex<dyn MappingEntry>>) {
        me.lock().unwrap().fill_program(cc, self.program.as_ref());
        let static_address = me.lock().unwrap().get_static_address();
        if let Some(addr) = static_address {
            self.inbound_by_static_address.put(addr, me);
        }
    }

    /// Port of `InfoPerProgram.clearEntries(ChangeCollector)`.
    ///
    /// Java reaches the open traces' infos through `ctx`; they are passed in here instead (see the
    /// module divergence note).
    pub fn clear_entries(
        &self,
        cc: &mut ChangeCollector,
        trace_infos: &[Arc<Mutex<dyn InfoPerTrace>>],
    ) {
        if self.url.is_none() {
            return;
        }
        for info in trace_infos {
            info.lock().unwrap().clear_entries_for_program(cc, self);
        }
    }

    /// Port of `InfoPerProgram.fillEntries(ChangeCollector)`.
    ///
    /// Java reaches the open traces' infos through `ctx`; they are passed in here instead (see the
    /// module divergence note).
    pub fn fill_entries(
        &self,
        cc: &mut ChangeCollector,
        trace_infos: &[Arc<Mutex<dyn InfoPerTrace>>],
    ) {
        if self.url.is_none() {
            return;
        }
        for info in trace_infos {
            info.lock().unwrap().fill_entries_for_program(cc, self);
        }
    }

    /// Port of `InfoPerProgram.getOpenMappedTraceLocations(Address)`.
    pub fn get_open_mapped_trace_locations(&self, address: &Address) -> Vec<Box<dyn TraceLocation>> {
        let mut result = Vec::new();
        for set in self.inbound_by_static_address.head_inclusive(address) {
            for me in set {
                let guard = me.lock().unwrap();
                if guard.is_mapping_deleted() {
                    Msg::warn("InfoPerProgram", &"Encountered deleted mapping");
                    continue;
                }
                if !guard.is_in_program_range(address) {
                    continue;
                }
                result.push(guard.map_program_address_to_trace_location(address));
            }
        }
        result
    }

    /// Port of `InfoPerProgram.getOpenMappedTraceLocation(Trace, Address, long)`.
    pub fn get_open_mapped_trace_location(
        &self,
        trace: &Arc<dyn Trace>,
        address: &Address,
        snap: i64,
    ) -> Option<Box<dyn TraceLocation>> {
        for set in self.inbound_by_static_address.head_inclusive(address) {
            for me in set {
                let guard = me.lock().unwrap();
                if guard.is_mapping_deleted() {
                    Msg::warn("InfoPerProgram", &"Encountered deleted mapping");
                    continue;
                }
                if !Arc::ptr_eq(&guard.get_trace(), trace) {
                    continue;
                }
                if !guard.is_in_program_range(address) {
                    continue;
                }
                if !guard.is_in_trace_lifespan(snap) {
                    continue;
                }
                return Some(guard.map_program_address_to_trace_location(address));
            }
        }
        None
    }

    /// Port of the private `InfoPerProgram.collectOpenMappedViews(Map, AddressRange)`.
    fn collect_open_mapped_views(
        &self,
        result: &mut HashMap<DefaultTraceSpan, Vec<MappedAddressRange>>,
        rng: &AddressRange,
    ) {
        for set in self.inbound_by_static_address.head_inclusive(rng.max_address()) {
            for me in set {
                let guard = me.lock().unwrap();
                if guard.is_mapping_deleted() {
                    Msg::warn("InfoPerProgram", &"Encountered deleted mapping");
                    continue;
                }
                // NB. No lifespan to consider.
                if !guard.is_in_program_range_for_range(rng) {
                    continue;
                }
                let Some(static_range) = guard.get_static_range() else {
                    continue;
                };
                let Some(src_range) = static_range.intersect(rng) else {
                    continue;
                };
                let dst_range = guard.map_program_range_to_trace(rng);
                result
                    .entry(guard.get_trace_span())
                    .or_default()
                    .push(MappedAddressRange::new(src_range, dst_range));
            }
        }
    }

    /// Port of `InfoPerProgram.getOpenMappedViews(AddressSetView)`.
    pub fn get_open_mapped_views(
        &self,
        set: &dyn AddressSetView,
    ) -> HashMap<DefaultTraceSpan, Vec<MappedAddressRange>> {
        let mut result = HashMap::new();
        for rng in set.address_ranges() {
            self.collect_open_mapped_views(&mut result, &rng);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_file::DomainFile;
    use crate::framework::model::domain_object::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::model::thread::trace_thread::TraceThread;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockDomainFile {
        url: Option<String>,
    }

    impl DomainFile for MockDomainFile {
        fn get_shared_project_url(&self, _reference: Option<&str>) -> Option<String> {
            self.url.clone()
        }
    }

    struct MockProgram {
        url: Mutex<Option<String>>,
    }

    impl DomainObject for MockProgram {
        fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
            Some(Box::new(MockDomainFile {
                url: self.url.lock().unwrap().clone(),
            }))
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    struct MockTrace;
    impl DomainObject for MockTrace {
        fn get_name(&self) -> String {
            "mock-trace".to_string()
        }
    }
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
            unimplemented!("not exercised by this smoke test")
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
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
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

    struct MockMappingEntry {
        trace: Arc<dyn Trace>,
        static_range: Mutex<Option<AddressRange>>,
        target_static_range: AddressRange,
        static_program_url: String,
        deleted: bool,
        lifespan_ok: bool,
        clear_calls: AtomicUsize,
        fill_calls: AtomicUsize,
    }

    impl MappingEntry for MockMappingEntry {
        fn get_trace(&self) -> Arc<dyn Trace> {
            Arc::clone(&self.trace)
        }

        fn get_static_range(&self) -> Option<AddressRange> {
            self.static_range.lock().unwrap().clone()
        }

        fn get_static_address(&self) -> Option<Address> {
            self.static_range
                .lock()
                .unwrap()
                .as_ref()
                .map(|r| r.min_address().clone())
        }

        fn get_trace_span(&self) -> DefaultTraceSpan {
            DefaultTraceSpan::new(Arc::clone(&self.trace), crate::trace::model::lifespan::Lifespan::span(0, 10))
        }

        fn is_in_trace_lifespan(&self, _snap: i64) -> bool {
            self.lifespan_ok
        }

        fn is_in_program_range(&self, address: &Address) -> bool {
            self.static_range
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|r| r.contains(address))
        }

        fn is_in_program_range_for_range(&self, rng: &AddressRange) -> bool {
            self.static_range
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|r| r.intersects(rng))
        }

        fn map_program_address_to_trace_location(&self, _address: &Address) -> Box<dyn TraceLocation> {
            Box::new(MockTraceLocation)
        }

        fn map_program_range_to_trace(&self, rng: &AddressRange) -> AddressRange {
            rng.clone()
        }

        fn get_static_program_url(&self) -> Option<String> {
            Some(self.static_program_url.clone())
        }

        fn is_mapping_deleted(&self) -> bool {
            self.deleted
        }

        fn clear_program(&mut self, _cc: &mut ChangeCollector, _program: &dyn Program) {
            self.clear_calls.fetch_add(1, Ordering::SeqCst);
            *self.static_range.lock().unwrap() = None;
        }

        fn fill_program(&mut self, _cc: &mut ChangeCollector, _program: &dyn Program) {
            self.fill_calls.fetch_add(1, Ordering::SeqCst);
            *self.static_range.lock().unwrap() = Some(self.target_static_range.clone());
        }
    }

    struct MockTraceLocation;
    impl TraceLocation for MockTraceLocation {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_lifespan(&self) -> crate::trace::model::lifespan::Lifespan {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            addr(0)
        }
    }

    fn make_program(url: Option<&str>) -> Arc<MockProgram> {
        Arc::new(MockProgram {
            url: Mutex::new(url.map(|s| s.to_string())),
        })
    }

    #[test]
    fn new_computes_url_from_program_domain_file() {
        let program = make_program(Some("ghidra://repo/a"));
        let info = InfoPerProgram::new(program);
        assert_eq!(info.url.as_deref(), Some("ghidra://repo/a"));
        assert!(info.url_matches());
    }

    #[test]
    fn url_matches_false_after_program_url_changes() {
        let program = make_program(Some("ghidra://repo/a"));
        let info = InfoPerProgram::new(Arc::clone(&program) as Arc<dyn Program>);
        *program.url.lock().unwrap() = Some("ghidra://repo/b".to_string());
        assert!(!info.url_matches());
    }

    #[test]
    fn fill_program_then_clear_program_round_trips_index() {
        let program = make_program(Some("ghidra://repo/a"));
        let info = InfoPerProgram::new(Arc::clone(&program) as Arc<dyn Program>);
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry {
            trace: Arc::clone(&trace),
            static_range: Mutex::new(None),
            target_static_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            static_program_url: "ghidra://repo/a".to_string(),
            deleted: false,
            lifespan_ok: true,
            clear_calls: AtomicUsize::new(0),
            fill_calls: AtomicUsize::new(0),
        }));

        let mut cc = ChangeCollector::new();
        let mut info = info;
        info.fill_program(&mut cc, Arc::clone(&me));

        let found = info.get_open_mapped_trace_location(&trace, &addr(0x1800), 5);
        assert!(found.is_some());

        let locations = info.get_open_mapped_trace_locations(&addr(0x1800));
        assert_eq!(locations.len(), 1);

        info.clear_program(&mut cc, Arc::clone(&me));
        assert!(info
            .get_open_mapped_trace_location(&trace, &addr(0x1800), 5)
            .is_none());
    }

    #[test]
    fn get_open_mapped_trace_location_respects_lifespan_and_trace_identity() {
        let program = make_program(Some("ghidra://repo/a"));
        let mut info = InfoPerProgram::new(Arc::clone(&program) as Arc<dyn Program>);
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let other_trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry {
            trace: Arc::clone(&trace),
            static_range: Mutex::new(None),
            target_static_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            static_program_url: "ghidra://repo/a".to_string(),
            deleted: false,
            lifespan_ok: false,
            clear_calls: AtomicUsize::new(0),
            fill_calls: AtomicUsize::new(0),
        }));
        let mut cc = ChangeCollector::new();
        info.fill_program(&mut cc, Arc::clone(&me));

        // Wrong trace identity.
        assert!(info
            .get_open_mapped_trace_location(&other_trace, &addr(0x1800), 5)
            .is_none());
        // Right trace, but lifespan check fails (mock always returns false).
        assert!(info
            .get_open_mapped_trace_location(&trace, &addr(0x1800), 5)
            .is_none());
    }

    #[test]
    fn get_open_mapped_views_maps_static_range_to_trace_range() {
        let program = make_program(Some("ghidra://repo/a"));
        let mut info = InfoPerProgram::new(Arc::clone(&program) as Arc<dyn Program>);
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let target = AddressRange::new(addr(0x1000), addr(0x1fff));
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry {
            trace: Arc::clone(&trace),
            static_range: Mutex::new(None),
            target_static_range: target.clone(),
            static_program_url: "ghidra://repo/a".to_string(),
            deleted: false,
            lifespan_ok: true,
            clear_calls: AtomicUsize::new(0),
            fill_calls: AtomicUsize::new(0),
        }));
        let mut cc = ChangeCollector::new();
        info.fill_program(&mut cc, Arc::clone(&me));

        let mut set = crate::program::model::address::AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1fff));

        let views = info.get_open_mapped_views(&set);
        assert_eq!(views.len(), 1);
        let ranges = views.values().next().unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(*ranges[0].source_address_range(), target);
    }
}
