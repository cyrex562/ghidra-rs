//! Port of `ghidra.app.plugin.core.memory.MemoryMapPlugin`.
//!
//! Displays a memory map of all blocks in the current program's memory. Options for adding,
//! editing, and deleting memory blocks are available through the [`MemoryMapProvider`] window.
//!
//! # Shape
//!
//! Java's `MemoryMapPlugin` is a concrete class (nothing extends it), so it becomes a plain
//! `struct` (rule R14a-concrete-leaf, per `scripts/shape_rules.py`). It extends `ProgramPlugin`
//! (itself extending `Plugin`), neither of which is ported yet. Rather than invent a
//! `ProgramPlugin` base for this one caller, this struct directly holds `ProgramPlugin`'s
//! `currentProgram` field and re-implements the subset of its `processEvent` dispatch that
//! `MemoryMapPlugin` actually overrides -- `programActivated`/`programDeactivated` (driven by
//! `ProgramActivatedPluginEvent`) and `locationChanged` (driven by `ProgramLocationPluginEvent`)
//! -- exactly as [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) and
//! [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin) already
//! re-implement `Plugin`'s own base state rather than inheriting it. `ProgramPlugin`'s other four
//! event branches (`ProgramOpenedPluginEvent`, `ProgramClosedPluginEvent`,
//! `ProgramSelectionPluginEvent`, `ProgramHighlightPluginEvent`, `ProgramPostActivatedPluginEvent`)
//! all resolve to `ProgramPlugin`'s default no-op overrides in this class, so they are omitted
//! rather than registering interest in events with no observable effect.
//!
//! # Seams
//!
//! * **`MemoryMapManager`/`MemoryMapProvider`.** Neither is ported. Java's constructor builds
//!   both with a back-reference to the plugin (`new MemoryMapManager(this)`, `new
//!   MemoryMapProvider(this)`); that cycle is broken by having [`MemoryMapPlugin::new`] take
//!   already-built collaborators instead, the same approach `DecompilePlugin`/`DisassemblerPlugin`
//!   use for their own unported collaborators. Minimal placeholder traits for both live in
//!   [`seam_stubs`].
//! * **`Program.addListener(this)`/`removeListener(this)`.** `DomainObject::add_listener` takes
//!   an owned `Box<dyn DomainObjectListener>`, and `remove_listener` compares against a
//!   previously-added reference; there is no way for a `&self` method to hand out an owned box of
//!   itself without an interior-mutable self-registration mechanism this crate does not have yet
//!   for `Plugin`s. Since nothing about this plugin's own behavior depends on actually being
//!   registered as a listener (its [`domain_object_changed`](Self::domain_object_changed) is
//!   exercised directly, e.g. by tests, instead), the registration calls are omitted; wiring a
//!   live plugin instance up as a program's listener is left to whatever framework code manages
//!   plugin lifecycles.
//! * **`GoToService`.** Java resolves it once in `init()` and reuses it later in `blockSelected`.
//!   This crate's [`PluginTool::get_service`] hands services back type-erased as `Arc<dyn Any +
//!   Send + Sync>`, with no way to recover a `dyn GoToService` from it (the same gap documented on
//!   `DecompilePlugin`'s clipboard service). `init()` therefore does not resolve or store it;
//!   [`MemoryMapPlugin::block_selected`] takes the resolved service as a parameter instead,
//!   mirroring `DecompilePlugin::export_location`.

use super::seam_stubs::{MemoryMapManager, MemoryMapProvider};

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::events::{ProgramActivatedPluginEvent, ProgramLocationPluginEvent};
use crate::app::plugin::plugin_category_names::PluginCategoryNames;
use crate::app::seam_stubs::CorePluginPackage;
use crate::app::services::GoToService;
use crate::framework::model::{DomainObjectChangedEvent, DomainObjectEvent, DomainObjectListener};
use crate::framework::plugintool::util::{
    PluginDescription, PluginEventListener, PluginStatus, ServiceListener,
};
use crate::framework::plugintool::{Plugin, PluginEvent};
use crate::framework::seam_stubs::{PluginPackageLike, PluginTool};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::{Memory, MemoryBlock};
use crate::program::util::{ProgramEvent, ProgramLocation};
use crate::util::classfinder::ExtensionPoint;

/// Fully-qualified name of the single service `@PluginInfo(servicesRequired = ...)` lists.
const GO_TO_SERVICE: &str = "ghidra.app.services.GoToService";

/// The events this plugin (via its unported `ProgramPlugin` base) has observable behavior for;
/// see the module docs for why the other `ProgramPlugin`-registered events are omitted.
const EVENTS_CONSUMED_NAMES: [&str; 2] = [
    "Program Activated",
    crate::app::events::program_location_plugin_event::NAME,
];

/// The `new ProgramLocation(currentProgram, addr)` Java's `blockSelected` builds.
struct AddressProgramLocation {
    program: Arc<dyn Program>,
    address: Address,
}

impl ProgramLocation for AddressProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }

    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte_address(&self) -> Address {
        self.address.clone()
    }
}

/// Displays a memory map of all blocks in the current program's memory. Options for adding,
/// editing, and deleting those memory blocks are available.
///
/// Port of `ghidra.app.plugin.core.memory.MemoryMapPlugin`.
pub struct MemoryMapPlugin {
    tool: Arc<dyn PluginTool + Send + Sync>,
    provider: Arc<dyn MemoryMapProvider>,
    mem_manager: Arc<dyn MemoryMapManager>,

    // `ProgramPlugin`'s `currentProgram` field; see the module docs for why the rest of that
    // base class is not ported.
    current_program: Mutex<Option<Arc<dyn Program>>>,

    // State Java inherits from the `Plugin` base class; see the module docs on `DecompilePlugin`.
    services_provided: Mutex<HashMap<String, Vec<Arc<dyn Any + Send + Sync>>>>,
    events_consumed: Mutex<HashSet<String>>,
    disposed: AtomicBool,
    description: MemoryMapPluginDescription,
}

impl MemoryMapPlugin {
    /// Port of `MemoryMapPlugin(PluginTool)`.
    ///
    /// Java also constructs its manager and provider here (`new MemoryMapManager(this)`, `new
    /// MemoryMapProvider(this)`); both are passed in instead (see the module docs).
    pub fn new(
        tool: Arc<dyn PluginTool + Send + Sync>,
        provider: Arc<dyn MemoryMapProvider>,
        mem_manager: Arc<dyn MemoryMapManager>,
    ) -> Self {
        Self {
            tool,
            provider,
            mem_manager,
            current_program: Mutex::new(None),
            services_provided: Mutex::new(HashMap::new()),
            events_consumed: Mutex::new(HashSet::new()),
            disposed: AtomicBool::new(false),
            description: MemoryMapPluginDescription,
        }
    }

    /// Port of the package-private `getMemoryMapManager()`.
    fn memory_map_manager(&self) -> &Arc<dyn MemoryMapManager> {
        &self.mem_manager
    }

    /// Port of the package-private `getMemoryMapProvider()`.
    fn memory_map_provider(&self) -> &Arc<dyn MemoryMapProvider> {
        &self.provider
    }

    /// Port of the package-private `getMemory()`.
    ///
    /// Java assumes `currentProgram` is non-null here (as does the Java caller); panics the same
    /// way Java's `NullPointerException` would if called with no active program.
    fn memory(&self) -> Arc<dyn Memory> {
        self.current_program
            .lock()
            .unwrap()
            .as_ref()
            .expect("getMemory() called with no active program")
            .get_memory()
            .expect("program has no memory")
    }

    /// Port of the package-private `blockSelected(MemoryBlock, Address)`, called when a memory
    /// location in a memory block line is selected in the memory map dialog.
    ///
    /// Java's `block` parameter is unused in the method body; kept here for signature fidelity.
    /// See the module docs for why `go_to_service` is a parameter rather than a stored field.
    pub fn block_selected(
        &self,
        _block: &dyn MemoryBlock,
        addr: Address,
        go_to_service: &dyn GoToService,
    ) {
        let Some(program) = self.current_program.lock().unwrap().clone() else {
            return;
        };
        let loc = AddressProgramLocation { program, address: addr };
        go_to_service.go_to(&loc);
    }

    /// Port of `init()`'s remaining body once `GoToService` resolution is factored out (see the
    /// module docs): if a program is already current, activate it as `ProgramPlugin`'s
    /// constructor-time `programActivated(currentProgram)` call would.
    fn init_current_program(&self) {
        if let Some(program) = self.current_program.lock().unwrap().clone() {
            self.program_activated(&program);
        }
    }

    /// Port of the protected `programActivated(Program)`.
    fn program_activated(&self, program: &Arc<dyn Program>) {
        self.mem_manager.set_program(Some(program.clone()));
        self.provider.set_program(Some(program.clone()));
    }

    /// Port of the protected `programDeactivated(Program)`.
    fn program_deactivated(&self, _program: &Arc<dyn Program>) {
        self.mem_manager.set_program(None);
        self.provider.set_program(None);
    }

    /// Port of `processEvent`'s `ProgramActivatedPluginEvent` branch, inherited (in Java) from
    /// `ProgramPlugin`.
    pub fn process_program_activated_event(&self, event: &ProgramActivatedPluginEvent) {
        let new_program = event.get_active_program();
        let old_program = {
            let mut current = self.current_program.lock().unwrap();
            std::mem::replace(&mut *current, new_program.clone())
        };
        if let Some(old_program) = old_program {
            self.program_deactivated(&old_program);
        }
        if let Some(new_program) = &new_program {
            self.program_activated(new_program);
        }
    }

    /// Port of `processEvent`'s `ProgramLocationPluginEvent` branch, delegating to
    /// `locationChanged`, inherited (in Java) from `ProgramPlugin`.
    pub fn process_program_location_event(&self, event: &ProgramLocationPluginEvent) {
        if self.current_program.lock().unwrap().is_none() {
            // currentProgram is null because we haven't gotten the open program event yet.
            return;
        }
        if let Some(location) = event.get_location() {
            self.location_changed(location.as_ref());
        }
    }

    /// Port of the protected `locationChanged(ProgramLocation)`.
    fn location_changed(&self, location: &dyn ProgramLocation) {
        self.provider.location_changed(location);
    }
}

impl ExtensionPoint for MemoryMapPlugin {}

impl PluginEventListener for MemoryMapPlugin {
    fn event_sent(&self, event: &PluginEvent) {
        self.handle_plugin_event(event);
    }
}

impl ServiceListener for MemoryMapPlugin {
    fn service_added(&self, _interface_class: std::any::TypeId, _service: Arc<dyn Any + Send + Sync>) {}
    fn service_removed(&self, _interface_class: std::any::TypeId, _service: Arc<dyn Any + Send + Sync>) {}
}

impl DomainObjectListener for MemoryMapPlugin {
    /// Port of `domainObjectChanged(DomainObjectChangedEvent)`.
    ///
    /// Java's `provider == null` half of the guard is not modeled: `provider` is never optional
    /// here (see the module docs), so only visibility is checked.
    fn domain_object_changed(&mut self, ev: &DomainObjectChangedEvent<'_>) {
        if !self.provider.is_visible() {
            return;
        }
        if ev.contains_any(&[
            &ProgramEvent::MemoryBlockAdded,
            &ProgramEvent::MemoryBlockRemoved,
            &ProgramEvent::MemoryBlockMoved,
            &ProgramEvent::MemoryBlockSplit,
            &ProgramEvent::MemoryBlocksJoined,
            &DomainObjectEvent::Restored,
        ]) {
            self.provider.update_map();
        } else if ev.contains(&ProgramEvent::MemoryBlockChanged) {
            self.provider.update_data();
        }
    }
}

impl Plugin for MemoryMapPlugin {
    fn name(&self) -> String {
        "MemoryMapPlugin".to_string()
    }

    fn tool(&self) -> Arc<dyn PluginTool> {
        self.tool.clone()
    }

    fn plugin_description(&self) -> &dyn PluginDescription {
        &self.description
    }

    fn is_disposed(&self) -> bool {
        self.disposed.load(Ordering::SeqCst)
    }

    fn events_consumed(&self) -> Vec<String> {
        let mut names: Vec<String> = EVENTS_CONSUMED_NAMES.iter().map(|n| n.to_string()).collect();
        for name in self.events_consumed.lock().unwrap().iter() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }

    fn service_classes(&self) -> Vec<String> {
        self.services_provided.lock().unwrap().keys().cloned().collect()
    }

    fn service_provider_instances(&self, interface_class: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        self.services_provided
            .lock()
            .unwrap()
            .get(interface_class)
            .cloned()
            .unwrap_or_default()
    }

    fn register_service_provided(&self, interface_class: &str, service: Arc<dyn Any + Send + Sync>) {
        self.services_provided
            .lock()
            .unwrap()
            .entry(interface_class.to_string())
            .or_default()
            .push(service);
    }

    fn deregister_service(&self, interface_class: &str, service: &Arc<dyn Any + Send + Sync>) {
        let mut services = self.services_provided.lock().unwrap();
        if let Some(instances) = services.get_mut(interface_class) {
            instances.retain(|registered| !Arc::ptr_eq(registered, service));
            if instances.is_empty() {
                services.remove(interface_class);
            }
        }
    }

    fn internal_register_event_consumed(&self, event_class: &str) {
        self.events_consumed.lock().unwrap().insert(event_class.to_string());
    }

    /// Port of `init()`. See the module docs for why `GoToService` resolution is not part of it.
    fn init(&self) {
        self.init_current_program();
    }

    /// Port of `dispose()`.
    fn dispose(&self) {
        self.provider.dispose();
        *self.current_program.lock().unwrap() = None;
    }

    fn cleanup(&self) {
        self.dispose();
        self.disposed.store(true, Ordering::SeqCst);
    }

    /// Port of `processEvent(PluginEvent)`, inherited (in Java) from `ProgramPlugin`. See the
    /// module docs for why this recognizes only the two events with observable effect here.
    fn process_event(&self, _event: &PluginEvent) {}
}

/// The `@PluginInfo` metadata declared on `MemoryMapPlugin`, as a [`PluginDescription`].
///
/// Java derives this from the annotation by reflection at registration time; with no annotations
/// to read, the values are stated directly here.
struct MemoryMapPluginDescription;

impl PluginCategoryNames for MemoryMapPluginDescription {}

impl PluginDescription for MemoryMapPluginDescription {
    fn plugin_class_name(&self) -> String {
        "ghidra.app.plugin.core.memory.MemoryMapPlugin".to_string()
    }

    fn name(&self) -> String {
        "MemoryMapPlugin".to_string()
    }

    fn short_description(&self) -> String {
        "Memory Map View".to_string()
    }

    fn description(&self) -> String {
        "This plugin provides the memory map component which allows users to add, remove, and \
         edit memory blocks."
            .to_string()
    }

    fn category(&self) -> String {
        Self::COMMON.to_string()
    }

    fn status(&self) -> PluginStatus {
        PluginStatus::Released
    }

    fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
        Box::new(CorePluginPackage)
    }

    fn is_slow_installation(&self) -> bool {
        false
    }

    fn services_required(&self) -> Vec<String> {
        vec![GO_TO_SERVICE.to_string()]
    }

    fn services_provided(&self) -> Vec<String> {
        Vec::new()
    }

    fn events_consumed(&self) -> Vec<String> {
        Vec::new()
    }

    fn events_produced(&self) -> Vec<String> {
        vec!["ghidra.app.events.ProgramLocationPluginEvent".to_string()]
    }

    fn source_location(&self) -> String {
        String::new()
    }

    fn module_name(&self) -> String {
        "Base".to_string()
    }

    fn is_in_extension(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn test_address(offset: i64) -> Address {
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    struct MockManager {
        set_programs: Mutex<Vec<Option<String>>>,
    }

    impl Default for MockManager {
        fn default() -> Self {
            Self { set_programs: Mutex::new(Vec::new()) }
        }
    }

    impl MemoryMapManager for MockManager {
        fn set_program(&self, program: Option<Arc<dyn Program>>) {
            self.set_programs
                .lock()
                .unwrap()
                .push(program.map(|p| Program::get_name(p.as_ref())));
        }
    }

    #[derive(Default)]
    struct MockProvider {
        visible: std::sync::atomic::AtomicBool,
        disposed: AtomicUsize,
        map_updates: AtomicUsize,
        data_updates: AtomicUsize,
        set_programs: Mutex<Vec<Option<String>>>,
        locations: Mutex<Vec<i64>>,
    }

    impl MockProvider {
        fn visible() -> Arc<Self> {
            let provider = Self::default();
            provider.visible.store(true, Ordering::SeqCst);
            Arc::new(provider)
        }
    }

    impl MemoryMapProvider for MockProvider {
        fn dispose(&self) {
            self.disposed.fetch_add(1, Ordering::SeqCst);
        }

        fn is_visible(&self) -> bool {
            self.visible.load(Ordering::SeqCst)
        }

        fn update_map(&self) {
            self.map_updates.fetch_add(1, Ordering::SeqCst);
        }

        fn update_data(&self) {
            self.data_updates.fetch_add(1, Ordering::SeqCst);
        }

        fn set_program(&self, program: Option<Arc<dyn Program>>) {
            self.set_programs
                .lock()
                .unwrap()
                .push(program.map(|p| Program::get_name(p.as_ref())));
        }

        fn location_changed(&self, location: &dyn ProgramLocation) {
            self.locations.lock().unwrap().push(location.get_address().offset());
        }
    }

    struct MockProgram {
        name: String,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            None
        }
    }

    struct MockMemory;

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(0x42)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
    }

    struct MockProgramWithMemory {
        name: String,
    }

    impl crate::framework::model::DomainObject for MockProgramWithMemory {}

    impl Program for MockProgramWithMemory {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(Arc::new(MockMemory))
        }
    }

    struct MockGoToService {
        calls: Mutex<Vec<i64>>,
    }

    struct MockNavigatable;
    impl crate::app::seam_stubs::Navigatable for MockNavigatable {
        fn is_connected(&self) -> bool {
            true
        }
        fn get_program(&self) -> Box<dyn Program> {
            Box::new(MockProgram { name: "mock".to_string() })
        }
    }

    impl GoToService for MockGoToService {
        fn go_to(&self, loc: &dyn ProgramLocation) -> bool {
            self.calls.lock().unwrap().push(loc.get_address().offset());
            true
        }

        fn go_to_in_program(&self, _loc: &dyn ProgramLocation, _program: &dyn Program) -> bool {
            false
        }

        fn go_to_navigatable_location(
            &self,
            _navigatable: &dyn crate::app::seam_stubs::Navigatable,
            _loc: &dyn ProgramLocation,
            _program: &dyn Program,
        ) -> bool {
            false
        }

        fn go_to_navigatable_address_with_ref(
            &self,
            _navigatable: &dyn crate::app::seam_stubs::Navigatable,
            _program: &dyn Program,
            _address: &Address,
            _ref_address: &Address,
        ) -> bool {
            false
        }

        fn go_to_from_address(&self, _from_address: &Address, _address: &Address) -> bool {
            false
        }

        fn go_to_navigatable_address(
            &self,
            _navigatable: &dyn crate::app::seam_stubs::Navigatable,
            _go_to_address: &Address,
        ) -> bool {
            false
        }

        fn go_to_address(&self, _go_to_address: &Address) -> bool {
            false
        }

        fn go_to_address_in_program(&self, _go_to_address: &Address, _program: &dyn Program) -> bool {
            false
        }

        fn go_to_external_location(
            &self,
            _external_loc: &dyn crate::program::model::symbol::ExternalLocation,
            _check_navigation_option: bool,
        ) -> bool {
            false
        }

        fn go_to_navigatable_external_location(
            &self,
            _navigatable: &dyn crate::app::seam_stubs::Navigatable,
            _external_loc: &dyn crate::program::model::symbol::ExternalLocation,
            _check_navigation_option: bool,
        ) -> bool {
            false
        }

        fn go_to_query(
            &self,
            _from_addr: &Address,
            _query_data: &crate::app::services::query_data::QueryData,
            _listener: &dyn crate::app::services::GoToServiceListener,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            false
        }

        fn go_to_query_navigatable(
            &self,
            _navigatable: &dyn crate::app::seam_stubs::Navigatable,
            _from_addr: &Address,
            _query_data: &crate::app::services::query_data::QueryData,
            _listener: &dyn crate::app::services::GoToServiceListener,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            false
        }

        fn get_default_navigatable(&self) -> Arc<dyn crate::app::seam_stubs::Navigatable> {
            Arc::new(MockNavigatable)
        }

        fn get_override_service(&self) -> Option<Arc<dyn crate::app::seam_stubs::GoToOverrideService>> {
            None
        }

        fn set_override_service(
            &mut self,
            _override_service: Option<Arc<dyn crate::app::seam_stubs::GoToOverrideService>>,
        ) {
        }
    }

    struct MockTool;
    impl PluginTool for MockTool {}

    fn plugin_with(
        provider: Arc<dyn MemoryMapProvider>,
        manager: Arc<dyn MemoryMapManager>,
    ) -> MemoryMapPlugin {
        MemoryMapPlugin::new(Arc::new(MockTool), provider, manager)
    }

    fn make_program(name: &str) -> Arc<dyn Program> {
        Arc::new(MockProgram { name: name.to_string() })
    }

    #[test]
    fn program_activated_pushes_program_into_manager_and_provider() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let plugin = plugin_with(provider.clone(), manager.clone());
        let program = make_program("hello");

        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            program.clone(),
        ));

        assert_eq!(*manager.set_programs.lock().unwrap(), vec![Some("hello".to_string())]);
        assert_eq!(*provider.set_programs.lock().unwrap(), vec![Some("hello".to_string())]);
    }

    #[test]
    fn activating_a_new_program_deactivates_the_old_one_first() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let plugin = plugin_with(provider.clone(), manager.clone());
        let first = make_program("first");
        let second = make_program("second");

        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            first.clone(),
        ));
        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            second.clone(),
        ));

        assert_eq!(
            *manager.set_programs.lock().unwrap(),
            vec![Some("first".to_string()), None, Some("second".to_string())]
        );
    }

    #[test]
    fn dispose_disposes_the_provider_and_clears_the_current_program() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let plugin = plugin_with(provider.clone(), manager);
        let program = make_program("hello");
        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            program.clone(),
        ));

        plugin.dispose();

        assert_eq!(provider.disposed.load(Ordering::SeqCst), 1);
        assert!(plugin.current_program.lock().unwrap().is_none());
    }

    #[test]
    fn domain_object_changed_updates_map_for_block_structure_events() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let mut plugin = plugin_with(provider.clone(), manager);

        let source = MockProgram { name: "p".to_string() };
        let record = crate::framework::model::DomainObjectChangeRecord::new(
            Box::new(ProgramEvent::MemoryBlockAdded),
        );
        let event = DomainObjectChangedEvent::new(&source, vec![record]);

        plugin.domain_object_changed(&event);

        assert_eq!(provider.map_updates.load(Ordering::SeqCst), 1);
        assert_eq!(provider.data_updates.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn domain_object_changed_updates_data_for_block_changed_event() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let mut plugin = plugin_with(provider.clone(), manager);

        let source = MockProgram { name: "p".to_string() };
        let record = crate::framework::model::DomainObjectChangeRecord::new(
            Box::new(ProgramEvent::MemoryBlockChanged),
        );
        let event = DomainObjectChangedEvent::new(&source, vec![record]);

        plugin.domain_object_changed(&event);

        assert_eq!(provider.map_updates.load(Ordering::SeqCst), 0);
        assert_eq!(provider.data_updates.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn domain_object_changed_is_ignored_while_the_provider_is_not_visible() {
        let manager = Arc::new(MockManager::default());
        let provider = Arc::new(MockProvider::default());
        let mut plugin = plugin_with(provider.clone(), manager);

        let source = MockProgram { name: "p".to_string() };
        let record = crate::framework::model::DomainObjectChangeRecord::new(
            Box::new(ProgramEvent::MemoryBlockAdded),
        );
        let event = DomainObjectChangedEvent::new(&source, vec![record]);

        plugin.domain_object_changed(&event);

        assert_eq!(provider.map_updates.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn block_selected_goes_to_the_selected_address_in_the_current_program() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let plugin = plugin_with(provider, manager);
        let program = make_program("hello");
        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            program.clone(),
        ));
        let go_to_service = MockGoToService { calls: Mutex::new(Vec::new()) };
        let addr = test_address(0x400);

        struct DummyBlock;
        impl MemoryBlock for DummyBlock {
            fn get_name(&self) -> &str {
                "dummy"
            }
            fn get_start(&self) -> Address {
                test_address(0)
            }
            fn get_end(&self) -> Address {
                test_address(0)
            }
            fn get_size(&self) -> u64 {
                0
            }
            fn is_initialized(&self) -> bool {
                false
            }
            fn get_byte(&self, _addr: &Address) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
                Ok(0)
            }
            fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
                0
            }
            fn set_bytes(
                &mut self,
                _addr: &Address,
                _source: &[u8],
            ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
                Ok(())
            }
        }

        plugin.block_selected(&DummyBlock, addr, &go_to_service);

        assert_eq!(*go_to_service.calls.lock().unwrap(), vec![0x400]);
    }

    #[test]
    fn plugin_description_matches_the_plugin_info_annotation() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let plugin = plugin_with(provider, manager);
        let description = plugin.plugin_description();

        assert_eq!(description.name(), "MemoryMapPlugin");
        assert_eq!(description.short_description(), "Memory Map View");
        assert_eq!(description.category(), "Common");
        assert_eq!(description.services_required(), vec!["ghidra.app.services.GoToService"]);
        assert_eq!(
            description.events_produced(),
            vec!["ghidra.app.events.ProgramLocationPluginEvent"]
        );
    }

    #[test]
    fn accessors_expose_the_manager_provider_and_current_program_memory() {
        let manager = Arc::new(MockManager::default());
        let provider = MockProvider::visible();
        let plugin = plugin_with(provider.clone(), manager.clone());
        let program: Arc<dyn Program> = Arc::new(MockProgramWithMemory { name: "hello".to_string() });

        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            program.clone(),
        ));

        let manager_as_trait: Arc<dyn MemoryMapManager> = manager.clone();
        let provider_as_trait: Arc<dyn MemoryMapProvider> = provider.clone();
        assert!(Arc::ptr_eq(plugin.memory_map_manager(), &manager_as_trait));
        assert!(Arc::ptr_eq(plugin.memory_map_provider(), &provider_as_trait));
        assert_eq!(
            plugin.memory().get_byte(&test_address(0)).unwrap(),
            0x42
        );
    }
}
