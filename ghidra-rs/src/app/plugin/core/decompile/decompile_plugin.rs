//! Port of `ghidra.app.plugin.core.decompile.DecompilePlugin`.
//!
//! The tool plugin behind the Decompiler window: it owns the connected (primary) decompiler
//! window plus any number of disconnected snapshot windows, keeps them in step with the tool's
//! current program/location/selection, and saves and restores them with the tool's data state.
//!
//! # Shape
//!
//! Java's `DecompilePlugin` is a concrete class (nothing extends it), so it becomes a plain
//! `struct` (rule R14a-concrete-leaf). It extends `Plugin`, which is ported as a trait, so the
//! methods it `@Override`s there are implemented through
//! [`Plugin`](crate::framework::plugintool::Plugin) (and its
//! [`ServiceListener`]/[`PluginEventListener`]/[`ExtensionPoint`] supertraits). The state Java
//! inherits from the `Plugin` base class -- the provided-service registry, the consumed-event set
//! and the disposed flag -- has no base struct to live in, so this struct holds it, the same way
//! the `Plugin` trait's own test double does.
//!
//! # Seams
//!
//! `DecompilerProvider` is not ported yet, and Java's constructor builds both the connected
//! provider and each disconnected one with a back-reference to the plugin (`new
//! PrimaryDecompilerProvider(this)`). That cycle is broken the only way it can be in Rust: the
//! providers are constructed by the caller and handed in ([`DecompilePlugin::new`],
//! [`DecompilePlugin::create_new_disconnected_provider`]). The connected provider is typed as the
//! [`DecompilerProvider`] stub rather than as `PrimaryDecompilerProvider`, since the plugin only
//! ever uses the inherited surface (`PrimaryDecompilerProvider` adds nothing but a hard-coded
//! `isConnected()`), and it must be identity-comparable against the disconnected ones.
//!
//! Two further seams shape the method signatures below:
//!
//! * Services. This crate's [`PluginTool::get_service`] hands services back type-erased as
//!   `Arc<dyn Any>`, with no way to recover an `Arc<dyn SomeService>`. Where the erased handle is
//!   only passed along (the clipboard service, the hover services) it is passed along erased.
//!   Where Java actually calls the service ([`export_location`](DecompilePlugin::export_location),
//!   [`read_data_state_restoring_providers`](DecompilePlugin::read_data_state_restoring_providers)),
//!   the resolved service is taken as a parameter instead.
//! * Events. This crate models `PluginEvent` as one concrete struct with no subclass payload and
//!   no downcasting seam, so the `instanceof` ladder in `processEvent` becomes one typed method
//!   per event (`process_*_event`), and [`Plugin::process_event`] can only document that.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::decompiler::ClangToken;
use crate::app::events::{ProgramActivatedPluginEvent, ProgramClosedPluginEvent};
use crate::app::plugin::plugin_category_names::PluginCategoryNames;
use crate::app::seam_stubs::{
    CorePluginPackage, DecompilerHoverService, DecompilerProvider, ProgramLocationPluginEvent,
    ProgramSelection, ProgramSelectionPluginEvent,
};
use crate::app::services::{GoToService, ProgramManager};
use crate::framework::plugintool::util::{
    PluginDescription, PluginEventListener, PluginStatus, ServiceListener,
};
use crate::framework::plugintool::{Plugin, PluginEvent};
use crate::framework::seam_stubs::{PluginPackageLike, PluginTool, SaveState};
use crate::program::model::listing::Program;
use crate::program::seam_stubs::SpecExtension;
use crate::program::util::ProgramLocation;
use crate::util::classfinder::ExtensionPoint;
use crate::util::seam_stubs::SwingUpdateManager;

/// A [`ProgramLocation`] handle as this plugin stores and forwards it. The plugin is `Send +
/// Sync` (its `Plugin` supertrait [`ServiceListener`] requires it) and holds the current location
/// across event deliveries, which the bare `dyn ProgramLocation` trait object is not.
pub type SharedProgramLocation = Arc<dyn ProgramLocation + Send + Sync>;

/// Fully-qualified names of the services `@PluginInfo(servicesRequired = ...)` lists.
const GO_TO_SERVICE: &str = "ghidra.app.services.GoToService";
const NAVIGATION_HISTORY_SERVICE: &str = "ghidra.app.services.NavigationHistoryService";
const CLIPBOARD_SERVICE: &str = "ghidra.app.services.ClipboardService";
const DATA_TYPE_MANAGER_SERVICE: &str = "ghidra.app.services.DataTypeManagerService";

/// Fully-qualified names of the services `@PluginInfo(servicesProvided = ...)` lists.
const DECOMPILER_HIGHLIGHT_SERVICE: &str = "ghidra.app.decompiler.DecompilerHighlightService";
const DECOMPILER_MARGIN_SERVICE: &str = "ghidra.app.decompiler.DecompilerMarginService";

/// Fully-qualified names of the events `@PluginInfo(eventsConsumed = ...)` lists, in declaration
/// order.
const EVENTS_CONSUMED_CLASSES: [&str; 5] = [
    "ghidra.app.events.ProgramActivatedPluginEvent",
    "ghidra.app.events.ProgramOpenedPluginEvent",
    "ghidra.app.events.ProgramLocationPluginEvent",
    "ghidra.app.events.ProgramSelectionPluginEvent",
    "ghidra.app.events.ProgramClosedPluginEvent",
];

/// The same five events by [`PluginEvent::event_name`], which is how
/// [`Plugin::process_last_events`] matches an event against the consumed set in this crate.
const EVENTS_CONSUMED_NAMES: [&str; 5] = [
    "Program Activated",
    "Program Opened",
    ProgramLocationPluginEvent::NAME,
    ProgramSelectionPluginEvent::NAME,
    "Program Closed",
];

/// Plugin for producing a high-level C interpretation of assembly functions.
///
/// Port of `ghidra.app.plugin.core.decompile.DecompilePlugin`.
pub struct DecompilePlugin {
    tool: Arc<dyn PluginTool + Send + Sync>,

    /// Java's field is a `PrimaryDecompilerProvider`; see the module docs for why it is typed as
    /// the base provider here. Java null-checks it defensively even though the constructor always
    /// assigns it and nothing ever clears it, so it is not optional here.
    connected_provider: Arc<dyn DecompilerProvider>,
    disconnected_providers: Mutex<Vec<Arc<dyn DecompilerProvider>>>,

    current_program: Mutex<Option<Arc<dyn Program>>>,
    current_location: Mutex<Option<SharedProgramLocation>>,
    current_selection: Mutex<Option<Arc<dyn ProgramSelection>>>,

    /// Delays location changes to allow location events to settle down. This happens when a
    /// `readDataState` occurs when a tool is restored or when switching program tabs.
    ///
    /// Java constructs the manager here with the callback inline; the callback body is
    /// [`delayed_location_update`](Self::delayed_location_update) instead (see
    /// [`SwingUpdateManager`]). `None` -- no manager wired up -- simply means nothing ever fires.
    delayed_location_update_mgr: Option<Arc<dyn SwingUpdateManager>>,

    // State Java inherits from the `Plugin` base class; see the module docs.
    services_provided: Mutex<HashMap<String, Vec<Arc<dyn Any + Send + Sync>>>>,
    events_consumed: Mutex<HashSet<String>>,
    disposed: AtomicBool,
    description: DecompilePluginDescription,
}

impl DecompilePlugin {
    /// Mirrors `DecompilePlugin.OPTIONS_TITLE`.
    pub const OPTIONS_TITLE: &'static str = "Decompiler";

    /// The `SwingUpdateManager`'s minimum and maximum delay, in milliseconds, as passed to `new
    /// SwingUpdateManager(200, 200, ...)`.
    pub const LOCATION_UPDATE_DELAY_MS: i32 = 200;

    /// Port of `DecompilePlugin(PluginTool)`.
    ///
    /// Java also constructs its connected provider (`new PrimaryDecompilerProvider(this)`) and its
    /// `SwingUpdateManager` here; both are passed in instead (see the module docs).
    pub fn new(
        tool: Arc<dyn PluginTool + Send + Sync>,
        connected_provider: Arc<dyn DecompilerProvider>,
        delayed_location_update_mgr: Option<Arc<dyn SwingUpdateManager>>,
    ) -> Self {
        let plugin = Self {
            tool,
            connected_provider,
            disconnected_providers: Mutex::new(Vec::new()),
            current_program: Mutex::new(None),
            current_location: Mutex::new(None),
            current_selection: Mutex::new(None),
            delayed_location_update_mgr,
            services_provided: Mutex::new(HashMap::new()),
            events_consumed: Mutex::new(HashSet::new()),
            disposed: AtomicBool::new(false),
            description: DecompilePluginDescription,
        };
        plugin.register_services();
        plugin
    }

    /// Port of the private `registerServices()`.
    fn register_services(&self) {
        self.register_service_provided(
            DECOMPILER_HIGHLIGHT_SERVICE,
            self.connected_provider.clone().as_any_arc(),
        );
        // Allow pluggable margin providers for disconnected providers?
        self.register_service_provided(
            DECOMPILER_MARGIN_SERVICE,
            self.connected_provider.clone().as_any_arc(),
        );
    }

    /// The connected (primary) decompiler window.
    pub fn connected_provider(&self) -> &Arc<dyn DecompilerProvider> {
        &self.connected_provider
    }

    /// Port of the package-private `createNewDisconnectedProvider()`.
    ///
    /// Java constructs `new DecompilerProvider(this, false)` here; that type is not ported and
    /// needs a back-reference to this plugin, so the freshly built provider is passed in and this
    /// method performs the rest of Java's body. Returns the provider it was given, matching Java's
    /// return of the provider it built.
    pub fn create_new_disconnected_provider(
        &self,
        provider: Arc<dyn DecompilerProvider>,
    ) -> Arc<dyn DecompilerProvider> {
        if let Some(clipboard_service) = self.tool.get_service(CLIPBOARD_SERVICE) {
            provider.set_clipboard_service(clipboard_service);
        }
        self.disconnected_providers
            .lock()
            .unwrap()
            .push(provider.clone());
        self.tool
            .show_component_provider(provider.clone().as_any_arc(), true);
        provider
    }

    /// Port of the package-private `exportLocation(Program, ProgramLocation)`.
    ///
    /// Java looks the service up with `tool.getService(GoToService.class)` and skips the call when
    /// the tool has none; that lookup cannot be typed through this crate's service seam, so the
    /// resolved service is passed in, with `None` standing in for Java's null.
    pub fn export_location(
        &self,
        go_to_service: Option<&dyn GoToService>,
        program: &dyn Program,
        location: &dyn ProgramLocation,
    ) {
        if let Some(service) = go_to_service {
            service.go_to_in_program(location, program);
        }
    }

    /// Port of the package-private `updateSelection(DecompilerProvider, Program,
    /// ProgramSelection)`.
    pub fn update_selection(
        &self,
        provider: &Arc<dyn DecompilerProvider>,
        sel_program: Arc<dyn Program>,
        selection: Arc<dyn ProgramSelection>,
    ) {
        if Arc::ptr_eq(provider, &self.connected_provider) {
            let event = ProgramSelectionPluginEvent::new(self.name(), selection, sel_program);
            self.fire_plugin_event(event.into_plugin_event());
        }
    }

    /// Port of the package-private `closeProvider(DecompilerProvider)`.
    pub fn close_provider(&self, provider: &Arc<dyn DecompilerProvider>) {
        if Arc::ptr_eq(provider, &self.connected_provider) {
            self.tool
                .show_component_provider(provider.clone().as_any_arc(), false);
        } else {
            self.disconnected_providers
                .lock()
                .unwrap()
                .retain(|p| !Arc::ptr_eq(p, provider));
            self.remove_provider(provider);
        }
    }

    /// Port of the package-private `locationChanged(DecompilerProvider, ProgramLocation)`.
    pub fn location_changed(
        &self,
        provider: &Arc<dyn DecompilerProvider>,
        location: SharedProgramLocation,
    ) {
        if provider.should_send_events() {
            let program = location.get_program();
            let event = ProgramLocationPluginEvent::new(self.name(), location, program);
            self.fire_plugin_event(event.into_plugin_event());
        }
    }

    /// Port of the package-private `selectionChanged(DecompilerProvider, ProgramSelection)`.
    ///
    /// Java fires the event with the plugin's current program, which may be null; with no program
    /// there is nothing to fire against, so the event is skipped in that case.
    pub fn selection_changed(
        &self,
        provider: &Arc<dyn DecompilerProvider>,
        selection: Arc<dyn ProgramSelection>,
    ) {
        if !provider.should_send_events() {
            return;
        }
        let Some(current_program) = self.current_program.lock().unwrap().clone() else {
            return;
        };
        let event = ProgramSelectionPluginEvent::new(self.name(), selection, current_program);
        self.fire_plugin_event(event.into_plugin_event());
    }

    /// Port of the package-private `handleTokenRenamed(ClangToken, String)`.
    pub fn handle_token_renamed(&self, token_at_cursor: &dyn ClangToken, new_name: &str) {
        self.connected_provider
            .handle_token_renamed(token_at_cursor, new_name);
        for provider in self.disconnected_providers.lock().unwrap().iter() {
            provider.handle_token_renamed(token_at_cursor, new_name);
        }
    }

    /// Port of the private `removeProvider(DecompilerProvider)`.
    fn remove_provider(&self, provider: &Arc<dyn DecompilerProvider>) {
        self.tool
            .remove_component_provider(provider.clone().as_any_arc());
        provider.dispose();
    }

    /// Port of `processEvent`'s `ProgramActivatedPluginEvent` branch.
    pub fn process_program_activated_event(&self, event: &ProgramActivatedPluginEvent) {
        let program = event.get_active_program();
        *self.current_program.lock().unwrap() = program.clone();
        self.connected_provider.do_set_program(program.clone());
        if let Some(program) = program {
            SpecExtension::register_options(program.as_ref());
        }
    }

    /// Port of `processEvent`'s `ProgramLocationPluginEvent` branch.
    ///
    /// Java additionally drops locations that land on a `Data` code unit
    /// (`listing.getCodeUnitContaining(address) instanceof Data`). That check needs `&mut Program`
    /// -- this crate's [`Program::get_listing`] takes `&mut self` -- and the plugin only ever
    /// holds a shared handle to the current program, so it cannot be made here; such locations are
    /// forwarded rather than dropped.
    pub fn process_program_location_event(&self, event: &ProgramLocationPluginEvent) {
        let location = event.get_location();
        if location.get_address().is_external_address() {
            return;
        }
        *self.current_location.lock().unwrap() = Some(location.clone());
        // Delay location change to allow immediate location changes to settle down.  This happens
        // when switching program tabs in code browser which produces multiple location changes
        if let Some(manager) = &self.delayed_location_update_mgr {
            manager.update_later();
        }
    }

    /// Port of `processEvent`'s `ProgramSelectionPluginEvent` branch.
    pub fn process_program_selection_event(&self, event: &ProgramSelectionPluginEvent) {
        let selection = event.get_selection().clone();
        *self.current_selection.lock().unwrap() = Some(selection.clone());
        self.connected_provider.set_selection(Some(selection));
    }

    /// Port of `processEvent`'s `ProgramClosedPluginEvent` branch, which delegates to the private
    /// `programClosed(Program)`. A closed program whose handle has already been dropped matches no
    /// provider and is ignored.
    pub fn process_program_closed_event(&self, event: &ProgramClosedPluginEvent) {
        if let Some(closed_program) = event.get_program() {
            self.program_closed(&closed_program);
        }
    }

    /// Port of the private `programClosed(Program)`.
    fn program_closed(&self, closed_program: &Arc<dyn Program>) {
        let mut removed = Vec::new();
        {
            let mut providers = self.disconnected_providers.lock().unwrap();
            providers.retain(|provider| {
                let is_closed = provider
                    .get_program_handle()
                    .is_some_and(|program| Arc::ptr_eq(&program, closed_program));
                if is_closed {
                    removed.push(provider.clone());
                }
                !is_closed
            });
        }
        for provider in &removed {
            self.remove_provider(provider);
        }
        self.connected_provider.program_closed(closed_program.as_ref());
    }

    /// Port of `getCurrentLocation()`.
    pub fn get_current_location(&self) -> Option<SharedProgramLocation> {
        self.current_location.lock().unwrap().clone()
    }

    /// The body of the `delayedLocationUpdateMgr` callback: once the location events have settled
    /// down, push the most recent location into the connected provider.
    ///
    /// Java declares this as a lambda passed to the `SwingUpdateManager` constructor; see
    /// [`SwingUpdateManager`] for why it lives on the plugin here.
    pub fn delayed_location_update(&self) {
        let Some(location) = self.current_location.lock().unwrap().clone() else {
            return;
        };
        let location_program = location.get_program();
        if location_program.is_closed() {
            return; // not sure if this can happen
        }
        self.connected_provider.set_location(location, None);
    }

    /// Port of `init()`'s body, which pushes the tool's clipboard service into every provider.
    ///
    /// [`Plugin::init`] takes no arguments, so it resolves the service through the tool and
    /// delegates here; the service stays type-erased (see the module docs).
    fn set_clipboard_service(&self, clipboard_service: Arc<dyn Any + Send + Sync>) {
        self.connected_provider
            .set_clipboard_service(clipboard_service.clone());
        for provider in self.disconnected_providers.lock().unwrap().iter() {
            provider.set_clipboard_service(clipboard_service.clone());
        }
    }

    /// The full port of `readDataState(SaveState)`, which reopens each disconnected window's
    /// program through the tool's `ProgramManager` and rebuilds the window around it.
    ///
    /// [`Plugin::read_data_state`] can only restore the connected provider: it has no way to get a
    /// typed `ProgramManager` out of this crate's service seam, and no way to build a
    /// `DecompilerProvider` (see the module docs). Both are supplied here instead --
    /// `new_provider` stands in for Java's `new DecompilerProvider(this, false)`, invoked once per
    /// window being restored.
    pub fn read_data_state_restoring_providers(
        &self,
        save_state: &dyn SaveState,
        program_manager: &mut dyn ProgramManager,
        new_provider: &mut dyn FnMut() -> Arc<dyn DecompilerProvider>,
    ) {
        self.connected_provider.read_data_state(save_state);

        let num_disconnected = save_state.get_int("Num Disconnected", 0);
        for i in 0..num_disconnected {
            let Some(provider_save_state) = save_state.get_save_state(&format!("Provider{i}"))
            else {
                continue;
            };
            let program_path = provider_save_state
                .get_string("Program Path", Some(""))
                .unwrap_or_default();
            let Some(project) = self.tool.get_project() else {
                continue;
            };
            let Some(file) = project.get_project_data().get_file(&program_path) else {
                continue;
            };
            let Some(program) = program_manager.open_program(file.as_ref()) else {
                continue;
            };
            let provider = self.create_new_disconnected_provider(new_provider());
            provider.do_set_program(Some(program));
            provider.read_data_state(provider_save_state.as_ref());
        }
    }
}

impl ExtensionPoint for DecompilePlugin {}

impl PluginEventListener for DecompilePlugin {
    fn event_sent(&self, event: &PluginEvent) {
        self.handle_plugin_event(event);
    }
}

impl ServiceListener for DecompilePlugin {
    /// Port of `serviceAdded(Class<?>, Object)`.
    fn service_added(&self, interface_class: TypeId, service: Arc<dyn Any + Send + Sync>) {
        if interface_class != TypeId::of::<dyn DecompilerHoverService>() {
            return;
        }
        self.connected_provider
            .get_decompiler_panel()
            .add_hover_service(service.clone());
        for provider in self.disconnected_providers.lock().unwrap().iter() {
            provider
                .get_decompiler_panel()
                .add_hover_service(service.clone());
        }
    }

    /// Port of `serviceRemoved(Class<?>, Object)`.
    fn service_removed(&self, interface_class: TypeId, service: Arc<dyn Any + Send + Sync>) {
        if interface_class != TypeId::of::<dyn DecompilerHoverService>() {
            return;
        }
        self.connected_provider
            .get_decompiler_panel()
            .remove_hover_service(service.clone());
        for provider in self.disconnected_providers.lock().unwrap().iter() {
            provider
                .get_decompiler_panel()
                .remove_hover_service(service.clone());
        }
    }
}

impl Plugin for DecompilePlugin {
    fn name(&self) -> String {
        "DecompilePlugin".to_string()
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
        let mut names: Vec<String> = EVENTS_CONSUMED_NAMES
            .iter()
            .map(|name| name.to_string())
            .collect();
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
        self.events_consumed
            .lock()
            .unwrap()
            .insert(event_class.to_string());
    }

    /// Port of `init()`.
    fn init(&self) {
        if let Some(clipboard_service) = self.tool.get_service(CLIPBOARD_SERVICE) {
            self.set_clipboard_service(clipboard_service);
        }
    }

    /// Port of `dispose()`.
    fn dispose(&self) {
        *self.current_program.lock().unwrap() = None;

        self.remove_provider(&self.connected_provider);

        let mut providers = self.disconnected_providers.lock().unwrap();
        for provider in providers.iter() {
            self.remove_provider(provider);
        }
        providers.clear();
    }

    fn cleanup(&self) {
        self.dispose();
        self.disposed.store(true, Ordering::SeqCst);
    }

    /// Port of `writeDataState(SaveState)`.
    ///
    /// Java writes each disconnected window's state as `putXmlElement("Provider" + i,
    /// providerSaveState.saveToXml())`; the XML round-trip is an implementation detail of the real
    /// `SaveState`, so the nested states are stored directly (see
    /// [`SaveState::put_save_state`]). A window whose program is not contained within the project
    /// (no parent folder) is skipped without consuming an index, as in Java.
    fn write_data_state(&self, save_state: &mut dyn SaveState) {
        self.connected_provider.write_data_state(save_state);

        let providers = self.disconnected_providers.lock().unwrap();
        save_state.put_int("Num Disconnected", providers.len() as i32);
        let mut i = 0;
        for provider in providers.iter() {
            let Some(mut provider_save_state) = save_state.new_save_state() else {
                continue;
            };
            let Some(domain_file) = provider
                .get_program_handle()
                .and_then(|program| program.get_domain_file())
            else {
                continue;
            };
            if domain_file.get_parent().is_none() {
                continue; // not contained within project
            }
            let program_pathname = domain_file.get_pathname();
            provider_save_state.put_string("Program Path", Some(&program_pathname));
            provider.write_data_state(provider_save_state.as_mut());
            save_state.put_save_state(&format!("Provider{i}"), provider_save_state);
            i += 1;
        }
    }

    /// Port of `readDataState(SaveState)`, restoring the connected window only.
    ///
    /// Rebuilding the disconnected windows needs a `ProgramManager` and a way to construct a
    /// `DecompilerProvider`, neither of which is reachable from this signature; call
    /// [`read_data_state_restoring_providers`](DecompilePlugin::read_data_state_restoring_providers)
    /// for the full body.
    fn read_data_state(&self, save_state: &dyn SaveState) {
        self.connected_provider.read_data_state(save_state);
    }

    /// Port of `processEvent(PluginEvent)`.
    ///
    /// Java switches on the event's concrete subclass and reads the program/location/selection
    /// payload off it. A [`PluginEvent`] here carries no such payload and cannot be downcast, so
    /// the five branches live in the typed `process_*_event` methods
    /// ([`process_program_activated_event`](DecompilePlugin::process_program_activated_event) and
    /// friends), which the tool's event plumbing should call once it can hand out the concrete
    /// events. This override recognizes nothing on its own.
    fn process_event(&self, _event: &PluginEvent) {}
}

/// The `@PluginInfo` metadata declared on `DecompilePlugin`, as a [`PluginDescription`].
///
/// Java derives this from the annotation by reflection at registration time; with no annotations
/// to read, the values are stated directly here.
struct DecompilePluginDescription;

impl PluginCategoryNames for DecompilePluginDescription {}

impl PluginDescription for DecompilePluginDescription {
    fn plugin_class_name(&self) -> String {
        "ghidra.app.plugin.core.decompile.DecompilePlugin".to_string()
    }

    fn name(&self) -> String {
        "DecompilePlugin".to_string()
    }

    fn short_description(&self) -> String {
        "Decompiler".to_string()
    }

    fn description(&self) -> String {
        "Plugin for producing high-level decompilation".to_string()
    }

    fn category(&self) -> String {
        Self::ANALYSIS.to_string()
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
        // ProgramManager is commented out in the Java annotation, and stays out here.
        vec![
            GO_TO_SERVICE.to_string(),
            NAVIGATION_HISTORY_SERVICE.to_string(),
            CLIPBOARD_SERVICE.to_string(),
            DATA_TYPE_MANAGER_SERVICE.to_string(),
        ]
    }

    fn services_provided(&self) -> Vec<String> {
        vec![
            DECOMPILER_HIGHLIGHT_SERVICE.to_string(),
            DECOMPILER_MARGIN_SERVICE.to_string(),
        ]
    }

    fn events_consumed(&self) -> Vec<String> {
        EVENTS_CONSUMED_CLASSES
            .iter()
            .map(|class_name| class_name.to_string())
            .collect()
    }

    fn events_produced(&self) -> Vec<String> {
        // The annotation declares none, even though the plugin fires location/selection events.
        Vec::new()
    }

    fn source_location(&self) -> String {
        String::new()
    }

    fn module_name(&self) -> String {
        "Decompiler".to_string()
    }

    fn is_in_extension(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicUsize;

    use crate::app::seam_stubs::{DecompilerController, DecompilerPanel, Navigatable};
    use crate::framework::model::{DomainFile, DomainFolder, DomainObject};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::HighFunction;
    use crate::program::model::listing::Function;
    use crate::app::decompiler::ClangTokenGroup;

    struct MockProgram {
        name: String,
        closed: bool,
        /// `None` models a program with no associated domain file.
        pathname: Option<String>,
        /// Whether the domain file has a parent folder, i.e. is contained within the project.
        has_parent: bool,
    }

    impl MockProgram {
        fn new(name: &str) -> Arc<dyn Program> {
            Arc::new(Self {
                name: name.to_string(),
                closed: false,
                pathname: Some(format!("/{name}")),
                has_parent: true,
            })
        }
    }

    impl DomainObject for MockProgram {
        fn is_closed(&self) -> bool {
            self.closed
        }

        fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
            self.pathname.as_ref().map(|pathname| {
                Box::new(MockDomainFile {
                    pathname: pathname.clone(),
                    has_parent: self.has_parent,
                }) as Box<dyn DomainFile>
            })
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock".to_string()
        }
    }

    struct MockDomainFile {
        pathname: String,
        has_parent: bool,
    }

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            self.pathname.clone()
        }

        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }

        fn get_parent(&self) -> Option<Box<dyn DomainFolder>> {
            if self.has_parent {
                Some(Box::new(MockDomainFolder))
            } else {
                None
            }
        }
    }

    struct MockDomainFolder;
    impl DomainFolder for MockDomainFolder {}

    struct MockLocation {
        program: Arc<dyn Program>,
        address: Address,
    }

    impl MockLocation {
        fn new(program: Arc<dyn Program>, offset: i64) -> SharedProgramLocation {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            Arc::new(Self {
                program,
                address: Address::new(space, offset),
            })
        }
    }

    impl ProgramLocation for MockLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct MockSelection;
    impl ProgramSelection for MockSelection {}

    /// The single hover service the tests register; `DecompilePlugin` only ever compares the
    /// service's interface `TypeId` against `dyn DecompilerHoverService`.
    struct MockHoverService;
    impl DecompilerHoverService for MockHoverService {}

    #[derive(Default)]
    struct PanelLog {
        hover_added: AtomicUsize,
        hover_removed: AtomicUsize,
    }

    struct MockPanel(Arc<PanelLog>);

    impl DecompilerPanel for MockPanel {
        fn add_hover_service(&self, _hover_service: Arc<dyn Any + Send + Sync>) {
            self.0.hover_added.fetch_add(1, Ordering::SeqCst);
        }

        fn remove_hover_service(&self, _hover_service: Arc<dyn Any + Send + Sync>) {
            self.0.hover_removed.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockController;
    impl DecompilerController for MockController {
        fn get_function(&self) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_high_function(&self) -> Option<Arc<dyn HighFunction>> {
            None
        }
        fn get_c_code_model(&self) -> Option<ClangTokenGroup> {
            None
        }
        fn set_status_message(&self, _message: &str) {}
    }

    /// Everything a provider records for the assertions below.
    #[derive(Default)]
    struct ProviderLog {
        panel: Arc<PanelLog>,
        clipboard_services: AtomicUsize,
        disposed: AtomicUsize,
        programs_closed: Mutex<Vec<String>>,
        set_programs: Mutex<Vec<Option<String>>>,
        set_locations: Mutex<Vec<i64>>,
        selections_set: AtomicUsize,
        data_states_written: AtomicUsize,
    }

    struct MockProvider {
        log: Arc<ProviderLog>,
        program: Option<Arc<dyn Program>>,
        send_events: bool,
        connected: bool,
    }

    impl MockProvider {
        fn new(log: Arc<ProviderLog>) -> Arc<dyn DecompilerProvider> {
            Arc::new(Self {
                log,
                program: None,
                send_events: false,
                connected: true,
            })
        }

        fn with_program(log: Arc<ProviderLog>, program: Arc<dyn Program>) -> Arc<dyn DecompilerProvider> {
            Arc::new(Self {
                log,
                program: Some(program),
                send_events: false,
                connected: false,
            })
        }

        fn sending_events(log: Arc<ProviderLog>) -> Arc<dyn DecompilerProvider> {
            Arc::new(Self {
                log,
                program: None,
                send_events: true,
                connected: true,
            })
        }
    }

    impl Navigatable for MockProvider {
        fn is_connected(&self) -> bool {
            self.connected
        }

        fn get_program(&self) -> Box<dyn Program> {
            Box::new(MockProgram {
                name: "mock".to_string(),
                closed: false,
                pathname: None,
                has_parent: false,
            })
        }
    }

    impl DecompilerProvider for MockProvider {
        fn get_tool(&self) -> Arc<dyn PluginTool> {
            Arc::new(MockTool::default())
        }

        fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }

        fn get_decompiler_panel(&self) -> Box<dyn DecompilerPanel> {
            Box::new(MockPanel(self.log.panel.clone()))
        }

        fn get_controller(&self) -> Box<dyn DecompilerController> {
            Box::new(MockController)
        }

        fn get_text_selection(&self) -> String {
            String::new()
        }

        fn get_program_handle(&self) -> Option<Arc<dyn Program>> {
            self.program.clone()
        }

        fn do_set_program(&self, new_program: Option<Arc<dyn Program>>) {
            self.log
                .set_programs
                .lock()
                .unwrap()
                .push(new_program.map(|program| Program::get_name(program.as_ref())));
        }

        fn set_location(
            &self,
            loc: SharedProgramLocation,
            _viewer_position: Option<crate::docking::widgets::fieldpanel::support::ViewerPosition>,
        ) {
            self.log
                .set_locations
                .lock()
                .unwrap()
                .push(loc.get_address().offset());
        }

        fn set_selection(&self, _selection: Option<Arc<dyn ProgramSelection>>) {
            self.log.selections_set.fetch_add(1, Ordering::SeqCst);
        }

        fn set_clipboard_service(&self, _service: Arc<dyn Any + Send + Sync>) {
            self.log.clipboard_services.fetch_add(1, Ordering::SeqCst);
        }

        fn should_send_events(&self) -> bool {
            self.send_events
        }

        fn write_data_state(&self, _save_state: &mut dyn SaveState) {
            self.log.data_states_written.fetch_add(1, Ordering::SeqCst);
        }

        fn program_closed(&self, closed_program: &dyn Program) {
            self.log
                .programs_closed
                .lock()
                .unwrap()
                .push(Program::get_name(closed_program));
        }

        fn dispose(&self) {
            self.log.disposed.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct MockTool {
        clipboard_service: Option<Arc<dyn Any + Send + Sync>>,
        fired_events: Mutex<Vec<String>>,
        shown: Mutex<Vec<bool>>,
        removed_providers: AtomicUsize,
    }

    impl MockTool {
        fn with_clipboard_service() -> Self {
            Self {
                clipboard_service: Some(Arc::new("clipboard")),
                ..Self::default()
            }
        }
    }

    impl PluginTool for MockTool {
        fn get_service(&self, iface: &str) -> Option<Arc<dyn Any + Send + Sync>> {
            if iface == CLIPBOARD_SERVICE {
                self.clipboard_service.clone()
            } else {
                None
            }
        }

        fn fire_plugin_event(&self, event: PluginEvent) {
            self.fired_events
                .lock()
                .unwrap()
                .push(format!("{}:{}", event.source_name(), event.event_name()));
        }

        fn show_component_provider(&self, _provider: Arc<dyn Any + Send + Sync>, visible: bool) {
            self.shown.lock().unwrap().push(visible);
        }

        fn remove_component_provider(&self, _provider: Arc<dyn Any + Send + Sync>) {
            self.removed_providers.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A `SaveState` recording the values `DecompilePlugin` writes, and able to hand out nested
    /// states (which the real class does through its XML round-trip).
    #[derive(Default)]
    struct MockSaveState {
        ints: HashMap<String, i32>,
        strings: HashMap<String, String>,
        nested: Vec<String>,
    }

    impl SaveState for MockSaveState {
        fn has_value(&self, name: &str) -> bool {
            self.ints.contains_key(name) || self.strings.contains_key(name)
        }

        fn get_boolean(&self, _name: &str, default_value: bool) -> bool {
            default_value
        }
        fn put_boolean(&mut self, _name: &str, _value: bool) {}

        fn get_byte(&self, _name: &str, default_value: i8) -> i8 {
            default_value
        }
        fn put_byte(&mut self, _name: &str, _value: i8) {}

        fn get_short(&self, _name: &str, default_value: i16) -> i16 {
            default_value
        }
        fn put_short(&mut self, _name: &str, _value: i16) {}

        fn get_int(&self, name: &str, default_value: i32) -> i32 {
            self.ints.get(name).copied().unwrap_or(default_value)
        }
        fn put_int(&mut self, name: &str, value: i32) {
            self.ints.insert(name.to_string(), value);
        }

        fn get_long(&self, _name: &str, default_value: i64) -> i64 {
            default_value
        }
        fn put_long(&mut self, _name: &str, _value: i64) {}

        fn get_float(&self, _name: &str, default_value: f32) -> f32 {
            default_value
        }
        fn put_float(&mut self, _name: &str, _value: f32) {}

        fn get_double(&self, _name: &str, default_value: f64) -> f64 {
            default_value
        }
        fn put_double(&mut self, _name: &str, _value: f64) {}

        fn get_string(&self, name: &str, default_value: Option<&str>) -> Option<String> {
            self.strings
                .get(name)
                .cloned()
                .or_else(|| default_value.map(|value| value.to_string()))
        }
        fn put_string(&mut self, name: &str, value: Option<&str>) {
            match value {
                Some(value) => {
                    self.strings.insert(name.to_string(), value.to_string());
                }
                None => {
                    self.strings.remove(name);
                }
            }
        }

        fn get_booleans(&self, _name: &str, default_value: Option<&[bool]>) -> Option<Vec<bool>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_booleans(&mut self, _name: &str, _value: Option<&[bool]>) {}

        fn get_bytes(&self, _name: &str, default_value: Option<&[u8]>) -> Option<Vec<u8>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_bytes(&mut self, _name: &str, _value: Option<&[u8]>) {}

        fn get_shorts(&self, _name: &str, default_value: Option<&[i16]>) -> Option<Vec<i16>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_shorts(&mut self, _name: &str, _value: Option<&[i16]>) {}

        fn get_ints(&self, _name: &str, default_value: Option<&[i32]>) -> Option<Vec<i32>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_ints(&mut self, _name: &str, _value: Option<&[i32]>) {}

        fn get_longs(&self, _name: &str, default_value: Option<&[i64]>) -> Option<Vec<i64>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_longs(&mut self, _name: &str, _value: Option<&[i64]>) {}

        fn get_floats(&self, _name: &str, default_value: Option<&[f32]>) -> Option<Vec<f32>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_floats(&mut self, _name: &str, _value: Option<&[f32]>) {}

        fn get_doubles(&self, _name: &str, default_value: Option<&[f64]>) -> Option<Vec<f64>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_doubles(&mut self, _name: &str, _value: Option<&[f64]>) {}

        fn get_strings(&self, _name: &str, default_value: Option<&[String]>) -> Option<Vec<String>> {
            default_value.map(|value| value.to_vec())
        }
        fn put_strings(&mut self, _name: &str, _value: Option<&[String]>) {}

        fn get_file(&self, _name: &str, default_value: Option<&Path>) -> Option<PathBuf> {
            default_value.map(|value| value.to_path_buf())
        }
        fn put_file(&mut self, _name: &str, _value: Option<&Path>) {}

        fn get_enum_name(&self, name: &str) -> Option<String> {
            self.strings.get(name).cloned()
        }
        fn put_enum_name(&mut self, name: &str, value: Option<&str>) {
            self.put_string(name, value);
        }

        fn new_save_state(&self) -> Option<Box<dyn SaveState>> {
            Some(Box::new(MockSaveState::default()))
        }

        fn put_save_state(&mut self, name: &str, _value: Box<dyn SaveState>) {
            self.nested.push(name.to_string());
        }
    }

    fn plugin_with(
        tool: Arc<MockTool>,
        connected: Arc<dyn DecompilerProvider>,
    ) -> DecompilePlugin {
        DecompilePlugin::new(tool, connected, None)
    }

    #[test]
    fn options_title_matches_java() {
        assert_eq!(DecompilePlugin::OPTIONS_TITLE, "Decompiler");
    }

    #[test]
    fn description_mirrors_the_plugin_info_annotation() {
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(Arc::default()),
        );
        let description = plugin.plugin_description();

        assert_eq!(description.name(), "DecompilePlugin");
        assert_eq!(description.short_description(), "Decompiler");
        assert_eq!(
            description.description(),
            "Plugin for producing high-level decompilation"
        );
        assert_eq!(description.category(), "Analysis");
        assert_eq!(description.status(), PluginStatus::Released);
        assert_eq!(description.plugin_package().name(), "Ghidra Core");
        assert_eq!(
            description.services_required(),
            vec![
                "ghidra.app.services.GoToService",
                "ghidra.app.services.NavigationHistoryService",
                "ghidra.app.services.ClipboardService",
                "ghidra.app.services.DataTypeManagerService",
            ]
        );
        assert_eq!(
            description.services_provided(),
            vec![
                "ghidra.app.decompiler.DecompilerHighlightService",
                "ghidra.app.decompiler.DecompilerMarginService",
            ]
        );
        assert_eq!(description.events_consumed().len(), 5);
        assert!(description.events_produced().is_empty());
    }

    #[test]
    fn construction_registers_both_provided_services_against_the_connected_provider() {
        let connected = MockProvider::new(Arc::default());
        let plugin = plugin_with(Arc::new(MockTool::default()), connected.clone());

        assert!(plugin.provides_service(DECOMPILER_HIGHLIGHT_SERVICE));
        assert!(plugin.provides_service(DECOMPILER_MARGIN_SERVICE));

        let registered = plugin.service_provider_instances(DECOMPILER_HIGHLIGHT_SERVICE);
        assert_eq!(registered.len(), 1);
        assert!(Arc::ptr_eq(
            &registered[0],
            &connected.clone().as_any_arc()
        ));
    }

    #[test]
    fn init_pushes_the_tools_clipboard_service_into_every_provider() {
        let connected_log = Arc::new(ProviderLog::default());
        let disconnected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::with_clipboard_service()),
            MockProvider::new(connected_log.clone()),
        );
        plugin.create_new_disconnected_provider(MockProvider::new(disconnected_log.clone()));

        // Creating the disconnected window already handed it the clipboard service once.
        assert_eq!(disconnected_log.clipboard_services.load(Ordering::SeqCst), 1);

        plugin.init();

        assert_eq!(connected_log.clipboard_services.load(Ordering::SeqCst), 1);
        assert_eq!(disconnected_log.clipboard_services.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn init_without_a_clipboard_service_touches_no_provider() {
        let connected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(connected_log.clone()),
        );

        plugin.init();

        assert_eq!(connected_log.clipboard_services.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn creating_a_disconnected_provider_shows_it_in_the_tool() {
        let tool = Arc::new(MockTool::default());
        let plugin = plugin_with(tool.clone(), MockProvider::new(Arc::default()));

        plugin.create_new_disconnected_provider(MockProvider::new(Arc::default()));

        assert_eq!(*tool.shown.lock().unwrap(), vec![true]);
    }

    #[test]
    fn program_activated_sets_the_current_program_on_the_connected_provider() {
        let connected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(connected_log.clone()),
        );
        let program = MockProgram::new("hello");

        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            program.clone(),
        ));

        assert_eq!(
            *connected_log.set_programs.lock().unwrap(),
            vec![Some("hello".to_string())]
        );
    }

    #[test]
    fn a_location_event_is_only_applied_once_the_delayed_update_fires() {
        let connected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(connected_log.clone()),
        );
        let program = MockProgram::new("hello");
        let location = MockLocation::new(program.clone(), 0x1234);

        plugin.process_program_location_event(&ProgramLocationPluginEvent::new(
            "Test",
            location,
            program,
        ));

        // Java stores the location and asks the SwingUpdateManager to run later; nothing reaches
        // the provider yet.
        assert!(plugin.get_current_location().is_some());
        assert!(connected_log.set_locations.lock().unwrap().is_empty());

        plugin.delayed_location_update();

        assert_eq!(*connected_log.set_locations.lock().unwrap(), vec![0x1234]);
    }

    #[test]
    fn the_delayed_update_skips_a_location_whose_program_has_been_closed() {
        let connected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(connected_log.clone()),
        );
        let program: Arc<dyn Program> = Arc::new(MockProgram {
            name: "closed".to_string(),
            closed: true,
            pathname: None,
            has_parent: false,
        });
        let location = MockLocation::new(program.clone(), 0x20);

        plugin.process_program_location_event(&ProgramLocationPluginEvent::new(
            "Test", location, program,
        ));
        plugin.delayed_location_update();

        assert!(connected_log.set_locations.lock().unwrap().is_empty());
    }

    #[test]
    fn a_selection_event_reaches_the_connected_provider() {
        let connected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(connected_log.clone()),
        );
        let program = MockProgram::new("hello");

        plugin.process_program_selection_event(&ProgramSelectionPluginEvent::new(
            "Test",
            Arc::new(MockSelection),
            program,
        ));

        assert_eq!(connected_log.selections_set.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn closing_a_program_removes_only_the_windows_showing_it() {
        let tool = Arc::new(MockTool::default());
        let connected_log = Arc::new(ProviderLog::default());
        let closing_log = Arc::new(ProviderLog::default());
        let surviving_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(tool.clone(), MockProvider::new(connected_log.clone()));

        let closing_program = MockProgram::new("closing");
        let other_program = MockProgram::new("other");
        plugin.create_new_disconnected_provider(MockProvider::with_program(
            closing_log.clone(),
            closing_program.clone(),
        ));
        plugin.create_new_disconnected_provider(MockProvider::with_program(
            surviving_log.clone(),
            other_program,
        ));

        plugin.process_program_closed_event(&ProgramClosedPluginEvent::new(
            "Test",
            closing_program.clone(),
        ));

        assert_eq!(closing_log.disposed.load(Ordering::SeqCst), 1);
        assert_eq!(surviving_log.disposed.load(Ordering::SeqCst), 0);
        assert_eq!(
            *connected_log.programs_closed.lock().unwrap(),
            vec!["closing".to_string()]
        );
        assert_eq!(plugin.disconnected_providers.lock().unwrap().len(), 1);
    }

    #[test]
    fn closing_the_connected_provider_only_hides_it() {
        let tool = Arc::new(MockTool::default());
        let connected = MockProvider::new(Arc::default());
        let plugin = plugin_with(tool.clone(), connected.clone());

        plugin.close_provider(&connected);

        assert_eq!(*tool.shown.lock().unwrap(), vec![false]);
        assert_eq!(tool.removed_providers.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn closing_a_disconnected_provider_removes_and_disposes_it() {
        let tool = Arc::new(MockTool::default());
        let disconnected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(tool.clone(), MockProvider::new(Arc::default()));
        let disconnected =
            plugin.create_new_disconnected_provider(MockProvider::new(disconnected_log.clone()));

        plugin.close_provider(&disconnected);

        assert!(plugin.disconnected_providers.lock().unwrap().is_empty());
        assert_eq!(tool.removed_providers.load(Ordering::SeqCst), 1);
        assert_eq!(disconnected_log.disposed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispose_tears_down_every_window() {
        let tool = Arc::new(MockTool::default());
        let connected_log = Arc::new(ProviderLog::default());
        let disconnected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(tool.clone(), MockProvider::new(connected_log.clone()));
        plugin.create_new_disconnected_provider(MockProvider::new(disconnected_log.clone()));
        plugin.process_program_activated_event(&ProgramActivatedPluginEvent::new(
            "Test",
            MockProgram::new("hello"),
        ));

        plugin.cleanup();

        assert_eq!(connected_log.disposed.load(Ordering::SeqCst), 1);
        assert_eq!(disconnected_log.disposed.load(Ordering::SeqCst), 1);
        assert_eq!(tool.removed_providers.load(Ordering::SeqCst), 2);
        assert!(plugin.disconnected_providers.lock().unwrap().is_empty());
        assert!(plugin.current_program.lock().unwrap().is_none());
        assert!(plugin.is_disposed());
    }

    #[test]
    fn a_hover_service_reaches_every_panel_but_other_services_do_not() {
        let connected_log = Arc::new(ProviderLog::default());
        let disconnected_log = Arc::new(ProviderLog::default());
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(connected_log.clone()),
        );
        plugin.create_new_disconnected_provider(MockProvider::new(disconnected_log.clone()));
        let service: Arc<dyn Any + Send + Sync> = Arc::new(MockHoverService);

        plugin.service_added(TypeId::of::<dyn DecompilerHoverService>(), service.clone());
        assert_eq!(connected_log.panel.hover_added.load(Ordering::SeqCst), 1);
        assert_eq!(disconnected_log.panel.hover_added.load(Ordering::SeqCst), 1);

        plugin.service_removed(TypeId::of::<dyn DecompilerHoverService>(), service.clone());
        assert_eq!(connected_log.panel.hover_removed.load(Ordering::SeqCst), 1);
        assert_eq!(disconnected_log.panel.hover_removed.load(Ordering::SeqCst), 1);

        // A service of some other type is ignored entirely.
        plugin.service_added(TypeId::of::<dyn GoToService>(), service);
        assert_eq!(connected_log.panel.hover_added.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn write_data_state_counts_the_disconnected_windows_and_skips_ones_outside_the_project() {
        let plugin = plugin_with(
            Arc::new(MockTool::default()),
            MockProvider::new(Arc::default()),
        );
        let in_project = MockProgram::new("in-project");
        let outside_project: Arc<dyn Program> = Arc::new(MockProgram {
            name: "outside".to_string(),
            closed: false,
            pathname: Some("/outside".to_string()),
            has_parent: false,
        });
        plugin.create_new_disconnected_provider(MockProvider::with_program(
            Arc::default(),
            in_project,
        ));
        plugin.create_new_disconnected_provider(MockProvider::with_program(
            Arc::default(),
            outside_project,
        ));

        let mut save_state = MockSaveState::default();
        plugin.write_data_state(&mut save_state);

        // Both windows are counted, but only the one contained within the project is written out.
        assert_eq!(save_state.get_int("Num Disconnected", -1), 2);
        assert_eq!(save_state.nested, vec!["Provider0".to_string()]);
    }

    #[test]
    fn a_location_change_is_only_broadcast_by_a_provider_that_sends_events() {
        let tool = Arc::new(MockTool::default());
        let plugin = plugin_with(tool.clone(), MockProvider::new(Arc::default()));
        let program = MockProgram::new("hello");
        let quiet = MockProvider::new(Arc::default());
        let noisy = MockProvider::sending_events(Arc::default());

        plugin.location_changed(&quiet, MockLocation::new(program.clone(), 0x10));
        assert!(tool.fired_events.lock().unwrap().is_empty());

        plugin.location_changed(&noisy, MockLocation::new(program, 0x10));
        assert_eq!(
            *tool.fired_events.lock().unwrap(),
            vec!["DecompilePlugin:ProgramLocationChange".to_string()]
        );
    }

    #[test]
    fn a_selection_update_is_only_broadcast_for_the_connected_provider() {
        let tool = Arc::new(MockTool::default());
        let connected = MockProvider::new(Arc::default());
        let plugin = plugin_with(tool.clone(), connected.clone());
        let program = MockProgram::new("hello");
        let other = MockProvider::new(Arc::default());

        plugin.update_selection(&other, program.clone(), Arc::new(MockSelection));
        assert!(tool.fired_events.lock().unwrap().is_empty());

        plugin.update_selection(&connected, program, Arc::new(MockSelection));
        assert_eq!(
            *tool.fired_events.lock().unwrap(),
            vec!["DecompilePlugin:ProgramSelection".to_string()]
        );
    }
}
