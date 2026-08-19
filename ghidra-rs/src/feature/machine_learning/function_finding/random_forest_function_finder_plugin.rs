//! Port of `ghidra.machinelearning.functionfinding.RandomForestFunctionFinderPlugin`.
//!
//! A plugin for training a model on the starts of known functions in a program and then using
//! that model to look for more functions (in the source program or another program selected by
//! the user).
//!
//! # Shape
//!
//! Java's `RandomForestFunctionFinderPlugin` is a concrete class (nothing extends it), so it
//! becomes a plain `struct` (rule R14a-concrete-leaf). It extends `ProgramPlugin`, which is not
//! ported; `ProgramPlugin` itself extends `Plugin` (already ported as a trait) and adds nothing
//! this class reads except the `programClosed(Program)` override hook, so this struct implements
//! [`Plugin`] directly and holds the state Java would otherwise inherit -- the same choice already
//! made by
//! [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin) and
//! [`AutoAnalysisPlugin`](crate::app::plugin::core::analysis::AutoAnalysisPlugin) for their own
//! unported/no-op base-class state.
//!
//! It also `implements OptionsChangeListener`, which is already ported as a trait and implemented
//! directly below.
//!
//! # Seams
//!
//! * **Action registration.** Java's `createActions()` builds a single action with `ActionBuilder`
//!   (menu path, help location, a `validWhen` filter on [`RestrictedAddressSetContext`], and an
//!   `onAction` callback into the plugin's own `displayDialog`). `ActionBuilder` is not ported. As
//!   in `DisassemblerPlugin`, the already-built action is taken as a constructor-injected,
//!   type-erased handle ([`Any`]) and [`create_actions`](RandomForestFunctionFinderPlugin::create_actions)
//!   performs the rest of Java's body (installing it in the tool). The `displayDialog` business
//!   logic itself -- unlike `DisassemblerPlugin`'s per-action classes -- belongs entirely to this
//!   plugin, not to the unported action, so it is fully ported below as
//!   [`display_dialog`](RandomForestFunctionFinderPlugin::display_dialog).
//! * **Options change registration.** Java's `initOptions` ends with
//!   `options.addOptionsChangeListener(this)`. Neither the ported
//!   [`Options`](crate::framework::options::Options) trait nor the
//!   [`ToolOptions`](crate::framework::seam_stubs::ToolOptions) placeholder it is registered
//!   against yet exposes a listener-registration hook, so that call has no modeled equivalent;
//!   this plugin's [`OptionsChangeListener`] implementation below is complete and correct, but is
//!   never actually wired up to fire by this port.
//! * **`FunctionStartRFParamsDialog`/`ProgramAssociatedComponentProviderAdapter`.** Neither is
//!   ported. Both are used as their real Java shape (a dialog and a `ComponentProvider` adapter,
//!   respectively), so they are stubbed as
//!   [`FunctionStartRFParamsDialog`](crate::feature::seam_stubs::FunctionStartRFParamsDialog) (a
//!   struct, since the Java class is concrete) and
//!   [`ProgramAssociatedComponentProviderAdapter`](crate::feature::seam_stubs::ProgramAssociatedComponentProviderAdapter)
//!   (a trait, since Java declares it as an interface-like adapter with unknown implementors) in
//!   `crate::feature::seam_stubs`.
//! * **Dialog placement.** Java's `tool.showDialog(paramsDialog, c.getComponentProvider())` passes
//!   the context's owning `ComponentProvider` so the dialog centers over it.
//!   [`ComponentProvider`](crate::docking::seam_stubs::ComponentProvider) is an empty marker trait
//!   with no `Any`/`Send`/`Sync` bounds, so it cannot be re-erased to the `Arc<dyn Any + Send +
//!   Sync>` [`PluginTool::show_dialog`](crate::framework::seam_stubs::PluginTool::show_dialog)
//!   expects; `display_dialog` below always passes `None`; the dialog is still shown, just not
//!   necessarily centered over the invoking component.
//! * **`org.tribuo.classification.Label`.** Tribuo is a third-party ML library with no Rust port
//!   in this crate. `FUNC_START`/`NON_START` are the two classification label *names* other
//!   (unported) classes in this package read, so they are ported as the underlying `&str` names
//!   rather than as `Label` instances.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::app::context::NavigatableActionContext;
use crate::app::events::ProgramClosedPluginEvent;
use crate::app::plugin::plugin_category_names::PluginCategoryNames;
use crate::app::seam_stubs::ProgramSelection;
use crate::feature::seam_stubs::{
    FunctionStartRFParamsDialog, MiscellaneousPluginPackage, ProgramAssociatedComponentProviderAdapter,
};
use crate::framework::options::OptionsChangeListener;
use crate::framework::plugintool::util::{
    PluginDescription, PluginEventListener, PluginStatus, ServiceListener,
};
use crate::framework::plugintool::{Plugin, PluginEvent};
use crate::framework::seam_stubs::{OptionsVetoException, PluginTool, ToolOptions};
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;
use crate::util::msg::Msg;

/// Java: `FUNC_START` -- the `org.tribuo.classification.Label` name for a function start. See the
/// module docs for why this is the label's name rather than a `Label` instance.
pub const FUNC_START: &str = "S";
/// Java: `NON_START` -- the `Label` name for a non-start. See [`FUNC_START`].
pub const NON_START: &str = "N";

const ACTION_NAME: &str = "Search for Code and Functions";
const MENU_PATH_ENTRY: &str = "For Code and Functions...";

const TEST_SET_MAX_SIZE_OPTION_NAME: &str = "Maximum size of test sets";
/// Java: `TEST_SET_MAX_SIZE_DEFAULT`.
pub(crate) const TEST_SET_MAX_SIZE_DEFAULT: i64 = 1_000_000;

const MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME: &str = "Minimum Length of Undefined Range to Search";
/// Java: `MIN_UNDEFINED_RANGE_SIZE_DEFAULT`.
pub(crate) const MIN_UNDEFINED_RANGE_SIZE_DEFAULT: i64 = 16;

const OPTIONS_CATEGORY_NAME: &str = "Random Forest Function Finder";

const PLUGIN_CLASS_NAME: &str =
    "ghidra.machinelearning.functionfinding.RandomForestFunctionFinderPlugin";
const PROGRAM_CLOSED_EVENT_CLASS: &str = "ghidra.app.events.ProgramClosedPluginEvent";
const PROGRAM_CLOSED_EVENT_NAME: &str = "Program Closed";
const PROGRAM_LOCATION_EVENT_CLASS: &str = "ghidra.app.events.ProgramLocationPluginEvent";
const GO_TO_SERVICE_CLASS: &str = "ghidra.app.services.GoToService";
const PROGRAM_MANAGER_CLASS: &str = "ghidra.app.services.ProgramManager";

/// A help location built from a topic and anchor, mirroring `new HelpLocation(String, String)`.
///
/// [`HelpLocation`](crate::framework::seam_stubs::HelpLocation) is an empty placeholder trait; this
/// mirrors the same local-concrete-implementor pattern already used by
/// [`AnalysisHelpLocation`](crate::app::plugin::core::analysis::AutoAnalysisPlugin) (see that
/// type's module for the precedent).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RandomForestHelpLocation {
    /// The help topic.
    pub topic: String,
    /// The anchor within the topic.
    pub anchor: String,
}

impl RandomForestHelpLocation {
    fn new(topic: impl Into<String>, anchor: impl Into<String>) -> Self {
        Self { topic: topic.into(), anchor: anchor.into() }
    }
}

impl crate::framework::seam_stubs::HelpLocation for RandomForestHelpLocation {}

/// Java: `new OptionsVetoException(String)`, thrown by `optionsChanged` when a new option value
/// fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RandomForestOptionsVetoException {
    message: String,
}

impl RandomForestOptionsVetoException {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl std::fmt::Display for RandomForestOptionsVetoException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RandomForestOptionsVetoException {}
impl OptionsVetoException for RandomForestOptionsVetoException {}

/// Trains a random forest model on the starts of known functions in a program and uses that model
/// to search for more.
///
/// Port of `ghidra.machinelearning.functionfinding.RandomForestFunctionFinderPlugin`.
pub struct RandomForestFunctionFinderPlugin {
    tool: Arc<dyn PluginTool + Send + Sync>,

    /// The pre-built action Java's `createActions()` installs; see the module docs.
    search_action: Arc<dyn Any + Send + Sync>,

    // State Java inherits from the `Plugin` base class; see the module docs.
    services_provided: Mutex<HashMap<String, Vec<Arc<dyn Any + Send + Sync>>>>,
    events_consumed: Mutex<std::collections::HashSet<String>>,
    disposed: std::sync::atomic::AtomicBool,
    description: RandomForestFunctionFinderPluginDescription,

    /// Java: `testSetMax`. `None` before [`init`](RandomForestFunctionFinderPlugin::init) runs,
    /// mirroring Java's uninitialized (`null`) `Long` field.
    test_set_max: Mutex<Option<i64>>,
    /// Java: `minUndefinedRangeSize`. See [`test_set_max`](Self::test_set_max).
    min_undefined_range_size: Mutex<Option<i64>>,

    /// Java: `paramsDialog`.
    params_dialog: Mutex<Option<Arc<FunctionStartRFParamsDialog>>>,

    /// Java: `programsToProviders`.
    programs_to_providers:
        Mutex<HashMap<Arc<dyn Program>, Vec<Arc<dyn ProgramAssociatedComponentProviderAdapter>>>>,

    /// Java: `currentSelection`, inherited from `ProgramPlugin`.
    current_selection: Mutex<Option<Arc<dyn ProgramSelection>>>,
}

impl RandomForestFunctionFinderPlugin {
    /// Port of `RandomForestFunctionFinderPlugin(PluginTool)`.
    ///
    /// `search_action` is the already-built action Java's constructor (via `init()`'s
    /// `createActions()`) would build with `ActionBuilder`; see the module docs.
    pub fn new(tool: Arc<dyn PluginTool + Send + Sync>, search_action: Arc<dyn Any + Send + Sync>) -> Self {
        Self {
            tool,
            search_action,
            services_provided: Mutex::new(HashMap::new()),
            events_consumed: Mutex::new(std::collections::HashSet::new()),
            disposed: std::sync::atomic::AtomicBool::new(false),
            description: RandomForestFunctionFinderPluginDescription,
            test_set_max: Mutex::new(None),
            min_undefined_range_size: Mutex::new(None),
            params_dialog: Mutex::new(None),
            programs_to_providers: Mutex::new(HashMap::new()),
            current_selection: Mutex::new(None),
        }
    }

    /// Port of the private `createActions()`, less the construction of the action itself; see the
    /// module docs.
    fn create_actions(&self) {
        self.tool.add_action(self.search_action.clone());
    }

    /// Port of the private `displayDialog(NavigatableActionContext)`.
    ///
    /// See the module docs for why the dialog is never centered over a `ComponentProvider`.
    pub fn display_dialog(&self, c: &dyn NavigatableActionContext) {
        let mut dialog_slot = self.params_dialog.lock().unwrap();
        if dialog_slot.is_none() {
            let training_source: Arc<dyn Program> = Arc::from(c.get_navigatable().get_program());
            *dialog_slot = Some(Arc::new(FunctionStartRFParamsDialog::new(training_source)));
        }
        let dialog = dialog_slot.clone().unwrap();
        drop(dialog_slot);

        let dialog_any: Arc<dyn Any + Send + Sync> = dialog;
        self.tool.show_dialog(dialog_any, None);
    }

    /// Port of the private `initOptions(ToolOptions)`, less the trailing
    /// `addOptionsChangeListener` call; see the module docs.
    fn init_options(&self) {
        let mut options = self.tool.get_options(OPTIONS_CATEGORY_NAME);

        options.register_option(
            TEST_SET_MAX_SIZE_OPTION_NAME,
            Box::new(TEST_SET_MAX_SIZE_DEFAULT),
            Some(Box::new(RandomForestHelpLocation::new(self.name(), "MaxTestSetSize"))),
            "Maximum sizes for test sets (must be positive).",
        );
        *self.test_set_max.lock().unwrap() =
            Some(options.get_long(TEST_SET_MAX_SIZE_OPTION_NAME, TEST_SET_MAX_SIZE_DEFAULT));

        options.register_option(
            MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME,
            Box::new(MIN_UNDEFINED_RANGE_SIZE_DEFAULT),
            Some(Box::new(RandomForestHelpLocation::new(self.name(), "MinLengthUndefinedRange"))),
            "Minimum Size of an Undefined AddressRange to search (must be positive).",
        );
        *self.min_undefined_range_size.lock().unwrap() = Some(
            options.get_long(MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME, MIN_UNDEFINED_RANGE_SIZE_DEFAULT),
        );
    }

    /// Port of the package-private `addProvider(ProgramAssociatedComponentProviderAdapter)`.
    pub(crate) fn add_provider(&self, provider: Arc<dyn ProgramAssociatedComponentProviderAdapter>) {
        self.programs_to_providers
            .lock()
            .unwrap()
            .entry(provider.get_program())
            .or_default()
            .push(provider.clone());
        self.tool.add_component_provider(provider.as_any_arc(), true);
    }

    /// Port of the package-private `removeProvider(ProgramAssociatedComponentProviderAdapter)`.
    pub(crate) fn remove_provider(&self, provider: &Arc<dyn ProgramAssociatedComponentProviderAdapter>) {
        if let Some(providers) =
            self.programs_to_providers.lock().unwrap().get_mut(&provider.get_program())
        {
            providers.retain(|p| !Arc::ptr_eq(p, provider));
        }
    }

    /// Port of the package-private `setSelection(ProgramSelection)`.
    pub(crate) fn set_selection(&self, selection: Arc<dyn ProgramSelection>) {
        *self.current_selection.lock().unwrap() = Some(selection);
    }

    /// Port of the package-private `getTestMaxSize()`.
    pub(crate) fn get_test_max_size(&self) -> Option<i64> {
        *self.test_set_max.lock().unwrap()
    }

    /// Port of the package-private `getMinUndefinedRangeSize()`.
    pub(crate) fn get_min_undefined_range_size(&self) -> Option<i64> {
        *self.min_undefined_range_size.lock().unwrap()
    }

    /// Port of the package-private `resetDialog()`.
    pub(crate) fn reset_dialog(&self) {
        *self.params_dialog.lock().unwrap() = None;
    }

    /// Port of `processEvent`'s `ProgramClosedPluginEvent` branch, which delegates to the
    /// protected `programClosed(Program)`. A closed program whose handle has already been dropped
    /// matches no tracked provider or dialog and is ignored.
    pub fn process_program_closed_event(&self, event: &ProgramClosedPluginEvent) {
        if let Some(closed_program) = event.get_program() {
            self.program_closed(&closed_program);
        }
    }

    /// Port of the protected `programClosed(Program)`.
    fn program_closed(&self, closed_program: &Arc<dyn Program>) {
        let providers_to_close =
            self.programs_to_providers.lock().unwrap().remove(closed_program).unwrap_or_default();
        for provider in &providers_to_close {
            provider.close_component();
        }

        let dialog_slot = self.params_dialog.lock().unwrap();
        let Some(dialog) = dialog_slot.as_ref() else {
            return;
        };
        if !Arc::ptr_eq(dialog.get_training_source(), closed_program) {
            return;
        }
        dialog.dismiss_callback();
    }
}

impl ExtensionPoint for RandomForestFunctionFinderPlugin {}

impl PluginEventListener for RandomForestFunctionFinderPlugin {
    fn event_sent(&self, event: &PluginEvent) {
        self.handle_plugin_event(event);
    }
}

impl ServiceListener for RandomForestFunctionFinderPlugin {
    /// Java's `RandomForestFunctionFinderPlugin` overrides neither `serviceAdded` nor
    /// `serviceRemoved`; the `Plugin` base class's bodies are empty.
    fn service_added(&self, _interface_class: std::any::TypeId, _service: Arc<dyn Any + Send + Sync>) {}

    fn service_removed(&self, _interface_class: std::any::TypeId, _service: Arc<dyn Any + Send + Sync>) {}
}

impl Plugin for RandomForestFunctionFinderPlugin {
    fn name(&self) -> String {
        "RandomForestFunctionFinderPlugin".to_string()
    }

    fn tool(&self) -> Arc<dyn PluginTool> {
        self.tool.clone()
    }

    fn plugin_description(&self) -> &dyn PluginDescription {
        &self.description
    }

    fn is_disposed(&self) -> bool {
        self.disposed.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn events_consumed(&self) -> Vec<String> {
        let mut names = vec![PROGRAM_CLOSED_EVENT_NAME.to_string()];
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
        self.services_provided.lock().unwrap().get(interface_class).cloned().unwrap_or_default()
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

    fn cleanup(&self) {
        self.dispose();
        self.disposed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Port of `init()`.
    fn init(&self) {
        self.create_actions();
        self.init_options();
    }

    /// Port of the protected `dispose()`.
    fn dispose(&self) {
        if let Some(dialog) = self.params_dialog.lock().unwrap().as_ref() {
            dialog.dispose();
        }
    }

    /// Port of `processEvent(PluginEvent)`. See
    /// [`process_program_closed_event`](Self::process_program_closed_event) for why the
    /// `ProgramClosedPluginEvent` branch lives there instead.
    fn process_event(&self, _event: &PluginEvent) {}
}

impl OptionsChangeListener for RandomForestFunctionFinderPlugin {
    /// Port of `optionsChanged(ToolOptions, String, Object, Object)`.
    fn options_changed(
        &mut self,
        _options: &dyn ToolOptions,
        option_name: &str,
        _old_value: Option<&dyn Any>,
        new_value: Option<&dyn Any>,
    ) -> Result<(), Box<dyn OptionsVetoException>> {
        match option_name {
            TEST_SET_MAX_SIZE_OPTION_NAME => {
                let new_max = new_value.and_then(|v| v.downcast_ref::<i64>()).copied().unwrap_or(0);
                if new_max <= 0 {
                    return Err(Box::new(RandomForestOptionsVetoException::new(format!(
                        "{TEST_SET_MAX_SIZE_OPTION_NAME} must be positive!"
                    ))));
                }
                *self.test_set_max.lock().unwrap() = Some(new_max);
            }
            MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME => {
                let new_min = new_value.and_then(|v| v.downcast_ref::<i64>()).copied().unwrap_or(0);
                if new_min <= 0 {
                    return Err(Box::new(RandomForestOptionsVetoException::new(format!(
                        "{MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME} must be positive!"
                    ))));
                }
                *self.min_undefined_range_size.lock().unwrap() = Some(new_min);
            }
            _ => {
                Msg::show_error(&self.name(), "Unknown option", &format!("Unknown option: {option_name}"));
            }
        }
        Ok(())
    }
}

/// The `@PluginInfo` metadata declared on `RandomForestFunctionFinderPlugin`, as a
/// [`PluginDescription`].
///
/// Java derives this from the annotation by reflection at registration time; with no annotations
/// to read, the values are stated directly here.
struct RandomForestFunctionFinderPluginDescription;

impl PluginCategoryNames for RandomForestFunctionFinderPluginDescription {}

impl PluginDescription for RandomForestFunctionFinderPluginDescription {
    fn plugin_class_name(&self) -> String {
        PLUGIN_CLASS_NAME.to_string()
    }

    fn name(&self) -> String {
        "RandomForestFunctionFinderPlugin".to_string()
    }

    fn short_description(&self) -> String {
        "Function Finder".to_string()
    }

    fn description(&self) -> String {
        "Trains a random forest model to find function starts.".to_string()
    }

    fn category(&self) -> String {
        Self::ANALYSIS.to_string()
    }

    fn status(&self) -> PluginStatus {
        PluginStatus::Released
    }

    fn plugin_package(&self) -> Box<dyn crate::framework::seam_stubs::PluginPackageLike> {
        Box::new(MiscellaneousPluginPackage)
    }

    fn is_slow_installation(&self) -> bool {
        false
    }

    fn services_required(&self) -> Vec<String> {
        vec![GO_TO_SERVICE_CLASS.to_string(), PROGRAM_MANAGER_CLASS.to_string()]
    }

    fn services_provided(&self) -> Vec<String> {
        Vec::new()
    }

    fn events_consumed(&self) -> Vec<String> {
        vec![PROGRAM_CLOSED_EVENT_CLASS.to_string()]
    }

    fn events_produced(&self) -> Vec<String> {
        vec![PROGRAM_LOCATION_EVENT_CLASS.to_string()]
    }

    fn source_location(&self) -> String {
        String::new()
    }

    fn module_name(&self) -> String {
        "MachineLearning".to_string()
    }

    fn is_in_extension(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::app::seam_stubs::Navigatable as NavigatableTrait;
    use crate::docking::action_context::ActionContext;
    use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};
    use crate::framework::model::DomainObject;
    use crate::framework::options::options_change_listener::OptionsChangeListener as _;
    use crate::framework::options::Options;

    struct MockProgram {
        name: &'static str,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.to_string()
        }

        fn get_language_id(&self) -> String {
            "mock".to_string()
        }
    }

    #[derive(Default)]
    struct MockOptions {
        long_values: HashMap<String, i64>,
    }

    impl Options for MockOptions {
        fn register_option(
            &mut self,
            option_name: &str,
            default_value: Box<dyn Any>,
            _help: Option<Box<dyn crate::framework::seam_stubs::HelpLocation>>,
            _description: &str,
        ) {
            if let Some(v) = default_value.downcast_ref::<i64>() {
                self.long_values.entry(option_name.to_string()).or_insert(*v);
            }
        }

        fn get_long(&self, option_name: &str, default_value: i64) -> i64 {
            *self.long_values.get(option_name).unwrap_or(&default_value)
        }
    }

    struct MockPluginTool;

    impl PluginTool for MockPluginTool {
        fn get_options(&self, _category: &str) -> Box<dyn Options> {
            Box::new(MockOptions::default())
        }
    }

    struct StubToolOptions;
    impl ToolOptions for StubToolOptions {}

    fn stub_action() -> Arc<dyn Any + Send + Sync> {
        Arc::new(())
    }

    fn new_plugin() -> RandomForestFunctionFinderPlugin {
        RandomForestFunctionFinderPlugin::new(Arc::new(MockPluginTool), stub_action())
    }

    struct MockProvider {
        program: Arc<dyn Program>,
        closed: Arc<AtomicBool>,
    }

    impl ProgramAssociatedComponentProviderAdapter for MockProvider {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }

        fn close_component(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }

        fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    struct MockNavigatable {
        program: Arc<dyn Program>,
    }

    impl NavigatableTrait for MockNavigatable {
        fn is_connected(&self) -> bool {
            true
        }

        fn get_program(&self) -> Box<dyn Program> {
            struct BoxedProgram(Arc<dyn Program>);
            impl DomainObject for BoxedProgram {}
            impl Program for BoxedProgram {
                fn get_name(&self) -> String {
                    Program::get_name(self.0.as_ref())
                }
                fn get_language_id(&self) -> String {
                    self.0.get_language_id()
                }
            }
            Box::new(BoxedProgram(self.program.clone()))
        }
    }

    #[derive(Default)]
    struct MockNavigatableActionContext {
        navigatable: Option<Arc<dyn crate::app::seam_stubs::Navigatable>>,
    }

    impl ActionContext for MockNavigatableActionContext {
        fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>> {
            None
        }
        fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }
        fn set_context_object(&mut self, _context_object: Option<Arc<dyn Any + Send + Sync>>) {}
        fn set_event_click_modifiers(&mut self, _modifiers: i32) {}
        fn event_click_modifiers(&self) -> i32 {
            0
        }
        fn has_any_event_click_modifiers(&self, _modifiers_mask: i32) -> bool {
            false
        }
        fn set_source_object(&mut self, _source_object: Option<Arc<dyn Any + Send + Sync>>) {}
        fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            None
        }
        fn set_context_provider(&mut self, _provider: Option<Arc<dyn ActionContextProvider>>) {}
        fn context_provider(&self) -> Option<Arc<dyn ActionContextProvider>> {
            None
        }
        fn set_mouse_event(&mut self, _event: Option<Arc<dyn MouseEvent>>) {}
        fn mouse_event(&self) -> Option<Arc<dyn MouseEvent>> {
            None
        }
        fn source_component(&self) -> Option<Arc<dyn Component>> {
            None
        }
        fn set_source_component(&mut self, _component: Option<Arc<dyn Component>>) {}
    }

    impl crate::app::context::NavigationActionContext for MockNavigatableActionContext {}

    impl NavigatableActionContext for MockNavigatableActionContext {
        fn get_navigatable(&self) -> Arc<dyn crate::app::seam_stubs::Navigatable> {
            self.navigatable.clone().expect("navigatable set for test")
        }
    }

    #[test]
    fn defaults_match_java_literals() {
        assert_eq!(TEST_SET_MAX_SIZE_DEFAULT, 1_000_000);
        assert_eq!(MIN_UNDEFINED_RANGE_SIZE_DEFAULT, 16);
        assert_eq!(FUNC_START, "S");
        assert_eq!(NON_START, "N");
        assert_eq!(ACTION_NAME, "Search for Code and Functions");
        assert_eq!(MENU_PATH_ENTRY, "For Code and Functions...");
    }

    #[test]
    fn name_matches_java_simple_class_name() {
        let plugin = new_plugin();
        assert_eq!(plugin.name(), "RandomForestFunctionFinderPlugin");
    }

    #[test]
    fn before_init_max_sizes_are_unset() {
        let plugin = new_plugin();
        assert_eq!(plugin.get_test_max_size(), None);
        assert_eq!(plugin.get_min_undefined_range_size(), None);
    }

    #[test]
    fn init_options_matches_java_defaults() {
        let plugin = new_plugin();
        plugin.init_options();
        assert_eq!(plugin.get_test_max_size(), Some(TEST_SET_MAX_SIZE_DEFAULT));
        assert_eq!(plugin.get_min_undefined_range_size(), Some(MIN_UNDEFINED_RANGE_SIZE_DEFAULT));
    }

    #[test]
    fn options_changed_vetoes_non_positive_test_set_max() {
        let mut plugin = new_plugin();
        let new_value: i64 = 0;
        let result = plugin.options_changed(
            &StubToolOptions,
            TEST_SET_MAX_SIZE_OPTION_NAME,
            None,
            Some(&new_value as &dyn Any),
        );
        assert!(result.is_err());
        assert_eq!(plugin.get_test_max_size(), None);
    }

    #[test]
    fn options_changed_accepts_positive_test_set_max() {
        let mut plugin = new_plugin();
        let new_value: i64 = 42;
        let result = plugin.options_changed(
            &StubToolOptions,
            TEST_SET_MAX_SIZE_OPTION_NAME,
            None,
            Some(&new_value as &dyn Any),
        );
        assert!(result.is_ok());
        assert_eq!(plugin.get_test_max_size(), Some(42));
    }

    #[test]
    fn options_changed_vetoes_non_positive_min_undefined_range_size() {
        let mut plugin = new_plugin();
        let new_value: i64 = -5;
        let result = plugin.options_changed(
            &StubToolOptions,
            MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME,
            None,
            Some(&new_value as &dyn Any),
        );
        assert!(result.is_err());
    }

    #[test]
    fn options_changed_ignores_unknown_option_without_erroring() {
        let mut plugin = new_plugin();
        let result = plugin.options_changed(&StubToolOptions, "Some Unknown Option", None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn program_closed_closes_associated_providers_and_forgets_program() {
        let plugin = new_plugin();
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "p1" });
        let closed_flag = Arc::new(AtomicBool::new(false));
        let provider: Arc<dyn ProgramAssociatedComponentProviderAdapter> =
            Arc::new(MockProvider { program: program.clone(), closed: closed_flag.clone() });

        plugin.add_provider(provider.clone());
        plugin.process_program_closed_event(&ProgramClosedPluginEvent::new(
            plugin.name(),
            program.clone(),
        ));

        assert!(closed_flag.load(Ordering::SeqCst));
        assert!(plugin.programs_to_providers.lock().unwrap().get(&program).is_none());
    }

    #[test]
    fn remove_provider_drops_it_from_the_map() {
        let plugin = new_plugin();
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "p2" });
        let closed_flag = Arc::new(AtomicBool::new(false));
        let provider: Arc<dyn ProgramAssociatedComponentProviderAdapter> =
            Arc::new(MockProvider { program: program.clone(), closed: closed_flag.clone() });

        plugin.add_provider(provider.clone());
        plugin.remove_provider(&provider);

        assert!(plugin.programs_to_providers.lock().unwrap().get(&program).unwrap().is_empty());
        assert!(!closed_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn display_dialog_creates_the_dialog_once_and_reuses_it() {
        let plugin = new_plugin();
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "p3" });
        let navigatable: Arc<dyn crate::app::seam_stubs::Navigatable> =
            Arc::new(MockNavigatable { program: program.clone() });
        let ctx = MockNavigatableActionContext { navigatable: Some(navigatable) };

        plugin.display_dialog(&ctx);
        let first = plugin.params_dialog.lock().unwrap().clone().unwrap();

        plugin.display_dialog(&ctx);
        let second = plugin.params_dialog.lock().unwrap().clone().unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(Program::get_name(first.get_training_source().as_ref()), "p3");
    }

    #[test]
    fn program_closed_dismisses_dialog_trained_on_the_closed_program() {
        let plugin = new_plugin();
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "p4" });
        let navigatable: Arc<dyn crate::app::seam_stubs::Navigatable> =
            Arc::new(MockNavigatable { program: program.clone() });
        let ctx = MockNavigatableActionContext { navigatable: Some(navigatable) };

        plugin.display_dialog(&ctx);
        assert!(plugin.params_dialog.lock().unwrap().is_some());

        plugin.process_program_closed_event(&ProgramClosedPluginEvent::new(
            plugin.name(),
            program.clone(),
        ));

        // Java's `programClosed` calls `dismissCallback()` but does not null out `paramsDialog`.
        assert!(plugin.params_dialog.lock().unwrap().is_some());
    }

    #[test]
    fn reset_dialog_clears_the_cached_dialog() {
        let plugin = new_plugin();
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "p5" });
        let navigatable: Arc<dyn crate::app::seam_stubs::Navigatable> =
            Arc::new(MockNavigatable { program });
        let ctx = MockNavigatableActionContext { navigatable: Some(navigatable) };

        plugin.display_dialog(&ctx);
        assert!(plugin.params_dialog.lock().unwrap().is_some());

        plugin.reset_dialog();
        assert!(plugin.params_dialog.lock().unwrap().is_none());
    }

    #[test]
    fn set_selection_stores_the_current_selection() {
        struct MockSelection;
        impl ProgramSelection for MockSelection {}

        let plugin = new_plugin();
        assert!(plugin.current_selection.lock().unwrap().is_none());

        let selection: Arc<dyn ProgramSelection> = Arc::new(MockSelection);
        plugin.set_selection(selection);

        assert!(plugin.current_selection.lock().unwrap().is_some());
    }

    #[test]
    fn plugin_description_matches_java_plugin_info_annotation() {
        let plugin = new_plugin();
        let description = plugin.plugin_description();
        assert_eq!(description.short_description(), "Function Finder");
        assert_eq!(description.description(), "Trains a random forest model to find function starts.");
        assert_eq!(description.category(), "Analysis");
        assert_eq!(
            description.services_required(),
            vec![GO_TO_SERVICE_CLASS.to_string(), PROGRAM_MANAGER_CLASS.to_string()]
        );
        assert_eq!(description.events_consumed(), vec![PROGRAM_CLOSED_EVENT_CLASS.to_string()]);
        assert_eq!(description.events_produced(), vec![PROGRAM_LOCATION_EVENT_CLASS.to_string()]);
    }
}
