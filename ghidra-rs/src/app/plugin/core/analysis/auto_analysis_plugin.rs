//! Port of `ghidra.app.plugin.core.analysis.AutoAnalysisPlugin`.
//!
//! Provides support for auto analysis tasks. Manages a pipeline or priority of tasks to run given
//! some event has occurred.
//!
//! # Shape
//!
//! Java's `AutoAnalysisPlugin` is a concrete class (nothing extends it), so it becomes a plain
//! `struct` (rule R14a-concrete-leaf). It extends `Plugin` and implements
//! `AutoAnalysisManagerListener`, both of which are ported as traits, so the members it overrides
//! there are implemented through [`Plugin`] and
//! [`AutoAnalysisManagerListener`] respectively. The state Java inherits from the `Plugin` base
//! class -- the provided-service registry, the consumed-event set and the disposed flag -- has no
//! base struct to live in, so this struct holds it, exactly as
//! [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin) does.
//!
//! # Seams
//!
//! * **The manager.** `AutoAnalysisManager` is not ported; only the
//!   [placeholder](crate::app::seam_stubs::AutoAnalysisManager) is, and the statics the plugin
//!   would reach it through (`getAnalysisManager`, `hasAutoAnalysisManager`) are the forward edge
//!   of the cycle this file sits on. Every method that touches a manager therefore takes it as a
//!   parameter -- `program_closed` takes `Option<&dyn AutoAnalysisManager>`, whose `None` is
//!   Java's `hasAutoAnalysisManager(program) == false` -- rather than looking it up. That keeps
//!   each method's own decision logic intact and testable.
//! * **Listener identity.** Java registers `this` with the manager and later removes it by
//!   identity. The ported [`AutoAnalysisManagerListener`] is generic over the manager type, so the
//!   manager placeholder cannot name it as a trait object without closing the cycle; it registers
//!   type-erased handles instead. Each object that Java would register as `this` therefore carries
//!   a [`ListenerIdentity`] token, added and removed in the same places Java adds and removes
//!   `this`.
//! * **Actions.** Java's `createActions()` builds its two menu actions with `ActionBuilder`, which
//!   is not ported, and each carries a back-reference to the plugin. As in `DisassemblerPlugin`,
//!   the plugin is handed its already-built actions ([`AutoAnalysisActions`]) and
//!   [`create_actions`](AutoAnalysisPlugin::create_actions) performs the rest of Java's body. The
//!   per-analyzer [`OneShotAnalyzerAction`] *is* ported here, since Java declares it as an inner
//!   class of this very file.
//! * **Dialogs, tasks and commands.** `AnalysisOptionsDialog`, `AnalyzeAllOpenProgramsTask`,
//!   `AnalysisBackgroundCommand`, `OneShotAnalysisCommand`, `AnalysisOptionsEditor`,
//!   `StoredAnalyzerTimesPropertyEditor` and `MultiLineMessageDialog` are all unported. Where Java
//!   constructs one, this port either takes a factory (as `DisassemblerPlugin` does) or hands the
//!   caller the arguments Java would have passed: [`show_options_dialog`] takes the user's answer
//!   as a closure, [`analyze_all_callback`] takes a task factory,
//!   [`OneShotAnalyzerAction::analysis_request`] returns the command's constructor arguments, and
//!   [`analysis_summary`] returns the dialog's contents.
//!
//! [`show_options_dialog`]: AutoAnalysisPlugin::show_options_dialog
//! [`analyze_all_callback`]: AutoAnalysisPlugin::analyze_all_callback
//! [`analysis_summary`]: AutoAnalysisPlugin::analysis_summary

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::events::FirstTimeAnalyzedPluginEvent;
use crate::app::plugin::core::analysis::auto_analysis_manager_listener::AutoAnalysisManagerListener;
use crate::app::plugin::plugin_category_names::PluginCategoryNames;
use crate::app::seam_stubs::{
    ghidra_program_utilities, AutoAnalysisManager, CorePluginPackage, GhidraOptions,
    ListingActionContext, ListingContextAction, MultiLineMessageDialog, ProgramSelection,
    StoredAnalyzerTimes, Task,
};
use crate::app::services::Analyzer;
use crate::framework::options::Options;
use crate::framework::plugintool::util::{
    PluginDescription, PluginEventListener, PluginStatus, ServiceListener,
};
use crate::framework::plugintool::{Plugin, PluginEvent};
use crate::framework::seam_stubs::{
    CustomOptionType, HelpLocation, PluginPackageLike, PluginTool,
};
use crate::program::model::listing::{Program, ANALYSIS_PROPERTIES};
use crate::util::classfinder::ExtensionPoint;

/// The tool option forcing the analysis options dialog open on every invocation.
const SHOW_ANALYSIS_OPTIONS: &str = "Show Analysis Options";

/// The action group every action this plugin installs belongs to.
pub const ANALYZE_GROUP_NAME: &str = "Analyze";

/// The help topic every help location this plugin builds points at.
const HELP_TOPIC: &str = "AutoAnalysisPlugin";

/// Fully-qualified names of the four events `@PluginInfo(eventsConsumed = ...)` lists.
const CONSUMED_EVENT_CLASSES: [&str; 4] = [
    "ghidra.app.events.ProgramOpenedPluginEvent",
    "ghidra.app.events.ProgramClosedPluginEvent",
    "ghidra.app.events.ProgramActivatedPluginEvent",
    "ghidra.app.events.ProgramPostActivatedPluginEvent",
];

/// The same four events by [`PluginEvent::event_name`], which is how
/// [`Plugin::process_last_events`] matches an event against the consumed set in this crate.
const CONSUMED_EVENT_NAMES: [&str; 4] = [
    "Program Opened",
    "Program Closed",
    "Program Activated",
    "Program Post Activated",
];

/// The originator `analysisEnded` attributes its log flush to: Java passes
/// `AutoAnalysisManager.class`, which has no `Class` object here.
const ANALYSIS_LOG_ORIGINATOR: &str = "ghidra.app.plugin.core.analysis.AutoAnalysisManager";

/// How an [`Analyzer`] is held once discovered.
///
/// Java's `ClassSearcher.getInstances(Analyzer.class)` hands back one instance per analyzer, shared
/// between this plugin's list and the [`OneShotAnalyzerAction`] built from it. `Analyzer` is a Java
/// interface discovered at runtime, so `dyn` dispatch is genuine here; and
/// [`Analyzer::options_changed`] takes `&mut self`, so that sharing needs interior mutability.
pub type AnalyzerHandle = Arc<Mutex<dyn Analyzer + Send + Sync>>;

/// A `ghidra.util.HelpLocation`, which is not ported beyond an empty
/// [placeholder](crate::framework::seam_stubs::HelpLocation) trait.
///
/// Java's `new HelpLocation(topic, anchor)` is a value, so this is the concrete value the plugin
/// builds and hands to the options it registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisHelpLocation {
    /// The help topic, always `"AutoAnalysisPlugin"` for this plugin.
    pub topic: String,
    /// The anchor within the topic.
    pub anchor: String,
}

impl AnalysisHelpLocation {
    /// Mirrors `new HelpLocation(String, String)`.
    pub fn new(topic: impl Into<String>, anchor: impl Into<String>) -> Self {
        Self {
            topic: topic.into(),
            anchor: anchor.into(),
        }
    }
}

impl HelpLocation for AnalysisHelpLocation {}

/// The identity an object is registered with an [`AutoAnalysisManager`] under.
///
/// Stands in for Java's `this` in `analysisMgr.addListener(this)` /
/// `analysisMgr.removeListener(this)`; see the module docs. Every instance is a distinct
/// allocation, so `Arc::ptr_eq` distinguishes two listeners exactly as Java's reference equality
/// does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerIdentity;

impl ListenerIdentity {
    /// A fresh identity, type-erased for
    /// [`AutoAnalysisManager::add_listener`](crate::app::seam_stubs::AutoAnalysisManager::add_listener).
    pub fn new_handle() -> Arc<dyn Any + Send + Sync> {
        Arc::new(ListenerIdentity)
    }
}

/// The two actions Java's `createActions()` builds, one field per `ActionBuilder` call.
///
/// Each is constructed with a callback into the plugin, which is the cycle this type breaks; see
/// the module docs.
pub struct AutoAnalysisActions {
    /// `new ActionBuilder("Auto Analyze", getName())...buildAndInstall(tool)`.
    pub auto_analyze_action: Arc<dyn ListingContextAction>,
    /// `new ActionBuilder("Analyze All Open", getName())...buildAndInstall(tool)`.
    pub analyze_all_open_action: Arc<dyn ListingContextAction>,
}

/// The `MultiLineMessageDialog` Java raises from `analysisEnded`, as the arguments Java passes to
/// its constructor.
///
/// `MultiLineMessageDialog` and `DockingWindowManager.showDialog` are not ported (see the module
/// docs), so [`AutoAnalysisPlugin::analysis_summary`] hands the dialog's contents back instead of
/// showing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisSummary {
    /// The dialog title.
    pub title: String,
    /// The one-line message shown above the details.
    pub short_message: String,
    /// The full log text, prefixed by Java's note about the application log file.
    pub detailed_message: String,
    /// `MultiLineMessageDialog`'s message-type selector.
    pub message_type: i32,
    /// Whether the dialog is modal; Java passes `false`.
    pub modal: bool,
}

/// What a one-shot analysis should cover: Java's `if (context.hasSelection())` branch.
#[derive(Clone)]
pub enum OneShotAnalysisScope {
    /// The non-empty current selection.
    Selection(Arc<dyn ProgramSelection>),
    /// Java's `else` branch, `memory.union(external)`: all of memory plus the external space.
    ///
    /// This crate's [`Memory`](crate::program::model::mem::Memory) is not an `AddressSetView` and
    /// `AddressSpace.EXTERNAL_SPACE` is not ported, so the union cannot be computed here; the
    /// choice Java makes is what this variant records.
    AllMemoryAndExternal,
}

/// The `new OneShotAnalysisCommand(analyzer, set, analysisMgr.getMessageLog())` Java builds, plus
/// the priority it schedules the command at, as the arguments this port can compute.
#[derive(Clone)]
pub struct OneShotAnalysisRequest {
    /// `analyzer.getName()`, which also names the options subtree the analyzer was reconfigured
    /// from.
    pub analyzer_name: String,
    /// `analyzer.getPriority().priority()`, the `schedule` argument.
    pub priority: i32,
    /// The address set the command runs over.
    pub scope: OneShotAnalysisScope,
}

/// Port of the inner class `AutoAnalysisPlugin.OneShotAnalyzerAction`, the `Analysis -> One Shot`
/// menu item installed for each analyzer that supports one-time analysis.
pub struct OneShotAnalyzerAction {
    analyzer: AnalyzerHandle,
    tool: Arc<dyn PluginTool + Send + Sync>,
    name: String,
    owner: String,
    /// Java's `canAnalyzeProgram`/`canAnalyze` pair, which caches the last answer per program.
    /// Behind a lock because `isEnabledForContext` is called through a `&self` action.
    can_analyze: Mutex<Option<(Arc<dyn Program>, bool)>>,
}

impl OneShotAnalyzerAction {
    /// Port of `OneShotAnalyzerAction(Analyzer)`.
    ///
    /// Java's `super(analyzer.getName(), AutoAnalysisPlugin.this.getName())` reaches the owner off
    /// the enclosing plugin; with no enclosing instance, it is passed in.
    pub fn new(
        analyzer: AnalyzerHandle,
        owner: impl Into<String>,
        tool: Arc<dyn PluginTool + Send + Sync>,
    ) -> Self {
        let name = analyzer.lock().unwrap().get_name();
        Self {
            analyzer,
            tool,
            name,
            owner: owner.into(),
            can_analyze: Mutex::new(None),
        }
    }

    /// The action's name, which is the analyzer's.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The action's owner, which is the plugin's name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The analyzer this action runs.
    pub fn analyzer(&self) -> &AnalyzerHandle {
        &self.analyzer
    }

    /// Java's `setMenuBarData(new MenuData(new String[] { "Analysis", "One Shot", name }, null,
    /// ANALYZE_GROUP_NAME))` menu path.
    pub fn menu_path(&self) -> [&str; 3] {
        ["Analysis", "One Shot", &self.name]
    }

    /// Java's `setHelpLocation(new HelpLocation("AutoAnalysisPlugin", "Auto_Analyzers"))`.
    pub fn help_location(&self) -> AnalysisHelpLocation {
        AnalysisHelpLocation::new(HELP_TOPIC, "Auto_Analyzers")
    }

    /// Port of `actionPerformed`'s body up to (but not including) the command it schedules.
    ///
    /// Performs Java's side effect of pushing the analyzer's options subtree back into the
    /// analyzer, and returns the arguments Java hands `new OneShotAnalysisCommand(...)` and
    /// `analysisMgr.schedule(...)`. A context with no program has nothing to analyze, so returns
    /// `None`.
    pub fn analysis_request(
        &self,
        context: &dyn ListingActionContext,
    ) -> Option<OneShotAnalysisRequest> {
        let program = context.get_program()?;

        let scope = match context.get_selection().filter(|s| !s.is_empty()) {
            Some(selection) => OneShotAnalysisScope::Selection(selection),
            None => OneShotAnalysisScope::AllMemoryAndExternal,
        };

        let mut analyzer = self.analyzer.lock().unwrap();
        let analyzer_name = analyzer.get_name();
        let options = program
            .get_options(ANALYSIS_PROPERTIES)
            .get_options(&analyzer_name);
        analyzer.options_changed(options.as_ref(), program.as_ref());

        Some(OneShotAnalysisRequest {
            analyzer_name,
            priority: analyzer.get_priority().priority(),
            scope,
        })
    }

    /// Java's closing `tool.setStatusInfo("Analysis scheduled: " + analyzer.getName())`.
    pub fn status_message(&self) -> String {
        format!("Analysis scheduled: {}", self.name)
    }
}

impl ListingContextAction for OneShotAnalyzerAction {
    /// Port of `actionPerformed(ListingActionContext)`.
    ///
    /// Everything Java does that does not need the unported `AutoAnalysisManager` happens here:
    /// the analyzer is reconfigured from the program's options and the status line is updated. The
    /// `OneShotAnalysisCommand` Java builds in between is described by
    /// [`analysis_request`](Self::analysis_request), which callers with a manager in hand can
    /// schedule themselves.
    fn action_performed(&self, context: &dyn ListingActionContext) {
        if self.analysis_request(context).is_none() {
            return;
        }
        self.tool.set_status_info(&self.status_message(), false);
    }

    /// Port of `isEnabledForContext(ListingActionContext)`, cache and all: `canAnalyze` is only
    /// re-asked when the context's program is not the one the cached answer was computed for.
    fn is_enabled_for_context(&self, context: &dyn ListingActionContext) -> bool {
        let Some(program) = context.get_program() else {
            return false;
        };

        let mut cache = self.can_analyze.lock().unwrap();
        if let Some((cached_program, can_analyze)) = cache.as_ref() {
            if Arc::ptr_eq(cached_program, &program) {
                return *can_analyze;
            }
        }

        let can_analyze = self.analyzer.lock().unwrap().can_analyze(program.as_ref());
        *cache = Some((program, can_analyze));
        can_analyze
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// Port of the inner class `AutoAnalysisPlugin.FirstTimeAnalyzedCallback`, registered with the
/// manager when a program is analyzed for the first time so a
/// [`FirstTimeAnalyzedPluginEvent`] can be fired once analysis completes.
pub struct FirstTimeAnalyzedCallback {
    tool: Arc<dyn PluginTool + Send + Sync>,
    plugin_name: String,
    identity: Arc<dyn Any + Send + Sync>,
}

impl FirstTimeAnalyzedCallback {
    /// Builds a callback that will fire its event as `plugin_name`.
    pub fn new(tool: Arc<dyn PluginTool + Send + Sync>, plugin_name: impl Into<String>) -> Self {
        Self {
            tool,
            plugin_name: plugin_name.into(),
            identity: ListenerIdentity::new_handle(),
        }
    }

    /// The handle this callback is registered with the manager under; see the module docs.
    pub fn identity(&self) -> Arc<dyn Any + Send + Sync> {
        self.identity.clone()
    }

    /// Java's `new FirstTimeAnalyzedPluginEvent(AutoAnalysisPlugin.this.getName(),
    /// manager.getProgram())`.
    pub fn event_for(&self, manager: &dyn AutoAnalysisManager) -> FirstTimeAnalyzedPluginEvent {
        FirstTimeAnalyzedPluginEvent::new(self.plugin_name.clone(), manager.get_program())
    }
}

impl AutoAnalysisManagerListener<dyn AutoAnalysisManager> for FirstTimeAnalyzedCallback {
    /// Port of `analysisEnded(AutoAnalysisManager, boolean)`: unregister, then -- unless analysis
    /// was cancelled -- announce the first-time-analyzed event.
    ///
    /// [`PluginTool::fire_plugin_event`] takes the base [`PluginEvent`], and this crate's typed
    /// event wrappers have no conversion onto it, so the event that reaches the tool carries the
    /// typed event's naming but not its program payload;
    /// [`event_for`](Self::event_for) hands out the full event.
    fn analysis_ended(&mut self, manager: &dyn AutoAnalysisManager, is_cancelled: bool) {
        manager.remove_listener(&self.identity);

        if is_cancelled {
            return;
        }
        let event = self.event_for(manager);
        self.tool.fire_plugin_event(PluginEvent::new(
            event.event().source_name(),
            event.event().event_name(),
        ));
    }
}

/// Provides support for auto analysis tasks. Manages a pipeline or priority of tasks to run given
/// some event has occurred.
///
/// Port of `ghidra.app.plugin.core.analysis.AutoAnalysisPlugin`.
pub struct AutoAnalysisPlugin {
    tool: Arc<dyn PluginTool + Send + Sync>,

    actions: AutoAnalysisActions,
    help_location: AnalysisHelpLocation,
    analyzers: Vec<AnalyzerHandle>,
    one_shot_actions: Mutex<Vec<Arc<OneShotAnalyzerAction>>>,
    /// The handle this plugin registers itself with managers under; see the module docs.
    identity: Arc<dyn Any + Send + Sync>,

    // State Java inherits from the `Plugin` base class; see the module docs.
    services_provided: Mutex<HashMap<String, Vec<Arc<dyn Any + Send + Sync>>>>,
    events_consumed: Mutex<HashSet<String>>,
    disposed: AtomicBool,
    description: AutoAnalysisPluginDescription,
}

impl AutoAnalysisPlugin {
    /// Port of `AutoAnalysisPlugin(PluginTool)`.
    ///
    /// Java's constructor discovers its analyzers with `ClassSearcher.getInstances(Analyzer.class)`
    /// and builds its two actions with `ActionBuilder`; neither has a Rust equivalent, so both are
    /// passed in. Everything else Java's constructor does -- sorting the analyzers, installing the
    /// actions, and registering the `Show Analysis Options` tool option under its help location --
    /// happens here.
    pub fn new(
        tool: Arc<dyn PluginTool + Send + Sync>,
        actions: AutoAnalysisActions,
        analyzers: Vec<AnalyzerHandle>,
    ) -> Self {
        let help_location = AnalysisHelpLocation::new(HELP_TOPIC, "AnalysisOptions");

        let plugin = Self {
            tool,
            actions,
            analyzers: Self::sort_analyzers(analyzers),
            help_location: help_location.clone(),
            one_shot_actions: Mutex::new(Vec::new()),
            identity: ListenerIdentity::new_handle(),
            services_provided: Mutex::new(HashMap::new()),
            events_consumed: Mutex::new(HashSet::new()),
            disposed: AtomicBool::new(false),
            description: AutoAnalysisPluginDescription,
        };
        plugin.create_actions();

        // get the option so that an owner is associated with it, otherwise it will not show up in
        // the Options dialog for the tool.
        let mut options = plugin
            .tool
            .get_options(GhidraOptions::CATEGORY_AUTO_ANALYSIS);
        let description = "This option forces the analysis options dialog to appear whenever \
                           auto-analysis action is invoked.";
        options.set_options_help_location(Some(Box::new(help_location.clone())));
        options.register_option(
            SHOW_ANALYSIS_OPTIONS,
            Box::new(true),
            Some(Box::new(help_location)),
            description,
        );

        plugin
    }

    /// Port of the static `getDescription()`.
    pub fn get_description() -> &'static str {
        "Provides coordination and a service for All Auto Analysis tasks"
    }

    /// Port of the static `getDescriptiveName()`.
    pub fn get_descriptive_name() -> &'static str {
        "AutoAnalysisManager"
    }

    /// Port of the static `getCategory()`.
    pub fn get_category() -> &'static str {
        "Analysis"
    }

    /// The analyzers this plugin offers, in the order the menu lists them.
    pub fn analyzers(&self) -> &[AnalyzerHandle] {
        &self.analyzers
    }

    /// The actions this plugin installed.
    pub fn actions(&self) -> &AutoAnalysisActions {
        &self.actions
    }

    /// The help location Java's constructor stores in its `helpLocation` field.
    pub fn help_location(&self) -> &AnalysisHelpLocation {
        &self.help_location
    }

    /// The one-shot actions currently installed, in installation order.
    pub fn one_shot_actions(&self) -> Vec<Arc<OneShotAnalyzerAction>> {
        self.one_shot_actions.lock().unwrap().clone()
    }

    /// Port of `findAnalyzers()`, less the `ClassSearcher` scan that produces the instances: sorts
    /// them by name so that the menu items are always in the same order.
    fn sort_analyzers(mut analyzers: Vec<AnalyzerHandle>) -> Vec<AnalyzerHandle> {
        analyzers.sort_by_key(|analyzer| analyzer.lock().unwrap().get_name());
        analyzers
    }

    /// Port of the private `createActions()`, less the construction of the two actions themselves.
    fn create_actions(&self) {
        self.tool
            .add_action(self.actions.auto_analyze_action.clone().as_any_arc());
        self.tool
            .add_action(self.actions.analyze_all_open_action.clone().as_any_arc());
        self.tool
            .set_menu_group(&["Analysis", "One Shot"], ANALYZE_GROUP_NAME);
    }

    /// Port of `updateActionName(ActionContext)`, which relabels the auto-analyze menu item with
    /// the program it would act on.
    ///
    /// Java reads and writes the name through `autoAnalyzeAction.getMenuBarData()`; `MenuData` is
    /// not ported, so the current name is passed in and the replacement -- already carrying Java's
    /// `&` mnemonic prefix -- is returned. `None` means Java would have left the name alone: the
    /// context has no program (Java's non-`ListingActionContext` early return), or the name is
    /// already correct.
    pub fn update_action_name(
        &self,
        context: &dyn ListingActionContext,
        current_name: &str,
    ) -> Option<String> {
        let program = context.get_program()?;
        let file_name = program.get_domain_file()?.get_name();
        let new_name = format!("Auto Analyze '{file_name}'...");
        if current_name == new_name {
            return None;
        }
        Some(format!("&{new_name}"))
    }

    /// Port of `addOneShotActions(Program)`: replace the installed one-shot actions with one per
    /// analyzer that supports one-time analysis of this program.
    pub fn add_one_shot_actions(&self, program: &dyn Program) {
        self.remove_one_shot_actions();

        let mut installed = self.one_shot_actions.lock().unwrap();
        for analyzer in &self.analyzers {
            {
                let analyzer = analyzer.lock().unwrap();
                if !analyzer.supports_one_time_analysis() || !analyzer.can_analyze(program) {
                    continue;
                }
            }
            let action = Arc::new(OneShotAnalyzerAction::new(
                analyzer.clone(),
                self.name(),
                self.tool.clone(),
            ));
            self.tool.add_action(action.clone().as_any_arc());
            installed.push(action);
        }
    }

    /// Port of `removeOneShotActions()`.
    pub fn remove_one_shot_actions(&self) {
        let mut installed = self.one_shot_actions.lock().unwrap();
        for action in installed.drain(..) {
            self.tool.remove_action(action.as_any_arc());
        }
    }

    /// Port of `analyzeAllCallback()`.
    ///
    /// Java builds `new AnalyzeAllOpenProgramsTask(this)` and hands it to a `TaskLauncher`; neither
    /// class is ported, so the task comes from `new_task` and is returned rather than launched.
    pub fn analyze_all_callback(&self, new_task: &mut dyn FnMut() -> Arc<dyn Task>) -> Arc<dyn Task> {
        new_task()
    }

    /// Port of `analyzeCallback(Program, ProgramSelection)`.
    ///
    /// The manager is passed in rather than looked up, and `ask_user` stands in for the
    /// `AnalysisOptionsDialog` (see the module docs). Returns whether analysis was started --
    /// Java's early `return` when the user dismisses the dialog is `false`.
    ///
    /// The `tool.executeBackgroundCommand(new AnalysisBackgroundCommand(analysisMgr, true),
    /// program)` Java runs just before re-analyzing has no counterpart yet: `AnalysisBackgroundCommand`
    /// is not ported, and the tool needs a shared `Arc<dyn Program>` where a mutable borrow is all
    /// this method has.
    pub fn analyze_callback(
        &self,
        program: &mut dyn Program,
        selection: Option<Arc<dyn ProgramSelection>>,
        analysis_mgr: &dyn AutoAnalysisManager,
        ask_user: &mut dyn FnMut() -> bool,
    ) -> bool {
        // this allows analyzers to register options with defaults
        analysis_mgr.initialize_options();

        if !self.show_options_dialog(program, ask_user) {
            return false;
        }

        // reloads the options in case the user changed them
        analysis_mgr.initialize_options();

        // check if this is the first time this program is being analyzed. If so, schedule a
        // callback when it is completed to send a FirstTimeAnalyzedPluginEvent
        if !ghidra_program_utilities::is_analyzed(program) {
            let callback = FirstTimeAnalyzedCallback::new(self.tool.clone(), self.name());
            analysis_mgr.add_listener(callback.identity());
        }

        // if has a selection use it; if no selection, use all of memory
        analysis_mgr.re_analyze_all(selection);
        true
    }

    /// Port of the private `showOptionsDialog(Program)`: show the options panel for the auto
    /// analysis options, and report whether the user chose to analyze.
    ///
    /// `ask_user` stands in for `new AnalysisOptionsDialog(program)` plus
    /// `dialog.wasAnalyzeButtonSelected()`; it is only invoked when Java would have shown the
    /// dialog, and Java's transaction is opened around it and committed either way.
    pub fn show_options_dialog(
        &self,
        program: &mut dyn Program,
        ask_user: &mut dyn FnMut() -> bool,
    ) -> bool {
        self.tool.clear_status_info();
        let options = self.tool.get_options(GhidraOptions::CATEGORY_AUTO_ANALYSIS);
        if !options.get_boolean(SHOW_ANALYSIS_OPTIONS, true) {
            return true;
        }

        let id = program.start_transaction("Analysis Options");
        let analyze = ask_user();
        program.end_transaction(id, true);
        analyze
    }

    /// Port of the protected `programClosed(Program)`.
    ///
    /// `None` is Java's `hasAutoAnalysisManager(program) == false`, in which case nothing happens.
    pub fn program_closed(&self, analysis_mgr: Option<&dyn AutoAnalysisManager>) {
        let Some(analysis_mgr) = analysis_mgr else {
            return;
        };
        analysis_mgr.remove_tool(self.tool.clone());
        analysis_mgr.remove_listener(&self.identity);
    }

    /// Port of the protected `programOpened(Program)`: join the program's manager and register the
    /// analyzer options editor.
    ///
    /// The `() -> new AnalysisOptionsEditor(program)` supplier Java registers has no counterpart
    /// (`AnalysisOptionsEditor` is not ported), so an editor-less supplier is registered in its
    /// place; the help location Java attaches is registered as Java attaches it.
    pub fn program_opened(&self, program: &dyn Program, analysis_mgr: &dyn AutoAnalysisManager) {
        analysis_mgr.add_tool(self.tool.clone());
        analysis_mgr.add_listener(self.identity.clone());

        let mut options = program.get_options(ANALYSIS_PROPERTIES);
        options.register_options_editor(Box::new(|| None));
        options.set_options_help_location(Some(Box::new(AnalysisHelpLocation::new(
            HELP_TOPIC,
            "Auto_Analysis_Option",
        ))));
    }

    /// Port of the private `programActivated(Program)`, which registers the program's cumulative
    /// analysis-task times as a custom option.
    ///
    /// `StoredAnalyzerTimesPropertyEditor` is not ported, so the editor supplier Java passes yields
    /// nothing; every other argument is Java's.
    pub fn program_activated(&self, program: &dyn Program) {
        let mut options = program.get_options(StoredAnalyzerTimes::OPTIONS_LIST);
        options.register_option_with_editor(
            StoredAnalyzerTimes::OPTION_NAME,
            Box::new(CustomOptionType),
            None,
            None,
            "Cumulative analysis task times",
            Some(Box::new(|| None)),
        );
    }

    /// Port of the private `postProgramActivated(Program)`: offer to analyze a program that has
    /// never been analyzed.
    ///
    /// Returns whether analysis was started.
    pub fn post_program_activated(
        &self,
        program: &mut dyn Program,
        analysis_mgr: &dyn AutoAnalysisManager,
        ask_user: &mut dyn FnMut() -> bool,
    ) -> bool {
        if !analysis_mgr.ask_to_analyze(&*self.tool) {
            return false;
        }
        self.analyze_callback(program, None, analysis_mgr, ask_user)
    }

    /// Port of `processEvent`'s `ProgramActivatedPluginEvent` branch, which is the one branch that
    /// needs no manager.
    ///
    /// `None` is Java's null active program: every one-shot action is withdrawn. Otherwise the
    /// program is activated and its one-shot actions installed.
    pub fn process_program_activated(&self, active_program: Option<&dyn Program>) {
        match active_program {
            None => self.remove_one_shot_actions(),
            Some(program) => {
                self.program_activated(program);
                self.add_one_shot_actions(program);
            }
        }
    }

    /// Port of `analysisEnded`'s body: flush the manager's log and describe the summary dialog
    /// Java raises, or `None` when the log recorded nothing and Java raises no dialog.
    pub fn analysis_summary(&self, manager: &dyn AutoAnalysisManager) -> Option<AnalysisSummary> {
        let log = manager.get_message_log();
        if !log.has_messages() {
            return None;
        }

        log.write(ANALYSIS_LOG_ORIGINATOR, "Analysis Log Messages");

        Some(AnalysisSummary {
            title: "Auto Analysis Summary".to_string(),
            short_message: "There were warnings/errors issued during analysis.".to_string(),
            detailed_message: format!(
                "(These messages are also written to the application log file)\n\n{}",
                log.to_display_string()
            ),
            message_type: MultiLineMessageDialog::WARNING_MESSAGE,
            modal: false,
        })
    }
}

impl AutoAnalysisManagerListener<dyn AutoAnalysisManager> for AutoAnalysisPlugin {
    /// Port of `analysisEnded(AutoAnalysisManager, boolean)`.
    ///
    /// The summary dialog Java shows through `DockingWindowManager.showDialog` is not ported (see
    /// the module docs), so the summary this computes -- log flush included -- is discarded here;
    /// [`analysis_summary`](AutoAnalysisPlugin::analysis_summary) is the member callers with a
    /// window manager should use. Java ignores `isCancelled` in this override.
    fn analysis_ended(&mut self, manager: &dyn AutoAnalysisManager, _is_cancelled: bool) {
        let _ = self.analysis_summary(manager);
    }
}

impl ExtensionPoint for AutoAnalysisPlugin {}

impl PluginEventListener for AutoAnalysisPlugin {
    fn event_sent(&self, event: &PluginEvent) {
        self.handle_plugin_event(event);
    }
}

impl ServiceListener for AutoAnalysisPlugin {
    /// Java's `AutoAnalysisPlugin` overrides neither `serviceAdded` nor `serviceRemoved`; the
    /// `Plugin` base class's bodies are empty.
    fn service_added(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}

    fn service_removed(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}
}

impl Plugin for AutoAnalysisPlugin {
    fn name(&self) -> String {
        "AutoAnalysisPlugin".to_string()
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
        let mut names: Vec<String> = CONSUMED_EVENT_NAMES.iter().map(|n| n.to_string()).collect();
        for name in self.events_consumed.lock().unwrap().iter() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }

    fn service_classes(&self) -> Vec<String> {
        self.services_provided
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
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

    fn cleanup(&self) {
        self.dispose();
        self.disposed.store(true, Ordering::SeqCst);
    }

    /// Port of `processEvent(PluginEvent)`.
    ///
    /// Java tests the event's concrete subclass and reads the program off it. A [`PluginEvent`]
    /// here carries no such payload and cannot be downcast, so the branches live in the typed
    /// members above -- [`process_program_activated`](AutoAnalysisPlugin::process_program_activated),
    /// [`program_opened`](AutoAnalysisPlugin::program_opened),
    /// [`program_closed`](AutoAnalysisPlugin::program_closed) and
    /// [`post_program_activated`](AutoAnalysisPlugin::post_program_activated) -- which the tool's
    /// event plumbing should call once it can hand out the concrete events. This override
    /// recognizes nothing on its own.
    fn process_event(&self, _event: &PluginEvent) {}
}

/// The `@PluginInfo` metadata declared on `AutoAnalysisPlugin`, as a [`PluginDescription`].
///
/// Java derives this from the annotation by reflection at registration time; with no annotations to
/// read, the values are stated directly here.
struct AutoAnalysisPluginDescription;

impl PluginCategoryNames for AutoAnalysisPluginDescription {}

impl PluginDescription for AutoAnalysisPluginDescription {
    fn plugin_class_name(&self) -> String {
        "ghidra.app.plugin.core.analysis.AutoAnalysisPlugin".to_string()
    }

    fn name(&self) -> String {
        "AutoAnalysisPlugin".to_string()
    }

    fn short_description(&self) -> String {
        "Manages auto-analysis".to_string()
    }

    fn description(&self) -> String {
        "Provides coordination and a service for All Auto Analysis tasks.".to_string()
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
        // The annotation declares none.
        Vec::new()
    }

    fn services_provided(&self) -> Vec<String> {
        // The annotation declares none.
        Vec::new()
    }

    fn events_consumed(&self) -> Vec<String> {
        CONSUMED_EVENT_CLASSES
            .iter()
            .map(|name| name.to_string())
            .collect()
    }

    fn events_produced(&self) -> Vec<String> {
        Vec::new()
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

    use crate::app::services::analysis_priority::AnalysisPriority;
    use crate::app::services::analyzer_type::AnalyzerType;
    use crate::app::seam_stubs::MessageLog;
    use crate::framework::model::{DomainFile, DomainObject};
    use crate::framework::plugintool::util::PluginDescription as _;
    use crate::program::model::address::AddressSetView;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    // --- analyzer ------------------------------------------------------------------------------

    /// An [`Analyzer`] answering only the members this plugin calls; everything else keeps the
    /// trait's default or is never reached.
    struct MockAnalyzer {
        name: String,
        one_time: bool,
        /// Shared so a test can flip the answer after the analyzer is behind a `dyn` handle.
        can_analyze: Arc<Mutex<bool>>,
        priority: i32,
        /// Every options subtree `optionsChanged` was handed, by name.
        reconfigured: Arc<Mutex<Vec<String>>>,
    }

    impl MockAnalyzer {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                one_time: true,
                can_analyze: Arc::new(Mutex::new(true)),
                priority: 100,
                reconfigured: Arc::default(),
            }
        }

        fn incapable(name: &str) -> Self {
            Self {
                can_analyze: Arc::new(Mutex::new(false)),
                ..Self::new(name)
            }
        }

        fn handle(self) -> AnalyzerHandle {
            Arc::new(Mutex::new(self))
        }
    }

    impl Analyzer for MockAnalyzer {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_analysis_type(&self) -> AnalyzerType {
            AnalyzerType::ByteAnalyzer
        }

        fn get_default_enablement(&self, _program: &dyn Program) -> bool {
            true
        }

        fn supports_one_time_analysis(&self) -> bool {
            self.one_time
        }

        fn get_description(&self) -> String {
            format!("{} description", self.name)
        }

        fn get_priority(&self) -> AnalysisPriority {
            AnalysisPriority::new(self.priority)
        }

        fn can_analyze(&self, _program: &dyn Program) -> bool {
            *self.can_analyze.lock().unwrap()
        }

        fn added(
            &mut self,
            _program: &mut dyn Program,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
            _log: &mut dyn MessageLog,
        ) -> Result<bool, CancelledException> {
            Ok(true)
        }

        fn removed(
            &mut self,
            _program: &mut dyn Program,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
            _log: &mut dyn MessageLog,
        ) -> Result<bool, CancelledException> {
            Ok(true)
        }

        fn register_options(&self, _options: &mut dyn Options, _program: &dyn Program) {}

        fn options_changed(&mut self, options: &dyn Options, _program: &dyn Program) {
            self.reconfigured.lock().unwrap().push(options.get_name());
        }

        fn analysis_ended(&mut self, _program: &dyn Program) {}

        fn is_prototype(&self) -> bool {
            false
        }
    }

    // --- program -------------------------------------------------------------------------------

    /// The options subtree a [`MockProgram`] hands out; records what was asked for and registered.
    #[derive(Default)]
    struct Recorder {
        /// Every options list asked for, by name, including nested `getOptions` paths.
        asked: Mutex<Vec<String>>,
        /// Every `"name=default"` registration.
        registered: Mutex<Vec<String>>,
        /// Every help location attached.
        help: Mutex<Vec<AnalysisHelpLocation>>,
        /// How many editor suppliers were registered.
        editors: Mutex<usize>,
    }

    struct RecordingOptions {
        name: String,
        recorder: Arc<Recorder>,
    }

    impl Options for RecordingOptions {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_options(&self, path: &str) -> Box<dyn Options> {
            self.recorder
                .asked
                .lock()
                .unwrap()
                .push(format!("{}/{path}", self.name));
            Box::new(RecordingOptions {
                name: path.to_string(),
                recorder: self.recorder.clone(),
            })
        }

        fn register_option(
            &mut self,
            option_name: &str,
            default_value: Box<dyn Any>,
            help: Option<Box<dyn HelpLocation>>,
            _description: &str,
        ) {
            let default = *default_value
                .downcast::<bool>()
                .expect("the plugin registers only a boolean here");
            self.recorder
                .registered
                .lock()
                .unwrap()
                .push(format!("{option_name}={default}"));
            assert!(help.is_some(), "Java passes its help location here");
        }

        fn register_option_with_editor(
            &mut self,
            option_name: &str,
            _option_type: Box<dyn crate::framework::seam_stubs::OptionType>,
            default_value: Option<Box<dyn Any>>,
            _help: Option<Box<dyn HelpLocation>>,
            _description: &str,
            _editor: Option<
                crate::util::function::Supplier<
                    Box<dyn crate::framework::seam_stubs::PropertyEditor>,
                >,
            >,
        ) {
            assert!(default_value.is_none(), "Java passes a null default");
            self.recorder
                .registered
                .lock()
                .unwrap()
                .push(format!("{option_name}=custom"));
        }

        fn register_options_editor(
            &mut self,
            _editor: crate::util::function::Supplier<
                Box<dyn crate::framework::seam_stubs::OptionsEditor>,
            >,
        ) {
            *self.recorder.editors.lock().unwrap() += 1;
        }

        fn set_options_help_location(&mut self, help_location: Option<Box<dyn HelpLocation>>) {
            // The concrete value is not recoverable through the opaque stub trait, so the module's
            // own help locations are recorded by the options list they were attached to.
            assert!(help_location.is_some());
            self.recorder
                .help
                .lock()
                .unwrap()
                .push(AnalysisHelpLocation::new(HELP_TOPIC, self.name.clone()));
        }

        fn get_boolean(&self, _option_name: &str, default_value: bool) -> bool {
            default_value
        }
    }

    struct MockProgram {
        analyzed: bool,
        file_name: String,
        recorder: Arc<Recorder>,
        /// Every `(description, commit)` transaction opened and closed.
        transactions: Mutex<Vec<(String, bool)>>,
    }

    impl MockProgram {
        fn new() -> Self {
            Self {
                analyzed: false,
                file_name: "hello.exe".to_string(),
                recorder: Arc::default(),
                transactions: Mutex::default(),
            }
        }

        fn analyzed() -> Self {
            Self {
                analyzed: true,
                ..Self::new()
            }
        }

        fn arc(self) -> Arc<dyn Program> {
            Arc::new(self)
        }
    }

    impl DomainObject for MockProgram {
        fn get_options(&self, property_list_name: &str) -> Box<dyn Options> {
            self.recorder
                .asked
                .lock()
                .unwrap()
                .push(property_list_name.to_string());
            Box::new(RecordingOptions {
                name: property_list_name.to_string(),
                recorder: self.recorder.clone(),
            })
        }

        fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
            Some(Box::new(MockDomainFile {
                name: self.file_name.clone(),
            }))
        }

        fn start_transaction(&mut self, description: &str) -> i32 {
            self.transactions
                .lock()
                .unwrap()
                .push((description.to_string(), false));
            7
        }

        fn end_transaction(&mut self, transaction_id: i32, commit: bool) -> bool {
            assert_eq!(transaction_id, 7);
            if let Some(last) = self.transactions.lock().unwrap().last_mut() {
                last.1 = commit;
            }
            commit
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.file_name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    /// A program whose `Program Information` options report it as already analyzed, which is what
    /// `GhidraProgramUtilities.isAnalyzed` reads.
    struct AnalyzedOptions;

    impl Options for AnalyzedOptions {
        fn get_name(&self) -> String {
            crate::program::model::listing::PROGRAM_INFO.to_string()
        }

        fn get_boolean(&self, option_name: &str, default_value: bool) -> bool {
            if option_name == crate::program::model::listing::ANALYZED_OPTION_NAME {
                true
            } else {
                default_value
            }
        }
    }

    struct MockDomainFile {
        name: String,
    }

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    // --- tool ----------------------------------------------------------------------------------

    #[derive(Default)]
    struct MockTool {
        actions_added: Mutex<usize>,
        actions_removed: Mutex<usize>,
        menu_groups: Mutex<Vec<(Vec<String>, String)>>,
        status: Mutex<Vec<String>>,
        status_cleared: Mutex<usize>,
        events_fired: Mutex<Vec<String>>,
        /// The answer `Show Analysis Options` reads back.
        show_analysis_options: bool,
        tool_options: Arc<Recorder>,
    }

    impl MockTool {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                show_analysis_options: true,
                ..Self::default()
            })
        }

        fn without_options_dialog() -> Arc<Self> {
            Arc::new(Self {
                show_analysis_options: false,
                ..Self::default()
            })
        }
    }

    impl PluginTool for MockTool {
        fn add_action(&self, _action: Arc<dyn Any + Send + Sync>) {
            *self.actions_added.lock().unwrap() += 1;
        }

        fn remove_action(&self, _action: Arc<dyn Any + Send + Sync>) {
            *self.actions_removed.lock().unwrap() += 1;
        }

        fn set_menu_group(&self, menu_path: &[&str], group: &str) {
            self.menu_groups.lock().unwrap().push((
                menu_path.iter().map(|s| s.to_string()).collect(),
                group.to_string(),
            ));
        }

        fn get_options(&self, category: &str) -> Box<dyn Options> {
            Box::new(ToolOptions {
                name: category.to_string(),
                show_analysis_options: self.show_analysis_options,
                recorder: self.tool_options.clone(),
            })
        }

        fn clear_status_info(&self) {
            *self.status_cleared.lock().unwrap() += 1;
        }

        fn set_status_info(&self, text: &str, _beep: bool) {
            self.status.lock().unwrap().push(text.to_string());
        }

        fn fire_plugin_event(&self, event: PluginEvent) {
            self.events_fired
                .lock()
                .unwrap()
                .push(event.event_name().to_string());
        }
    }

    struct ToolOptions {
        name: String,
        show_analysis_options: bool,
        recorder: Arc<Recorder>,
    }

    impl Options for ToolOptions {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_boolean(&self, option_name: &str, default_value: bool) -> bool {
            if option_name == SHOW_ANALYSIS_OPTIONS {
                self.show_analysis_options
            } else {
                default_value
            }
        }

        fn register_option(
            &mut self,
            option_name: &str,
            default_value: Box<dyn Any>,
            help: Option<Box<dyn HelpLocation>>,
            description: &str,
        ) {
            let default = *default_value.downcast::<bool>().unwrap();
            assert!(help.is_some());
            assert!(description.contains("forces the analysis options"));
            self.recorder
                .registered
                .lock()
                .unwrap()
                .push(format!("{option_name}={default}"));
        }

        fn set_options_help_location(&mut self, help_location: Option<Box<dyn HelpLocation>>) {
            assert!(help_location.is_some());
            *self.recorder.editors.lock().unwrap() += 1;
        }
    }

    // --- manager -------------------------------------------------------------------------------

    #[derive(Default)]
    struct MockManager {
        initialize_calls: Mutex<usize>,
        listeners: Mutex<Vec<Arc<dyn Any + Send + Sync>>>,
        tools_added: Mutex<usize>,
        tools_removed: Mutex<usize>,
        /// `Some(true)` = re-analyzed with a selection, `Some(false)` = with all of memory.
        reanalyzed: Mutex<Option<bool>>,
        ask_to_analyze: bool,
        log: Arc<RecordingLog>,
    }

    impl MockManager {
        fn new() -> Self {
            Self::default()
        }

        fn asking_to_analyze() -> Self {
            Self {
                ask_to_analyze: true,
                ..Self::default()
            }
        }

        fn with_messages(messages: &[&str]) -> Self {
            Self {
                log: Arc::new(RecordingLog {
                    messages: messages.iter().map(|m| m.to_string()).collect(),
                    written: Mutex::default(),
                }),
                ..Self::default()
            }
        }
    }

    impl AutoAnalysisManager for MockManager {
        fn schedule_worker(
            &self,
            _worker: &dyn crate::app::plugin::core::analysis::analysis_worker::AnalysisWorker,
            _worker_context: &dyn Any,
            _analyze_changes: bool,
            _worker_monitor: &dyn TaskMonitor,
        ) -> std::io::Result<bool> {
            unimplemented!("the plugin never schedules a worker")
        }

        fn initialize_options(&self) {
            *self.initialize_calls.lock().unwrap() += 1;
        }

        fn add_listener(&self, listener: Arc<dyn Any + Send + Sync>) {
            self.listeners.lock().unwrap().push(listener);
        }

        fn remove_listener(&self, listener: &Arc<dyn Any + Send + Sync>) {
            self.listeners
                .lock()
                .unwrap()
                .retain(|registered| !Arc::ptr_eq(registered, listener));
        }

        fn add_tool(&self, _tool: Arc<dyn PluginTool>) {
            *self.tools_added.lock().unwrap() += 1;
        }

        fn remove_tool(&self, _tool: Arc<dyn PluginTool>) {
            *self.tools_removed.lock().unwrap() += 1;
        }

        fn re_analyze_all(&self, set: Option<Arc<dyn ProgramSelection>>) {
            *self.reanalyzed.lock().unwrap() = Some(set.is_some());
        }

        fn ask_to_analyze(&self, _tool: &dyn PluginTool) -> bool {
            self.ask_to_analyze
        }

        fn get_message_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }

        fn get_program(&self) -> Arc<dyn Program> {
            MockProgram::new().arc()
        }
    }

    #[derive(Default)]
    struct RecordingLog {
        messages: Vec<String>,
        written: Mutex<Vec<String>>,
    }

    impl MessageLog for RecordingLog {
        fn has_messages(&self) -> bool {
            !self.messages.is_empty()
        }

        fn to_display_string(&self) -> String {
            self.messages.join("\n")
        }

        fn write(&self, originator: &str, header: &str) {
            self.written
                .lock()
                .unwrap()
                .push(format!("{originator}: {header}"));
        }
    }

    // --- action context ------------------------------------------------------------------------

    struct MockSelection {
        empty: bool,
    }

    impl ProgramSelection for MockSelection {
        fn is_empty(&self) -> bool {
            self.empty
        }
    }

    struct MockContext {
        program: Option<Arc<dyn Program>>,
        selection: Option<bool>,
    }

    impl MockContext {
        fn over(program: Arc<dyn Program>) -> Self {
            Self {
                program: Some(program),
                selection: None,
            }
        }

        fn with_selection(program: Arc<dyn Program>, empty: bool) -> Self {
            Self {
                program: Some(program),
                selection: Some(empty),
            }
        }
    }

    impl ListingActionContext for MockContext {
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            self.program.clone()
        }

        fn get_selection(&self) -> Option<Arc<dyn ProgramSelection>> {
            self.selection
                .map(|empty| Arc::new(MockSelection { empty }) as Arc<dyn ProgramSelection>)
        }
    }

    // --- actions -------------------------------------------------------------------------------

    struct StubAction;

    impl ListingContextAction for StubAction {
        fn action_performed(&self, _context: &dyn ListingActionContext) {}

        fn is_enabled_for_context(&self, _context: &dyn ListingActionContext) -> bool {
            true
        }

        fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    fn actions() -> AutoAnalysisActions {
        AutoAnalysisActions {
            auto_analyze_action: Arc::new(StubAction),
            analyze_all_open_action: Arc::new(StubAction),
        }
    }

    fn plugin_with(tool: Arc<MockTool>, analyzers: Vec<AnalyzerHandle>) -> AutoAnalysisPlugin {
        AutoAnalysisPlugin::new(tool, actions(), analyzers)
    }

    // --- tests ---------------------------------------------------------------------------------

    #[test]
    fn constructor_installs_both_actions_and_files_the_one_shot_submenu() {
        let tool = MockTool::new();
        let _plugin = plugin_with(tool.clone(), vec![]);

        // Java's createActions() calls buildAndInstall(tool) twice, then setMenuGroup once.
        assert_eq!(*tool.actions_added.lock().unwrap(), 2);
        assert_eq!(
            *tool.menu_groups.lock().unwrap(),
            vec![(
                vec!["Analysis".to_string(), "One Shot".to_string()],
                "Analyze".to_string()
            )]
        );
    }

    #[test]
    fn constructor_registers_show_analysis_options_defaulting_to_true() {
        let tool = MockTool::new();
        let _plugin = plugin_with(tool.clone(), vec![]);

        assert_eq!(
            *tool.tool_options.registered.lock().unwrap(),
            vec!["Show Analysis Options=true".to_string()]
        );
    }

    #[test]
    fn analyzers_are_sorted_by_name() {
        let plugin = plugin_with(
            MockTool::new(),
            vec![
                MockAnalyzer::new("Stack").handle(),
                MockAnalyzer::new("ASCII Strings").handle(),
                MockAnalyzer::new("Demangler").handle(),
            ],
        );

        let names: Vec<String> = plugin
            .analyzers()
            .iter()
            .map(|a| a.lock().unwrap().get_name())
            .collect();
        assert_eq!(names, vec!["ASCII Strings", "Demangler", "Stack"]);
    }

    #[test]
    fn help_location_matches_java_topic_and_anchor() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        assert_eq!(
            plugin.help_location(),
            &AnalysisHelpLocation::new("AutoAnalysisPlugin", "AnalysisOptions")
        );
    }

    #[test]
    fn one_shot_actions_are_installed_only_for_capable_analyzers() {
        let tool = MockTool::new();
        let unsupported = MockAnalyzer {
            one_time: false,
            ..MockAnalyzer::new("No One Shot")
        };
        let plugin = plugin_with(
            tool.clone(),
            vec![
                MockAnalyzer::new("Stack").handle(),
                unsupported.handle(),
                MockAnalyzer::incapable("Wrong Processor").handle(),
            ],
        );

        let program = MockProgram::new();
        plugin.add_one_shot_actions(&program);

        let installed = plugin.one_shot_actions();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].name(), "Stack");
        assert_eq!(installed[0].owner(), "AutoAnalysisPlugin");
        // the two menu actions from the constructor, plus this one
        assert_eq!(*tool.actions_added.lock().unwrap(), 3);
    }

    #[test]
    fn adding_one_shot_actions_replaces_the_previous_set() {
        let tool = MockTool::new();
        let plugin = plugin_with(tool.clone(), vec![MockAnalyzer::new("Stack").handle()]);
        let program = MockProgram::new();

        plugin.add_one_shot_actions(&program);
        plugin.add_one_shot_actions(&program);

        assert_eq!(plugin.one_shot_actions().len(), 1);
        assert_eq!(*tool.actions_removed.lock().unwrap(), 1);
    }

    #[test]
    fn deactivating_the_program_withdraws_every_one_shot_action() {
        let tool = MockTool::new();
        let plugin = plugin_with(tool.clone(), vec![MockAnalyzer::new("Stack").handle()]);
        let program = MockProgram::new();

        plugin.process_program_activated(Some(&program));
        assert_eq!(plugin.one_shot_actions().len(), 1);

        // Java's `program == null` branch
        plugin.process_program_activated(None);
        assert!(plugin.one_shot_actions().is_empty());
        assert_eq!(*tool.actions_removed.lock().unwrap(), 1);
    }

    #[test]
    fn activating_a_program_registers_the_stored_analyzer_times_option() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let program = MockProgram::new();

        plugin.program_activated(&program);

        assert_eq!(
            *program.recorder.asked.lock().unwrap(),
            vec!["Program Information.Analysis Times".to_string()]
        );
        assert_eq!(
            *program.recorder.registered.lock().unwrap(),
            vec!["Times=custom".to_string()]
        );
    }

    #[test]
    fn opening_a_program_joins_the_manager_and_registers_the_analyzer_options_editor() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let program = MockProgram::new();
        let manager = MockManager::new();

        plugin.program_opened(&program, &manager);

        assert_eq!(*manager.tools_added.lock().unwrap(), 1);
        assert_eq!(manager.listeners.lock().unwrap().len(), 1);
        assert_eq!(
            *program.recorder.asked.lock().unwrap(),
            vec!["Analyzers".to_string()]
        );
        assert_eq!(*program.recorder.editors.lock().unwrap(), 1);
    }

    #[test]
    fn closing_a_program_leaves_the_manager_it_joined() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let program = MockProgram::new();
        let manager = MockManager::new();

        plugin.program_opened(&program, &manager);
        plugin.program_closed(Some(&manager));

        assert_eq!(*manager.tools_removed.lock().unwrap(), 1);
        // the very handle `program_opened` registered was the one withdrawn
        assert!(manager.listeners.lock().unwrap().is_empty());
    }

    #[test]
    fn closing_a_program_with_no_manager_does_nothing() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        // Java's `hasAutoAnalysisManager(program) == false`
        plugin.program_closed(None);
    }

    #[test]
    fn options_dialog_is_skipped_when_the_tool_option_is_off() {
        let plugin = plugin_with(MockTool::without_options_dialog(), vec![]);
        let mut program = MockProgram::new();
        let mut asked = false;

        let analyze = plugin.show_options_dialog(&mut program, &mut || {
            asked = true;
            false
        });

        assert!(analyze, "Java returns true without showing the dialog");
        assert!(!asked);
        assert!(program.transactions.lock().unwrap().is_empty());
    }

    #[test]
    fn options_dialog_runs_inside_a_committed_transaction() {
        let tool = MockTool::new();
        let plugin = plugin_with(tool.clone(), vec![]);
        let mut program = MockProgram::new();

        let analyze = plugin.show_options_dialog(&mut program, &mut || false);

        assert!(!analyze, "the user declined to analyze");
        assert_eq!(*tool.status_cleared.lock().unwrap(), 1);
        assert_eq!(
            *program.transactions.lock().unwrap(),
            vec![("Analysis Options".to_string(), true)]
        );
    }

    #[test]
    fn declining_the_options_dialog_starts_no_analysis() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let mut program = MockProgram::new();
        let manager = MockManager::new();

        let started = plugin.analyze_callback(&mut program, None, &manager, &mut || false);

        assert!(!started);
        // Java initializes the options once before the dialog, and only reloads them after an
        // accepted dialog.
        assert_eq!(*manager.initialize_calls.lock().unwrap(), 1);
        assert!(manager.reanalyzed.lock().unwrap().is_none());
    }

    #[test]
    fn analyzing_an_unanalyzed_program_registers_the_first_time_callback() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let mut program = MockProgram::new();
        let manager = MockManager::new();
        let selection: Arc<dyn ProgramSelection> = Arc::new(MockSelection { empty: false });

        let started =
            plugin.analyze_callback(&mut program, Some(selection), &manager, &mut || true);

        assert!(started);
        assert_eq!(*manager.initialize_calls.lock().unwrap(), 2);
        assert_eq!(manager.listeners.lock().unwrap().len(), 1);
        assert_eq!(*manager.reanalyzed.lock().unwrap(), Some(true));
    }

    #[test]
    fn analyzing_an_already_analyzed_program_registers_no_callback() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let mut program = AlreadyAnalyzedProgram(MockProgram::analyzed());
        let manager = MockManager::new();

        let started = plugin.analyze_callback(&mut program, None, &manager, &mut || true);

        assert!(started);
        assert!(manager.listeners.lock().unwrap().is_empty());
        // no selection: Java re-analyzes all of memory
        assert_eq!(*manager.reanalyzed.lock().unwrap(), Some(false));
    }

    /// A program whose `Program Information` options report `Analyzed=true`.
    struct AlreadyAnalyzedProgram(MockProgram);

    impl DomainObject for AlreadyAnalyzedProgram {
        fn get_options(&self, property_list_name: &str) -> Box<dyn Options> {
            if property_list_name == crate::program::model::listing::PROGRAM_INFO {
                return Box::new(AnalyzedOptions);
            }
            self.0.get_options(property_list_name)
        }

        fn start_transaction(&mut self, description: &str) -> i32 {
            self.0.start_transaction(description)
        }

        fn end_transaction(&mut self, transaction_id: i32, commit: bool) -> bool {
            self.0.end_transaction(transaction_id, commit)
        }
    }

    impl Program for AlreadyAnalyzedProgram {
        fn get_name(&self) -> String {
            Program::get_name(&self.0)
        }

        fn get_language_id(&self) -> String {
            self.0.get_language_id()
        }
    }

    #[test]
    fn post_activation_only_analyzes_when_the_manager_asks() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let mut program = MockProgram::new();

        let quiet = MockManager::new();
        assert!(!plugin.post_program_activated(&mut program, &quiet, &mut || true));
        assert!(quiet.reanalyzed.lock().unwrap().is_none());

        let asking = MockManager::asking_to_analyze();
        assert!(plugin.post_program_activated(&mut program, &asking, &mut || true));
        assert_eq!(*asking.reanalyzed.lock().unwrap(), Some(false));
    }

    #[test]
    fn action_name_carries_the_programs_file_name() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let context = MockContext::over(MockProgram::new().arc());

        assert_eq!(
            plugin.update_action_name(&context, "&Auto Analyze..."),
            Some("&Auto Analyze 'hello.exe'...".to_string())
        );
    }

    #[test]
    fn action_name_is_left_alone_when_already_correct() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let context = MockContext::over(MockProgram::new().arc());

        assert_eq!(
            plugin.update_action_name(&context, "Auto Analyze 'hello.exe'..."),
            None
        );
    }

    #[test]
    fn analysis_summary_is_raised_only_when_the_log_has_messages() {
        let plugin = plugin_with(MockTool::new(), vec![]);

        assert!(plugin.analysis_summary(&MockManager::new()).is_none());

        let noisy = MockManager::with_messages(&["bad flow at 1000", "unknown opcode"]);
        let summary = plugin.analysis_summary(&noisy).expect("log has messages");

        assert_eq!(summary.title, "Auto Analysis Summary");
        assert_eq!(
            summary.short_message,
            "There were warnings/errors issued during analysis."
        );
        assert_eq!(
            summary.detailed_message,
            "(These messages are also written to the application log file)\n\n\
             bad flow at 1000\nunknown opcode"
        );
        assert_eq!(summary.message_type, 2);
        assert!(!summary.modal);
        assert_eq!(
            *noisy.log.written.lock().unwrap(),
            vec![format!("{ANALYSIS_LOG_ORIGINATOR}: Analysis Log Messages")]
        );
    }

    #[test]
    fn one_shot_action_scopes_to_a_non_empty_selection() {
        let tool = MockTool::new();
        let analyzer = MockAnalyzer::new("Stack");
        let reconfigured = analyzer.reconfigured.clone();
        let action = OneShotAnalyzerAction::new(analyzer.handle(), "AutoAnalysisPlugin", tool);

        let program = MockProgram::new().arc();
        let context = MockContext::with_selection(program, false);
        let request = action.analysis_request(&context).expect("has a program");

        assert_eq!(request.analyzer_name, "Stack");
        assert_eq!(request.priority, 100);
        assert!(matches!(
            request.scope,
            OneShotAnalysisScope::Selection(_)
        ));
        // Java re-reads the analyzer's own options subtree under "Analyzers".
        assert_eq!(*reconfigured.lock().unwrap(), vec!["Stack".to_string()]);
    }

    #[test]
    fn one_shot_action_falls_back_to_all_memory_for_an_empty_selection() {
        let action = OneShotAnalyzerAction::new(
            MockAnalyzer::new("Stack").handle(),
            "AutoAnalysisPlugin",
            MockTool::new(),
        );
        let context = MockContext::with_selection(MockProgram::new().arc(), true);

        let request = action.analysis_request(&context).unwrap();
        assert!(matches!(
            request.scope,
            OneShotAnalysisScope::AllMemoryAndExternal
        ));
    }

    #[test]
    fn one_shot_action_reports_the_scheduled_analyzer_on_the_status_line() {
        let tool = MockTool::new();
        let action = OneShotAnalyzerAction::new(
            MockAnalyzer::new("Stack").handle(),
            "AutoAnalysisPlugin",
            tool.clone(),
        );
        let context = MockContext::over(MockProgram::new().arc());

        action.action_performed(&context);

        assert_eq!(
            *tool.status.lock().unwrap(),
            vec!["Analysis scheduled: Stack".to_string()]
        );
    }

    #[test]
    fn one_shot_action_caches_can_analyze_per_program() {
        let incapable = MockAnalyzer::incapable("Wrong Processor");
        let can_analyze = incapable.can_analyze.clone();
        let action =
            OneShotAnalyzerAction::new(incapable.handle(), "AutoAnalysisPlugin", MockTool::new());

        let program = MockProgram::new().arc();
        let context = MockContext::over(program.clone());
        assert!(!action.is_enabled_for_context(&context));

        // Java only re-asks when the program changes, so flipping the analyzer's answer under a
        // cached program is not observed...
        *can_analyze.lock().unwrap() = true;
        assert!(!action.is_enabled_for_context(&context));

        // ...but a different program re-asks.
        let other = MockContext::over(MockProgram::new().arc());
        assert!(action.is_enabled_for_context(&other));
    }

    #[test]
    fn one_shot_action_menu_path_and_help_match_java() {
        let action = OneShotAnalyzerAction::new(
            MockAnalyzer::new("Stack").handle(),
            "AutoAnalysisPlugin",
            MockTool::new(),
        );

        assert_eq!(action.menu_path(), ["Analysis", "One Shot", "Stack"]);
        assert_eq!(
            action.help_location(),
            AnalysisHelpLocation::new("AutoAnalysisPlugin", "Auto_Analyzers")
        );
    }

    #[test]
    fn first_time_callback_unregisters_and_fires_unless_cancelled() {
        let tool = MockTool::new();
        let mut callback = FirstTimeAnalyzedCallback::new(tool.clone(), "AutoAnalysisPlugin");
        let manager = MockManager::new();
        manager.add_listener(callback.identity());

        callback.analysis_ended(&manager, false);

        assert!(manager.listeners.lock().unwrap().is_empty());
        assert_eq!(
            *tool.events_fired.lock().unwrap(),
            vec!["FirstTimeAnalyzed".to_string()]
        );
    }

    #[test]
    fn first_time_callback_fires_nothing_when_cancelled() {
        let tool = MockTool::new();
        let mut callback = FirstTimeAnalyzedCallback::new(tool.clone(), "AutoAnalysisPlugin");
        let manager = MockManager::new();
        manager.add_listener(callback.identity());

        callback.analysis_ended(&manager, true);

        assert!(manager.listeners.lock().unwrap().is_empty());
        assert!(tool.events_fired.lock().unwrap().is_empty());
    }

    #[test]
    fn plugin_description_matches_the_plugin_info_annotation() {
        let plugin = plugin_with(MockTool::new(), vec![]);
        let description = plugin.plugin_description();

        assert_eq!(description.name(), "AutoAnalysisPlugin");
        assert_eq!(description.short_description(), "Manages auto-analysis");
        assert_eq!(description.category(), "Analysis");
        assert_eq!(description.status(), PluginStatus::Released);
        assert_eq!(description.plugin_package().name(), "Ghidra Core");
        assert_eq!(
            description.events_consumed(),
            vec![
                "ghidra.app.events.ProgramOpenedPluginEvent",
                "ghidra.app.events.ProgramClosedPluginEvent",
                "ghidra.app.events.ProgramActivatedPluginEvent",
                "ghidra.app.events.ProgramPostActivatedPluginEvent",
            ]
        );
        assert!(description.events_produced().is_empty());
    }

    #[test]
    fn static_names_match_java() {
        assert_eq!(
            AutoAnalysisPlugin::get_description(),
            "Provides coordination and a service for All Auto Analysis tasks"
        );
        assert_eq!(
            AutoAnalysisPlugin::get_descriptive_name(),
            "AutoAnalysisManager"
        );
        assert_eq!(AutoAnalysisPlugin::get_category(), "Analysis");
    }
}
