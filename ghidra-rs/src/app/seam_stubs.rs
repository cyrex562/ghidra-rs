//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::app::decompiler::{
    ClangLine, ClangNode, ClangTokenBase, ClangTokenGroup, DecompiledFunction,
};
use crate::app::util::address_factory_service::AddressFactoryService;
use crate::app::util::opinion::library_exported_symbol::LibraryExportedSymbol;
use crate::app::util::option_listener::OptionListener;
use crate::program::model::data::array::Array;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::listing::Program;
use crate::program::model::symbol::Namespace;
use crate::program::seam_stubs::LanguageCompilerSpecPair;
use crate::program::util::program_location::ProgramLocation;
use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::model::target::path::KeyPath;
use crate::trace::model::thread::TraceThread;
use crate::trace::model::trace::Trace;
use crate::util::task::TaskMonitor;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use crate::util::seam_stubs::ResourceFile;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::any::Any;
use std::option::Option as StdOption;
use std::sync::Arc;

/// Placeholder for `ghidra.framework.options.ToolOptions`, referenced by
/// [`EclipseIntegrationService`](crate::app::services::EclipseIntegrationService) and
/// [`VSCodeIntegrationService`](crate::app::services::VSCodeIntegrationService) before the
/// real class is ported. Both services only ever return this type, so no members are needed yet.
pub trait ToolOptions {}

/// Placeholder for `ghidra.app.plugin.core.byteviewer.ByteViewerConfigOptions`, referenced by
/// [`DataFormatModel`](crate::app::plugin::core::format::DataFormatModel) before the real class
/// is ported. Java's version is a concrete class (not an interface), so this is a plain struct
/// rather than a `dyn`-dispatched trait, matching [`DockingAction`]'s convention.
/// `DataFormatModel` only ever passes this type through as a parameter, so no fields are needed
/// yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteViewerConfigOptions;

/// Placeholder for `ghidra.app.util.importer.MessageLog`, referenced by
/// [`Analyzer`](crate::app::services::Analyzer),
/// [`SourceLanguageSpecExtension`](crate::app::util::sourcelanguage::source_language_spec_extension::SourceLanguageSpecExtension)
/// and
/// [`UnixAoutProgramLoader`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader)
/// before the real class is ported. Most callers only pass this type through as a parameter; the
/// two `appendMsg` overloads the a.out loader records its progress with are modeled here.
///
/// Both take `&self`, not `&mut self`: a log is threaded through loaders alongside the objects
/// they mutate, so implementors buffer their messages behind interior mutability rather than
/// forcing every holder to take a unique borrow.
pub trait MessageLog: Send + Sync {
    /// `MessageLog.appendMsg(String)`. Defaults to discarding the message, so implementors that
    /// existed before this method did (and that never had a message to record) keep compiling.
    fn append_msg(&self, message: &str) {
        let _ = message;
    }

    /// `MessageLog.appendMsg(String originator, String message)`, which Java renders as
    /// `originator + ": " + message`.
    fn append_msg_from(&self, originator: &str, message: &str) {
        self.append_msg(&format!("{originator}: {message}"));
    }

    /// `MessageLog.copyFrom(MessageLog)`, which appends every message of `other` onto this log.
    /// Defaults to discarding them, matching [`append_msg`](Self::append_msg)'s default.
    fn copy_from(&self, other: &dyn MessageLog) {
        let _ = other;
    }

    /// `MessageLog.toString()`, the accumulated messages joined by newlines. Defaults to the
    /// empty string, which is what Java's `toString` returns for a log that recorded nothing --
    /// the case [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) tests for when
    /// picking which log to report an import failure from.
    fn to_display_string(&self) -> String {
        String::new()
    }

    /// `MessageLog.hasMessages()`. Defaults to `false`, matching
    /// [`to_display_string`](Self::to_display_string)'s empty default.
    ///
    /// Grown in for
    /// [`AutoAnalysisPlugin`](crate::app::plugin::core::analysis::AutoAnalysisPlugin), which only
    /// raises its analysis summary when the manager's log recorded something.
    fn has_messages(&self) -> bool {
        false
    }

    /// `MessageLog.write(Class<?>, String)`, which flushes the accumulated messages to the
    /// application log under `header`, attributed to `originator`. Java takes the originating
    /// class; with no `Class` object to pass, the caller names it. Defaults to discarding the
    /// write, as [`append_msg`](Self::append_msg) does.
    fn write(&self, originator: &str, header: &str) {
        let _ = (originator, header);
    }
}

/// Placeholder for `ghidra.features.base.codecompare.model.FunctionComparisonModel`, referenced
/// by [`FunctionComparisonService`](crate::app::services::FunctionComparisonService) before the
/// real class is ported. `FunctionComparisonService` only ever passes this type through as a
/// parameter, so no members are needed yet.
pub trait FunctionComparisonModel {}

/// Placeholder for `ghidra.features.base.codecompare.panel.FunctionComparisonPanel`, referenced
/// by [`FunctionComparisonService`](crate::app::services::FunctionComparisonService) before the
/// real class is ported. `FunctionComparisonService` only ever returns this type, so no members
/// are needed yet.
pub trait FunctionComparisonPanel {}

/// Placeholder for `ghidra.debug.api.control.ControlMode`, referenced by
/// [`DebuggerControlService`](crate::app::services::DebuggerControlService) and its nested
/// `ControlModeChangeListener` before the real class is ported. `DebuggerControlService` only
/// ever passes this type through as a parameter/return value, so no members are needed yet.
pub trait ControlMode {}

/// Placeholder for `ghidra.debug.api.action.AutoMapSpec`, referenced by
/// [`DebuggerAutoMappingService`](crate::app::services::DebuggerAutoMappingService) before the
/// real class is ported. `DebuggerAutoMappingService` only ever passes this type through as a
/// parameter/return value, so no members are needed yet.
pub trait AutoMapSpec {}

/// Placeholder for `ghidra.debug.api.tracermi.TraceRmiLaunchOffer`, referenced by
/// [`TraceRmiLauncherService`](crate::app::services::TraceRmiLauncherService) before the real
/// class is ported. `TraceRmiLauncherService` only ever returns this type, so no members are
/// needed yet.
pub trait TraceRmiLaunchOffer {}

/// Placeholder for `ghidra.app.util.viewer.listingpanel.ListingMarginProvider`, referenced by
/// [`ListingMarginProviderService`](crate::app::services::ListingMarginProviderService) before
/// the real class is ported. `ListingMarginProviderService` only ever passes this type through
/// as a parameter/return value, so no members are needed yet.
pub trait ListingMarginProvider {}

/// Placeholder for `ghidra.app.util.viewer.listingpanel.ListingOverviewProvider`, referenced by
/// [`ListingOverviewProviderService`](crate::app::services::ListingOverviewProviderService) before
/// the real class is ported. `ListingOverviewProviderService` only ever passes this type through
/// as a parameter/return value, so no members are needed yet.
pub trait ListingOverviewProvider: Send + Sync {}

/// Placeholder for `ghidra.debug.api.target.Target`, referenced by
/// [`DebuggerTargetService`](crate::app::services::DebuggerTargetService),
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService), and
/// [`InternalPcodeDebuggerDataAccess`](crate::app::plugin::core::debug::service::emulation::InternalPcodeDebuggerDataAccess)
/// before the real class is ported.
///
/// Grown with the members
/// [`DebuggerCoordinates`](crate::debug::api::tracemgr::DebuggerCoordinates) resolves focus
/// through. Those default to panicking so the existing two-member implementors (all of them test
/// doubles that only ever report liveness and a snap) keep compiling unchanged; the real port
/// replaces every default.
pub trait Target {
    /// Check if the target is still valid.
    fn is_valid(&self) -> bool;

    /// Get the current snapshot key for the target.
    fn get_snap(&self) -> i64;

    /// Get the trace into which this target is recorded.
    ///
    /// Mirrors `Target.getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("Target::get_trace placeholder not overridden")
    }

    /// Check if the target supports a notion of focus, i.e., whether [`Self::get_focus`] means
    /// anything.
    ///
    /// Mirrors `Target.isSupportsFocus()`.
    fn is_supports_focus(&self) -> bool {
        unimplemented!("Target::is_supports_focus placeholder not overridden")
    }

    /// Get the path of the object the target currently has focused, if any.
    ///
    /// Mirrors `Target.getFocus()`, whose `null` return becomes `None`.
    fn get_focus(&self) -> StdOption<KeyPath> {
        unimplemented!("Target::get_focus placeholder not overridden")
    }

    /// Find the thread containing the object at the given path.
    ///
    /// Mirrors `Target.getThreadForSuccessor(KeyPath)`.
    fn get_thread_for_successor(&self, path: &KeyPath) -> StdOption<Box<dyn TraceThread>> {
        let _ = path;
        unimplemented!("Target::get_thread_for_successor placeholder not overridden")
    }

    /// Find the stack frame containing the object at the given path.
    ///
    /// Mirrors `Target.getStackFrameForSuccessor(KeyPath)`.
    fn get_stack_frame_for_successor(&self, path: &KeyPath) -> StdOption<Box<dyn TraceStackFrame>> {
        let _ = path;
        unimplemented!("Target::get_stack_frame_for_successor placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.util.viewer.format.FormatManager`, referenced by
/// [`CodeFormatService`](crate::app::services::CodeFormatService) before the real class is
/// ported. `CodeFormatService` only ever returns this type, so no members are needed yet.
pub trait FormatManager {}

/// Placeholder for `ghidra.app.util.viewer.format.FieldFormatModel`, referenced by
/// [`FormatModelListener`](crate::app::util::viewer::format::format_model_listener::FormatModelListener)
/// before the real class is ported.
pub trait FieldFormatModel: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.datamgr.archive.Archive`, referenced by
/// [`DataTypeArchiveService`](crate::app::services::DataTypeArchiveService) before the real
/// class is ported. `DataTypeArchiveService` only ever returns this type, so no members are
/// needed yet.
pub trait Archive {}

/// Placeholder for `ghidra.app.nav.Navigatable`, referenced by
/// [`MemorySearchService`](crate::app::services::MemorySearchService) (which only ever passes
/// this type through as a parameter), by
/// [`NavigatableActionContext`](crate::app::context::NavigatableActionContext) (whose
/// `is_active_program` default method mirrors `NavigatableActionContext.isActiveProgram()`,
/// which calls `Navigatable.isConnected()`), and by
/// [`AddressAnnotatedStringHandler`](crate::app::util::viewer::field::address_annotated_string_handler::AddressAnnotatedStringHandler)
/// (whose `handle_mouse_click` mirrors `Navigatable.getProgram()`, grown in here for that caller)
/// before the real class is ported.
pub trait Navigatable {
    /// Stands in for `Navigatable.isConnected()`.
    fn is_connected(&self) -> bool;

    /// Stands in for `Navigatable.getProgram()`.
    fn get_program(&self) -> Box<dyn crate::program::model::listing::program::Program>;

    /// Whether this is a dynamic (debugger) listing rather than a static program listing, mirroring
    /// `Navigatable.isDynamic()`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin), which
    /// disables its actions over a dynamic listing (the Debugger has its own Disassemble actions)
    /// and skips follow-on code analysis there. Java's default implementation on `Navigatable`
    /// likewise returns `false`.
    fn is_dynamic(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.app.nav.LocationMemento`, referenced by
/// [`NavigationHistoryService`](crate::app::services::NavigationHistoryService) before the real
/// class is ported. Java's version is a concrete container class (not an interface), so this is
/// a plain struct rather than a `dyn`-dispatched trait. `NavigationHistoryService` only ever
/// passes this type through as a parameter/return value, so no fields are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocationMemento;

/// Placeholder for `ghidra.features.base.memsearch.gui.SearchSettings`, referenced by
/// [`MemorySearchService`](crate::app::services::MemorySearchService) before the real class is
/// ported. `MemorySearchService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait SearchSettings {}

/// Placeholder for `ghidra.app.plugin.core.osgi.BundleHost`, referenced by
/// [`GhidraBundleBase`](crate::app::plugin::core::osgi::GhidraBundleBase) before the real class
/// is ported. Java's version is a concrete class (not an interface) with a large API surface for
/// managing the OSGi framework's installed bundles; only the members its current callers
/// (`GhidraBundleBase` and [`ghidra_script_util`](crate::script::ghidra_script_util)) need are
/// modeled here. The stub holds no bundles, so every query answers "nothing installed".
#[derive(Debug, Clone, Default)]
pub struct BundleHost;

impl BundleHost {
    /// Mirrors `BundleHost.getOSGiBundle(String)`. Always returns `None` until the real bundle
    /// host is ported and can track installed OSGi bundles by location identifier.
    pub fn get_os_gi_bundle(
        &self,
        _location_identifier: &str,
    ) -> std::option::Option<crate::app::plugin::core::osgi::Bundle> {
        std::option::Option::None
    }

    /// Mirrors `BundleHost.startFramework()`, which starts the embedded OSGi framework.
    pub fn start_framework(&self) -> std::io::Result<()> {
        std::result::Result::Ok(())
    }

    /// Mirrors `BundleHost.stopFramework()`.
    pub fn stop_framework(&self) {}

    /// Mirrors `BundleHost.add(ResourceFile, boolean, boolean)`, which creates a managed bundle
    /// for `bundle_file`. The real method returns the new `GhidraBundle`; no caller of this stub
    /// uses that return value yet, and the stub has nowhere to store it.
    pub fn add(
        &self,
        _bundle_file: &crate::generic::jar::resource_file::ResourceFile,
        _enabled: bool,
        _system_bundle: bool,
    ) {
    }

    /// Mirrors `BundleHost.add(List<ResourceFile>, boolean, boolean)`.
    pub fn add_all(
        &self,
        _bundle_files: &[crate::generic::jar::resource_file::ResourceFile],
        _enabled: bool,
        _system_bundle: bool,
    ) {
    }

    /// Mirrors `BundleHost.getBundleFiles()`: the files of all managed bundles.
    pub fn get_bundle_files(&self) -> Vec<crate::generic::jar::resource_file::ResourceFile> {
        Vec::new()
    }

    /// Mirrors `BundleHost.getEnabledBundleFiles()`: the files of the enabled managed bundles.
    pub fn get_enabled_bundle_files(&self) -> Vec<crate::generic::jar::resource_file::ResourceFile> {
        Vec::new()
    }

    /// Mirrors the static `BundleHost.getOsgiDir()`, the user-settings subdirectory holding OSGi
    /// artifacts. Java resolves it against the `Application` singleton; following this crate's
    /// convention for Java statics that read the singleton, the application is passed in, and the
    /// result is `None` when the application has no user settings directory.
    pub fn get_osgi_dir(
        app: &dyn crate::framework::application::Application,
    ) -> std::option::Option<std::path::PathBuf> {
        app.user_settings_directory().map(|dir| dir.join("osgi"))
    }

    /// Mirrors `BundleHost.getExistingGhidraBundle(ResourceFile)`, which looks up the bundle
    /// already created for `bundle_file` without creating a new one. Java returns any concrete
    /// `GhidraBundle` (`JavaScriptProvider` narrows the result to a `GhidraSourceBundle`); since
    /// the stub tracks no bundles at all (see the struct doc comment), it always answers "no
    /// bundle registered here yet", same as [`BundleHost::get_bundle_files`].
    pub fn get_existing_ghidra_bundle(
        &self,
        _bundle_file: &crate::generic::jar::resource_file::ResourceFile,
    ) -> std::option::Option<GhidraSourceBundle> {
        std::option::Option::None
    }

    /// Mirrors `BundleHost.deactivateSynchronously(Bundle)`. Always succeeds: the stub never
    /// activates a bundle in the first place (see [`BundleHost::get_os_gi_bundle`]).
    pub fn deactivate_synchronously(
        &self,
        _bundle: &crate::app::plugin::core::osgi::Bundle,
    ) -> std::result::Result<(), crate::app::plugin::core::osgi::GhidraBundleException> {
        std::result::Result::Ok(())
    }

    /// Mirrors `BundleHost.activateAll(Collection<GhidraBundle>, TaskMonitor, PrintWriter)`. A
    /// no-op: the stub has no OSGi framework backing it to activate bundles in.
    pub fn activate_all(
        &self,
        _bundles: &[&GhidraSourceBundle],
        _monitor: &dyn TaskMonitor,
        _console: &mut dyn std::io::Write,
    ) {
    }
}

/// Placeholder for `ghidra.app.plugin.core.osgi.GhidraSourceBundle`, referenced by
/// [`BundleHost::get_existing_ghidra_bundle`] before the real class is ported. Java's version is
/// a concrete leaf subclass of the abstract `GhidraBundle` (compiling a directory of Java source
/// into an OSGi bundle); only the two members [`JavaScriptProvider`](crate::script::java_script_provider::JavaScriptProvider)
/// needs -- the OSGi bundle it produces, and the compiled class name for a given source file --
/// are modeled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhidraSourceBundle;

impl GhidraSourceBundle {
    /// Mirrors `GhidraBundle.getOSGiBundle()` as inherited by `GhidraSourceBundle`. Always `None`
    /// until the real bundle host can track installed OSGi bundles.
    pub fn os_gi_bundle(&self) -> std::option::Option<crate::app::plugin::core::osgi::Bundle> {
        std::option::Option::None
    }

    /// Mirrors `GhidraSourceBundle.classNameForScript(ResourceFile)`, which resolves the fully
    /// qualified class name a source file compiles to within its bundle. That resolution depends
    /// on the bundle's compiled class map, which does not exist until the real bundle host
    /// activates and builds source bundles; always reports the class as not found until then.
    pub fn class_name_for_script(
        &self,
        source_file: &crate::generic::jar::resource_file::ResourceFile,
    ) -> std::io::Result<String> {
        std::result::Result::Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "class name for script not available: {} (source bundle activation is not yet ported)",
                source_file.absolute_path()
            ),
        ))
    }
}

/// Placeholder for `docking.action.DockingAction`, referenced by
/// [`InterpreterConsole`](crate::app::plugin::core::interpreter::InterpreterConsole) before the
/// real class is ported. Java's version is a concrete class (not an interface), so this is a
/// plain struct rather than a `dyn`-dispatched trait, matching [`LocationMemento`]'s
/// convention. `InterpreterConsole` only ever passes this type through as a parameter, so no
/// fields are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DockingAction;


/// Placeholder for `ghidra.app.plugin.core.programtree.ViewProviderService`, referenced by
/// [`ViewManagerService`](crate::app::services::ViewManagerService) before the real class is
/// ported. `ViewManagerService` only ever passes this type through as a parameter/return value,
/// so no members are needed yet.
pub trait ViewProviderService {}

/// Placeholder for `ghidra.debug.api.progress.MonitorReceiver`, referenced by
/// [`ProgressService`](crate::app::services::ProgressService) before the real interface is
/// ported. `ProgressService` only ever returns this type opaquely, so no members are needed yet.
pub trait MonitorReceiver {}

/// Placeholder for `ghidra.debug.api.progress.ProgressListener`, referenced by
/// [`ProgressService`](crate::app::services::ProgressService) before the real interface is
/// ported. `ProgressService` only ever passes this type through as a parameter, so no members
/// are needed yet.
pub trait ProgressListener {}

/// Placeholder for `ghidra.app.plugin.core.debug.service.tracermi.DefaultTraceRmiAcceptor`,
/// returned by [`InternalTraceRmiService`](crate::app::services::InternalTraceRmiService) before
/// the real class is ported. `InternalTraceRmiService` only ever returns this type opaquely, so
/// no members are needed yet.
pub trait DefaultTraceRmiAcceptor {}

/// Placeholder for `ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler`, returned by
/// [`InternalTraceRmiService`](crate::app::services::InternalTraceRmiService) before the real
/// class is ported. `InternalTraceRmiService` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait TraceRmiHandler {}

/// Placeholder for `ghidra.util.task.Task`, referenced by
/// [`ProgressService`](crate::app::services::ProgressService)'s default `execute` method before
/// the real class is ported. Models just the two members that default method calls.
pub trait Task {
    /// Stands in for `Task.canCancel()`.
    fn can_cancel(&self) -> bool;

    /// Stands in for `Task.run(TaskMonitor)`.
    fn run(
        &self,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Result<(), crate::util::exception::CancelledException>;
}

/// Placeholder for `ghidra.trace.model.time.schedule.TraceSchedule`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService) and
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService) before the
/// real class is ported. Both services only ever pass this type through as a parameter/return
/// value, so no members are needed yet.
// `Send` so an `EmulationResult` holding a `Box<dyn TraceSchedule>` can cross threads,
// as required by the `+ Send` `RunFuture` (ports Java's `CompletableFuture<EmulationResult>`).
pub trait TraceSchedule: Send {}

/// Placeholder for `ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService)'s nested
/// `CachedEmulator` before the real class is ported. `CachedEmulator` only ever stores and
/// returns this type opaquely, so no members are needed yet.
pub trait Writer {}

/// Placeholder for `ghidra.trace.model.time.schedule.Scheduler.RunResult`, the base interface
/// extended by `DebuggerEmulationService.EmulationResult` before that nested interface (and the
/// `RecordRunResult` record, and the `Scheduler.run` default method that constructs it) is
/// ported -- see [`Scheduler`](crate::trace::model::time::schedule::scheduler::Scheduler)'s
/// module docs for why that trio isn't portable yet. Models the two accessors that
/// `EmulationResult` and `RecordEmulationResult` (both in
/// [`debugger_emulation_service`](crate::app::services::debugger_emulation_service)) build on.
// `Send` so `dyn EmulationResult` (its subtrait) is `Send`, letting the `+ Send` `RunFuture`
// carry a `Box<dyn EmulationResult>` across threads.
pub trait RunResult: Send {
    /// Stands in for `RunResult.schedule()`.
    fn schedule(&self) -> &dyn TraceSchedule;

    /// Stands in for `RunResult.error()`.
    fn error(&self) -> StdOption<&(dyn std::error::Error + Send + Sync)>;
}

/// Placeholder for `ghidra.app.services.GoToOverrideService`, referenced by
/// [`GoToService`](crate::app::services::GoToService) before the real interface is ported.
/// `GoToService` only ever passes this type through as a parameter/return value, so no members
/// are needed yet. Bounded by `Send + Sync` to match `GoToService`'s own `Send + Sync` bound
/// (an implementor holding `Arc<dyn GoToOverrideService>` can only itself be `Send + Sync` if
/// this is too).
pub trait GoToOverrideService: Send + Sync {}

/// Placeholder for `ghidra.debug.api.modules.DebuggerAddressTranslator`, the base interface
/// extended by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real interface is ported. `DebuggerStaticMappingService` does not itself call any
/// `DebuggerAddressTranslator` members, so no members are needed yet.
pub trait DebuggerAddressTranslator {}

/// Placeholder for `ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through
/// as a parameter, so no members are needed yet.
pub trait ModuleMapEntry {}

/// Placeholder for `ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through
/// as a parameter, so no members are needed yet.
pub trait SectionMapEntry {}

/// Placeholder for `ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through
/// as a parameter, so no members are needed yet.
pub trait RegionMapEntry {}

/// Placeholder for `ghidra.debug.api.modules.ModuleMapProposal`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever returns this type, so no
/// members are needed yet.
pub trait ModuleMapProposal {}

/// Placeholder for `ghidra.debug.api.modules.SectionMapProposal`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever returns this type, so no
/// members are needed yet.
pub trait SectionMapProposal {}

/// Placeholder for `ghidra.debug.api.modules.RegionMapProposal`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever returns this type, so no
/// members are needed yet.
pub trait RegionMapProposal {}

/// Placeholder for `javax.swing.tree.TreePath`, referenced by
/// [`DataTypeManagerService`](crate::app::services::DataTypeManagerService) before the real class
/// is ported. `DataTypeManagerService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait TreePath {}

/// Placeholder for `ghidra.app.util.bin.ByteProvider`, referenced by
/// [`Loader`](crate::app::util::opinion::loader::Loader) before the real class is ported.
/// `Loader`'s default `get_preferred_file_name` only ever calls `getFSRL()`/`getName()`, so no
/// other members are needed yet.
pub trait ByteProviderLike {
    /// Stands in for `ByteProvider.getFSRL()`.
    fn get_fsrl(&self) -> StdOption<Box<dyn crate::filesystem::gfilesystem::fsrl::Fsrl>>;

    /// Stands in for `ByteProvider.getName()`.
    fn get_name(&self) -> StdOption<String>;
}

/// Placeholder for `ghidra.app.util.AbstractOptionBuilder`, referenced by
/// [`Option`](crate::app::seam_stubs::Option) before the real class is ported. Java's version is
/// generic over the option's value type (`AbstractOptionBuilder<ValueType, OptionType>`); since a
/// `dyn Builder` cannot itself be generic, [`value`](Self::value) instead takes a type-erased
/// `Box<dyn Any + Send + Sync>`, downcast by the implementor to whichever concrete value type it
/// builds. Only the three chained calls
/// [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) makes
/// (`.value(..).commandLineArgument(..).build()`) are modeled; Java's `group`/`description`/
/// `stateKey`/`hidden` setters are left out.
pub trait Builder: Send + Sync {
    /// Mirrors `AbstractOptionBuilder.value(ValueType)`.
    fn value(self: Box<Self>, value: Box<dyn std::any::Any + Send + Sync>) -> Box<dyn Builder>;

    /// Mirrors `AbstractOptionBuilder.commandLineArgument(String)`.
    fn command_line_argument(self: Box<Self>, arg: String) -> Box<dyn Builder>;

    /// Mirrors `AbstractOptionBuilder.stateKey(String)`, which names the project save state the
    /// built option is persisted under. Added for
    /// [`AbstractOrdinalSupportLoader`](crate::app::util::opinion::abstract_ordinal_support_loader::AbstractOrdinalSupportLoader),
    /// whose ordinal-lookup option is saved under
    /// [`OPTIONS_PROJECT_SAVE_STATE_KEY`](crate::app::util::opinion::loader::OPTIONS_PROJECT_SAVE_STATE_KEY).
    fn state_key(self: Box<Self>, state_key: String) -> Box<dyn Builder>;

    /// Mirrors `AbstractOptionBuilder.build()`.
    fn build(self: Box<Self>) -> Box<dyn Option>;
}

/// Placeholder for `ghidra.app.util.Option`, referenced by
/// [`OptionListener`](crate::app::util::option_listener::OptionListener),
/// [`Loader`](crate::app::util::opinion::loader::Loader), and
/// [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) before
/// the real class is ported. Only [`get_name`](Self::get_name) and [`get_value`](Self::get_value)
/// are required; every other member defaults (mirroring the "Target" stub convention elsewhere in
/// this file) since no current caller exercises them, which also keeps the eight `Option.newX`
/// static factories -- modeled as the free functions [`new_boolean`]/[`new_string`]/
/// [`new_integer`] below, since Rust has no static trait methods to hang them on -- from needing
/// an `Option` instance to call through.
pub trait Option: Send + Sync {
    /// Mirrors `Option.getName()`.
    fn get_name(&self) -> String;

    /// Mirrors `Option.getValue()`.
    fn get_value(&self) -> Box<dyn std::any::Any>;

    fn set_option_listener(&self, listener: &dyn OptionListener) {
        let _ = listener;
        unimplemented!("Option::set_option_listener placeholder not overridden")
    }

    fn get_custom_editor_component(
        &self,
        address_factory_service: &dyn AddressFactoryService,
    ) -> Box<dyn crate::docking::seam_stubs::Component> {
        let _ = address_factory_service;
        unimplemented!("Option::get_custom_editor_component placeholder not overridden")
    }

    fn get_value_class(&self) -> Box<dyn Class> {
        unimplemented!("Option::get_value_class placeholder not overridden")
    }

    fn get_group(&self) -> String {
        unimplemented!("Option::get_group placeholder not overridden")
    }

    fn set_value(&self, object: &dyn std::any::Any) -> std::io::Result<()> {
        let _ = object;
        unimplemented!("Option::set_value placeholder not overridden")
    }

    fn parse_and_set_value_by_type(
        &self,
        str: &str,
        address_factory: &dyn crate::program::model::address::AddressFactory,
    ) -> bool {
        let _ = (str, address_factory);
        false
    }

    /// Mirrors `Option.getArg()`.
    fn get_arg(&self) -> String {
        String::new()
    }

    fn get_state_key(&self) -> String {
        unimplemented!("Option::get_state_key placeholder not overridden")
    }

    fn get_state(&self) -> Box<dyn crate::framework::seam_stubs::SaveState> {
        unimplemented!("Option::get_state placeholder not overridden")
    }

    fn is_hidden(&self) -> bool {
        false
    }

    fn get_description(&self) -> String {
        String::new()
    }

    fn to_string(&self) -> String {
        self.get_name()
    }

    fn copy(&self) -> Box<dyn Option> {
        unimplemented!("Option::copy placeholder not overridden")
    }
}

/// The concrete value carried by a [`SimpleOption`]/[`SimpleOptionBuilder`]. Only the three value
/// types `Option.newBoolean`/`newString`/`newInteger` build
/// (`ghidra.app.util.importer.options.BooleanOption`/`StringOption`/`IntegerOption`) are modeled.
enum SimpleOptionValue {
    Bool(bool),
    Str(String),
    Int(i32),
}

/// Minimal constructible implementor of [`Option`], standing in for the
/// `BooleanOption`/`StringOption`/`IntegerOption` subclasses of `ghidra.app.util.Option` before
/// those (and their shared `AbstractOption` superclass) are ported. Built via
/// [`new_boolean`]/[`new_string`]/[`new_integer`] and [`SimpleOptionBuilder`]; holds only the
/// state that builder chain actually sets.
struct SimpleOption {
    name: String,
    value: SimpleOptionValue,
    command_line_argument: std::option::Option<String>,
    state_key: std::option::Option<String>,
}

impl Option for SimpleOption {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_value(&self) -> Box<dyn std::any::Any> {
        match &self.value {
            SimpleOptionValue::Bool(v) => Box::new(*v),
            SimpleOptionValue::Str(v) => Box::new(v.clone()),
            SimpleOptionValue::Int(v) => Box::new(*v),
        }
    }

    fn get_arg(&self) -> String {
        self.command_line_argument.clone().unwrap_or_default()
    }

    /// The empty string stands in for Java's `null` default, as it already does for
    /// [`get_arg`](Self::get_arg).
    fn get_state_key(&self) -> String {
        self.state_key.clone().unwrap_or_default()
    }
}

/// Builder for [`SimpleOption`]; see that type's docs. Returned (as `Box<dyn Builder>`) by
/// [`new_boolean`]/[`new_string`]/[`new_integer`].
struct SimpleOptionBuilder {
    name: String,
    value: std::option::Option<SimpleOptionValue>,
    command_line_argument: std::option::Option<String>,
    state_key: std::option::Option<String>,
}

impl SimpleOptionBuilder {
    fn named(name: &str) -> Self {
        SimpleOptionBuilder {
            name: name.to_string(),
            value: None,
            command_line_argument: None,
            state_key: None,
        }
    }
}

impl Builder for SimpleOptionBuilder {
    fn value(mut self: Box<Self>, value: Box<dyn std::any::Any + Send + Sync>) -> Box<dyn Builder> {
        let value = match value.downcast::<bool>() {
            Ok(v) => {
                self.value = Some(SimpleOptionValue::Bool(*v));
                return self;
            }
            Err(value) => value,
        };
        let value = match value.downcast::<String>() {
            Ok(v) => {
                self.value = Some(SimpleOptionValue::Str(*v));
                return self;
            }
            Err(value) => value,
        };
        match value.downcast::<i32>() {
            Ok(v) => self.value = Some(SimpleOptionValue::Int(*v)),
            Err(_) => panic!("SimpleOptionBuilder::value: unsupported option value type"),
        }
        self
    }

    fn command_line_argument(mut self: Box<Self>, arg: String) -> Box<dyn Builder> {
        self.command_line_argument = Some(arg);
        self
    }

    fn state_key(mut self: Box<Self>, state_key: String) -> Box<dyn Builder> {
        self.state_key = Some(state_key);
        self
    }

    fn build(self: Box<Self>) -> Box<dyn Option> {
        Box::new(SimpleOption {
            name: self.name,
            value: self.value.expect("Option value must be set via .value(..) before .build()"),
            command_line_argument: self.command_line_argument,
            state_key: self.state_key,
        })
    }
}

/// Mirrors the static factory `Option.newBoolean(String)`.
pub fn new_boolean(name: &str) -> Box<dyn Builder> {
    Box::new(SimpleOptionBuilder::named(name))
}

/// Mirrors the static factory `Option.newString(String)`.
pub fn new_string(name: &str) -> Box<dyn Builder> {
    Box::new(SimpleOptionBuilder::named(name))
}

/// Mirrors the static factory `Option.newInteger(String)`.
pub fn new_integer(name: &str) -> Box<dyn Builder> {
    Box::new(SimpleOptionBuilder::named(name))
}

/// Placeholder for `ghidra.app.util.OptionUtils`, referenced by
/// [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) before
/// the real class is ported. Java's version is a final class of statics, so this is a plain
/// module of free functions rather than a trait. `getOption`'s generic `<T> T getOption(String,
/// List<Option>, T)` becomes three type-specialized functions (`get_bool_option`/
/// `get_string_option`/`get_int_option`) since Rust has no unchecked-cast equivalent to reuse
/// across value types; each returns `default_value` both when the name is absent AND when a
/// same-named option holds a differently-typed value (Java's unchecked cast would instead throw
/// `ClassCastException` on a type mismatch, but every option list this module actually sees is
/// built by [`elf_loader_options_factory`] itself with matching types, so that path is never
/// exercised in practice).
pub mod option_utils {
    use super::Option;

    /// Mirrors `OptionUtils.containsOption(String, List<Option>)`.
    pub fn contains_option(option_name: &str, options: &[Box<dyn Option>]) -> bool {
        options.iter().any(|o| o.get_name() == option_name)
    }

    /// Mirrors `OptionUtils.getOption(String, List<Option>, T)` specialized to `bool`.
    pub fn get_bool_option(option_name: &str, options: &[Box<dyn Option>], default_value: bool) -> bool {
        options
            .iter()
            .find(|o| o.get_name() == option_name)
            .and_then(|o| o.get_value().downcast_ref::<bool>().copied())
            .unwrap_or(default_value)
    }

    /// Mirrors `OptionUtils.getOption(String, List<Option>, T)` specialized to a nullable
    /// `String` (Java's `(String) null` default).
    pub fn get_string_option(
        option_name: &str,
        options: &[Box<dyn Option>],
        default_value: std::option::Option<String>,
    ) -> std::option::Option<String> {
        options
            .iter()
            .find(|o| o.get_name() == option_name)
            .and_then(|o| o.get_value().downcast_ref::<String>().cloned())
            .or(default_value)
    }

    /// Mirrors `OptionUtils.getOption(String, List<Option>, T)` specialized to `i32`.
    pub fn get_int_option(option_name: &str, options: &[Box<dyn Option>], default_value: i32) -> i32 {
        options
            .iter()
            .find(|o| o.get_name() == option_name)
            .and_then(|o| o.get_value().downcast_ref::<i32>().copied())
            .unwrap_or(default_value)
    }
}

/// Placeholder for `ghidra.app.util.opinion.LoadSpec`, referenced by
/// [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) and
/// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader) before the real class is
/// ported. Java's version additionally carries a `Loader` back-reference; no in-repo caller reads
/// it back (`getLoader()`), so it is dropped. Grown from the ELF-only placeholder (which modeled
/// just the `LanguageCompilerSpecPair` field, required rather than nullable, since an ELF
/// `LoadSpec` always carries one) to also carry `desiredImageBase`, `isPreferred`, and
/// `requiresLanguageCompilerSpec`, mirroring the field derivation in Java's
/// `LoadSpec(Loader, long, LanguageCompilerSpecPair, boolean)` constructor, so
/// `language_compiler_spec` is now nullable (`dyld_cache_loader`'s fallback `LoadSpec` has none).
pub struct LoadSpec {
    /// Mirrors `LoadSpec.getDesiredImageBase()`.
    pub desired_image_base: i64,
    /// Mirrors `LoadSpec.getLanguageCompilerSpec()`. `None` when the associated `Loader` doesn't
    /// use, or wasn't able to determine, a language/compiler.
    pub language_compiler_spec: StdOption<crate::program::seam_stubs::LanguageCompilerSpecPair>,
    /// Mirrors `LoadSpec.isPreferred()`.
    pub preferred: bool,
    /// Mirrors `LoadSpec.requiresLanguageCompilerSpec()`.
    pub requires_language_compiler_spec: bool,
}

impl LoadSpec {
    /// Port of the field derivation in `LoadSpec(Loader, long, LanguageCompilerSpecPair,
    /// boolean)`: a "preferred" null language/compiler means the loader doesn't use one; a
    /// "non-preferred" null language/compiler means the loader does use one but couldn't
    /// determine it on its own.
    fn new_full(
        desired_image_base: i64,
        language_compiler_spec: StdOption<crate::program::seam_stubs::LanguageCompilerSpecPair>,
        preferred: bool,
    ) -> Self {
        let requires_language_compiler_spec = language_compiler_spec.is_some() || !preferred;
        Self { desired_image_base, language_compiler_spec, preferred, requires_language_compiler_spec }
    }

    /// Constructs a [`LoadSpec`] from a manually supplied `LanguageCompilerSpecPair`, as used by
    /// [`elf_loader_options_factory`]. Equivalent to calling the full Java constructor with
    /// `imageBase = 0` and `isPreferred = false`, all that caller's [`get_language`](Self::get_language)
    /// needs.
    pub fn new(language_compiler_spec: crate::program::seam_stubs::LanguageCompilerSpecPair) -> Self {
        Self::new_full(0, Some(language_compiler_spec), false)
    }

    /// Port of `LoadSpec(Loader, long, LanguageCompilerSpecPair, boolean)`, as used by
    /// [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader), which (unlike
    /// [`new`](Self::new)) needs to mark its language/compiler spec preferred.
    pub fn with_language_compiler_spec(
        desired_image_base: i64,
        language_compiler_spec: crate::program::seam_stubs::LanguageCompilerSpecPair,
        preferred: bool,
    ) -> Self {
        Self::new_full(desired_image_base, Some(language_compiler_spec), preferred)
    }

    /// Port of `LoadSpec(Loader, long, QueryResult)`.
    pub fn from_query_result(desired_image_base: i64, result: &QueryResult) -> Self {
        Self::new_full(desired_image_base, Some(result.pair.clone()), result.preferred)
    }

    /// Port of `LoadSpec(Loader, long, boolean requiresLanguageCompilerSpec)`.
    pub fn without_language_compiler_spec(
        desired_image_base: i64,
        requires_language_compiler_spec: bool,
    ) -> Self {
        Self::new_full(desired_image_base, None, !requires_language_compiler_spec)
    }

    /// Port of `LoadSpec.isComplete()`.
    pub fn is_complete(&self) -> bool {
        !self.requires_language_compiler_spec || self.language_compiler_spec.is_some()
    }

    /// Mirrors `loadSpec.getLanguageCompilerSpec().getLanguage()`. Java resolves the language via
    /// the `DefaultLanguageService` singleton; that singleton accessor was dropped when
    /// `DefaultLanguageService` was ported (see its module docs), so the equivalent
    /// `LanguageService` is supplied explicitly here, mirroring the substitution already
    /// established in
    /// [`resolve_language_by_id`](crate::program::model::data::program_architecture_translator::resolve_language_by_id).
    ///
    /// # Panics
    /// Panics if [`language_compiler_spec`](Self::language_compiler_spec) is `None`; only
    /// [`elf_loader_options_factory`] calls this, and it always builds a `LoadSpec` with one set.
    pub fn get_language(
        &self,
        language_service: &dyn crate::program::model::lang::language_service::LanguageService,
    ) -> Result<
        Box<dyn crate::program::model::lang::language::Language>,
        crate::program::seam_stubs::LanguageNotFoundException,
    > {
        let pair = self
            .language_compiler_spec
            .as_ref()
            .expect("LoadSpec::get_language requires a language/compiler spec");
        language_service.get_language(pair.get_language_id())
    }
}

/// Placeholder for `ghidra.app.util.opinion.ElfProgramBuilder`, referenced by
/// [`ElfLoader::load`](crate::app::util::opinion::elf_loader::ElfLoader::load) before the real
/// class is ported. Java's `loadElf` is the sole static entry point `ElfLoader.load` calls (the
/// rest of the class -- program creation, memory/symbol/relocation processing -- is a large
/// unported subsystem), so it is modeled as a free function rather than a trait, the same way
/// [`option_utils`]/[`query_opinion_service_handler`] stand in for other statics-only Java
/// classes.
pub mod elf_program_builder {
    use super::{MessageLog, Option};
    use crate::format::elf::elf_exception::ElfException;
    use crate::format::seam_stubs::ElfHeader;
    use crate::program::model::listing::Program;
    use crate::util::task::TaskMonitor;

    /// Mirrors the static `ElfProgramBuilder.loadElf(ElfHeader, Program, List<Option>,
    /// MessageLog, TaskMonitor)`. The real method builds an entire `Program` from the parsed ELF
    /// (memory blocks, symbols, relocations, ...); that subsystem is not ported yet, so this
    /// placeholder always panics until it lands.
    pub fn load_elf(
        elf: &dyn ElfHeader,
        program: &mut dyn Program,
        options: &[Box<dyn Option>],
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ElfException> {
        let _ = (elf, program, options, log, monitor);
        unimplemented!("elf_program_builder::load_elf placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.util.bin.RandomAccessByteProvider`, referenced by
/// [`DbgLoader::load`](crate::app::util::opinion::dbg_loader::DbgLoader::load) before the real
/// class is ported. Java's version wraps a `GhidraRandomAccessFile` over an arbitrary local file
/// (opened `"r"`, per the single-`File`-argument constructor `DbgLoader` uses); this stub models
/// exactly that read path over a real [`std::fs::File`] -- unlike the auto-generated stub shape,
/// it is backed by the crate's real
/// [`ByteProvider`](crate::filesystem::ghidra::g_binary_reader::ByteProvider) trait (rather than a
/// disconnected placeholder trait), so it can actually back a `BinaryReader` once one exists over
/// it. `getName`/`getAbsolutePath`/`getInputStream`/`toString`/`setFsrl` are not modeled: nothing
/// in the currently-ported tree reads them.
pub struct RandomAccessByteProvider {
    file: std::fs::File,
    path: std::path::PathBuf,
}

impl RandomAccessByteProvider {
    /// Port of `RandomAccessByteProvider(File)`, which delegates to the `(File, "r")` constructor.
    pub fn new(path: std::path::PathBuf) -> std::io::Result<Self> {
        let file = std::fs::File::open(&path)?;
        Ok(RandomAccessByteProvider { file, path })
    }

    /// Port of `RandomAccessByteProvider.close()`. Rust's `File` has no separate close step (the
    /// descriptor is released when `self` drops), so this only exists so callers can mirror
    /// Java's explicit `try`/`finally` call.
    pub fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for RandomAccessByteProvider {
    fn length(&mut self) -> std::io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        self.length().map(|len| index < len).unwrap_or(false)
    }

    fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
        use std::io::{Read, Seek, SeekFrom};
        self.file.seek(SeekFrom::Start(index))?;
        let mut buf = [0u8; 1];
        self.file.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        self.file.seek(SeekFrom::Start(index))?;
        let mut buf = vec![0u8; length];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_byte(&mut self, index: u64, value: u8) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.file.seek(SeekFrom::Start(index))?;
        self.file.write_all(&[value])
    }

    fn write_bytes(&mut self, index: u64, values: &[u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.file.seek(SeekFrom::Start(index))?;
        self.file.write_all(values)
    }

    fn get_file(&self) -> std::option::Option<std::path::PathBuf> {
        Some(self.path.clone())
    }
}

/// Placeholder for `ghidra.app.util.opinion.AbstractPeDebugLoader`, the (package-private,
/// unported) superclass
/// [`DbgLoader`](crate::app::util::opinion::dbg_loader::DbgLoader) extends. Only `processDebug` is
/// modeled -- the sole inherited method `DbgLoader.load` calls -- as a free function rather than a
/// trait, the same way [`elf_program_builder`] stands in for `ElfProgramBuilder`.
pub mod abstract_pe_debug_loader {
    use super::Option;
    use crate::format::seam_stubs::DebugDirectoryParser;
    use crate::program::model::listing::Program;
    use crate::util::task::TaskMonitor;

    /// Port of `AbstractPeDebugLoader.processDebug(DebugDirectoryParser, NTHeader,
    /// Map<SectionHeader, Address>, Program, List<Option>, TaskMonitor)`.
    ///
    /// Java's caller (`DbgLoader.load`) always builds the `NTHeader`/`sectionToAddress` argument
    /// pair first -- by reopening the parent program's backing file and parsing it as a
    /// `PortableExecutable`, regardless of whether `parser` ends up null -- and only this method
    /// itself short-circuits on a null `parser`. Since that parsing (`PortableExecutable`,
    /// `NTHeader`, `FileHeader`, PE `SectionHeader`, plus the misc/fixup/CodeView/COFF debug-info
    /// application this method performs once a parser is present) is all one large unported
    /// subsystem with no way to produce a real `NTHeader`/`SectionHeader` tree yet, both halves
    /// are bundled here as a single placeholder that panics unconditionally, the same way
    /// [`elf_program_builder::load_elf`] stands in for `ElfProgramBuilder.loadElf` -- `nt_header`
    /// and `section_to_address` are dropped from the signature entirely since nothing can build
    /// them.
    pub fn process_debug(
        parser: std::option::Option<&DebugDirectoryParser>,
        program: &mut dyn Program,
        options: &[Box<dyn Option>],
        monitor: &dyn TaskMonitor,
    ) {
        let _ = (parser, program, options, monitor);
        unimplemented!("abstract_pe_debug_loader::process_debug placeholder not overridden")
    }
}

/// Placeholder for `ghidra.program.util.ExternalSymbolResolver`, referenced by
/// [`ElfLoader::post_load_program_fixups`](crate::app::util::opinion::elf_loader::ElfLoader::post_load_program_fixups)
/// before the real class is ported. Java's version is a concrete `Closeable` class that resolves
/// unresolved external-library symbols against sibling programs found via `ProjectData`; that
/// resolution logic (`ProgramSymbolResolver`) is a large unported subsystem, so only the
/// bookkeeping half -- `addProgramToFixup` collecting the programs to later process, and both
/// `fixUnresolvedExternalSymbols`/`logInfo` correctly no-op-ing when nothing was collected (their
/// real bodies are themselves just a loop over that collection) -- is modeled for real. `close()`
/// (Java's `Closeable.close`, called at the end of the `try`-with-resources block) releases the
/// `Program` consumers this stub never registers, so it is not modeled; a value simply drops.
pub struct ExternalSymbolResolver {
    /// Count of `Loaded` programs handed to
    /// [`add_program_to_fixup`](Self::add_program_to_fixup), standing in for the real class's
    /// internal `programsToFix` list (whose element type wraps a `Program` this stub cannot open
    /// on its own).
    programs_to_fixup: usize,
}

impl ExternalSymbolResolver {
    /// Port of `ExternalSymbolResolver(ProjectData, TaskMonitor)`. The real constructor retains
    /// both parameters for later library lookups; this placeholder does neither, since nothing
    /// here reads them yet.
    pub fn new(
        project_data: StdOption<Box<dyn crate::framework::model::ProjectData>>,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Self {
        let _ = (project_data, monitor);
        ExternalSymbolResolver { programs_to_fixup: 0 }
    }

    /// Port of `ExternalSymbolResolver.addProgramToFixup(Loaded<Program>)`. Only the
    /// `Loaded`-taking overload is modeled; `ElfLoader.postLoadProgramFixups` is the only current
    /// caller and it always has a `Loaded<Program>` in hand, not a bare `Program`.
    pub fn add_program_to_fixup(
        &mut self,
        loaded: &dyn crate::app::util::opinion::loaded::Loaded,
    ) {
        let _ = loaded;
        self.programs_to_fixup += 1;
    }

    /// Port of `ExternalSymbolResolver.hasProblemLibraries()`. Not yet implemented; the real body
    /// reports whether any fixup pass recorded a missing library.
    pub fn has_problem_libraries(&self) -> bool {
        unimplemented!("ExternalSymbolResolver::has_problem_libraries placeholder not overridden")
    }

    /// Port of `ExternalSymbolResolver.fixUnresolvedExternalSymbols()`. The real body is a loop
    /// over every collected program; with none collected there is nothing to resolve, so that
    /// case is modeled exactly, while a non-empty collection still needs the unported
    /// `ProgramSymbolResolver`.
    pub fn fix_unresolved_external_symbols(
        &self,
    ) -> Result<(), crate::util::exception::CancelledException> {
        if self.programs_to_fixup == 0 {
            return Ok(());
        }
        unimplemented!(
            "ExternalSymbolResolver::fix_unresolved_external_symbols placeholder not overridden"
        )
    }

    /// Port of `ExternalSymbolResolver.logInfo(Consumer<String>, boolean)`. Java's `logger` is a
    /// `Consumer<String>`; modeled as `&mut dyn FnMut(&str)` since [`MessageLog::append_msg`]
    /// takes `&str`. The real body is a loop over every collected program, so (matching
    /// [`fix_unresolved_external_symbols`](Self::fix_unresolved_external_symbols)) an empty
    /// collection is modeled exactly as calling `logger` zero times.
    pub fn log_info(&self, logger: &mut dyn FnMut(&str), short_summary: bool) {
        let _ = short_summary;
        if self.programs_to_fixup == 0 {
            return;
        }
        unimplemented!("ExternalSymbolResolver::log_info placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.util.opinion.LoaderMap`, referenced by
/// [`LoadSpecChooser`](crate::app::util::importer::load_spec_chooser::LoadSpecChooser) before the
/// real class is ported. Java's version is a `TreeMap<Loader, Collection<LoadSpec>>` sorted by
/// [`Loader::compare_to`](crate::app::util::opinion::loader::Loader::compare_to); entries here are
/// kept sorted the same way on [`insert`](Self::insert) so
/// [`values`](Self::values) iterates in the same order Java's `TreeMap.values()` would.
pub struct LoaderMap {
    entries: Vec<(Box<dyn crate::app::util::opinion::loader::Loader>, Vec<LoadSpec>)>,
}

impl LoaderMap {
    /// An empty [`LoaderMap`], mirroring `new LoaderMap()`.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Associates `loader` with `load_specs`, mirroring `LoaderMap.put(Loader, Collection<LoadSpec>)`.
    /// Keeps [`entries`](Self::entries) sorted by [`Loader::compare_to`], matching the `TreeMap`
    /// key ordering the Java class inherits.
    pub fn insert(
        &mut self,
        loader: Box<dyn crate::app::util::opinion::loader::Loader>,
        load_specs: Vec<LoadSpec>,
    ) {
        self.entries.push((loader, load_specs));
        self.entries.sort_by(|(a, _), (b, _)| a.compare_to(b.as_ref()));
    }

    /// The `LoadSpec` collections in `Loader` sort order, mirroring `LoaderMap.values()`.
    pub fn values(&self) -> impl Iterator<Item = &Vec<LoadSpec>> {
        self.entries.iter().map(|(_, load_specs)| load_specs)
    }
}

impl Default for LoaderMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder for `ghidra.app.util.Option`, referenced by
/// [`Loader`](crate::app::util::opinion::loader::Loader) before the real class is ported.
/// `Loader` only ever passes lists of this type through as a parameter/return value.
pub trait OptionLike {}

/// Placeholder for `ghidra.app.util.opinion.LoadSpec`, referenced by
/// [`Loader`](crate::app::util::opinion::loader::Loader) before the real class is ported.
/// `Loader` only ever passes this type through as a parameter/return value, so no members are
/// needed yet.
pub trait LoadSpecLike {}

/// Placeholder for `ghidra.app.util.opinion.LoadResults`, referenced by
/// [`Loader`](crate::app::util::opinion::loader::Loader) before the real class is ported. Java's
/// `LoadResults<? extends DomainObject>` wildcard generic is dropped, since this crate has no
/// generic parameter to substitute yet. `Loader` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait LoadResultsLike {}

/// Placeholder for `ghidra.app.util.PseudoInstruction`, referenced by
/// [`PseudoFlowProcessor`](crate::app::util::pseudo_flow_processor::PseudoFlowProcessor) before
/// the real class is ported. `PseudoFlowProcessor` only ever passes this type through as a
/// parameter, so no members are needed yet.
pub trait PseudoInstructionLike {}

/// Placeholder for `ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol`, referenced by
/// [`SleighParserContext`](crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext)
/// before the real class is ported. This is distinct from the identically-named
/// `TripleSymbol` in [`crate::decompiler::slghsymbol::triple_symbol`] (a port of
/// `ghidra.pcodeCPort.slghsymbol.TripleSymbol`, a different Java class) and the symbol structs in
/// [`crate::program::model::lang::sleigh::symbol`] (which model the `.sla` decoder's symbol
/// table, also a different Java class). Only the one method `SleighParserContext::apply_commits`
/// needs -- resolving this symbol's storage location for a pending context commit -- is modeled.
pub trait TripleSymbol: Send + Sync {
    /// Stands in for `TripleSymbol.getFixedHandle(FixedHandle, ParserWalker)`, which resolves
    /// `hand` to this symbol's storage location within the given parse tree walk.
    fn get_fixed_handle(
        &self,
        hand: &mut crate::program::model::lang::sleigh::FixedHandle,
        walker: &mut crate::program::model::lang::sleigh::ParserWalker,
    );
}

/// Placeholder for `ghidra.program.model.lang.RegisterValue`'s `RegisterValue(Register, byte[])`
/// constructor, referenced by
/// [`ContextCache::set_context`](crate::app::plugin::processors::sleigh::context_cache::ContextCache::set_context)
/// before the real `RegisterValue` class is ported. Distinct from
/// [`program::seam_stubs::RegisterValue`](crate::program::seam_stubs::RegisterValue), which
/// models read-only access to an already-built value; `set_context` additionally needs to build
/// one from a base register and raw mask/value bytes, which that trait cannot express. Only this
/// one construction capability is modeled.
pub trait RegisterValueBuilder {
    /// Stands in for `new RegisterValue(register, bytes)`.
    fn build_register_value(
        &self,
        register: crate::program::model::lang::register::RegisterRef,
        bytes: Vec<u8>,
    ) -> Box<dyn crate::program::seam_stubs::RegisterValue>;
}

/// Placeholder for `ghidra.app.plugin.processors.sleigh.ConstructState`, referenced by
/// [`OpTplWalker`](crate::app::plugin::processors::sleigh::op_tpl_walker::OpTplWalker) before the
/// real class is ported. Java's `ConstructState` exposes direct `getConstructor()`/
/// `getSubState(int)`/`getParent()` pointer-style navigation of an already-built parse tree; the
/// crate's existing `program::model::lang::sleigh::walker::ConstructState` models a different
/// traversal shape (a flat `Vec<ConstructState>` arena addressed by index, built for
/// `ParserWalker`) that doesn't support this directly, so this seam models only the three
/// accessors `OpTplWalker` needs, in terms of the already-ported
/// [`Constructor`](crate::program::model::lang::sleigh::constructor::Constructor).
pub trait ConstructState: Send + Sync {
    /// Stands in for `ConstructState.getConstructor()`.
    fn constructor(
        &self,
    ) -> StdOption<std::sync::Arc<crate::program::model::lang::sleigh::constructor::Constructor>>;

    /// Stands in for `ConstructState.getSubState(int)`.
    fn sub_state(&self, index: i32) -> std::sync::Arc<dyn ConstructState>;

    /// Stands in for `ConstructState.getParent()`.
    fn parent(&self) -> StdOption<std::sync::Arc<dyn ConstructState>>;
}

/// Placeholder for `ghidra.app.plugin.languages.sleigh.SleighConstructorTraversal`, referenced by
/// [`SleighLanguages`](crate::app::plugin::languages::sleigh::sleigh_languages::SleighLanguages)
/// before the real class -- which walks every subtable in a `SleighLanguage`'s symbol table,
/// invoking a nested [`SubtableTraversal`] per subtable -- is ported. Models
/// `SleighConstructorTraversal.traverse(ConstructorEntryVisitor)`, the one entry point
/// `SleighLanguages` needs; callers supply an already-scoped traversal rather than this trait's
/// (unported) implementor being built from a concrete `SleighLanguage`, keeping the seam
/// decoupled from any one traversal implementation.
pub trait ConstructorTraversal {
    /// Stands in for `SleighConstructorTraversal.traverse(ConstructorEntryVisitor)`.
    fn traverse(
        &self,
        visitor: &mut dyn crate::app::plugin::languages::sleigh::constructor_entry_visitor::ConstructorEntryVisitor,
    ) -> crate::app::plugin::languages::sleigh::visitor_results::VisitorResult;
}

/// Placeholder for `ghidra.app.plugin.languages.sleigh.SleighSubtableTraversal`, referenced by
/// [`SleighLanguages`](crate::app::plugin::languages::sleigh::sleigh_languages::SleighLanguages)
/// before the real class -- which recursively descends a subtable's decision tree -- is ported.
/// Models `SleighSubtableTraversal.traverse(SubtableEntryVisitor)`, the one entry point
/// `SleighLanguages` needs.
pub trait SubtableTraversal {
    /// Stands in for `SleighSubtableTraversal.traverse(SubtableEntryVisitor)`.
    fn traverse(
        &self,
        visitor: &mut dyn crate::app::plugin::languages::sleigh::subtable_entry_visitor::SubtableEntryVisitor,
    ) -> crate::app::plugin::languages::sleigh::visitor_results::VisitorResult;
}

/// Placeholder for `ghidra.app.plugin.languages.sleigh.SleighPcodeTraversal`, referenced by
/// [`SleighLanguages`](crate::app::plugin::languages::sleigh::sleigh_languages::SleighLanguages)
/// before the real class -- which walks a single constructor's p-code template ops -- is ported.
/// Models `SleighPcodeTraversal.traverse(OnlyPcodeOpEntryVisitor)` with a plain `FnMut` callback
/// in place of Java's package-private `OnlyPcodeOpEntryVisitor` marker interface, since that
/// interface exists solely to type this one callback and has no other purpose worth a seam of
/// its own.
pub trait PcodeTraversal {
    /// Stands in for `SleighPcodeTraversal.traverse(OnlyPcodeOpEntryVisitor)`.
    fn traverse(
        &self,
        visit: &mut dyn FnMut(
            &crate::program::model::lang::sleigh::template::OpTpl,
        ) -> crate::app::plugin::languages::sleigh::visitor_results::VisitorResult,
    ) -> crate::app::plugin::languages::sleigh::visitor_results::VisitorResult;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock`, referenced by
/// [`AssemblyResolvedPatterns`](crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedPatterns)
/// and by [`AssemblySelector`](crate::app::plugin::assembler::AssemblySelector) before the real
/// class is ported. `AssemblySelector` only ever reads the raw instruction bytes (to compare two
/// candidate encodings by length, then lexicographically) and asks for a fully-masked copy of the
/// chosen encoding, so only `getVals()` and `fillMask()` are needed.
pub trait AssemblyPatternBlock {
    /// Mirrors `AssemblyPatternBlock.getVals()`.
    fn get_vals(&self) -> Vec<i8>;

    /// Mirrors `AssemblyPatternBlock.fillMask()`.
    fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock>;
}

/// One record from an [`AssemblyResolutionResults`] set, already discriminated the way
/// `AssemblySelector.filterCompatibleAndSort` discriminates it in Java: via an unchecked cast
/// guarded by `AssemblyResolution.isError()` -- error records are cast to `AssemblyResolvedError`,
/// and every other record encountered there is cast to `AssemblyResolvedPatterns` (backfill
/// records are not expected in a finished `AssemblyResolutionResults`). Modeling the split as an
/// enum lets this stub hand back an already-downcast value instead of requiring an unsafe/`Any`
/// based cast that the real, already-ported `AssemblyResolution` trait does not support.
pub enum AssemblyResolutionEntry {
    Error(Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedError>),
    Patterns(Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedPatterns>),
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults`, referenced
/// by [`AssemblySelector`](crate::app::plugin::assembler::AssemblySelector) (which only ever
/// iterates it, hence [`resolutions`](Self::resolutions)'s already-discriminated
/// [`AssemblyResolutionEntry`] view -- see its docs for why) and by
/// [`AbstractAssemblyTreeResolver`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver)
/// (whose [`parent`](
/// crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver::parent) default
/// method rebuilds a results set from another one's raw entries, including any still-pending
/// backfill records -- which `resolutions()`'s finished-result split doesn't accommodate, hence
/// the separate [`iter_all`](Self::iter_all)/[`add`](Self::add) pair) before the real class is
/// ported. Java's version is a `Set<AssemblyResolution>` decorator with a much larger API
/// (`apply`, `absorb`, `stream`, ...); only the members these two callers actually need are
/// modeled.
pub trait AssemblyResolutionResults {
    /// Mirrors iterating `AssemblyResolutionResults` (a `Set<AssemblyResolution>`), for callers
    /// that only expect finished results (errors and resolved patterns, no pending backfills).
    fn resolutions(&self) -> Vec<AssemblyResolutionEntry>;

    /// Mirrors iterating `AssemblyResolutionResults` as a raw `Set<AssemblyResolution>`, without
    /// the finished-result assumption `resolutions()` makes, so pending backfill records (still
    /// possible mid-resolution) are included too.
    fn iter_all(
        &self,
    ) -> Vec<Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>>;

    /// Mirrors `AssemblyResolutionResults.add(AssemblyResolution)`.
    fn add(&mut self, ar: Box<dyn crate::app::plugin::assembler::sleigh::sem::AssemblyResolution>);
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyContextGraph`, referenced by
/// [`AbstractAssemblyTreeResolver`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver)
/// before the real class is ported. `AbstractAssemblyTreeResolver` only ever stores this type (the
/// constructor-assigned `ctxGraph` field, exposed via its
/// [`ctx_graph`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver::ctx_graph)
/// hook) and passes it to `resolveRootRecursion` -- a required trait method left bodyless for a
/// future port rather than a default here (see that method's docs) -- so no members are needed
/// yet.
pub trait AssemblyContextGraph {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator`,
/// referenced by
/// [`AbstractAssemblyTreeResolver`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver)
/// (whose `getStateGenerator`/`getHiddenStateGenerator` construct and return one) before the real
/// (abstract) class -- itself the other half of the dependency cycle
/// `AbstractAssemblyTreeResolver` was cut to break, since its subclasses each hold a `resolver:
/// AbstractAssemblyTreeResolver` field -- is ported. Both methods only ever return this type
/// opaquely, so no members are needed yet.
pub trait AbstractAssemblyStateGenerator {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.MaskedLong`, referenced by
/// [`AbstractAssemblyResolutionFactory`](
/// crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyResolutionFactory)'s `backfill` and
/// `solveOrBackfill` family before the real class is ported. Java's version is an immutable value
/// type pairing a mask with a value (plus a large arithmetic/bit-manipulation API); only the mask
/// and value fields themselves, and the two static constructors those callers actually use
/// (`fromLong`, `fromMaskAndValue`), are modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskedLong {
    pub mask: i64,
    pub val: i64,
}

impl MaskedLong {
    /// Mirrors `MaskedLong.fromLong(long)`: a fully-defined value (mask of all-ones).
    pub fn from_long(val: i64) -> Self {
        Self { mask: -1, val }
    }

    /// Mirrors `MaskedLong.fromMaskAndValue(long, long)`.
    pub fn from_mask_and_value(mask: i64, val: i64) -> Self {
        Self { mask, val }
    }

    /// Mirrors `MaskedLong.isFullyDefined()`: true iff there are no undefined bits. Added for
    /// [`AbstractBinaryExpressionSolver`](
    /// crate::app::plugin::assembler::sleigh::expr::AbstractBinaryExpressionSolver), which checks
    /// this on each operand before treating it as a known constant.
    pub fn is_fully_defined(&self) -> bool {
        self.mask == -1
    }

    /// Mirrors `MaskedLong.agrees(MaskedLong)`: true iff the two values' defined bit positions
    /// (where both masks have a defined bit) match. Added for
    /// [`AbstractBinaryExpressionSolver`](
    /// crate::app::plugin::assembler::sleigh::expr::AbstractBinaryExpressionSolver)'s constant-vs-goal
    /// check (`ConstantValueSolver.checkConstAgrees`, not yet ported as its own type).
    pub fn agrees(&self, that: MaskedLong) -> bool {
        let both_mask = self.mask & that.mask;
        (self.val & both_mask) == (that.val & both_mask)
    }
}

impl std::fmt::Display for MaskedLong {
    /// A simplified stand-in for `MaskedLong.toString()` (which formats via
    /// `NumericUtilities.convertMaskedValueToHexString`, not modeled on this minimal placeholder):
    /// used only to interpolate a value into error-resolution messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}:{:#x}", self.val, self.mask)
    }
}

/// Placeholder for `ghidra.app.plugin.assembler.AssemblySyntaxException`, thrown by
/// [`AssemblySelector::filter_parse`](crate::app::plugin::assembler::AssemblySelector::filter_parse)'s
/// default implementation before the real class is ported. Extends `std::error::Error` so it can
/// stand in for the Java checked exception as a boxed `Result` error, mirroring
/// [`TraceConflictedMappingException`](crate::trace::model::modules::trace_conflicted_mapping_exception::TraceConflictedMappingException).
pub trait AssemblySyntaxException: std::error::Error {}

/// Minimal constructible implementor of [`AssemblySyntaxException`]. `AssemblySelector::filter_parse`'s
/// default body needs to actually construct one (mirroring `new
/// AssemblySyntaxException(syntaxErrors)`, whose message joins each erroring
/// `AssemblyParseResult`'s display with `\n`, per `StringUtils.join(errors, "\n")`), so this
/// stores just that joined message rather than the original `AssemblyParseResult` set -- the real
/// port's fuller `getErrors()` API is left for its own future port.
#[derive(Debug)]
pub struct AssemblySyntaxError {
    message: String,
}

impl AssemblySyntaxError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl std::fmt::Display for AssemblySyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AssemblySyntaxError {}
impl AssemblySyntaxException for AssemblySyntaxError {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal`, referenced by
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) (which
/// only ever passes this type through as a parameter/return value) and by
/// [`AssemblyExtendedNonTerminal`](
/// crate::app::plugin::assembler::sleigh::symbol::AssemblyExtendedNonTerminal) (a real port, which
/// wraps a value of this type and calls `getName()`/`toString()` on it, mirroring
/// `AssemblyExtendedNonTerminal extends AssemblyNonTerminal`) before the real class is ported. The
/// `Display` bound and `get_name` method stand in for those two calls; `toString()` isn't
/// overridden by `AssemblyNonTerminal` itself, so this stub can't yet reproduce its
/// `"[" + name + "]"` formatting, only expose that a display exists.
pub trait AssemblyNonTerminal: std::fmt::Display {
    /// Get the name of this non-terminal.
    fn get_name(&self) -> String;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction`, referenced by
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) (which
/// only ever passes/returns this type opaquely) and by
/// [`AssemblyParseBranch`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch)
/// (which additionally calls `getRHS()`/`getLHS()` -- inherited from the now-ported
/// [`AbstractAssemblyProduction`](crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction)
/// supertrait, mirroring `AssemblyProduction extends AbstractAssemblyProduction<AssemblyNonTerminal>`
/// -- and its own `isConstructor()`) before the real class is ported. `is_constructor` is modeled
/// as a default method always returning `true`, mirroring the Java class's hardcoded
/// `isConstructor() { return true; }` override.
pub trait AssemblyProduction:
    crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction
{
    /// Mirrors `AssemblyProduction.isConstructor()`, which unconditionally returns `true`.
    fn is_constructor(&self) -> bool {
        true
    }
}

/// Placeholder for `ghidra.app.plugin.processors.sleigh.Constructor`, referenced by
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) (which
/// only ever passes this type through as a parameter) and by
/// [`AbstractAssemblyTreeResolver`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver)
/// (whose [`compute_offset`](
/// crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver::compute_offset)
/// default method walks a constructor's operands to compute an encoded bit offset) before the
/// real class is ported. Distinct from
/// [`crate::program::model::lang::sleigh::constructor::Constructor`] (a port of the unrelated
/// `ghidra.pcodeCPort.slghsymbol.Constructor` backend class).
pub trait Constructor {
    /// Mirrors `Constructor.getOperand(int)`.
    fn operand(&self, index: i32) -> std::sync::Arc<dyn OperandSymbol>;
}

/// Placeholder for `ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol`, referenced by
/// [`AbstractAssemblyTreeResolver`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver)
/// before the real class is ported. Only the three accessors its
/// [`compute_offset`](crate::app::plugin::assembler::sleigh::sem::AbstractAssemblyTreeResolver::compute_offset)
/// default method needs -- to recursively compute an operand's encoded bit offset, following the
/// `offsetBase` chain to a base operand when the offset is relative -- are modeled; the fuller
/// symbol-table surface (`getDefiningSymbol()`, pattern/handle resolution, etc.) is left for that
/// class's own future port.
pub trait OperandSymbol {
    /// Mirrors `OperandSymbol.getOffsetBase()`. `-1` means the offset is absolute (matching
    /// Java's sentinel); any other value is the index, within the same constructor, of the base
    /// operand this one's offset is relative to.
    fn offset_base(&self) -> i32;

    /// Mirrors `OperandSymbol.getRelativeOffset()`.
    fn relative_offset(&self) -> i32;

    /// Mirrors `OperandSymbol.getMinimumLength()`.
    fn minimum_length(&self) -> i32;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic`,
/// referenced by
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) (which
/// only ever passes/returns this type opaquely) and by
/// [`AssemblyParseBranch`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch)
/// (whose `print_indented` default method formats a collection of these via `toString()`, mirroring
/// `AssemblyParseBranch.print`'s `StringUtils.join(sems, ", ")`) before the real class is ported.
/// The `Display` bound stands in for `AssemblyConstructorSemantic.toString()`.
pub trait AssemblyConstructorSemantic: std::fmt::Display {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol`, referenced by
/// [`AssemblyTerminal`](crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal) (as its
/// supertrait, mirroring `AssemblyTerminal extends AssemblySymbol`) before the real class is
/// ported. `AssemblyTerminal`'s own consumers only ever display, compare, and hash a terminal, so
/// this stub exposes just that: a `Display` bound (stands in for the inherited
/// `Object#toString()`, which `AssemblySymbol.toString()` mirrors LAZILY) plus a stable identity
/// tag (stands in for `AssemblySymbol`'s LAZY `equals`/`hashCode`, both defined in terms of
/// `toString()`), mirroring the [`SolverHint::tag`](
/// crate::app::plugin::assembler::sleigh::expr::SolverHint::tag) convention used for the same
/// purpose elsewhere in this crate.
pub trait AssemblySymbol: std::fmt::Display {
    /// A stable identity for this symbol, used for equality and hashing.
    fn terminal_tag(&self) -> &str;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols`, referenced
/// by [`AssemblyTerminal`](crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal) and
/// [`AssemblyNumericTerminal`](crate::app::plugin::assembler::sleigh::symbol::AssemblyNumericTerminal)
/// before the real class is ported. `AssemblyTerminal::match`/`get_suggestions` only ever pass
/// this type through to implementers, but `AssemblyNumericTerminal` actually calls
/// `choose`/`getSuggestions` on it (to resolve program labels/equates for a bare identifier, and
/// to offer label completions), so those two methods are added here -- the minimum this concrete
/// class's real API that `AssemblyNumericTerminal` needs.
pub trait AssemblyNumericSymbols {
    /// Choose the value(s) bound to a label name, optionally scoped to an address space.
    ///
    /// Mirrors `AssemblyNumericSymbols.choose(String, AddressSpace)`. `space` mirrors Java's
    /// nullable `AddressSpace` parameter (`None` means "no space hint", matching Java's `null`).
    fn choose(
        &self,
        name: &str,
        space: StdOption<&crate::program::model::address::AddressSpace>,
    ) -> std::collections::BTreeSet<i64>;

    /// Suggest up to `max` label names having the given prefix, optionally scoped to an address
    /// space.
    ///
    /// Mirrors `AssemblyNumericSymbols.getSuggestions(String, AddressSpace, int)`.
    fn get_suggestions(
        &self,
        got: &str,
        space: StdOption<&crate::program::model::address::AddressSpace>,
        max: usize,
    ) -> Vec<String>;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.grammars.AssemblyExtendedProduction`,
/// referenced by
/// [`AssemblyExtendedGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyExtendedGrammar)
/// before the real class is ported. Distinct from (not a subtype of) the
/// [`AssemblyProduction`] placeholder above: in Java both `AssemblyExtendedProduction` and
/// `AssemblyProduction` are sibling concrete subclasses of `AbstractAssemblyProduction`,
/// parameterized over different non-terminal types, rather than one extending the other.
/// `AssemblyExtendedGrammar` only ever returns this type opaquely, so no members are needed yet.
pub trait AssemblyExtendedProduction {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode`, referenced by
/// [`AssemblyParseBranch`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch)
/// (whose own `substs: List<AssemblyParseTreeNode>` field holds heterogeneous children -- either
/// further branches or the already-ported
/// [`AssemblyParseToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken)/
/// [`AssemblyParseNumericToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseNumericToken))
/// before the real (abstract) class is ported. Only the three members
/// `AssemblyParseBranch.java` itself calls on a child are modeled: `getSym()` (used by
/// `addChild`'s expectation check), `print(PrintStream, String)` (recursed into by
/// `AssemblyParseBranch`'s own override -- renamed `print_indented` per this crate's
/// `display_string`/`print_indented` convention, and taking the grammar explicitly as a parameter
/// since this stub has no `grammar` field of its own to inherit), and `generateString()` (recursed
/// into by `AssemblyParseBranch`'s own override). The inherited `getParent()`/`setParent()`/
/// `getGrammar()`/public `print(PrintStream)` surface is left out for the same reason
/// [`AssemblyParseToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken)'s own
/// doc comment gives: it belongs to this still-unported class's own future port.
pub trait AssemblyParseTreeNode {
    /// Mirrors `AssemblyParseTreeNode.getSym()`.
    fn get_sym(&self) -> std::sync::Arc<dyn AssemblySymbol>;

    /// Mirrors `AssemblyParseTreeNode.print(PrintStream, String)`, returning the formatted text
    /// instead of writing it to a stream.
    fn print_indented(
        &self,
        grammar: &dyn crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar,
        indent: &str,
    ) -> String;

    /// Mirrors `AssemblyParseTreeNode.generateString()`.
    fn generate_string(&self) -> String;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.match.BinaryExpressionMatcher` (and
/// its nested `Commutative` variant), referenced by
/// [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s binary-form
/// factory methods (`and`/`div`/`shl`/`mul`/`or`/`plus`/`shr`/`sub`/`xor`) before the real class is
/// ported. `Context` only ever returns this type as an opaque
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher),
/// so no members beyond that are needed yet.
pub trait BinaryExpressionMatcher:
    crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher
{
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.match.ConstantValueMatcher`,
/// referenced by [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s
/// `cv` factory method before the real class is ported. `Context` only ever returns this type as
/// an opaque
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher),
/// so no members beyond that are needed yet.
pub trait ConstantValueMatcher:
    crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher
{
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.match.AnyMatcher`, referenced by
/// [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s `var`/`var_of`
/// factory methods before the real class is ported. `Context` only ever returns this type as an
/// opaque
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher),
/// so no members beyond that are needed yet.
pub trait AnyMatcher: crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.match.OperandValueMatcher`,
/// referenced by [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s
/// `opnd` factory method before the real class is ported. `Context` only ever returns this type
/// as an opaque
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher),
/// so no members beyond that are needed yet.
pub trait OperandValueMatcher:
    crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher
{
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.match.FieldSizeMatcher`, referenced
/// by [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s `fld_sz`
/// factory method before the real class is ported. `Context` only ever returns this type as an
/// opaque
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher),
/// so no members beyond that are needed yet.
pub trait FieldSizeMatcher:
    crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher
{
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.match.UnaryExpressionMatcher`,
/// referenced by [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s
/// `neg`/`not` factory methods before the real class is ported. `Context` only ever returns this
/// type as an opaque
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher),
/// so no members beyond that are needed yet.
pub trait UnaryExpressionMatcher:
    crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher
{
}

/// Shared placeholder implementor for the six matcher-construction stubs above.
/// [`Context`](crate::app::plugin::assembler::sleigh::expr::r#match::Context)'s factory methods
/// each need *some* concrete value to hand back as an
/// [`ExpressionMatcher`](crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher);
/// none of the six real sibling classes above are ported yet, so every factory method returns one
/// of these -- it never matches anything, standing in until each sibling class gets its own real
/// port.
#[derive(Debug)]
pub struct UnimplementedExpressionMatcher;

impl crate::app::plugin::assembler::sleigh::expr::r#match::ExpressionMatcher
    for UnimplementedExpressionMatcher
{
    fn match_into(
        &self,
        _expression: &crate::program::model::lang::sleigh::expression::PatternExpression,
        _result: &mut crate::app::plugin::assembler::sleigh::expr::r#match::MatchResult,
    ) -> bool {
        false
    }
}

impl BinaryExpressionMatcher for UnimplementedExpressionMatcher {}
impl ConstantValueMatcher for UnimplementedExpressionMatcher {}
impl AnyMatcher for UnimplementedExpressionMatcher {}
impl OperandValueMatcher for UnimplementedExpressionMatcher {}
impl FieldSizeMatcher for UnimplementedExpressionMatcher {}
impl UnaryExpressionMatcher for UnimplementedExpressionMatcher {}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.SleighAssembler`, referenced by
/// [`SleighAssemblerBuilder`](crate::app::plugin::assembler::sleigh::sleigh_assembler_builder::SleighAssemblerBuilder)
/// before the real class is ported. Mirrors `SleighAssembler extends
/// AbstractSleighAssembler<AssemblyResolvedPatterns> implements Assembler`;
/// `SleighAssemblerBuilder` only ever returns this type opaquely (its own covariant narrowing of
/// `AssemblerBuilder::get_assembler`/`get_assembler_with_program`), so no members beyond the
/// `Assembler` supertrait are needed yet.
pub trait SleighAssembler: crate::app::plugin::assembler::Assembler {}

/// Placeholder for `ghidra.debug.api.action.AutoReadMemorySpec`, referenced by
/// [`DebuggerListingService`](crate::app::services::DebuggerListingService) before the real class
/// is ported. `DebuggerListingService` only ever returns this type opaquely, so no members are
/// needed yet.
pub trait AutoReadMemorySpec {}

/// Placeholder for `docking.widgets.fieldpanel.support.BackgroundColorModel`, the parent interface
/// for `ListingBackgroundColorModel`. Referenced by `ListingBackgroundColorModel` and its
/// implementations. BackgroundColorModel has 11 concrete implementations in Ghidra, so this is
/// genuinely polymorphic. Replace with the real port when available.
pub trait BackgroundColorModel: Send + Sync {
    // (no public methods parsed from the Java source)
}

/// Placeholder for `ghidra.debug.api.listing.MultiBlendedListingBackgroundColorModel`, referenced
/// by [`DebuggerListingService`](crate::app::services::DebuggerListingService) before the real
/// class is ported. `DebuggerListingService` only ever returns this type, so no members are
/// needed yet.
pub trait MultiBlendedListingBackgroundColorModel {}

/// Placeholder for `ghidra.app.services.CodeViewerService`, the base interface extended by
/// [`DebuggerListingService`](crate::app::services::DebuggerListingService) before the real
/// interface is ported. `DebuggerListingService` does not itself call any `CodeViewerService`
/// members, so no members are needed yet.
pub trait CodeViewerService {}

/// Placeholder for `ghidra.app.util.viewer.listingpanel.ListingPanel`, referenced by
/// [`DebuggerListingService`](crate::app::services::DebuggerListingService) before the real class
/// is ported. `DebuggerListingService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait ListingPanel {}

/// Placeholder for `ghidra.program.util.ProgramSelection`, referenced by
/// [`DebuggerListingService`](crate::app::services::DebuggerListingService) and by
/// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) before the real class
/// is ported. Both only ever pass this type through as a parameter (`DecompilePlugin` additionally
/// holds one across threads, hence `Send + Sync`), so no members are needed yet.
///
/// Grown for [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin),
/// which branches on `selection.isEmpty()` in every one of its disassemble callbacks. Java's
/// `ProgramSelection` is an `AddressSetView`, and this placeholder carries no addresses at all, so
/// the default answer is "empty".
pub trait ProgramSelection: Send + Sync {
    /// Whether this selection covers no addresses, mirroring `AddressSetView.isEmpty()`.
    fn is_empty(&self) -> bool {
        true
    }
}

/// The mode of the Go-to dialog's Sleigh expressions.
///
/// Placeholder for `ghidra.pcode.exec.SleighUtils.LitIdMode`, referenced by
/// [`DebuggerListingService`](crate::app::services::DebuggerListingService) before the real
/// `SleighUtils` class is ported. Mirrors the enum's three variants; the associated display
/// name/radix/`preferId` fields aren't needed by `DebuggerListingService`, so are left for that
/// class's own future port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LitIdMode {
    Normal,
    Hex,
    IdHex,
}

/// Placeholder for `ghidra.app.emulator.FilteredMemoryState`, referenced by
/// [`Emulator::get_filtered_mem_state`](crate::app::emulator::Emulator::get_filtered_mem_state)
/// before the real class is ported. Mirrors `FilteredMemoryState extends DefaultMemoryState`
/// (itself `implements MemoryState` via the already-ported `AbstractMemoryState`); `Emulator` only
/// ever returns this type opaquely, so no members beyond the supertrait are needed yet.
pub trait FilteredMemoryState: crate::pcode::memstate::memory_state::MemoryState {}

/// Placeholder for `ghidra.app.emulator.MemoryAccessFilter`, referenced by
/// [`Emulator::add_memory_access_filter`](crate::app::emulator::Emulator::add_memory_access_filter)
/// before the real class is ported. `Emulator` only ever passes this type through as a parameter,
/// so no members are needed yet.
pub trait MemoryAccessFilter {}

/// Placeholder for `ghidra.app.services.ClipboardContentProviderService`, referenced by
/// [`ClipboardService`](crate::app::services::ClipboardService) before the real class is ported.
/// `ClipboardService` only ever passes this type through as a parameter, so no members are needed
/// yet.
pub trait ClipboardContentProviderService {}

/// Placeholder for `ghidra.app.context.ListingActionContext`, referenced by
/// [`DataService`](crate::app::services::DataService) before the real class is ported.
/// `DataService` only ever passes this type through as a parameter, so no members are needed yet.
///
/// Grown for [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin),
/// whose action callbacks read the program, location, selection, navigatable and component
/// provider off the context. Java inherits all five from `ProgramActionContext` /
/// `NavigatableActionContext` / `ActionContext`, where the program and navigatable are non-null;
/// here every member is defaulted and inert (`None`) so the opaque placeholder above keeps
/// compiling, and `DisassemblerPlugin` treats a context that yields nothing as nothing to do.
pub trait ListingActionContext {
    /// The program the action was invoked against, mirroring `ProgramActionContext.getProgram()`.
    fn get_program(&self) -> StdOption<Arc<dyn Program>> {
        None
    }

    /// The cursor location, mirroring `NavigatableActionContext.getLocation()`.
    fn get_location(&self) -> StdOption<Arc<dyn ProgramLocation + Send + Sync>> {
        None
    }

    /// The current selection, mirroring `NavigatableActionContext.getSelection()`. Java's version
    /// returns an empty selection rather than null in practice, but callers null-check it anyway.
    fn get_selection(&self) -> StdOption<Arc<dyn ProgramSelection>> {
        None
    }

    /// The navigatable the action was invoked from, mirroring
    /// `NavigatableActionContext.getNavigatable()`.
    fn get_navigatable(&self) -> StdOption<Arc<dyn Navigatable + Send + Sync>> {
        None
    }

    /// The component provider the action was invoked from, mirroring
    /// `ActionContext.getComponentProvider()`. Type-erased because `ComponentProvider` is not
    /// ported (only an empty marker exists in [`docking::seam_stubs`](crate::docking::seam_stubs)).
    fn get_component_provider(&self) -> StdOption<Arc<dyn Any + Send + Sync>> {
        None
    }
}

/// Placeholder for `ghidra.app.context.ListingContextAction`, the common base of all sixteen
/// actions [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin)
/// installs (`DisassembleAction`, `ArmDisassembleAction`, `SetFlowOverrideAction`, ...), none of
/// which is ported. Java declares those fields as `DockingAction`, a supertype of
/// `ListingContextAction`; this is typed at the tighter shared base because that is where the
/// members below live.
///
/// Each of those actions is constructed with a back-reference to the plugin (`new
/// DisassembleAction(this, GROUP_NAME)`), which is the dependency cycle this stub breaks: the
/// plugin is handed its already-built actions rather than building them.
pub trait ListingContextAction: Send + Sync {
    /// Mirrors `ListingContextAction.actionPerformed(ListingActionContext)`.
    fn action_performed(&self, context: &dyn ListingActionContext);

    /// Mirrors `ListingContextAction.isEnabledForContext(ListingActionContext)`.
    fn is_enabled_for_context(&self, context: &dyn ListingActionContext) -> bool;

    /// Re-erases this action so it can be handed to
    /// [`PluginTool::add_action`](crate::framework::seam_stubs::PluginTool::add_action), which
    /// takes the type-erased handle `crate::framework` uses for unported `crate::app` types (the
    /// same arrangement [`DecompilerProvider::as_any_arc`] uses).
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

/// Placeholder for `ghidra.app.cmd.disassemble.DisassembleCommand`, referenced by
/// [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin) before the
/// real class is ported. The plugin's five architecture-specific commands
/// (`ArmDisassembleCommand`, `Hcs12DisassembleCommand`, `MipsDisassembleCommand`,
/// `PowerPCDisassembleCommand`, `X86_64DisassembleCommand`) all extend `DisassembleCommand`, and
/// the plugin only ever touches the base surface, so one stub covers all six.
pub trait DisassembleCommand: Send + Sync {
    /// Mirrors `DisassembleCommand.enableCodeAnalysis(boolean)`.
    fn enable_code_analysis(&self, enable: bool);

    /// Re-erases this command so it can be handed to
    /// [`PluginTool::execute_background_command`](crate::framework::seam_stubs::PluginTool::execute_background_command);
    /// see [`ListingContextAction::as_any_arc`].
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

/// Placeholder for `ghidra.app.plugin.core.disassembler.ProcessorStateDialog`, referenced by
/// [`DisassemblerPlugin`](crate::app::plugin::core::disassembler::DisassemblerPlugin)'s
/// `setDefaultContext` before the real class is ported.
pub trait ProcessorStateDialog: Send + Sync {
    /// Mirrors `ProcessorStateDialog.okCallback()`.
    fn ok_callback(&self);

    /// Re-erases this dialog so it can be handed to
    /// [`PluginTool::show_dialog`](crate::framework::seam_stubs::PluginTool::show_dialog); see
    /// [`ListingContextAction::as_any_arc`].
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

/// Placeholder for `ghidra.app.services.DataTypeReference`, referenced by
/// [`DataTypeReferenceFinder`](crate::app::services::DataTypeReferenceFinder) before the real
/// class is ported. Java's version is a concrete container class (not an interface), so this is
/// a plain struct rather than a `dyn`-dispatched trait. `DataTypeReferenceFinder` only ever
/// delivers this type through its callback opaquely, so no fields are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataTypeReference;

/// Placeholder for `ghidra.app.services.FieldMatcher`, referenced by
/// [`DataTypeReferenceFinder`](crate::app::services::DataTypeReferenceFinder) before the real
/// class is ported. Java's version is a concrete class (not an interface), so this is a plain
/// struct rather than a `dyn`-dispatched trait. Only `field_name` and
/// [`is_ignored`](Self::is_ignored) are modeled -- the two members
/// `DataTypeReferenceFinder`'s callers need to build/inspect an 'empty' (match-everything)
/// matcher -- leaving the fuller offset-matching API (`FieldMatcher(DataType, int)`, `matches`,
/// `getDisplayText`, ...) for that class's own future port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldMatcher {
    pub field_name: StdOption<String>,
}

impl FieldMatcher {
    /// Mirrors `FieldMatcher.isIgnored()`: true if no specific field has been specified, so an
    /// empty matcher signals "match all fields".
    pub fn is_ignored(&self) -> bool {
        self.field_name.is_none()
    }
}

/// Placeholder for Java's `Class<?>`, referenced by
/// [`FieldMouseHandler`] before the real class is ported. Used as a type token to represent
/// supported program location types. No members are needed yet.
pub trait Class: Send + Sync {}

/// Placeholder for `ghidra.app.util.viewer.field.FieldMouseHandler`, referenced by
/// [`FieldMouseHandlerService`](crate::app::services::FieldMouseHandlerService) before the real
/// class is ported. This is a genuine open extension point with multiple implementations.
pub trait FieldMouseHandler: Send + Sync {
    /// Called when a field has been clicked. The object being passed in is guaranteed to be
    /// one of the types returned in [`get_supported_program_locations`](Self::get_supported_program_locations).
    fn field_element_clicked(
        &self,
        clicked_object: &dyn std::any::Any,
        source_navigatable: &dyn Navigatable,
        program_location: &dyn crate::program::util::program_location::ProgramLocation,
        mouse_event: &dyn crate::docking::seam_stubs::MouseEvent,
        service_provider: &dyn crate::framework::plugintool::service_provider::ServiceProvider,
    ) -> bool;

    /// Returns the types that this handler wishes to handle.
    fn get_supported_program_locations(&self) -> Vec<Box<dyn Class>>;
}

/// Placeholder for `ghidra.app.services.StringValidatorQuery`, referenced by
/// [`StringValidatorService`](crate::app::services::StringValidatorService) before the real class
/// is ported. Java's version is a record with a `stringValue()` accessor. Only that method is
/// modeled; any other members are left for that class's own future port.
pub trait StringValidatorQuery {
    /// Returns the string value to validate.
    fn string_value(&self) -> &str;
}

/// Placeholder for `docking.widgets.fieldpanel.Layout`, referenced by
/// [`ListingModel`](crate::app::util::viewer::listingpanel::listing_model::ListingModel) before
/// the real class is ported. `ListingModel` only ever returns this type opaquely from
/// `get_layout`, so no members are needed yet.
pub trait Layout: Send + Sync {}

/// Placeholder for `docking.widgets.fieldpanel.support.Highlight`, referenced by
/// [`ListingHighlightProvider`](crate::app::util::listing_highlight_provider::ListingHighlightProvider)
/// before the real class is ported. Models the minimal interface needed: color and span information.
pub trait Highlight: Send + Sync {
    /// Returns the starting position of this highlight in the text.
    fn get_start(&self) -> i32;

    /// Returns the ending position of this highlight in the text.
    fn get_end(&self) -> i32;

    /// Returns the length of this highlight.
    fn length(&self) -> i32;

    /// Returns the color for this highlight.
    fn get_color(&self) -> Box<dyn Color>;

    /// Sets the offset for this highlight.
    fn set_offset(&self, new_offset: i32);

    /// Returns a string representation of this highlight.
    fn to_string(&self) -> String;
}

/// Placeholder for `java.awt.Color`, referenced by [`Highlight`] before the real class is
/// ported. `Highlight` only ever returns this type opaquely, so minimal interface is needed.
pub trait Color: Send + Sync {}

/// Placeholder for `ghidra.framework.plugintool.PluginTool`, referenced by
/// [`StringValidatorService`](crate::app::services::StringValidatorService) before the real class
/// is ported. `StringValidatorService` only uses `get_services()` to look up all registered
/// services, so only that method is modeled; the full tool interface is left for its own future
/// port.
pub trait PluginTool: Send + Sync {
    /// Returns all services of the given type that are currently registered with this tool.
    fn get_services(&self, service_type: &dyn Class) -> Vec<Box<dyn std::any::Any>>;
}

/// Placeholder for `docking.widgets.fieldpanel.field.Field`, referenced by
/// [`ListingField`](crate::app::util::viewer::field::listing_field::ListingField) before the real
/// class is ported. This is a genuine open extension point with multiple implementations.
pub trait Field: Send + Sync {
    fn get_width(&self) -> i32;
    fn get_preferred_width(&self) -> i32;
    fn get_height(&self) -> i32;
    fn get_height_above(&self) -> i32;
    fn get_height_below(&self) -> i32;
    fn get_start_x(&self) -> i32;
    fn paint(&self, c: &dyn std::any::Any, g: &dyn std::any::Any, context: &dyn std::any::Any, clip: &dyn std::any::Any, color_manager: &dyn std::any::Any, cursor_loc: &dyn std::any::Any, row_height: i32);
    fn contains(&self, x: i32, y: i32) -> bool;
    fn get_num_data_rows(&self) -> i32;
    fn get_num_rows(&self) -> i32;
    fn get_num_cols(&self, row: i32) -> i32;
    fn get_x(&self, row: i32, col: i32) -> i32;
    fn get_y(&self, row: i32) -> i32;
    fn get_row(&self, y: i32) -> i32;
    fn get_col(&self, row: i32, x: i32) -> i32;
    fn is_valid(&self, row: i32, col: i32) -> bool;
    fn get_cursor_bounds(&self, row: i32, col: i32) -> Box<dyn std::any::Any>;
    fn get_scrollable_unit_increment(&self, top_of_screen: i32, direction: i32, max: i32) -> i32;
    fn is_primary(&self) -> bool;
    fn row_height_changed(&self, height_above: i32, height_below: i32);
    fn get_text(&self) -> String;
    fn get_text_with_line_separators(&self) -> String;
    fn text_offset_to_screen_location(&self, text_offset: i32) -> Box<dyn std::any::Any>;
    fn screen_location_to_text_offset(&self, row: i32, col: i32) -> i32;
}

/// Placeholder for `docking.widgets.fieldpanel.support.FieldLocation`, referenced by
/// [`ListingField`](crate::app::util::viewer::field::listing_field::ListingField) before the real
/// class is ported.
pub trait FieldLocation: Send + Sync {
    fn get_index(&self) -> Box<dyn std::any::Any>;
    fn get_field_num(&self) -> i32;
    fn get_row(&self) -> i32;
    fn get_col(&self) -> i32;
    fn equals(&self, obj: &dyn std::any::Any) -> bool;
    fn compare_to(&self, o: &dyn FieldLocation) -> i32;
    fn hash_code(&self) -> i32;
    fn to_string(&self) -> String;
    fn get_element(&self, name: &str) -> Box<dyn std::any::Any>;
    fn set(&self, loc: &dyn FieldLocation);
    fn set_index(&self, index: &dyn std::any::Any);
}

/// Placeholder for `ghidra.app.util.viewer.field.FieldFactory`, referenced by
/// [`ListingField`](crate::app::util::viewer::field::listing_field::ListingField) before the real
/// class is ported. This is a genuine open extension point with multiple implementations.
pub trait FieldFactory: Send + Sync {
    fn services_changed(&self);
    fn new_instance(&self, format_model: &dyn std::any::Any, highlight_provider: &dyn std::any::Any, options: &dyn std::any::Any, field_options: &dyn std::any::Any) -> Box<dyn FieldFactory>;
    fn display_options_changed(&self, options: &dyn std::any::Any, option_name: &str, old_value: &dyn std::any::Any, new_value: &dyn std::any::Any);
    fn field_options_changed(&self, options: &dyn std::any::Any, option_name: &str, old_value: &dyn std::any::Any, new_value: &dyn std::any::Any);
    fn get_field_name(&self) -> String;
    fn get_start_x(&self) -> i32;
    fn set_start_x(&self, x: i32);
    fn get_width(&self) -> i32;
    fn set_width(&self, w: i32);
    fn get_field_model(&self) -> Box<dyn std::any::Any>;
    fn is_enabled(&self) -> bool;
    fn set_enabled(&self, state: bool);
    fn supports_location(&self, listing_field: &dyn std::any::Any, location: &dyn std::any::Any) -> bool;
    fn get_field(&self, obj: &dyn ProxyObj, var_width: i32) -> Box<dyn std::any::Any>;
    fn get_field_location(&self, bf: &dyn std::any::Any, index: &dyn std::any::Any, field_num: i32, loc: &dyn std::any::Any) -> Box<dyn FieldLocation>;
    fn get_program_location(&self, row: i32, col: i32, bf: &dyn std::any::Any) -> Box<dyn std::any::Any>;
    fn accepts_type(&self, category: i32, proxy_object_class: &dyn Class) -> bool;
    fn get_field_text(&self) -> String;
    fn get_metrics(&self) -> Box<dyn std::any::Any>;
}

/// Placeholder for `ghidra.app.util.viewer.proxy.ProxyObj`, referenced by
/// [`ListingField`](crate::app::util::viewer::field::listing_field::ListingField) before the real
/// class is ported.
pub trait ProxyObj: Send + Sync {
    fn get_listing_layout_model(&self) -> Box<dyn crate::app::util::viewer::listingpanel::listing_model::ListingModel>;
    fn get_object(&self) -> Box<dyn std::any::Any>;
    fn contains(&self, a: &dyn std::any::Any) -> bool;
}

/// Placeholder for `ghidra.app.decompiler.ClangFunction`, referenced by
/// [`ClangTokenGroup::get_clang_function`](crate::app::decompiler::clang_token_group::ClangTokenGroup)
/// before the real class is ported. Both only ever pass this type through as a return value, so
/// no members are needed yet.
pub trait ClangFunction: Send + Sync {}

/// Placeholder for `ghidra.app.decompiler.component.DecompilerUtils`, referenced by
/// [`PrettyPrinter`](crate::app::decompiler::pretty_printer::PrettyPrinter) before the real class
/// is ported. Only `toLines` -- which `PrettyPrinter`'s constructor calls to derive its `lines`
/// field from a decoded [`ClangTokenGroup`](crate::app::decompiler::clang_token_group::ClangTokenGroup)
/// -- is modeled; `DecompilerUtils`'s much larger action-context/data-type-tracing/selection
/// surface belongs to that class's own future port.
///
/// The real `toLines` splits its input into multiple `ClangLine`s at `ClangBreak` boundaries and
/// merges runs of `ClangCommentToken`s -- neither of which exists as a distinguishable Rust type
/// yet ([`ClangTokenBase::build_token`](crate::app::decompiler::ClangTokenBase::build_token)
/// builds every leaf as a plain [`ClangTokenBase`], since `ClangToken`'s eleven subclasses are
/// unported). This stub can therefore only flatten the group into one [`ClangLine`] at indent 0;
/// replace with a faithful multi-line split once those subclasses (in particular `ClangBreak`)
/// are ported.
pub struct DecompilerUtils;

impl DecompilerUtils {
    /// Stands in for `DecompilerUtils.toLines(ClangTokenGroup)`. See the struct docs for why this
    /// always returns at most one line.
    pub fn to_lines(group: &ClangTokenGroup) -> Vec<ClangLine> {
        let mut nodes = Vec::new();
        group.flatten(&mut nodes);
        if nodes.is_empty() {
            return Vec::new();
        }
        let mut line = ClangLine::new(0, 0);
        for node in nodes {
            line.add_token(Box::new(ClangTokenBase::with_text(None, node.to_string())));
        }
        vec![line]
    }

    /// Stands in for `DecompilerUtils.getFunction(Program, ClangFuncNameToken)`, called by
    /// [`DecompilerActionContext::get_function_for_location`](crate::app::plugin::core::decompile::decompiler_action_context::DecompilerActionContext::get_function_for_location).
    /// Java dispatches on the `ClangFuncNameToken` subclass via its static type; `ClangToken`'s
    /// subclasses aren't ported (see the module docs), so callers instead check
    /// [`ClangToken::kind`](crate::app::decompiler::ClangToken::kind) `==`
    /// [`ClangTokenKind::FuncName`](crate::app::decompiler::ClangTokenKind::FuncName) themselves
    /// and pass the token through as a plain `&dyn ClangToken`. The real body resolves the
    /// function at the token's underlying `Varnode`/high-symbol address; not yet implemented.
    pub fn get_function(
        program: &dyn Program,
        token: &dyn crate::app::decompiler::ClangToken,
    ) -> StdOption<Arc<dyn crate::program::model::listing::Function>> {
        let _ = (program, token);
        unimplemented!("DecompilerUtils::get_function placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.decompiler.signature.BlockSignature`, referenced by
/// [`decode_signatures`](crate::app::decompiler::signature::decode_signatures) before the real
/// class is ported. `decode_signatures` only needs to construct an instance and drive it through
/// the [`DebugSignature`](crate::app::decompiler::signature::DebugSignature) trait, so `decode`/
/// `print_raw` are left as no-ops here; the real port will fill in `BlockSignature`'s `blockSeq`/
/// `index`/`opSeq`/`opcode`/`previousOpSeq`/`previousOpcode` fields and their stream format.
pub struct BlockSignature {
    base: crate::app::decompiler::signature::DebugSignatureBase,
}

impl BlockSignature {
    pub fn new() -> Self {
        Self { base: crate::app::decompiler::signature::DebugSignatureBase::new() }
    }
}

impl Default for BlockSignature {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::app::decompiler::signature::DebugSignature for BlockSignature {
    fn decode(
        &mut self,
        _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
    ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
        Ok(())
    }

    fn print_raw(&self, _language: &dyn crate::program::model::lang::language::Language, buf: &mut String) {
        buf.push_str(&format!("{:x}", self.base.hash));
    }
}

/// Placeholder for `ghidra.app.decompiler.signature.CopySignature`, referenced by
/// [`decode_signatures`](crate::app::decompiler::signature::decode_signatures) before the real
/// class is ported. See [`BlockSignature`]'s doc comment for the shape of this placeholder; the
/// real port will fill in `CopySignature`'s `index` field and its stream format.
pub struct CopySignature {
    base: crate::app::decompiler::signature::DebugSignatureBase,
}

impl CopySignature {
    pub fn new() -> Self {
        Self { base: crate::app::decompiler::signature::DebugSignatureBase::new() }
    }
}

impl Default for CopySignature {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::app::decompiler::signature::DebugSignature for CopySignature {
    fn decode(
        &mut self,
        _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
    ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
        Ok(())
    }

    fn print_raw(&self, _language: &dyn crate::program::model::lang::language::Language, buf: &mut String) {
        buf.push_str(&format!("{:x}", self.base.hash));
    }
}

/// Placeholder for `ghidra.app.decompiler.signature.VarnodeSignature`, referenced by
/// [`decode_signatures`](crate::app::decompiler::signature::decode_signatures) before the real
/// class is ported. See [`BlockSignature`]'s doc comment for the shape of this placeholder; the
/// real port will fill in `VarnodeSignature`'s `vn`/`seqNum`/`opcode` fields and its stream
/// format.
pub struct VarnodeSignature {
    base: crate::app::decompiler::signature::DebugSignatureBase,
}

impl VarnodeSignature {
    pub fn new() -> Self {
        Self { base: crate::app::decompiler::signature::DebugSignatureBase::new() }
    }
}

impl Default for VarnodeSignature {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::app::decompiler::signature::DebugSignature for VarnodeSignature {
    fn decode(
        &mut self,
        _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
    ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
        Ok(())
    }

    fn print_raw(&self, _language: &dyn crate::program::model::lang::language::Language, buf: &mut String) {
        buf.push_str(&format!("{:x}", self.base.hash));
    }
}

/// Placeholder for `ghidra.app.decompiler.CTokenHighlightMatcher`, referenced by
/// [`DecompilerHighlightService`](crate::app::decompiler::DecompilerHighlightService). This
/// trait matches tokens and provides highlighting information for the decompiler.
pub trait CTokenHighlightMatcher: Send + Sync {
    /// Start matching tokens at the given root node.
    fn start(&self, root: &dyn ClangNode);

    /// End the matching session.
    fn end(&self);

    /// Get the highlight color for a token.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to get highlighting for.
    ///
    /// # Returns
    ///
    /// A boxed trait object representing the color for this token.
    fn get_token_highlight(&self, token: &dyn ClangNode) -> Box<dyn Color>;
}

/// Placeholder trait for `ghidra.app.decompiler.DecompileResults`, referenced by
/// [`DecompilerLocation`](crate::app::decompiler::DecompilerLocation). This represents
/// the decompilation results (C-AST, DFG, and CFG). The real class is not yet ported.
pub trait DecompileResults: Send + Sync {
    /// Returns whether decompilation has completed.
    fn decompile_completed(&self) -> bool;

    /// Returns the function that was decompiled.
    fn get_function(&self) -> Box<dyn crate::program::model::listing::function::Function>;

    /// Returns whether the decompilation timed out.
    fn is_timed_out(&self) -> bool;

    /// Returns whether the decompilation was cancelled.
    fn is_cancelled(&self) -> bool;

    /// Returns whether the decompilation failed to start.
    fn failed_to_start(&self) -> bool;

    /// Returns whether the decompilation results are valid.
    fn is_valid(&self) -> bool;

    /// Returns the error message if decompilation failed.
    fn get_error_message(&self) -> String;

    /// Returns the high-level function representation.
    fn get_high_function(&self) -> Box<dyn HighFunction>;

    /// Returns the high-level parameter ID information.
    fn get_high_param_id(&self) -> Box<dyn HighParamID>;

    /// Returns the C code token markup.
    fn get_c_code_markup(&self) -> ClangTokenGroup;

    /// Returns the decompiled function representation.
    fn get_decompiled_function(&self) -> DecompiledFunction;
}

/// Placeholder trait for `ghidra.app.decompiler.HighFunction`.
pub trait HighFunction: Send + Sync {}

/// Placeholder trait for `ghidra.app.decompiler.HighParamID`.
pub trait HighParamID: Send + Sync {}

/// Placeholder trait for `ghidra.app.decompiler.component.DecompilerPanel`, referenced by
/// [`DecompilerActionContext`](crate::app::plugin::core::decompile::decompiler_action_context::DecompilerActionContext)
/// (whose `getTokenAtCursor()` mirrors `DecompilerPanel.getTokenAtCursor()`) before the real
/// class is ported. Defaults to panicking so the existing zero-method implementor
/// ([`DecompilerMarginService`](crate::app::decompiler::decompiler_margin_service)'s test double)
/// keeps compiling unchanged.
pub trait DecompilerPanel: Send + Sync {
    /// Stands in for `DecompilerPanel.getTokenAtCursor()`, which returns `null` when the cursor
    /// isn't over a token.
    fn get_token_at_cursor(&self) -> StdOption<Box<dyn crate::app::decompiler::ClangToken>> {
        unimplemented!("DecompilerPanel::get_token_at_cursor placeholder not overridden")
    }

    /// Stands in for `DecompilerPanel.addHoverService(DecompilerHoverService)`, called by
    /// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) when the tool
    /// gains a hover service. The service arrives type-erased because that is how this crate's
    /// [`ServiceListener`](crate::framework::plugintool::util::ServiceListener) seam delivers it
    /// (a `TypeId` plus an `Arc<dyn Any>`); the real port will take a
    /// [`DecompilerHoverService`](crate::app::decompiler::component::hover::DecompilerHoverService)
    /// once services can be handed out typed.
    fn add_hover_service(&self, _hover_service: Arc<dyn std::any::Any + Send + Sync>) {}

    /// Stands in for `DecompilerPanel.removeHoverService(DecompilerHoverService)`; see
    /// [`add_hover_service`](Self::add_hover_service) for why the service is type-erased.
    fn remove_hover_service(&self, _hover_service: Arc<dyn std::any::Any + Send + Sync>) {}
}

/// Placeholder trait for `ghidra.app.decompiler.component.DecompilerController`, referenced by
/// [`DecompilerActionContext`](crate::app::plugin::core::decompile::decompiler_action_context::DecompilerActionContext)
/// before the real class is ported. Only the four members that class calls are modeled; the
/// controller's much larger decompile-lifecycle/location surface belongs to its own future port.
pub trait DecompilerController: Send + Sync {
    /// Stands in for `DecompilerController.getFunction()`, which returns `null` before a
    /// decompile has produced results.
    fn get_function(&self) -> StdOption<Arc<dyn crate::program::model::listing::Function>>;

    /// Stands in for `DecompilerController.getHighFunction()`, which returns `null` before a
    /// decompile has produced results.
    fn get_high_function(&self) -> StdOption<Arc<dyn crate::program::model::pcode::HighFunction>>;

    /// Stands in for `DecompilerController.getCCodeModel()`, which returns `null` before a
    /// decompile has produced results.
    fn get_c_code_model(&self) -> StdOption<crate::app::decompiler::ClangTokenGroup>;

    /// Stands in for `DecompilerController.setStatusMessage(String)`.
    fn set_status_message(&self, message: &str);
}

/// Placeholder trait for `ghidra.app.plugin.core.decompile.DecompilerProvider`, referenced by
/// [`DecompilerActionContext`](crate::app::plugin::core::decompile::decompiler_action_context::DecompilerActionContext)
/// before the real class is ported. Java's version extends `NavigatableComponentProviderAdapter`
/// (hence `Navigatable`, whose `isConnected`/`getProgram` back
/// [`NavigatableActionContext::get_navigatable`](crate::app::context::NavigatableActionContext::get_navigatable));
/// only the members `DecompilerActionContext` and
/// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) themselves call
/// beyond that are modeled here. Everything `DecompilePlugin` needs is defaulted (to a no-op, or
/// to the value Java's field holds before anything is set) so the existing implementors keep
/// compiling; [`as_any_arc`](Self::as_any_arc) is the one exception, since no default body can
/// produce `self`.
pub trait DecompilerProvider: Navigatable + Send + Sync {
    /// Stands in for `ComponentProvider.getTool()`, inherited by `DecompilerProvider` from its
    /// (unported) `ComponentProviderAdapter` ancestor.
    fn get_tool(&self) -> Arc<dyn crate::framework::seam_stubs::PluginTool>;

    /// Erases this provider to the `Arc<dyn Any>` handle this crate's type-erased plumbing deals
    /// in: the plugin service registry
    /// ([`Plugin::register_service_provided`](crate::framework::plugintool::Plugin::register_service_provided),
    /// which `DecompilePlugin` hands the provider to as its `DecompilerHighlightService` /
    /// `DecompilerMarginService` implementation) and the tool's component-provider show/remove
    /// calls ([`PluginTool::show_component_provider`](crate::framework::seam_stubs::PluginTool::show_component_provider)).
    /// Rust cannot upcast an `Arc<dyn DecompilerProvider>` to an `Arc<dyn Any>`, so implementors
    /// supply the conversion; the body is always `self`.
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync>;

    /// Stands in for `DecompilerProvider.getDecompilerPanel()`.
    fn get_decompiler_panel(&self) -> Box<dyn DecompilerPanel>;

    /// Stands in for `DecompilerProvider.getController()`.
    fn get_controller(&self) -> Box<dyn DecompilerController>;

    /// Stands in for `DecompilerProvider.getTextSelection()`. Java may return `null` or a blank
    /// string; both collapse to the empty string here, matching this crate's usual "empty string
    /// stands in for null" convention for nullable `String` accessors (see e.g. [`MessageLog`]).
    fn get_text_selection(&self) -> String;

    /// Stands in for `DecompilerProvider.getProgram()`. [`Navigatable::get_program`] hands back an
    /// owned `Box`, which cannot be compared by identity;
    /// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) needs exactly
    /// that (`provider.getProgram() == closedProgram`), so this returns the shared handle, and
    /// `None` for Java's null (no program set yet).
    fn get_program_handle(&self) -> StdOption<Arc<dyn Program>> {
        None
    }

    /// Stands in for the package-private `DecompilerProvider.doSetProgram(Program)`, which swaps
    /// the program this provider is decompiling (`None` for Java's null).
    fn do_set_program(&self, _new_program: StdOption<Arc<dyn Program>>) {}

    /// Stands in for the package-private `DecompilerProvider.setLocation(ProgramLocation,
    /// ViewerPosition)`; `DecompilePlugin` always passes `None` for the viewer position.
    fn set_location(
        &self,
        _loc: Arc<dyn ProgramLocation + Send + Sync>,
        _viewer_position: StdOption<crate::docking::widgets::fieldpanel::support::ViewerPosition>,
    ) {
    }

    /// Stands in for `DecompilerProvider.setSelection(ProgramSelection)`.
    fn set_selection(&self, _selection: StdOption<Arc<dyn ProgramSelection>>) {}

    /// Stands in for the package-private `DecompilerProvider.setClipboardService(ClipboardService)`.
    /// The service arrives type-erased because that is how this crate's
    /// [`PluginTool::get_service`](crate::framework::seam_stubs::PluginTool::get_service) seam
    /// hands services back; the real port will take a
    /// [`ClipboardService`](crate::app::services::ClipboardService) once services can be handed
    /// out typed.
    fn set_clipboard_service(&self, _service: Arc<dyn std::any::Any + Send + Sync>) {}

    /// Stands in for the package-private `DecompilerProvider.shouldSendEvents()`: whether this
    /// provider is the tool's connected provider and is not currently replaying an incoming event.
    fn should_send_events(&self) -> bool {
        false
    }

    /// Stands in for `DecompilerProvider.writeDataState(SaveState)`.
    fn write_data_state(&self, _save_state: &mut dyn crate::framework::seam_stubs::SaveState) {}

    /// Stands in for `DecompilerProvider.readDataState(SaveState)`.
    fn read_data_state(&self, _save_state: &dyn crate::framework::seam_stubs::SaveState) {}

    /// Stands in for `DecompilerProvider.programClosed(Program)`.
    fn program_closed(&self, _closed_program: &dyn Program) {}

    /// Stands in for the package-private `DecompilerProvider.handleTokenRenamed(ClangToken,
    /// String)`, which forwards the rename to this provider's panel.
    fn handle_token_renamed(
        &self,
        _token_at_cursor: &dyn crate::app::decompiler::ClangToken,
        _new_name: &str,
    ) {
    }

    /// Stands in for `DecompilerProvider.dispose()`.
    fn dispose(&self) {}
}

/// Placeholder trait for `ghidra.app.decompiler.component.margin.DecompilerMarginProvider`.
pub trait DecompilerMarginProvider: Send + Sync {}

/// Placeholder for `generic.theme.GColor`, referenced by
/// [`search_constants`](crate::app::util::search_constants) before the real class is ported.
/// Only the constructor is modeled here. GColor is a Java class (not an interface), so this is
/// a concrete type, not a trait object. Uses OnceCell for lazy initialization of String fields
/// to maintain const-compatibility in constant contexts.
#[derive(Clone, Debug)]
pub struct GColor {
    id: &'static str,
}

impl GColor {
    /// Create a new GColor with the given theme ID.
    pub const fn new(id: &'static str) -> Self {
        GColor { id }
    }

    /// Get the theme ID for this color.
    pub const fn get_id(&self) -> &'static str {
        self.id
    }
}

/// Placeholder for `ghidra.app.util.datatype.microsoft.NewGuid`, referenced by
/// [`guid_util`](crate::app::util::datatype::microsoft::guid_util) before the real class is
/// ported. `NewGuid` sits on a dependency cycle with `GuidUtil` -- it reads `GuidUtil.GuidType`
/// and looks names up through `GuidUtil.getKnownGuid` -- so only the one static that `GuidUtil`
/// calls is modeled here. `NewGuid`'s own state (its decoded words, name, version and archive
/// type, and its `toString`/`equals`) belongs to that class's future port.
pub struct NewGuid;

impl NewGuid {
    /// Stands in for the static `NewGuid.isOKForGUID(byte[], int)`: true when the 16 bytes at
    /// `offset` are a plausible GUID -- either the fixed Microsoft OLE range (`..00 C0 .. 46`),
    /// or a version 1-2 or version 4 GUID whose variant field is the RFC 4122 `10xxxxxx`.
    ///
    /// Java's own comment on this method is "not really sure what's going on here"; the three
    /// checks are reproduced literally. Java's bytes are signed, but each of its comparisons
    /// works out to the unsigned test written here.
    pub fn is_ok_for_guid(bytes: &[u8], offset: usize) -> bool {
        /// `NewGuid.size`, the width of a GUID in bytes.
        const SIZE: usize = 16;

        if bytes.len() < offset + SIZE {
            return false;
        }
        let clock_seq_hi = bytes[offset + 7];
        let variant = bytes[offset + 8];
        if clock_seq_hi == 0x00 && variant == 0xC0 && bytes[offset + 15] == 0x46 {
            return true;
        }
        if (0x10..=0x12).contains(&clock_seq_hi) && (variant & 0xC0) == 0x80 {
            return true;
        }
        (clock_seq_hi & 0xF0) == 0x40 && (variant & 0xC0) == 0x80
    }
}

/// Placeholder for
/// `ghidra.app.plugin.core.navigation.locationreferences.DataTypeLocationDescriptor`, referenced
/// by
/// [`GenericDataTypeLocationDescriptorBase`](crate::app::plugin::core::navigation::locationreferences::generic_data_type_location_descriptor::GenericDataTypeLocationDescriptorBase)
/// before the real class (and its own abstract parent `LocationDescriptor`) is ported. Only the
/// one accessor that `GenericDataTypeLocationDescriptor` overrides is modeled here. No `Send +
/// Sync` bound: implementors hold a `Box<dyn DataType>`, and `DataType` itself is not `Send +
/// Sync` (see `program::model::data::data_type`).
pub trait DataTypeLocationDescriptor {
    fn get_type_name(&self) -> String;
}

/// Placeholder for
/// `ghidra.app.plugin.core.navigation.locationreferences.GenericDataTypeProgramLocation`,
/// referenced by
/// [`GenericDataTypeLocationDescriptorBase`](crate::app::plugin::core::navigation::locationreferences::generic_data_type_location_descriptor::GenericDataTypeLocationDescriptorBase)
/// before the real class is ported. Java's `GenericDataTypeProgramLocation extends
/// ProgramLocation`, so this stub carries that supertrait too. No `Send + Sync` bound: a real
/// implementor holds the `DataType` field directly (Java: `private final DataType dataType`), and
/// `DataType` itself is not `Send + Sync`.
pub trait GenericDataTypeProgramLocation: ProgramLocation {
    fn get_data_type(&self) -> Box<dyn DataType>;
}

/// Placeholder for `ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils`, a
/// `final` static-method-only utility class. Only `getBaseDataType(DataType)` is ported here --
/// the one member
/// [`GenericDataTypeLocationDescriptorBase`](crate::app::plugin::core::navigation::locationreferences::generic_data_type_location_descriptor::GenericDataTypeLocationDescriptorBase)
/// needs -- since it depends only on the already-ported [`DataType`]/[`Array`]/[`Pointer`]/
/// [`TypeDef`] traits; the reference-search/highlight helpers on the real class remain unported.
pub struct ReferenceUtils;

impl ReferenceUtils {
    /// Port of `ReferenceUtils.getBaseDataType(DataType)`, which forwards to the 2-arg overload
    /// with `includeTypedefs = false`.
    pub fn get_base_data_type(data_type: Box<dyn DataType>) -> Box<dyn DataType> {
        Self::get_base_data_type_impl(data_type, false)
    }

    /// Port of `ReferenceUtils.getBaseDataType(DataType, boolean)`.
    fn get_base_data_type_impl(
        data_type: Box<dyn DataType>,
        include_typedefs: bool,
    ) -> Box<dyn DataType> {
        let mut current = data_type;
        loop {
            let next: StdOption<Box<dyn DataType>> = if let Some(array) = current.as_array() {
                Some(array.get_data_type())
            } else if let Some(pointer) = current.as_pointer() {
                pointer.get_data_type()
            } else if include_typedefs {
                current.as_typedef().map(|type_def| type_def.get_base_data_type())
            } else {
                None
            };

            match next {
                Some(inner) => current = inner,
                None => return current,
            }
        }
    }
}

/// Placeholder for `ghidra.app.util.opinion.QueryResult`, referenced by
/// [`query_opinion_service`](crate::app::util::opinion::query_opinion_service) before the real
/// class is ported. Java's version is a plain immutable value class (two public final fields, a
/// `toString`, and `equals`/`hashCode` based only on `pair`, deliberately ignoring `preferred`),
/// so this is a concrete struct rather than a trait, the same way
/// [`LanguageCompilerSpecPair`] itself was placeholder-ported into `program::seam_stubs`.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The language/compiler-spec pair this result names.
    pub pair: LanguageCompilerSpecPair,
    /// Whether `pair` was the exact compiler spec asked for, rather than a broader match.
    pub preferred: bool,
}

impl QueryResult {
    /// Port of `QueryResult(LanguageCompilerSpecPair, boolean)`.
    pub fn new(pair: LanguageCompilerSpecPair, preferred: bool) -> Self {
        QueryResult { pair, preferred }
    }
}

impl fmt::Display for QueryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "query result: {:?} ({}preferred)",
            self.pair,
            if self.preferred { "" } else { "not " }
        )
    }
}

impl PartialEq for QueryResult {
    /// Mirrors `QueryResult.equals`, which compares only `pair` and deliberately ignores
    /// `preferred`.
    fn eq(&self, other: &Self) -> bool {
        self.pair == other.pair
    }
}

impl Eq for QueryResult {}

impl std::hash::Hash for QueryResult {
    /// Mirrors `QueryResult.hashCode`, which hashes only `pair`.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pair.hash(state);
    }
}

/// Placeholder for `ghidra.app.util.opinion.QueryOpinionServiceHandler`, referenced by
/// [`query_opinion_service::initialize`](crate::app::util::opinion::query_opinion_service) as
/// the forward half of a dependency cycle -- `QueryOpinionServiceHandler.read` calls back into
/// `QueryOpinionService.addQuery` -- before the real class is ported. Java's version is a final
/// class of statics (a single `read(XmlPullParser)` method), so this is a plain module of free
/// functions rather than a trait, the same way `option_utils` above stands in for
/// `OptionUtils`. The real port additionally needs `ghidra.xml.XmlPullParser`, which is not
/// ported yet either; until both land, `read` is a no-op, mirroring parsing an `.opinion` file
/// with no `<constraint>` elements.
pub mod query_opinion_service_handler {
    /// Mirrors the static `QueryOpinionServiceHandler.read(XmlPullParser)`.
    pub fn read() {}
}

/// Placeholder for `ghidra.xml.XmlMessageLog`, referenced by
/// [`DecompileDebugFormatManager`](crate::app::util::opinion::decompile_debug_format_manager::DecompileDebugFormatManager)
/// before the real class (and the `ghidra.app.util.importer.MessageLog` it extends) is ported.
/// Java's version is a concrete class, so this is a struct rather than a trait; it implements
/// the [`MessageLog`] marker stub above to record the `extends MessageLog` relationship.
///
/// Java's `XmlMessageLog` keeps the `XmlPullParser` it was handed by `setParser` so that its
/// one-argument `appendMsg` can prefix the parser's current line number. Holding the parser
/// here would mean aliasing the same `&mut` parser the caller is pulling elements from, so
/// `setParser` is dropped and callers pass the line number explicitly to
/// [`append_msg_at_line`](Self::append_msg_at_line) -- which is what the calling code already
/// does at every site that cares (`log.appendMsg(parser.getLineNumber(), msg)`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct XmlMessageLog {
    messages: Vec<String>,
}

impl XmlMessageLog {
    /// Port of `XmlMessageLog()`.
    pub fn new() -> Self {
        XmlMessageLog { messages: Vec::new() }
    }

    /// Port of `MessageLog.appendMsg(String)`.
    pub fn append_msg(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    /// Port of `MessageLog.appendMsg(int, String)`, which formats the message as
    /// `Line #<lineNum> - <msg>`.
    pub fn append_msg_at_line(&mut self, line_number: i32, msg: impl AsRef<str>) {
        self.messages.push(format!("Line #{} - {}", line_number, msg.as_ref()));
    }

    /// Port of `MessageLog.appendException(Throwable)`, which appends the exception's message.
    pub fn append_exception(&mut self, e: &dyn std::error::Error) {
        self.messages.push(e.to_string());
    }

    /// The messages appended so far, standing in for `MessageLog.getMessages()`.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

impl MessageLog for XmlMessageLog {}

impl fmt::Display for XmlMessageLog {
    /// Mirrors `MessageLog.toString()`, one message per line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for message in &self.messages {
            writeln!(f, "{}", message)?;
        }
        Ok(())
    }
}

/// Placeholder for the nested record `DecompileDebugXmlLoader.DecompileDebugProgramInfo`,
/// returned by
/// [`DecompileDebugFormatManager::get_program_info`](crate::app::util::opinion::decompile_debug_format_manager::DecompileDebugFormatManager::get_program_info)
/// before `DecompileDebugXmlLoader` is ported. `DecompileDebugXmlLoader` is the forward half of
/// a dependency cycle (the loader drives the format manager, which hands this record back), so
/// the record is stubbed rather than ported alongside its enclosing class. Java's version is a
/// `record` of three strings, so this is a plain value struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompileDebugProgramInfo {
    /// The `offset` attribute of the first `<bytechunk>` element.
    pub offset: String,
    /// The compiler-spec half of the `<binaryimage arch=...>` attribute (after the last `:`).
    pub compiler_string: String,
    /// The language half of the `<binaryimage arch=...>` attribute (before the last `:`).
    pub spec_string: String,
}

impl DecompileDebugProgramInfo {
    /// Port of the record's canonical constructor.
    pub fn new(
        offset: impl Into<String>,
        compiler_string: impl Into<String>,
        spec_string: impl Into<String>,
    ) -> Self {
        DecompileDebugProgramInfo {
            offset: offset.into(),
            compiler_string: compiler_string.into(),
            spec_string: spec_string.into(),
        }
    }
}

/// Placeholder for `ghidra.app.util.opinion.DecompileDebugDataTypeManager`, constructed and
/// driven by
/// [`DecompileDebugFormatManager`](crate::app::util::opinion::decompile_debug_format_manager::DecompileDebugFormatManager)
/// before the real class is ported.
///
/// Like [`query_opinion_service_handler`], the stubbed parse method is a no-op -- except that it
/// still discards the element subtree it was handed, because its callers loop while the parser
/// is positioned on a start element and would otherwise spin forever. It therefore reports no
/// data type, and the format manager skips creating data for the symbol (see its module docs).
///
/// The real class retains the `TaskMonitor`/`Program` it is constructed with; this stub drops
/// them, so callers keep full access to the program while the manager is alive.
pub struct DecompileDebugDataTypeManager;

impl DecompileDebugDataTypeManager {
    /// Port of `DecompileDebugDataTypeManager(TaskMonitor, Program)`.
    pub fn new(monitor: &dyn TaskMonitor, prog: &mut dyn Program) -> Self {
        let _ = (monitor, prog);
        DecompileDebugDataTypeManager
    }

    /// Stands in for `DataType parseDataTypeTag(XmlPullParser, XmlMessageLog)`; discards the
    /// type subtree and reports no data type.
    pub fn parse_data_type_tag<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        log: &mut XmlMessageLog,
    ) -> StdOption<Box<dyn DataType>> {
        let _ = log;
        parser.discard_sub_tree();
        None
    }
}

/// Placeholder for `ghidra.app.util.opinion.DecompileDebugFunctionManager`, constructed and
/// driven by
/// [`DecompileDebugFormatManager`](crate::app::util::opinion::decompile_debug_format_manager::DecompileDebugFormatManager)
/// before the real class is ported. See [`DecompileDebugDataTypeManager`] for why the stubbed
/// parse method still discards its subtree.
pub struct DecompileDebugFunctionManager;

impl DecompileDebugFunctionManager {
    /// Port of `DecompileDebugFunctionManager(Program, TaskMonitor, DecompileDebugDataTypeManager)`.
    pub fn new(
        prog: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        data_type_manager: &mut DecompileDebugDataTypeManager,
    ) -> Self {
        let _ = (prog, monitor, data_type_manager);
        DecompileDebugFunctionManager
    }

    /// Stands in for `void parseFunctionSignature(XmlPullParser, Map<Long, Namespace>,
    /// XmlMessageLog)`; discards the `<function>` subtree.
    pub fn parse_function_signature<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        scope_map: &BTreeMap<i64, Arc<dyn Namespace>>,
        log: &mut XmlMessageLog,
    ) {
        let _ = (scope_map, log);
        parser.discard_sub_tree();
    }
}

/// Placeholder for `ghidra.app.util.opinion.DecompileDebugByteManager`, constructed and driven
/// by
/// [`DecompileDebugFormatManager`](crate::app::util::opinion::decompile_debug_format_manager::DecompileDebugFormatManager)
/// before the real class is ported. See [`DecompileDebugDataTypeManager`] for why the stubbed
/// parse method still discards its subtree.
pub struct DecompileDebugByteManager;

impl DecompileDebugByteManager {
    /// Port of `DecompileDebugByteManager(TaskMonitor, Program, String)`.
    pub fn new(monitor: &dyn TaskMonitor, prog: &mut dyn Program, program_name: &str) -> Self {
        let _ = (monitor, prog, program_name);
        DecompileDebugByteManager
    }

    /// Stands in for `void parse(XmlPullParser, XmlMessageLog)`; discards the `<bytechunk>`
    /// subtree.
    pub fn parse<P: XmlPullParser>(&mut self, parser: &mut P, log: &mut XmlMessageLog) {
        let _ = log;
        parser.discard_sub_tree();
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.dyld.DyldArchitecture`, referenced by
/// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader) before the real class is
/// ported. Java's version is a concrete class (not an interface) holding a small fixed table of
/// named `dyld_v1*` signature constants; only the two members `DyldCacheLoader` actually calls --
/// looking an architecture up by its raw signature string, and reading back its processor name --
/// are modeled. `cpuType`/`cpuSubType`/`endianness`/`is64bit` are dropped since no in-repo caller
/// reads them yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldArchitecture {
    signature: &'static str,
    processor: &'static str,
}

impl DyldArchitecture {
    /// Port of `DyldArchitecture.DYLD_V1_SIGNATURE_LEN`.
    pub const DYLD_V1_SIGNATURE_LEN: usize = 0x10;

    // @formatter:off -- exact signature spacing matters (compared after only leading/trailing
    // `trim()`), so these are copied verbatim from `DyldArchitecture.ARCHITECTURES`.
    const ARCHITECTURES: &'static [DyldArchitecture] = &[
        DyldArchitecture { signature: "dyld_v1    i386", processor: "i386" },
        DyldArchitecture { signature: "dyld_v1  x86_64", processor: "x86_64" },
        DyldArchitecture { signature: "dyld_v1 x86_64h", processor: "x86_64" },
        DyldArchitecture { signature: "dyld_v1     ppc", processor: "rosetta" },
        DyldArchitecture { signature: "dyld_v1   armv6", processor: "armv6" },
        DyldArchitecture { signature: "dyld_v1   armv7", processor: "arm7" },
        DyldArchitecture { signature: "dyld_v1  armv7f", processor: "arm7" },
        DyldArchitecture { signature: "dyld_v1  armv7s", processor: "arm7" },
        DyldArchitecture { signature: "dyld_v1  armv7k", processor: "arm7" },
        DyldArchitecture { signature: "dyld_v1   arm64", processor: "AARCH64" },
        DyldArchitecture { signature: "dyld_v1  arm64e", processor: "AARCH64" },
        DyldArchitecture { signature: "dyld_v1arm64_32", processor: "ARM64_32" },
    ];
    // @formatter:on

    /// Port of `DyldArchitecture.getArchitecture(String)`.
    pub fn get_architecture(signature: &str) -> StdOption<DyldArchitecture> {
        Self::ARCHITECTURES.iter().find(|a| a.signature == signature).copied()
    }

    /// Port of `DyldArchitecture.getProcessor()`.
    pub fn get_processor(&self) -> &'static str {
        self.processor
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader`, referenced by
/// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader) before the real (over
/// 1500-line) class is ported. Java's constructor parses the entire DYLD cache header (magic,
/// mapping/image offsets, UUIDs, dozens of sub-cache and slide-info fields...); only the 16-byte
/// magic -- resolved to a [`DyldArchitecture`] the same way `DyldArchitecture.getArchitecture
/// (ByteProvider)` does -- is parsed here. [`base_address`](Self::base_address) and
/// [`is_subcache`](Self::is_subcache) are NOT derived from any of the (unparsed) later fields
/// the real `getBaseAddress()`/`isSubcache()` compute them from, and default to `0`/`false` until
/// the full port lands.
#[derive(Debug, Clone)]
pub struct DyldCacheHeader {
    /// Port of `DyldCacheHeader.getArchitecture()`.
    pub architecture: StdOption<DyldArchitecture>,
    /// Port of `DyldCacheHeader.getBaseAddress()`. Always `0` on this placeholder; see the type
    /// docs.
    pub base_address: i64,
    /// Port of `DyldCacheHeader.isSubcache()`. Always `false` on this placeholder; see the type
    /// docs.
    pub is_subcache: bool,
}

impl DyldCacheHeader {
    /// Port of the magic-parsing prefix of `DyldCacheHeader(BinaryReader)`.
    pub fn new(
        reader: &mut crate::filesystem::ghidra::g_binary_reader::GBinaryReader,
    ) -> std::io::Result<Self> {
        let magic = reader.read_next_ascii_string_fixed(Self::MAGIC_LEN)?;
        Ok(DyldCacheHeader {
            architecture: DyldArchitecture::get_architecture(magic.trim()),
            base_address: 0,
            is_subcache: false,
        })
    }

    const MAGIC_LEN: u64 = DyldArchitecture::DYLD_V1_SIGNATURE_LEN as u64;
}

/// Placeholder for `ghidra.app.util.opinion.DyldCacheUtils`, referenced by
/// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader) before the real class is
/// ported. Java's version is a final class of statics, so (per this crate's convention for such
/// classes, e.g. [`option_utils`]) this is a plain module of free functions. Only
/// `isDyldCache(ByteProvider)` -- the one overload `DyldCacheLoader` calls -- is modeled; the
/// `Program`-taking overload and the `SplitDyldCache`/image-record helpers are not needed by any
/// current caller.
pub mod dyld_cache_utils {
    use super::DyldArchitecture;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Port of `DyldCacheUtils.isDyldCache(ByteProvider)`.
    pub fn is_dyld_cache(provider: &Rc<RefCell<dyn ByteProvider>>) -> bool {
        let bytes =
            match provider.borrow_mut().read_bytes(0, DyldArchitecture::DYLD_V1_SIGNATURE_LEN) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
        let signature = String::from_utf8_lossy(&bytes);
        DyldArchitecture::get_architecture(signature.trim()).is_some()
    }
}

/// Placeholder for `ghidra.app.util.MemoryBlockUtils`, referenced by
/// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader) before the real class is
/// ported. A different, narrower placeholder for this same Java class already exists as a trait
/// at [`crate::format::seam_stubs::MemoryBlockUtils`] (added for
/// [`dyld_chained_fixups`](crate::format::macho::commands::chained::dyld_chained_fixups)'s
/// `addExternalBlock` call, before this crate settled on modeling final-statics classes as free
/// functions rather than traits -- see [`option_utils`]); this module is scoped to the one method
/// `DyldCacheLoader` needs instead of growing that trait, to avoid disturbing its existing caller.
pub mod memory_block_utils {
    use super::MessageLog;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::program::database::mem::file_bytes::FileBytes;
    use crate::program::model::address::{Address, AddressOverflowException};
    use crate::program::model::listing::Program;
    use crate::program::model::mem::MemoryBlock;
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    /// Port of `MemoryBlockUtils.createFileBytes(Program, ByteProvider, TaskMonitor)`. Not yet
    /// implemented (see module docs); the real body reads every byte out of `provider` and hands
    /// them to the program's file-bytes database, which needs far more infrastructure than this
    /// placeholder models.
    pub fn create_file_bytes(
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Arc<dyn FileBytes>> {
        let _ = (program, provider, monitor);
        unimplemented!("memory_block_utils::create_file_bytes placeholder not overridden")
    }

    /// Port of `MemoryBlockUtils.createInitializedBlock(Program, boolean isOverlay, String name,
    /// Address start, FileBytes fileBytes, long offset, long length, String comment, String
    /// source, boolean r, boolean w, boolean x, MessageLog log)`. `None` stands in for the `null`
    /// Java returns when the block could not be created (it logs and swallows the reason);
    /// `AddressOverflowException` is the one failure it propagates. Not yet implemented: the real
    /// body creates a database-backed block over a file-bytes range.
    #[allow(clippy::too_many_arguments)]
    pub fn create_initialized_block(
        program: &mut dyn Program,
        is_overlay: bool,
        name: &str,
        start: &Address,
        file_bytes: &Arc<dyn FileBytes>,
        offset: i64,
        length: i64,
        comment: Option<&str>,
        source: Option<&str>,
        r: bool,
        w: bool,
        x: bool,
        log: &dyn MessageLog,
    ) -> Result<Option<Box<dyn MemoryBlock>>, AddressOverflowException> {
        let _ = (program, is_overlay, name, start, file_bytes, offset, length);
        let _ = (comment, source, r, w, x, log);
        unimplemented!("memory_block_utils::create_initialized_block placeholder not overridden")
    }

    /// Port of `MemoryBlockUtils.createUninitializedBlock(Program, boolean isOverlay, String name,
    /// Address start, long length, String comment, String source, boolean r, boolean w, boolean x,
    /// MessageLog log)`. `None` stands in for the `null` Java returns when the block could not be
    /// created. Not yet implemented, as for [`create_initialized_block`].
    #[allow(clippy::too_many_arguments)]
    pub fn create_uninitialized_block(
        program: &mut dyn Program,
        is_overlay: bool,
        name: &str,
        start: &Address,
        length: i64,
        comment: Option<&str>,
        source: Option<&str>,
        r: bool,
        w: bool,
        x: bool,
        log: &dyn MessageLog,
    ) -> Option<Box<dyn MemoryBlock>> {
        let _ = (program, is_overlay, name, start, length);
        let _ = (comment, source, r, w, x, log);
        unimplemented!("memory_block_utils::create_uninitialized_block placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.util.opinion.DyldCacheProgramBuilder`, referenced by
/// [`dyld_cache_loader`](crate::app::util::opinion::dyld_cache_loader) before the real class is
/// ported. Java's version drives the entire DYLD cache program build (memory blocks, symbols,
/// exports, load-command markup, program tree); only the single static entry point
/// `DyldCacheLoader.load` calls is modeled, and it is not yet implemented (see
/// [`memory_block_utils::create_file_bytes`]) since the real build needs far more infrastructure
/// than this placeholder models.
pub mod dyld_cache_program_builder {
    use super::MessageLog;
    use crate::app::util::opinion::dyld_cache_options::DyldCacheOptions;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::program::database::mem::file_bytes::FileBytes;
    use crate::program::model::listing::Program;
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    /// Port of `DyldCacheProgramBuilder.buildProgram(Program, ByteProvider, FileBytes,
    /// DyldCacheOptions, MessageLog, TaskMonitor)`.
    pub fn build_program(
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        file_bytes: &Arc<dyn FileBytes>,
        options: DyldCacheOptions,
        log: &mut dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<()> {
        let _ = (program, provider, file_bytes, options, log, monitor);
        unimplemented!("dyld_cache_program_builder::build_program placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.util.pcodeInject.PcodeOpEmitter`, referenced by
/// [`array_methods`](crate::app::util::pcode_inject::array_methods) before the real class is
/// ported. Java's version accumulates pcode ops for a single injected pcode sequence and exposes a
/// much larger emit* API; only the four methods `ArrayMethods.getPcodeForMultiANewArray` calls are
/// modeled. `Send + Sync` so a caller holding a `Box<dyn PcodeOpEmitter>` can itself remain so.
pub trait PcodeOpEmitter: Send + Sync {
    /// Stands in for `PcodeOpEmitter.emitPushCat1Value(String)`.
    fn emit_push_cat1_value(&self, value_name: &str);

    /// Stands in for `PcodeOpEmitter.emitPopCat1Value(String)`.
    fn emit_pop_cat1_value(&self, dest_name: &str);

    /// Stands in for `PcodeOpEmitter.emitAssignVarnodeFromPcodeOpCall(String, int, String,
    /// String...)`.
    fn emit_assign_varnode_from_pcode_op_call(
        &self,
        varnode_name: &str,
        size: i32,
        pcodeop: &str,
        args: &[String],
    );

    /// Stands in for `PcodeOpEmitter.emitVoidPcodeOpCall(String, String...)`.
    fn emit_void_pcode_op_call(&self, pcodeop: &str, args: &[String]);
}

/// Placeholder for the two static string fields `ghidra.app.util.pcodeInject.ConstantPoolJava`
/// exposes (`CPOOL_OP`, `CPOOL_MULTIANEWARRAY`), referenced by
/// [`array_methods`](crate::app::util::pcode_inject::array_methods) before the real class is
/// ported. Java's `ConstantPoolJava` is an instantiable class (not a statics holder -- it extends
/// `ConstantPool` and has a `Program`-taking constructor), but these two `static final String`
/// fields are the only members `ArrayMethods` touches, so only they are modeled here.
pub mod constant_pool_java {
    /// Mirrors `ConstantPoolJava.CPOOL_OP`.
    pub const CPOOL_OP: &str = "cpool";
    /// Mirrors `ConstantPoolJava.CPOOL_MULTIANEWARRAY`.
    pub const CPOOL_MULTIANEWARRAY: &str = "12";
}

/// Placeholder for `ghidra.javaclass.format.DescriptorDecoder`, referenced by
/// [`array_methods`](crate::app::util::pcode_inject::array_methods) before the real class is
/// ported. Java's version is itself a statics holder (private constructor, only `static` methods),
/// so -- like `array_methods` -- it is modeled as a plain module of free functions rather than a
/// trait. Only the one static call `ArrayMethods.getArrayBaseType` makes,
/// `getDataTypeOfDescriptor(String, DataTypeManager)`, is modeled.
pub mod descriptor_decoder {
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;

    /// Mirrors `DescriptorDecoder.BASE_TYPE_BYTE`.
    pub const BASE_TYPE_BYTE: u8 = b'B';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_CHAR`.
    pub const BASE_TYPE_CHAR: u8 = b'C';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_SHORT`.
    pub const BASE_TYPE_SHORT: u8 = b'S';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_INT`.
    pub const BASE_TYPE_INT: u8 = b'I';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_LONG`.
    pub const BASE_TYPE_LONG: u8 = b'J';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_FLOAT`.
    pub const BASE_TYPE_FLOAT: u8 = b'F';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_DOUBLE`.
    pub const BASE_TYPE_DOUBLE: u8 = b'D';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_BOOLEAN`.
    pub const BASE_TYPE_BOOLEAN: u8 = b'Z';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_STRING`.
    pub const BASE_TYPE_STRING: u8 = b's';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_VOID`.
    pub const BASE_TYPE_VOID: u8 = b'V';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_CLASS`.
    pub const BASE_TYPE_CLASS: u8 = b'c';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_ARRAY`.
    pub const BASE_TYPE_ARRAY: u8 = b'[';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_REFERENCE`.
    pub const BASE_TYPE_REFERENCE: u8 = b'L';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_ENUM`.
    pub const BASE_TYPE_ENUM: u8 = b'e';
    /// Mirrors `DescriptorDecoder.BASE_TYPE_ANNOTATION`.
    pub const BASE_TYPE_ANNOTATION: u8 = b'@';

    /// Stands in for `DescriptorDecoder.getDataTypeOfDescriptor(String, DataTypeManager)`.
    pub fn get_data_type_of_descriptor(
        descriptor: &str,
        dt_manager: &dyn DataTypeManager,
    ) -> Box<dyn DataType> {
        let _ = (descriptor, dt_manager);
        unimplemented!(
            "descriptor_decoder::get_data_type_of_descriptor placeholder not overridden"
        )
    }
}

/// Placeholder for `generic.stl.Pair`, referenced by [`OptionChooser`](crate::app::util::importer::option_chooser::OptionChooser)
/// before the real class is ported. `OptionChooser` only ever holds this type in a collection
/// returned by `getArgs()`, so minimal members are needed yet.
pub trait Pair: Send + Sync {
    /// Mirrors `Pair.toString()`.
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.importer.ProgramLoader`, referenced by
/// [`OptionChooser`](crate::app::util::importer::option_chooser::OptionChooser) before the real
/// class is ported. `OptionChooser` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait ProgramLoader: Send + Sync {}

/// Placeholder for `ghidra.app.util.xml.XmlProgramOptions`, referenced by
/// [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) before the real class is
/// ported. Java's version is a plain mutable bean of ~24 `boolean` switches plus the
/// `List<Option>` conversions in [`get_options`](Self::get_options)/[`set_options`](Self::set_options);
/// `XmlLoader` only ever constructs one, feeds it a caller's options, flips
/// [`set_add_to_program`](Self::set_add_to_program), and hands it to [`ProgramXmlMgr::read`], so
/// only that surface is modeled here. The switches themselves are deliberately left out until
/// the real port brings them in with the reading/writing code that consumes them.
pub struct XmlProgramOptions {
    /// Mirrors `XmlProgramOptions.isAddToProgram`, the one switch `XmlLoader` sets directly.
    add_to_program: bool,
}

impl XmlProgramOptions {
    /// Port of `new XmlProgramOptions()`. Java's field initializers make every switch except
    /// `isAddToProgram` default to true; `isAddToProgram` starts false, which is all this
    /// placeholder models.
    pub fn new() -> Self {
        XmlProgramOptions { add_to_program: false }
    }

    /// Port of `XmlProgramOptions.isAddToProgram()`.
    pub fn is_add_to_program(&self) -> bool {
        self.add_to_program
    }

    /// Port of `XmlProgramOptions.setAddToProgram(boolean)`.
    pub fn set_add_to_program(&mut self, add_to_program: bool) {
        self.add_to_program = add_to_program;
    }

    /// Port of `XmlProgramOptions.getOptions(boolean isAddToProgram)`. Not yet implemented (see
    /// the type docs); the real body builds one `Option` per switch.
    pub fn get_options(&self, is_add_to_program: bool) -> Vec<Box<dyn Option>> {
        let _ = is_add_to_program;
        unimplemented!("XmlProgramOptions::get_options placeholder not overridden")
    }

    /// Port of `XmlProgramOptions.setOptions(List<Option>)`, which throws `OptionException` when
    /// an option's name or value type is not one it recognizes. Not yet implemented (see the type
    /// docs); the real body applies each option to its matching switch.
    pub fn set_options(
        &mut self,
        options: &[Box<dyn Option>],
    ) -> Result<(), crate::app::util::option_exception::OptionException> {
        let _ = options;
        unimplemented!("XmlProgramOptions::set_options placeholder not overridden")
    }
}

impl Default for XmlProgramOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder for `ghidra.app.util.xml.ProgramXmlMgr`, referenced by
/// [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) before the real class is
/// ported. Java's version owns the XML `ByteProvider`/`File` and drives the two dozen `*XmlMgr`
/// readers/writers over it; only the two constructors and the two reads `XmlLoader` performs are
/// modeled.
///
/// The real port will hold the `ByteProvider` it was constructed from. This placeholder keeps
/// only the underlying file path, so that it stays `Send + Sync`: `XmlLoader` shares one across
/// the `AnalysisWorker` it schedules, and this crate's `ByteProvider` handles are
/// `Rc<RefCell<..>>`, which are not.
pub struct ProgramXmlMgr {
    /// The XML file this manager reads, when known.
    file: StdOption<std::path::PathBuf>,
}

impl ProgramXmlMgr {
    /// Port of `ProgramXmlMgr(ByteProvider)`.
    pub fn from_provider(
        provider: &std::rc::Rc<
            std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>,
        >,
    ) -> Self {
        ProgramXmlMgr { file: provider.borrow().get_file() }
    }

    /// Port of `ProgramXmlMgr(File)`.
    pub fn from_file(file: std::path::PathBuf) -> Self {
        ProgramXmlMgr { file: Some(file) }
    }

    /// The XML file this manager was constructed over, if any. Not a port of a Java member; it
    /// exposes the one piece of state this placeholder retains.
    pub fn file(&self) -> StdOption<&std::path::Path> {
        self.file.as_deref()
    }

    /// Port of `ProgramXmlMgr.getProgramInfo()`, which parses just the `PROGRAM`/`INFO_SOURCE`/
    /// `LANGUAGE` tags at the head of the document. `None` mirrors the `null` Java returns for a
    /// document without those tags. Not yet implemented (see the type docs); the real body needs
    /// the XML pull parser and the `ProgramInfo` tag handlers.
    pub fn get_program_info(
        &self,
    ) -> std::io::Result<StdOption<crate::app::util::xml::program_info::ProgramInfo>> {
        unimplemented!("ProgramXmlMgr::get_program_info placeholder not overridden")
    }

    /// Port of `ProgramXmlMgr.read(Program, TaskMonitor, XmlProgramOptions)`, returning the
    /// manager's own `MessageLog`. Not yet implemented (see the type docs); the real body runs
    /// every enabled `*XmlMgr` over the document.
    pub fn read(
        &self,
        program: &dyn Program,
        monitor: &dyn TaskMonitor,
        options: &XmlProgramOptions,
    ) -> std::io::Result<Box<dyn MessageLog>> {
        let _ = (program, monitor, options);
        unimplemented!("ProgramXmlMgr::read placeholder not overridden")
    }
}

/// Placeholder for `ghidra.app.plugin.core.analysis.AutoAnalysisManager`, referenced by
/// [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) before the real class is
/// ported. Java's version has ~67 members; `XmlLoader` only ever schedules a worker on one, so
/// that is the only method modeled. The two statics it reaches the manager through are the free
/// functions in [`auto_analysis_manager`].
pub trait AutoAnalysisManager: Send + Sync {
    /// Mirrors `AutoAnalysisManager.scheduleWorker(AnalysisWorker, Object, boolean, TaskMonitor)`.
    /// Java additionally throws `InvocationTargetException`/`InterruptedException`/
    /// `CancelledException`; only the `IOException` cause `XmlLoader` unwraps out of the first is
    /// modeled, since the other two are Java threading plumbing.
    fn schedule_worker(
        &self,
        worker: &dyn crate::app::plugin::core::analysis::analysis_worker::AnalysisWorker,
        worker_context: &dyn std::any::Any,
        analyze_changes: bool,
        worker_monitor: &dyn TaskMonitor,
    ) -> std::io::Result<bool>;

    /// Mirrors `AutoAnalysisManager.initializeOptions()`, which lets every registered analyzer
    /// register its options with their defaults, then reloads them.
    fn initialize_options(&self) {}

    /// Mirrors `AutoAnalysisManager.addListener(AutoAnalysisManagerListener)`.
    ///
    /// The listener is type-erased. Java registers `this` -- the plugin -- and the ported
    /// [`AutoAnalysisManagerListener`](crate::app::plugin::core::analysis::AutoAnalysisManagerListener)
    /// is generic over the manager type, so it is not a trait object this stub can name without
    /// closing the very cycle it exists to break. Registration is therefore by identity only,
    /// exactly as [`PluginTool::add_action`](crate::framework::seam_stubs::PluginTool::add_action)
    /// erases its actions.
    fn add_listener(&self, listener: Arc<dyn Any + Send + Sync>) {
        let _ = listener;
    }

    /// Mirrors `AutoAnalysisManager.removeListener(AutoAnalysisManagerListener)`; the listener is
    /// matched by identity against the handle [`add_listener`](Self::add_listener) was given.
    fn remove_listener(&self, listener: &Arc<dyn Any + Send + Sync>) {
        let _ = listener;
    }

    /// Mirrors `AutoAnalysisManager.addTool(PluginTool)`.
    fn add_tool(&self, tool: Arc<dyn crate::framework::seam_stubs::PluginTool>) {
        let _ = tool;
    }

    /// Mirrors `AutoAnalysisManager.removeTool(PluginTool)`.
    fn remove_tool(&self, tool: Arc<dyn crate::framework::seam_stubs::PluginTool>) {
        let _ = tool;
    }

    /// Mirrors `AutoAnalysisManager.reAnalyzeAll(AddressSetView)`, which re-runs every enabled
    /// analyzer over `set` -- or, for Java's null, over all of memory.
    ///
    /// The set is a [`ProgramSelection`] rather than an `AddressSetView` because that is what the
    /// plugin has in hand (Java's `ProgramSelection` *is* an `AddressSetView`, a relationship this
    /// crate's placeholder does not model yet).
    fn re_analyze_all(&self, set: StdOption<Arc<dyn ProgramSelection>>) {
        let _ = set;
    }

    /// Mirrors `AutoAnalysisManager.askToAnalyze(PluginTool)`: whether the user should be prompted
    /// to analyze this program now. Defaults to `false`, the answer for an already-analyzed
    /// program.
    fn ask_to_analyze(&self, tool: &dyn crate::framework::seam_stubs::PluginTool) -> bool {
        let _ = tool;
        false
    }

    /// Mirrors `AutoAnalysisManager.getMessageLog()`, the log every analyzer writes into.
    fn get_message_log(&self) -> Arc<dyn MessageLog>;

    /// Mirrors `AutoAnalysisManager.getProgram()`, the program this manager analyzes.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Mirrors `AutoAnalysisManager.schedule(BackgroundCommand<Program>, int)`. The command is
    /// type-erased for the same reason
    /// [`PluginTool::execute_background_command`](crate::framework::seam_stubs::PluginTool::execute_background_command)'s
    /// is: `BackgroundCommand` is not ported.
    fn schedule(&self, cmd: Arc<dyn Any + Send + Sync>, priority: i32) {
        let _ = (cmd, priority);
    }
}

/// Placeholder for `ghidra.GhidraOptions`, referenced by
/// [`AutoAnalysisPlugin`](crate::app::plugin::core::analysis::AutoAnalysisPlugin) before the real
/// interface is ported. Java's version is an interface of `String` constants; only the one the
/// plugin looks its tool options up under is modeled.
pub struct GhidraOptions;

impl GhidraOptions {
    /// Mirrors `GhidraOptions.CATEGORY_AUTO_ANALYSIS`.
    pub const CATEGORY_AUTO_ANALYSIS: &'static str = "Auto Analysis";
}

/// Placeholder for `ghidra.app.plugin.core.analysis.StoredAnalyzerTimes`, referenced by
/// [`AutoAnalysisPlugin`](crate::app::plugin::core::analysis::AutoAnalysisPlugin)'s
/// `programActivated` before the real class is ported. The plugin only registers the option the
/// class is stored under, so its two name constants are all that is modeled.
pub struct StoredAnalyzerTimes;

impl StoredAnalyzerTimes {
    /// Mirrors `StoredAnalyzerTimes.OPTIONS_LIST`, which Java builds as
    /// `Program.PROGRAM_INFO + ".Analysis Times"`.
    pub const OPTIONS_LIST: &'static str = "Program Information.Analysis Times";

    /// Mirrors `StoredAnalyzerTimes.OPTION_NAME`.
    pub const OPTION_NAME: &'static str = "Times";
}

/// Placeholder for `docking.widgets.dialogs.MultiLineMessageDialog`, referenced by
/// [`AutoAnalysisPlugin`](crate::app::plugin::core::analysis::AutoAnalysisPlugin)'s
/// `analysisEnded` before the real class is ported. Only the message-type constant the plugin
/// passes is modeled; the dialog itself is described by
/// [`AnalysisSummary`](crate::app::plugin::core::analysis::AnalysisSummary).
pub struct MultiLineMessageDialog;

impl MultiLineMessageDialog {
    /// Mirrors `MultiLineMessageDialog.WARNING_MESSAGE`, which Java aliases to
    /// `JOptionPane.WARNING_MESSAGE`.
    pub const WARNING_MESSAGE: i32 = 2;
}

/// The one `ghidra.program.util.GhidraProgramUtilities` static
/// [`AutoAnalysisPlugin`](crate::app::plugin::core::analysis::AutoAnalysisPlugin) calls, before
/// the real class is ported. Java hangs it off the class itself; Rust has no static trait
/// methods, so -- as with [`auto_analysis_manager`] -- it becomes a free function in a module
/// named for the Java class.
///
/// Unlike the manager statics, this one has a real body: Java's is a two-line options read, so it
/// is implemented rather than left `unimplemented!()`.
pub mod ghidra_program_utilities {
    use crate::program::model::listing::{Program, ANALYZED_OPTION_NAME, PROGRAM_INFO};

    /// Mirrors `GhidraProgramUtilities.isAnalyzed(Program)`: whether the program's
    /// `Program Information` options record that it has already been analyzed.
    pub fn is_analyzed(program: &dyn Program) -> bool {
        program
            .get_options(PROGRAM_INFO)
            .get_boolean(ANALYZED_OPTION_NAME, false)
    }
}

/// The two `AutoAnalysisManager` statics
/// [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) calls. Java hangs them off the
/// class itself; Rust has no static trait methods, so -- as with [`memory_block_utils`] -- they
/// become free functions in a module named for the Java class.
pub mod auto_analysis_manager {
    use super::AutoAnalysisManager;
    use crate::program::model::listing::Program;

    /// Mirrors `AutoAnalysisManager.hasAutoAnalysisManager(Program)`. Not yet implemented; the
    /// real body consults the static per-program manager registry.
    pub fn has_auto_analysis_manager(program: &dyn Program) -> bool {
        let _ = program;
        unimplemented!("auto_analysis_manager::has_auto_analysis_manager placeholder not overridden")
    }

    /// Mirrors `AutoAnalysisManager.getAnalysisManager(Program)`, which creates the program's
    /// manager if it does not have one yet. Not yet implemented, as for
    /// [`has_auto_analysis_manager`].
    pub fn get_analysis_manager(program: &dyn Program) -> Box<dyn AutoAnalysisManager> {
        let _ = program;
        unimplemented!("auto_analysis_manager::get_analysis_manager placeholder not overridden")
    }
}

/// The `AbstractProgramLoader` helper
/// [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) inherits and calls. Java's
/// `AbstractProgramLoader` is the abstract base class every program loader extends; this crate
/// models loaders as standalone structs (see `XmlLoader`'s and
/// [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader)'s module docs), so the
/// inherited helpers become free functions here until the base class itself is ported.
pub mod abstract_program_loader {
    use super::MessageLog;
    use crate::program::model::listing::Program;
    use crate::util::task::TaskMonitor;

    /// Mirrors the protected `AbstractProgramLoader.createDefaultMemoryBlocks(Program,
    /// ImporterSettings)`, which lays down the language's default memory-block definitions. Java
    /// takes the whole `ImporterSettings` record but reads only its log and monitor, so those two
    /// are passed directly. Not yet implemented (see the module docs).
    pub fn create_default_memory_blocks(
        program: &mut dyn Program,
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) {
        let _ = (program, log, monitor);
        unimplemented!(
            "abstract_program_loader::create_default_memory_blocks placeholder not overridden"
        )
    }
}

/// Placeholder for `ghidra.app.util.opinion.PeLoader`, referenced by
/// [`library_lookup_table`](crate::app::util::opinion::library_lookup_table) before the real
/// class is ported. `LibraryLookupTable` only ever compares a program's executable format against
/// the loader's name constant, so that constant is the only member modeled.
pub struct PeLoader;

impl PeLoader {
    /// `PeLoader.PE_NAME`.
    pub const PE_NAME: &'static str = "Portable Executable (PE)";
}

/// Placeholder for `ghidra.app.util.opinion.LibrarySymbolTable`, referenced by
/// [`library_lookup_table`](crate::app::util::opinion::library_lookup_table) before the real
/// class is ported. The two form a dependency cycle -- `LibrarySymbolTable.getCacheKey(String,
/// int)` calls back into
/// [`strip_possible_extension_from_filename`](crate::app::util::opinion::library_lookup_table::strip_possible_extension_from_filename)
/// -- which is why this side is stubbed rather than ported alongside it.
///
/// Only the members `LibraryLookupTable` reaches are modeled. The two cache-key methods and
/// [`set_version`](Self::set_version) are implemented for real (they are pure name manipulation
/// and a field write, and the cache key decides map identity, so a panicking stub would make the
/// symbol-table cache untestable). Everything that needs the unported `.exports`/`.ord` XML
/// reader-writer or the `Program`-walking constructor panics.
pub struct LibrarySymbolTable {
    table_name: String,
    size: i32,
    version: String,
    forwards: Vec<String>,
    /// Mirrors the `symMap` field, keyed by [`LibraryExportedSymbol::name`]. Populated only by
    /// [`Self::insert_symbol`]; `from_exports_file`/`from_program` are not implemented yet, so it
    /// is always empty coming out of those two constructors.
    sym_map: HashMap<String, Arc<LibraryExportedSymbol>>,
    /// Mirrors the `ordMap` field, keyed by [`LibraryExportedSymbol::ordinal`]. Java's two maps
    /// share one symbol instance per export, which is why both hold an `Arc` here.
    ord_map: HashMap<i32, Arc<LibraryExportedSymbol>>,
}

impl LibrarySymbolTable {
    /// Mirrors `LibrarySymbolTable(String tableName, int size)`, which constructs an empty table
    /// and lowercases the name.
    pub fn new(table_name: &str, size: i32) -> Self {
        LibrarySymbolTable {
            table_name: table_name.to_lowercase(),
            size,
            version: "unknown".to_string(),
            forwards: Vec::new(),
            sym_map: HashMap::new(),
            ord_map: HashMap::new(),
        }
    }

    /// Mirrors `getSymbol(String)`: the symbol for the specified name, or `None` if not found.
    pub fn get_symbol(&self, symbol: &str) -> StdOption<&LibraryExportedSymbol> {
        self.sym_map.get(symbol).map(|s| &**s)
    }

    /// Mirrors `getSymbol(int)`: the symbol exported under the specified ordinal, or `None` if
    /// not found.
    pub fn get_symbol_by_ordinal(&self, ordinal: i32) -> StdOption<&LibraryExportedSymbol> {
        self.ord_map.get(&ordinal).map(|s| &**s)
    }

    /// Not part of the Java API surface (that role is filled by `addSymbol` deep inside the
    /// unported `.exports` XML reader / `Program`-walking constructor). Exposed for tests, and for
    /// whichever of those two constructors gets ported first to populate `symMap`/`ordMap` with.
    pub fn insert_symbol(&mut self, symbol: LibraryExportedSymbol) {
        let symbol = Arc::new(symbol);
        if let Some(name) = symbol.name() {
            self.sym_map.insert(name.to_string(), Arc::clone(&symbol));
        }
        self.ord_map.insert(symbol.ordinal(), symbol);
    }

    /// Mirrors `LibrarySymbolTable(ResourceFile libraryFile, int size)`, which parses an existing
    /// `.exports` file. Not yet implemented; the real body is the unported XML reader.
    pub fn from_exports_file(
        library_file: &crate::generic::jar::ResourceFile,
        size: i32,
    ) -> std::io::Result<Self> {
        let _ = (library_file, size);
        unimplemented!("LibrarySymbolTable::from_exports_file placeholder not overridden")
    }

    /// Mirrors `LibrarySymbolTable(Program library, TaskMonitor monitor)`, which walks the
    /// program's `Ordinal_#` symbols and pseudo-disassembles each export. Not yet implemented.
    pub fn from_program(
        library: &dyn Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, crate::util::exception::CancelledException> {
        let _ = (library, monitor);
        unimplemented!("LibrarySymbolTable::from_program placeholder not overridden")
    }

    /// Mirrors the instance `LibrarySymbolTable.getCacheKey()`.
    pub fn get_cache_key(&self) -> String {
        Self::cache_key_for(&self.table_name, self.size)
    }

    /// Mirrors the static `LibrarySymbolTable.getCacheKey(String dllName, int size)`.
    pub fn cache_key_for(dll_name: &str, size: i32) -> String {
        let stripped =
            crate::app::util::opinion::library_lookup_table::strip_possible_extension_from_filename(
                dll_name,
            );
        format!("{}:{size}", stripped.to_lowercase())
    }

    /// Mirrors `LibrarySymbolTable.getForwards()`, the libraries this one forwards exports to.
    pub fn get_forwards(&self) -> &[String] {
        &self.forwards
    }

    /// Mirrors `LibrarySymbolTable.setVersion(String)`.
    pub fn set_version(&mut self, version: &str) {
        self.version = version.to_string();
    }

    /// Mirrors `LibrarySymbolTable.getVersion()`.
    pub fn get_version(&self) -> &str {
        &self.version
    }

    /// Mirrors `LibrarySymbolTable.applyOrdinalFile(ResourceFile, boolean)`, which folds a
    /// DUMPBIN-produced `.ord` file into this table. Not yet implemented.
    pub fn apply_ordinal_file(
        &mut self,
        ordinal_exports_file: &crate::generic::jar::ResourceFile,
        add_missing_ordinals: bool,
    ) {
        let _ = (ordinal_exports_file, add_missing_ordinals);
        unimplemented!("LibrarySymbolTable::apply_ordinal_file placeholder not overridden")
    }

    /// Mirrors `LibrarySymbolTable.write(File output, File input, String lversion)`, which emits
    /// the `.exports` XML. Not yet implemented; the real body is the unported XML writer.
    pub fn write(
        &self,
        output: &std::path::Path,
        input: &std::path::Path,
        lversion: &str,
    ) -> std::io::Result<()> {
        let _ = (output, input, lversion);
        unimplemented!("LibrarySymbolTable::write placeholder not overridden")
    }

    /// Mirrors the static `LibrarySymbolTable.hasFileAndPathAndTimeStampMatch(ResourceFile,
    /// File)`. Java's first act is a null/exists guard on the exports file, which is modeled here
    /// (`None` stands in for the `null` `LibraryLookupTable` can pass); past that the real body
    /// parses the exports XML, so it is not yet implemented.
    pub fn has_file_and_path_and_time_stamp_match(
        exports_file: StdOption<&crate::generic::jar::ResourceFile>,
        library_file: &std::path::Path,
    ) -> std::io::Result<bool> {
        match exports_file {
            Some(file) if file.exists() => {
                let _ = library_file;
                unimplemented!(
                    "LibrarySymbolTable::has_file_and_path_and_time_stamp_match placeholder not overridden"
                )
            }
            _ => Ok(false),
        }
    }
}

/// Placeholder for `ghidra.app.cmd.function.CaptureFunctionDataTypesCmd`, referenced by
/// [`CaptureFunctionDataTypesListener`](crate::app::cmd::function::CaptureFunctionDataTypesListener)
/// before the real class is ported. Mirrors the command's status-reporting interface for
/// listeners; only `apply_to` and `task_completed` are modeled.
pub trait CaptureFunctionDataTypesCmd: Send + Sync {
    /// Mirrors `CaptureFunctionDataTypesCmd.applyTo(Program, TaskMonitor)`.
    fn apply_to(&self, program: &dyn crate::program::model::listing::Program, monitor: &dyn crate::util::task::TaskMonitor) -> bool;

    /// Mirrors `CaptureFunctionDataTypesCmd.taskCompleted()`.
    fn task_completed(&self);
}

/// Placeholder for the unported Java type `FGController`, referenced by `FGVertex` and
/// [`FunctionGraphRunnable`](crate::app::plugin::core::functiongraph::mvc::function_graph_runnable::FunctionGraphRunnable).
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait FGController: Send + Sync {
    /// Port of `FGController.getModel()`.
    fn get_model(&self) -> Arc<dyn FGModel>;
}

/// Placeholder for the unported Java type `FGModel`, referenced by
/// [`FGController::get_model`] and
/// [`FunctionGraphRunnable`](crate::app::plugin::core::functiongraph::mvc::function_graph_runnable::FunctionGraphRunnable)'s
/// port of `FGModel.setFunctionGraphData(FunctionGraphRunnable, FGData)`.
///
/// `FGModel` is a concrete Java class (not an interface) that in turn constructs and owns
/// `FunctionGraphRunnable` instances -- a genuine type-level cycle in Java between the two
/// classes. Since `FunctionGraphRunnable` keeps its required concrete-struct shape (see its own
/// module docs), this stub breaks the cycle the same way the "Suggested stubs" convention does
/// for any other forward reference: it takes `&FunctionGraphRunnable` directly rather than
/// inventing a trait for it. Only the one package-private method `FunctionGraphRunnable.swingRun`
/// calls is modeled.
pub trait FGModel: Send + Sync {
    /// Port of (package-private) `FGModel.setFunctionGraphData(FunctionGraphRunnable, FGData)`.
    fn set_function_graph_data(
        &self,
        graph_runnable: &crate::app::plugin::core::functiongraph::mvc::function_graph_runnable::FunctionGraphRunnable,
        graph_data: &dyn FGData,
    );
}

/// Placeholder for the unported Java type `FunctionGraphVertexAttributes`, referenced by `FGVertex`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait FunctionGraphVertexAttributes: Send + Sync {}

/// Placeholder for the unported Java type `GroupHistoryInfo`, referenced by `FGVertex`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait GroupHistoryInfo: Send + Sync {}

/// Placeholder for the unported Java type `FGVertex`, referenced by `FGEdge`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait FGVertex: Send + Sync {
    fn clone_vertex(&self, new_controller: &dyn FGController) -> Box<dyn FGVertex>;
    fn write_settings(&self, settings: &dyn FunctionGraphVertexAttributes);
    fn read_settings(&self, settings: &dyn FunctionGraphVertexAttributes);
    fn restore_color(&self, color: &dyn crate::framework::seam_stubs::Color);
    fn get_user_defined_color(&self) -> Box<dyn crate::framework::seam_stubs::Color>;
    fn get_vertex_type(&self) -> crate::app::plugin::core::functiongraph::graph::fg_vertex_type::FgVertexType;
    fn set_vertex_type(&self, vertex_type: crate::app::plugin::core::functiongraph::graph::fg_vertex_type::FgVertexType);
    fn get_vertex_address(&self) -> Box<crate::program::model::address::Address>;
    fn is_entry(&self) -> bool;
    fn get_flow_type(&self) -> Box<dyn crate::program::seam_stubs::FlowType>;
    fn get_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView>;
    fn get_program(&self) -> Box<dyn crate::program::model::listing::Program>;
    fn get_listing_model(&self, address: &crate::program::model::address::Address) -> Box<dyn crate::app::util::viewer::listingpanel::listing_model::ListingModel>;
    fn get_default_background_color(&self) -> Box<dyn crate::framework::seam_stubs::Color>;
    fn get_background_color(&self) -> Box<dyn crate::framework::seam_stubs::Color>;
    fn get_selection_color(&self) -> Box<dyn crate::framework::seam_stubs::Color>;
    fn set_background_color(&self, color: &dyn crate::framework::seam_stubs::Color);
    fn clear_color(&self);
    fn update_group_association_status(&self, group_info: &dyn GroupHistoryInfo);
    fn get_group_info(&self) -> Box<dyn GroupHistoryInfo>;
    fn is_uncollapsed_group_member(&self) -> bool;
    fn get_title(&self) -> String;
    fn get_tool_tip_text(&self, event: &dyn crate::docking::seam_stubs::MouseEvent) -> String;
    fn get_tool_tip_component_for_edge(&self, edge: &dyn std::any::Any) -> Box<dyn std::any::Any>;
    fn get_tool_tip_component_for_vertex(&self) -> Box<dyn std::any::Any>;
    fn is_default_background_color(&self) -> bool;
    fn get_bounds(&self) -> Box<dyn std::any::Any>;
    fn contains_program_location(&self, location: &dyn crate::program::util::program_location::ProgramLocation) -> bool;
    fn contains_address(&self, address: &crate::program::model::address::Address) -> bool;
    fn set_program_location(&self, location: &dyn crate::program::util::program_location::ProgramLocation);
    fn set_program_selection(&self, selection: &dyn crate::util::seam_stubs::ProgramSelection);
    fn get_program_selection(&self) -> Box<dyn crate::util::seam_stubs::ProgramSelection>;
    fn get_text_selection(&self) -> String;
    fn set_program_highlight(&self, highlight: &dyn crate::util::seam_stubs::ProgramSelection);
    fn get_program_location(&self) -> Box<dyn crate::program::util::program_location::ProgramLocation>;
    fn get_cursor_bounds(&self) -> Box<dyn std::any::Any>;
    fn edit_label(&self, component: &dyn std::any::Any);
    fn is_header_click(&self, clicked_component: &dyn std::any::Any) -> bool;
    fn is_full_screen_mode(&self) -> bool;
    fn set_full_screen_mode(&self, full_screen: bool);
    fn get_maximized_view_component(&self) -> Box<dyn std::any::Any>;
    fn refresh_model(&self);
    fn refresh_display(&self);
    fn refresh_display_for_address(&self, address: &crate::program::model::address::Address);
    fn set_showing(&self, is_showing: bool);
    fn dispose(&self);
}

/// Placeholder for `ghidra.app.CorePluginPackage`, referenced by
/// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin)'s `@PluginInfo`
/// metadata before the real class is ported. Only its `NAME` is needed; the real class also
/// carries the package's icon and description.
pub struct CorePluginPackage;

impl CorePluginPackage {
    /// Mirrors `CorePluginPackage.NAME`.
    pub const NAME: &'static str = "Ghidra Core";
}

impl crate::framework::seam_stubs::PluginPackageLike for CorePluginPackage {
    fn name(&self) -> String {
        Self::NAME.to_string()
    }
}

/// Placeholder for `ghidra.app.events.ProgramLocationPluginEvent`, referenced by
/// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) before the real class
/// is ported. Java's version is a `final` class extending the abstract
/// `AbstractLocationPluginEvent`, so this is a concrete struct that composes a
/// [`PluginEvent`](crate::framework::plugintool::PluginEvent) the same way the already-ported
/// sibling events ([`ProgramActivatedPluginEvent`](crate::app::events::ProgramActivatedPluginEvent)
/// and friends) do. Only the ancestor's location/program accessors are modeled.
pub struct ProgramLocationPluginEvent {
    event: crate::framework::plugintool::PluginEvent,
    location: Arc<dyn ProgramLocation + Send + Sync>,
    program_ref: std::sync::Weak<dyn Program>,
}

impl ProgramLocationPluginEvent {
    /// Mirrors `ProgramLocationPluginEvent.NAME`.
    pub const NAME: &'static str = "ProgramLocationChange";

    /// Mirrors `ProgramLocationPluginEvent(String, ProgramLocation, Program)`. Java logs an error
    /// (but still constructs the event) when the location is null; a non-null location is required
    /// here instead.
    pub fn new(
        src: impl Into<String>,
        location: Arc<dyn ProgramLocation + Send + Sync>,
        program: Arc<dyn Program>,
    ) -> Self {
        Self {
            event: crate::framework::plugintool::PluginEvent::new(src, Self::NAME),
            location,
            program_ref: Arc::downgrade(&program),
        }
    }

    /// Mirrors `AbstractLocationPluginEvent.getLocation()`.
    pub fn get_location(&self) -> &Arc<dyn ProgramLocation + Send + Sync> {
        &self.location
    }

    /// Mirrors `AbstractLocationPluginEvent.getProgram()`, which reads a `WeakReference` and so
    /// returns `None` once the program has been closed.
    pub fn get_program(&self) -> StdOption<Arc<dyn Program>> {
        self.program_ref.upgrade()
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &crate::framework::plugintool::PluginEvent {
        &self.event
    }

    /// Unwraps the underlying `PluginEvent` so it can be fired through
    /// [`Plugin::fire_plugin_event`](crate::framework::plugintool::Plugin::fire_plugin_event),
    /// which takes the base event by value. The location/program payload is dropped in the
    /// process: this crate's `PluginEvent` has no subclass payload, so only the source and event
    /// name survive the trip through the tool.
    pub fn into_plugin_event(self) -> crate::framework::plugintool::PluginEvent {
        self.event
    }
}

/// Placeholder for `ghidra.app.events.ProgramSelectionPluginEvent`, referenced by
/// [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) before the real class
/// is ported. Shaped like [`ProgramLocationPluginEvent`] above, mirroring the abstract
/// `AbstractSelectionPluginEvent` ancestor's selection/program accessors.
pub struct ProgramSelectionPluginEvent {
    event: crate::framework::plugintool::PluginEvent,
    selection: Arc<dyn ProgramSelection>,
    program_ref: std::sync::Weak<dyn Program>,
}

impl ProgramSelectionPluginEvent {
    /// Mirrors `ProgramSelectionPluginEvent.NAME`.
    pub const NAME: &'static str = "ProgramSelection";

    /// Mirrors `ProgramSelectionPluginEvent(String, ProgramSelection, Program)`.
    pub fn new(
        src: impl Into<String>,
        selection: Arc<dyn ProgramSelection>,
        program: Arc<dyn Program>,
    ) -> Self {
        Self {
            event: crate::framework::plugintool::PluginEvent::new(src, Self::NAME),
            selection,
            program_ref: Arc::downgrade(&program),
        }
    }

    /// Mirrors `AbstractSelectionPluginEvent.getSelection()`.
    pub fn get_selection(&self) -> &Arc<dyn ProgramSelection> {
        &self.selection
    }

    /// Mirrors `AbstractSelectionPluginEvent.getProgram()`.
    pub fn get_program(&self) -> StdOption<Arc<dyn Program>> {
        self.program_ref.upgrade()
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &crate::framework::plugintool::PluginEvent {
        &self.event
    }

    /// Unwraps the underlying `PluginEvent`; see
    /// [`ProgramLocationPluginEvent::into_plugin_event`] for what is lost.
    pub fn into_plugin_event(self) -> crate::framework::plugintool::PluginEvent {
        self.event
    }
}

/// Placeholder for `ghidra.app.plugin.core.osgi.BundleStatus`, referenced by
/// [`BundleStatusChangeRequestListener`](crate::app::plugin::core::osgi::BundleStatusChangeRequestListener)
/// before the real class is ported. This stub exposes the methods needed by the listener.
pub trait BundleStatus: Send + Sync {
    /// Compares this bundle status with another.
    fn compare_to(&self, o: &dyn BundleStatus) -> i32;

    /// Returns whether this bundle is enabled.
    fn is_enabled(&self) -> bool;

    /// Sets the enabled state of this bundle.
    fn set_enabled(&self, is_enabled: bool);

    /// Returns whether this bundle is read-only.
    fn is_read_only(&self) -> bool;

    /// Returns the type of this bundle.
    fn get_type(&self) -> Box<dyn crate::program::seam_stubs::Type>;

    /// Returns whether this bundle is active.
    fn is_active(&self) -> bool;

    /// Sets the active state of this bundle.
    fn set_active(&self, is_active: bool);

    /// Sets the summary for this bundle.
    fn set_summary(&self, summary: &str);

    /// Gets the summary for this bundle.
    fn get_summary(&self) -> String;

    /// Returns the file for this bundle.
    fn get_file(&self) -> Box<dyn ResourceFile>;

    /// Returns whether the bundle's file exists.
    fn file_exists(&self) -> bool;

    /// Gets the path as a string.
    fn get_path_as_string(&self) -> String;

    /// Gets the location identifier.
    fn get_location_identifier(&self) -> String;
}

/// Placeholder for `ghidra.app.plugin.core.datamgr.tree.Category`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait Category: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.datamgr.tree.CategoryNode`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait CategoryNode: Send + Sync {}

/// Placeholder for `ghidra.framework.model.DomainObject`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait GTreeNode: Send + Sync {}

/// Placeholder for `ghidra.program.model.data.DataTypeManager`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait DataTypeManager: Send + Sync {}

/// Placeholder for `ghidra.program.model.data.CategoryPath`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait CategoryPath: Send + Sync {}

/// Placeholder for `ghidra.program.model.data.DataTypePath`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait DataTypePath: Send + Sync {}

/// Placeholder for `ghidra.program.model.data.SourceArchive`, referenced by
/// [`ArchiveNode`] before the real class is ported.
pub trait SourceArchive: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.datamgr.tree.ArchiveNode`, referenced by
/// [`crate::app::plugin::core::datamgr::tree::ArchiveRootNodeListener`] before the
/// real class is ported. This stub exposes the methods needed by the listener.
pub trait ArchiveNode: Send + Sync {
    /// Disposes this node.
    fn dispose(&self);

    /// Returns the icon for this node, expanded or collapsed.
    fn get_icon(&self, expanded: bool) -> Box<dyn crate::generic::seam_stubs::Icon>;

    /// Returns the name of this node.
    fn get_name(&self) -> String;

    /// Returns the tool tip text for this node.
    fn get_tool_tip(&self) -> String;

    /// Returns whether this node is a leaf node.
    fn is_leaf(&self) -> bool;

    /// Returns whether this node is editable.
    fn is_editable(&self) -> bool;

    /// Returns the archive associated with this node.
    fn get_archive(&self) -> Box<dyn Archive>;

    /// Called when the structure of this node has changed.
    fn structure_changed(&self);

    /// Called when this node has changed.
    fn node_changed(&self);

    /// Returns whether this node can be cut.
    fn can_cut(&self) -> bool;

    /// Returns whether this node is cut.
    fn is_cut(&self) -> bool;

    /// Compares this node with another object.
    fn equals(&self, o: &dyn std::any::Any) -> bool;

    /// Compares this node with another tree node.
    fn compare_to(&self, node: &dyn GTreeNode) -> i32;

    /// Returns the hash code for this node.
    fn hash_code(&self) -> i32;

    /// Returns this node as an ArchiveNode.
    fn get_archive_node(&self) -> Box<dyn ArchiveNode>;

    /// Returns whether this node is modifiable.
    fn is_modifiable(&self) -> bool;

    /// Finds a category node for the given category.
    fn find_category_node(&self, local_category: &dyn Category) -> Box<dyn CategoryNode>;

    /// Called when a category is added.
    fn category_added(&self, dtm: &dyn DataTypeManager, path: &dyn CategoryPath);

    /// Called when a category is moved.
    fn category_moved(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &dyn CategoryPath,
        new_path: &dyn CategoryPath,
    );

    /// Called when a category is removed.
    fn category_removed(&self, dtm: &dyn DataTypeManager, path: &dyn CategoryPath);

    /// Called when a category is renamed.
    fn category_renamed(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &dyn CategoryPath,
        new_path: &dyn CategoryPath,
    );

    /// Called when a data type is added.
    fn data_type_added(&self, dtm: &dyn DataTypeManager, path: &dyn DataTypePath);

    /// Called when favorites change.
    fn favorites_changed(&self, dtm: &dyn DataTypeManager, path: &dyn DataTypePath, is_favorite: bool);

    /// Called when a data type is changed.
    fn data_type_changed(&self, dtm: &dyn DataTypeManager, path: &dyn DataTypePath);

    /// Called when a data type is moved.
    fn data_type_moved(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &dyn DataTypePath,
        new_path: &dyn DataTypePath,
    );

    /// Called when a data type is removed.
    fn data_type_removed(&self, dtm: &dyn DataTypeManager, path: &dyn DataTypePath);

    /// Called when a data type is renamed.
    fn data_type_renamed(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &dyn DataTypePath,
        new_path: &dyn DataTypePath,
    );

    /// Called when a data type is replaced.
    fn data_type_replaced(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &dyn DataTypePath,
        new_path: &dyn DataTypePath,
        new_data_type: &dyn DataType,
    );

    /// Called when a source archive is added.
    fn source_archive_added(&self, manager: &dyn DataTypeManager, source_archive: &dyn SourceArchive);

    /// Called when a source archive is changed.
    fn source_archive_changed(&self, manager: &dyn DataTypeManager, source_archive: &dyn SourceArchive);

    /// Called when the program architecture is changed.
    fn program_architecture_changed(&self, manager: &dyn DataTypeManager);

    /// Called when the manager is restored.
    fn restored(&self, manager: &dyn DataTypeManager);
}

/// Placeholder for `ghidra.app.plugin.core.decompiler.taint.TaintPlugin`, referenced by
/// [`TaintState`](crate::app::plugin::core::decompiler::taint::taint_state::TaintState) before
/// the real class is ported. `TaintState` only ever holds/passes this reference (e.g. as the
/// argument to `newInstance`); it never calls a method on it, so no members are modeled yet.
pub trait TaintPlugin: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.decompiler.taint.TaintLabel`, referenced by
/// [`TaintState`](crate::app::plugin::core::decompiler::taint::taint_state::TaintState) before
/// the real class is ported. `TaintState` only ever holds/returns this reference; it never calls
/// a method on it, so no members are modeled yet.
pub trait TaintLabel: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.decompiler.taint.TaintOptions`, referenced by
/// [`TaintState`](crate::app::plugin::core::decompiler::taint::taint_state::TaintState) before
/// the real class is ported. `TaintState` only ever returns this reference; it never calls a
/// method on it, so no members are modeled yet.
pub trait TaintOptions: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.decompiler.taint.TaintQueryResult`, referenced by
/// [`TaintState`](crate::app::plugin::core::decompiler::taint::taint_state::TaintState) before
/// the real class is ported. `TaintState` only ever holds/returns this reference; it never calls
/// a method on it, so no members are modeled yet.
pub trait TaintQueryResult: Send + Sync {}

/// A `TaintState` implementor discovered by [`ClassSearcher::get_taint_state_classes`], standing
/// in for a Java `Class<? extends TaintState>` plus its `TaintPlugin`-arg constructor.
pub struct TaintStateClass {
    /// Mirrors `Class.getName()`, matched (lowercased) against the requested engine type by
    /// [`TaintState::new_instance`](crate::app::plugin::core::decompiler::taint::taint_state::TaintState).
    pub name: &'static str,
    /// Mirrors `Constructor<?>.newInstance(plugin)`.
    pub construct: fn(&dyn TaintPlugin) -> Box<dyn crate::app::plugin::core::decompiler::taint::taint_state::TaintState>,
}

/// Placeholder for the `ghidra.util.classfinder.ClassSearcher` lookup that
/// [`TaintState::new_instance`](crate::app::plugin::core::decompiler::taint::taint_state::TaintState)
/// needs, before the real class is ported. Modeled as a statics holder (Java's version is a class
/// of static methods), matching
/// [`script::seam_stubs::ClassSearcher`](crate::script::seam_stubs::ClassSearcher).
pub struct ClassSearcher;

impl ClassSearcher {
    /// Mirrors `ClassSearcher.getClasses(TaintState.class)`. Java discovers implementations by
    /// scanning the classpath for extension points; Rust has no equivalent runtime scan, so this
    /// yields nothing until a provider registry is ported.
    pub fn get_taint_state_classes() -> Vec<TaintStateClass> {
        Vec::new()
    }
}

/// Placeholder for `ghidra.plugins.fsbrowser.FSBFileHandlerContext`, referenced by
/// [`FSBFileHandler`](crate::app::fsbrowser::fsb_file_handler::FSBFileHandler) before the real
/// class is ported. Java's version is a record (not an interface), so this is a plain struct
/// rather than a `dyn`-dispatched trait, matching [`DockingAction`]'s convention. The Java source
/// declares no members yet, so none are modeled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FSBFileHandlerContext;

/// Placeholder for `ghidra.plugins.fsbrowser.FSBFileNode`, referenced by
/// [`FSBFileHandler`](crate::app::fsbrowser::fsb_file_handler::FSBFileHandler) before the real
/// class is ported. Java's version is a concrete `GTreeNode` subclass (not an interface), so this
/// is a plain struct rather than a `dyn`-dispatched trait, matching [`DockingAction`]'s
/// convention. `FSBFileHandler` only ever passes this type through as a parameter, so no fields
/// are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FSBFileNode;

/// Placeholder for the unported Java type `FunctionGraph`, referenced by `FGLayout`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait FunctionGraph: Send + Sync {
    fn group_description_changed(&self, old_text: &str, new_text: &str);
    fn find_matching_vertex(&self, v: &dyn FGVertex) -> Box<dyn FGVertex>;
    fn get_function(&self) -> Box<dyn std::any::Any>;
    fn restore_settings(&self);
    fn save_settings(&self);
    fn clear_vertex_color(&self, vertex: &dyn FGVertex);
    fn get_settings(&self) -> Box<dyn FunctionGraphVertexAttributes>;
    fn get_saved_grouped_vertex_settings(&self) -> Box<dyn std::any::Any>;
    fn get_saved_group_history(&self) -> Box<dyn std::any::Any>;
    fn get_saved_vertex_locations(&self) -> std::collections::HashMap<Box<dyn FGVertex>, Box<dyn std::any::Any>>;
    fn clear_saved_vertex_locations(&self);
    fn clear_all_user_layout_settings(&self);
    fn vertex_location_changed(&self, v: &dyn FGVertex, point: &dyn std::any::Any, change_type: &dyn std::any::Any);
    fn get_options(&self) -> Box<dyn std::any::Any>;
    fn set_options(&self, options: &dyn std::any::Any);
    fn set_graph_layout(&self, layout: &dyn FGLayout);
    fn get_layout(&self) -> Box<dyn FGLayout>;
    fn get_vertex_for_address(&self, address: &dyn std::any::Any) -> Box<dyn FGVertex>;
    fn set_program_selection(&self, selection: &dyn std::any::Any);
    fn set_program_highlight(&self, highlight: &dyn std::any::Any);
    fn get_ungrouped_vertices(&self) -> Vec<Box<dyn FGVertex>>;
    fn get_ungrouped_edges(&self) -> Vec<Box<dyn std::any::Any>>;
    fn get_group_history(&self, vertex: &dyn FGVertex) -> Box<dyn std::any::Any>;
    fn set_group_history(&self, history: Vec<Box<dyn std::any::Any>>);
    fn remove_from_group_history(&self, vertex: &dyn FGVertex);
    fn group_restored(&self, group: &dyn std::any::Any);
    fn group_added(&self, group: &dyn std::any::Any);
    fn group_removed(&self, group: &dyn std::any::Any);
    fn get_root_vertex(&self) -> Box<dyn FGVertex>;
    fn set_root_vertex(&self, root_vertex: &dyn FGVertex);
    fn get_program_selection_for_all_vertices(&self) -> Box<dyn std::any::Any>;
    fn get_entry_points(&self) -> Vec<Box<dyn FGVertex>>;
    fn get_exit_points(&self) -> Vec<Box<dyn FGVertex>>;
    fn dispose(&self);
    fn copy(&self) -> Box<dyn FunctionGraph>;
    fn create_dummy_sources(&self) -> Vec<Box<dyn std::any::Any>>;
    fn create_dummy_sinks(&self) -> Vec<Box<dyn std::any::Any>>;
    fn empty_copy(&self) -> Box<dyn std::any::Any>;
}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.FGColorProvider`, referenced by
/// [`FgEnv`](crate::app::plugin::core::functiongraph::mvc::fg_env::FgEnv) before the real
/// interface is ported. `FgEnv` only ever passes this type through opaquely, so no members are
/// needed yet. Genuine open extension point (two implementors, `IndependentColorProvider` and
/// `ToolBasedColorProvider`), so this stays a `dyn`-dispatched trait.
pub trait FGColorProvider: Send + Sync {}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider`,
/// referenced by [`FgEnv`](crate::app::plugin::core::functiongraph::mvc::fg_env::FgEnv) before
/// the real class is ported. Java's version is a concrete (abstract) class rather than an
/// interface, so this is a plain struct rather than a `dyn`-dispatched trait, matching
/// [`DockingAction`]'s convention. `FgEnv` only ever passes this type through as a return value,
/// so no fields are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FGLayoutProvider;

/// Placeholder for `ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions`, referenced by
/// [`FgEnv`](crate::app::plugin::core::functiongraph::mvc::fg_env::FgEnv) before the real class is
/// ported. Java's version is a concrete class (not an interface), so this is a plain struct rather
/// than a `dyn`-dispatched trait, matching [`DockingAction`]'s convention. `FgEnv` only ever
/// passes this type through as a return value, so no fields are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionGraphOptions;

/// Placeholder for the unported Java type `FGLayout`, referenced by `FunctionGraph`.
/// Forward reference stub to break the dependency cycle between FGLayout and FunctionGraph.
pub trait FGLayout: Send + Sync {}

/// Placeholder for `ghidra.graph.viewer.GraphPerspectiveInfo`, referenced by
/// [`FunctionGraphViewSettings`] and
/// [`CurrentFunctionGraphViewSettings`](crate::app::plugin::core::functiongraph::mvc::current_function_graph_view_settings::CurrentFunctionGraphViewSettings)
/// before the real (generic-over-vertex/edge) class is ported. Java's version is a concrete class
/// (not an interface), so this is a plain struct rather than a `dyn`-dispatched trait, matching
/// [`FGLayoutProvider`]'s convention. Only the "invalid" factory/predicate those two callers use
/// are modeled; the zoom/translate-coordinate accessors are left for a future caller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GraphPerspectiveInfo {
    // `pub(crate)` (rather than private) solely so in-crate tests of callers -- which have no
    // other way to build a "valid" instance, since the real (non-invalid) Java constructors take
    // an unported `RenderContext`/`SaveState` -- can construct one directly.
    pub(crate) invalid: bool,
}

impl GraphPerspectiveInfo {
    /// Mirrors the static factory `GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo()`.
    pub fn create_invalid() -> Self {
        GraphPerspectiveInfo { invalid: true }
    }

    /// Mirrors `GraphPerspectiveInfo.isInvalid()`.
    pub fn is_invalid(&self) -> bool {
        self.invalid
    }
}

impl Default for GraphPerspectiveInfo {
    fn default() -> Self {
        Self::create_invalid()
    }
}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphViewSettings`,
/// referenced by
/// [`CurrentFunctionGraphViewSettings`](crate::app::plugin::core::functiongraph::mvc::current_function_graph_view_settings::CurrentFunctionGraphViewSettings)
/// before the real class is ported. Java's version is a package-private abstract class (not an
/// interface) that simply holds the location/selection/highlight/perspective state shared by
/// `CurrentFunctionGraphViewSettings` and `PendingFunctionGraphViewSettings`; modeled here as the
/// concrete base state `CurrentFunctionGraphViewSettings` composes rather than extends (Rust has
/// no class inheritance).
#[derive(Default)]
pub struct FunctionGraphViewSettings {
    location: StdOption<Arc<dyn ProgramLocation + Send + Sync>>,
    selection: StdOption<Arc<dyn ProgramSelection>>,
    highlight: StdOption<Arc<dyn ProgramSelection>>,
    info: GraphPerspectiveInfo,
}

impl FunctionGraphViewSettings {
    /// Mirrors `FunctionGraphViewSettings.setLocation(ProgramLocation)`.
    pub fn set_location(&mut self, location: StdOption<Arc<dyn ProgramLocation + Send + Sync>>) {
        self.location = location;
    }

    /// Mirrors `FunctionGraphViewSettings.setSelection(ProgramSelection)`.
    pub fn set_selection(&mut self, selection: StdOption<Arc<dyn ProgramSelection>>) {
        self.selection = selection;
    }

    /// Mirrors `FunctionGraphViewSettings.setHighlight(ProgramSelection)`.
    pub fn set_highlight(&mut self, highlight: StdOption<Arc<dyn ProgramSelection>>) {
        self.highlight = highlight;
    }

    /// Mirrors `FunctionGraphViewSettings.setFunctionGraphPerspectiveInfo(GraphPerspectiveInfo)`.
    pub fn set_function_graph_perspective_info(&mut self, info: GraphPerspectiveInfo) {
        self.info = info;
    }

    /// Mirrors `FunctionGraphViewSettings.getLocation()`.
    pub fn get_location(&self) -> StdOption<Arc<dyn ProgramLocation + Send + Sync>> {
        self.location.clone()
    }

    /// Mirrors `FunctionGraphViewSettings.getSelection()`.
    pub fn get_selection(&self) -> StdOption<Arc<dyn ProgramSelection>> {
        self.selection.clone()
    }

    /// Mirrors `FunctionGraphViewSettings.getHighlight()`.
    pub fn get_highlight(&self) -> StdOption<Arc<dyn ProgramSelection>> {
        self.highlight.clone()
    }

    /// Mirrors `FunctionGraphViewSettings.getFunctionGraphPerspectiveInfo()`.
    pub fn get_function_graph_perspective_info(&self) -> GraphPerspectiveInfo {
        self.info
    }
}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.mvc.FGView`, referenced by
/// [`CurrentFunctionGraphViewSettings`](crate::app::plugin::core::functiongraph::mvc::current_function_graph_view_settings::CurrentFunctionGraphViewSettings)
/// before the real class is ported. Java's version is a concrete class (not an interface)
/// extending `VisualGraphView`; only the package-private location/selection/highlight/perspective
/// setters `CurrentFunctionGraphViewSettings` calls are modeled, backed by `RefCell` so the stub
/// can be held behind a shared `Arc` (the real `FGView` is likewise shared with the controller)
/// while still recording what was last pushed to it, which is what makes this placeholder
/// test-observable instead of a silent no-op.
#[derive(Default)]
pub struct FGView {
    location: std::cell::RefCell<StdOption<Arc<dyn ProgramLocation + Send + Sync>>>,
    selection: std::cell::RefCell<StdOption<Arc<dyn ProgramSelection>>>,
    highlight: std::cell::RefCell<StdOption<Arc<dyn ProgramSelection>>>,
    perspective: std::cell::RefCell<StdOption<GraphPerspectiveInfo>>,
}

impl FGView {
    /// Mirrors (package-private) `FGView.setLocation(ProgramLocation)`.
    pub fn set_location(&self, location: StdOption<Arc<dyn ProgramLocation + Send + Sync>>) {
        *self.location.borrow_mut() = location;
    }

    /// Returns the location most recently pushed via [`Self::set_location`].
    pub fn get_location(&self) -> StdOption<Arc<dyn ProgramLocation + Send + Sync>> {
        self.location.borrow().clone()
    }

    /// Mirrors (package-private) `FGView.setSelection(ProgramSelection)`.
    pub fn set_selection(&self, selection: StdOption<Arc<dyn ProgramSelection>>) {
        *self.selection.borrow_mut() = selection;
    }

    /// Returns the selection most recently pushed via [`Self::set_selection`].
    pub fn get_selection(&self) -> StdOption<Arc<dyn ProgramSelection>> {
        self.selection.borrow().clone()
    }

    /// Mirrors (package-private) `FGView.setHighlight(ProgramSelection)`.
    pub fn set_highlight(&self, highlight: StdOption<Arc<dyn ProgramSelection>>) {
        *self.highlight.borrow_mut() = highlight;
    }

    /// Returns the highlight most recently pushed via [`Self::set_highlight`].
    pub fn get_highlight(&self) -> StdOption<Arc<dyn ProgramSelection>> {
        self.highlight.borrow().clone()
    }

    /// Mirrors `VisualGraphView.setGraphPerspective(GraphPerspectiveInfo)`, inherited by `FGView`.
    pub fn set_graph_perspective(&self, info: GraphPerspectiveInfo) {
        *self.perspective.borrow_mut() = Some(info);
    }

    /// Returns the perspective most recently pushed via [`Self::set_graph_perspective`].
    pub fn get_graph_perspective(&self) -> StdOption<GraphPerspectiveInfo> {
        *self.perspective.borrow()
    }
}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.mvc.FGData`, referenced by
/// [`FGControllerListener`](crate::app::plugin::core::functiongraph::mvc::FGControllerListener)
/// before the real class is ported.
///
/// `FGData` is a concrete Java class, not an interface. However, it is used by the listener
/// only through method calls, so a trait placeholder is appropriate. Implementors of
/// `FGControllerListener` receive `FGData` through the `data_changed` callback.
pub trait FGData: Send + Sync {
    /// Port of `FGData.getFunctionGraph()`.
    fn get_function_graph(&self) -> Box<dyn FunctionGraph>;

    /// Port of `FGData.hasResults()`.
    fn has_results(&self) -> bool;

    /// Port of `FGData.getMessage()`.
    fn get_message(&self) -> String;

    /// Port of `FGData.containsLocation(ProgramLocation)`.
    fn contains_location(&self, location: &dyn ProgramLocation) -> bool;

    /// Port of `FGData.containsSelection(ProgramSelection)`.
    fn contains_selection(&self, selection: &dyn ProgramSelection) -> bool;

    /// Port of `FGData.getFunction()`.
    fn get_function(&self) -> Box<dyn crate::program::model::listing::Function>;

    /// Port of `FGData.getOptions()`.
    fn get_options(&self) -> &FunctionGraphOptions;

    /// Port of `FGData.dispose()`.
    fn dispose(&self);

    /// Port of `FGData.toString()`.
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.mvc.EmptyFunctionGraphData`, referenced
/// by [`FunctionGraphRunnable`](crate::app::plugin::core::functiongraph::mvc::function_graph_runnable::FunctionGraphRunnable)
/// before the real class is ported. Java's version `extends FGData` (a concrete subclass, not an
/// interface); this implements the [`FGData`] placeholder trait directly rather than modeling
/// inheritance. `getFunctionGraph`/`getOptions` mirror Java's `UnsupportedOperationException`
/// throws via `panic!`; `getFunction` has no Java-side null-safe equivalent on this port's
/// non-`Option` [`FGData::get_function`], so it also panics -- neither is called by any known
/// caller.
pub struct EmptyFunctionGraphData {
    message: String,
}

impl EmptyFunctionGraphData {
    /// Stands in for `new EmptyFunctionGraphData(String)`.
    pub fn new(message: impl Into<String>) -> Self {
        EmptyFunctionGraphData { message: message.into() }
    }
}

impl FGData for EmptyFunctionGraphData {
    fn get_function_graph(&self) -> Box<dyn FunctionGraph> {
        panic!("Empty data cannot have a graph")
    }

    fn has_results(&self) -> bool {
        false
    }

    fn get_message(&self) -> String {
        self.message.clone()
    }

    fn contains_location(&self, _location: &dyn ProgramLocation) -> bool {
        false
    }

    fn contains_selection(&self, _selection: &dyn ProgramSelection) -> bool {
        false
    }

    fn get_function(&self) -> Box<dyn crate::program::model::listing::Function> {
        panic!("Empty data has no function")
    }

    fn get_options(&self) -> &FunctionGraphOptions {
        panic!("Empty data cannot have a graph")
    }

    fn dispose(&self) {}

    fn to_string(&self) -> String {
        "EmptyFunctionGraphData".to_string()
    }
}

/// Placeholder for `ghidra.app.plugin.core.functiongraph.graph.FunctionGraphFactory`, referenced
/// by [`FunctionGraphRunnable`](crate::app::plugin::core::functiongraph::mvc::function_graph_runnable::FunctionGraphRunnable)
/// before the real class -- with its full vertex/edge/layout graph construction -- is ported.
/// Java's version is a `public class` of only `static` methods (never instantiated), so this is a
/// unit struct with associated functions, matching
/// [`BookmarkComparator`](crate::program::model::listing::bookmark_comparator::BookmarkComparator)'s
/// convention, rather than a `dyn`-dispatched trait. Only `createNewGraph`, the one static method
/// `FunctionGraphRunnable` calls, is modeled; it stands in for the real vertex/edge graph build by
/// always reporting "no data in function" via [`EmptyFunctionGraphData`], mirroring the real
/// method's own `graph.getVertices().size() == 0` empty-graph fallback. Note the real method's
/// declared `throws CancelledException` (not an I/O error), which this signature preserves.
pub struct FunctionGraphFactory;

impl FunctionGraphFactory {
    /// Stands in for `FunctionGraphFactory.createNewGraph(Function, FGController, Program,
    /// TaskMonitor)`.
    pub fn create_new_graph(
        function: &dyn crate::program::model::listing::Function,
        _controller: &dyn FGController,
        _program: &dyn Program,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn FGData>, crate::util::exception::CancelledException> {
        Ok(Box::new(EmptyFunctionGraphData::new(format!(
            "No data in function: {}",
            crate::program::model::listing::Function::get_name(function)
        ))))
    }
}

/// Placeholder for `ghidra.app.merge.MergeConstants`, referenced by
/// [`ListingMergeConstants`](crate::app::merge::listing::listing_merge_constants) before the
/// real class is ported.
///
/// `MergeConstants` is, like `ListingMergeConstants`, a Java constant-interface (no methods) --
/// so this stub is a plain module of `pub const`s rather than a trait, matching the shape the
/// real port will take. Only the four title strings `ListingMergeConstants` re-exposes are
/// modeled; add the rest when a real consumer needs them.
pub mod merge_constants {
    /// Port of `MergeConstants.RESULT_TITLE`.
    pub const RESULT_TITLE: &str = "Result";
    /// Port of `MergeConstants.ORIGINAL_TITLE`.
    pub const ORIGINAL_TITLE: &str = "Original";
    /// Port of `MergeConstants.LATEST_TITLE`.
    pub const LATEST_TITLE: &str = "Latest";
    /// Port of `MergeConstants.MY_TITLE`.
    pub const MY_TITLE: &str = "Checked Out";
}

/// Placeholder for `ghidra.program.util.MarkerLocation`, referenced by
/// [`MarkerClickedListener`](crate::app::util::viewer::listingpanel::MarkerClickedListener)
/// before the real class is ported. A `MarkerLocation` describes a location in a program where
/// the user clicked in the marker margin, providing access to the program, address, marker set,
/// and pixel coordinates of the click.
pub trait MarkerLocation: Send + Sync {
    /// Corresponds to `MarkerLocation.getProgram()`.
    fn get_program(&self) -> Box<dyn Program>;

    /// Corresponds to `MarkerLocation.getAddr()`.
    fn get_addr(&self) -> crate::program::model::address::Address;

    /// Corresponds to `MarkerLocation.getMarkerSet()`.
    fn get_marker_set(&self) -> Box<dyn MarkerSet>;

    /// Corresponds to `MarkerLocation.getX()`, the x-coordinate in pixels.
    fn get_x(&self) -> i32;

    /// Corresponds to `MarkerLocation.getY()`, the y-coordinate in pixels.
    fn get_y(&self) -> i32;

    /// Corresponds to `Object.hashCode()`.
    fn hash_code(&self) -> i32;

    /// Corresponds to `Object.equals(Object)`, downcasted as `Any` for safe dynamic dispatch.
    fn equals(&self, obj: &dyn std::any::Any) -> bool;
}

/// Placeholder for `ghidra.program.util.MarkerSet`, referenced by
/// [`MarkerLocation`](MarkerLocation) before the real class is ported. A `MarkerSet` is a
/// collection of markers that can be displayed in the listing margin, typically used to
/// highlight addresses of interest.
pub trait MarkerSet: Send + Sync {}
