//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::app::decompiler::{
    ClangLine, ClangNode, ClangTokenBase, ClangTokenGroup, DecompiledFunction,
};
use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::model::target::path::KeyPath;
use crate::trace::model::thread::TraceThread;
use crate::trace::model::trace::Trace;

/// Placeholder for `ghidra.framework.options.ToolOptions`, referenced by
/// [`EclipseIntegrationService`](crate::app::services::EclipseIntegrationService) and
/// [`VSCodeIntegrationService`](crate::app::services::VSCodeIntegrationService) before the
/// real class is ported. Both services only ever return this type, so no members are needed yet.
pub trait ToolOptions {}

/// Placeholder for `ghidra.app.util.importer.MessageLog`, referenced by
/// [`Analyzer`](crate::app::services::Analyzer) before the real class is ported. `Analyzer` only
/// ever passes this type through as a parameter, so no members are needed yet.
pub trait MessageLog {}

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

/// Placeholder for `ghidra.debug.api.platform.DebuggerPlatformMapper`, referenced by
/// [`DebuggerPlatformService`](crate::app::services::DebuggerPlatformService) before the real
/// class is ported. `DebuggerPlatformService` only ever passes this type through as a
/// parameter/return value, so no members are needed yet.
pub trait DebuggerPlatformMapper {}

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
    fn get_focus(&self) -> Option<KeyPath> {
        unimplemented!("Target::get_focus placeholder not overridden")
    }

    /// Find the thread containing the object at the given path.
    ///
    /// Mirrors `Target.getThreadForSuccessor(KeyPath)`.
    fn get_thread_for_successor(&self, path: &KeyPath) -> Option<Box<dyn TraceThread>> {
        let _ = path;
        unimplemented!("Target::get_thread_for_successor placeholder not overridden")
    }

    /// Find the stack frame containing the object at the given path.
    ///
    /// Mirrors `Target.getStackFrameForSuccessor(KeyPath)`.
    fn get_stack_frame_for_successor(&self, path: &KeyPath) -> Option<Box<dyn TraceStackFrame>> {
        let _ = path;
        unimplemented!("Target::get_stack_frame_for_successor placeholder not overridden")
    }
}

/// Placeholder for `ghidra.debug.api.target.TargetPublicationListener`, referenced by
/// [`DebuggerTargetService`](crate::app::services::DebuggerTargetService) before the real class
/// is ported. `DebuggerTargetService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait TargetPublicationListener {}

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

/// Placeholder for `ghidra.debug.api.tracermi.TraceRmiConnection`, referenced by
/// [`TraceRmiService`](crate::app::services::TraceRmiService) before the real interface is
/// ported. `TraceRmiService` only ever passes this type through as a return value, so no members
/// are needed yet.
pub trait TraceRmiConnection {}

/// Placeholder for `ghidra.debug.api.tracermi.TraceRmiAcceptor`, referenced by
/// [`TraceRmiService`](crate::app::services::TraceRmiService) before the real interface is
/// ported. `TraceRmiService` only ever passes this type through as a return value, so no members
/// are needed yet.
pub trait TraceRmiAcceptor {}

/// Placeholder for `ghidra.debug.api.tracermi.TraceRmiServiceListener`, referenced by
/// [`TraceRmiService`](crate::app::services::TraceRmiService) before the real interface is
/// ported. `TraceRmiService` only ever passes this type through as a parameter, so no members
/// are needed yet.
pub trait TraceRmiServiceListener {}

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
    fn error(&self) -> Option<&(dyn std::error::Error + Send + Sync)>;
}

/// Placeholder for `ghidra.app.services.GoToOverrideService`, referenced by
/// [`GoToService`](crate::app::services::GoToService) before the real interface is ported.
/// `GoToService` only ever passes this type through as a parameter/return value, so no members
/// are needed yet. Bounded by `Send + Sync` to match `GoToService`'s own `Send + Sync` bound
/// (an implementor holding `Arc<dyn GoToOverrideService>` can only itself be `Send + Sync` if
/// this is too).
pub trait GoToOverrideService: Send + Sync {}

/// Placeholder for `ghidra.service.graph.GraphDisplayProvider`, referenced by
/// [`GraphDisplayBroker`](crate::app::services::GraphDisplayBroker) before the real class is
/// ported. `GraphDisplayBroker` only ever passes this type through as a parameter/return value,
/// so no members are needed yet.
pub trait GraphDisplayProvider {}

/// Placeholder for `ghidra.service.graph.GraphDisplay`, referenced by
/// [`GraphDisplayBroker`](crate::app::services::GraphDisplayBroker) before the real class is
/// ported. `GraphDisplayBroker` only ever returns this type, so no members are needed yet.
pub trait GraphDisplay {}

/// Placeholder for `ghidra.debug.api.modules.DebuggerAddressTranslator`, the base interface
/// extended by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real interface is ported. `DebuggerStaticMappingService` does not itself call any
/// `DebuggerAddressTranslator` members, so no members are needed yet.
pub trait DebuggerAddressTranslator {}

/// Placeholder for `ghidra.debug.api.modules.MapEntry`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. Java's `MapEntry<?, ?>` wildcard generics are dropped, since this
/// crate has no generic parameters to substitute yet. `DebuggerStaticMappingService` only ever
/// passes this type through as a parameter, so no members are needed yet.
pub trait MapEntry {}

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
    fn get_fsrl(&self) -> Option<Box<dyn crate::filesystem::gfilesystem::fsrl::Fsrl>>;

    /// Stands in for `ByteProvider.getName()`.
    fn get_name(&self) -> Option<String>;
}

/// Placeholder for `ghidra.app.util.Option`, referenced by
/// [`Loader`](crate::app::util::opinion::loader::Loader) before the real class is ported.
/// `Loader` only ever passes lists of this type through as a parameter/return value, so no
/// members are needed yet.
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
    ) -> Option<std::sync::Arc<crate::program::model::lang::sleigh::constructor::Constructor>>;

    /// Stands in for `ConstructState.getSubState(int)`.
    fn sub_state(&self, index: i32) -> std::sync::Arc<dyn ConstructState>;

    /// Stands in for `ConstructState.getParent()`.
    fn parent(&self) -> Option<std::sync::Arc<dyn ConstructState>>;
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
        space: Option<&crate::program::model::address::AddressSpace>,
    ) -> std::collections::BTreeSet<i64>;

    /// Suggest up to `max` label names having the given prefix, optionally scoped to an address
    /// space.
    ///
    /// Mirrors `AssemblyNumericSymbols.getSuggestions(String, AddressSpace, int)`.
    fn get_suggestions(
        &self,
        got: &str,
        space: Option<&crate::program::model::address::AddressSpace>,
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
/// [`DebuggerListingService`](crate::app::services::DebuggerListingService) before the real class
/// is ported. `DebuggerListingService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait ProgramSelection {}

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
pub trait ListingActionContext {}

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
    pub field_name: Option<String>,
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

/// Placeholder trait for `ghidra.app.decompiler.component.DecompilerPanel`.
pub trait DecompilerPanel: Send + Sync {}

/// Placeholder trait for `ghidra.app.decompiler.component.margin.DecompilerMarginProvider`.
pub trait DecompilerMarginProvider: Send + Sync {}

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
