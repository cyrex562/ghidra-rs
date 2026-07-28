//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

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

/// Placeholder for `ghidra.debug.api.tracemgr.DebuggerCoordinates`, referenced by
/// [`DebuggerControlService`](crate::app::services::DebuggerControlService) and its nested
/// `StateEditor`, and by
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService), before the
/// real class is ported. Both services only ever pass this type through as a parameter/return
/// value, so no members are needed yet.
pub trait DebuggerCoordinates {}

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

/// Placeholder for `ghidra.debug.api.platform.DebuggerPlatformMapper`, referenced by
/// [`DebuggerPlatformService`](crate::app::services::DebuggerPlatformService) before the real
/// class is ported. `DebuggerPlatformService` only ever passes this type through as a
/// parameter/return value, so no members are needed yet.
pub trait DebuggerPlatformMapper {}

/// Placeholder for `ghidra.trace.model.target.TraceObject`, referenced by
/// [`DebuggerPlatformService`](crate::app::services::DebuggerPlatformService) and
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService) before the
/// real class is ported. Both services only ever pass this type through as a parameter/return
/// value, so no members are needed yet.
pub trait TraceObject {}

/// Placeholder for `ghidra.debug.api.target.Target`, referenced by
/// [`DebuggerTargetService`](crate::app::services::DebuggerTargetService) and
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService) before the
/// real class is ported. Both services only ever pass this type through as a parameter/return
/// value, so no members are needed yet.
pub trait Target {}

/// Placeholder for `ghidra.debug.api.target.TargetPublicationListener`, referenced by
/// [`DebuggerTargetService`](crate::app::services::DebuggerTargetService) before the real class
/// is ported. `DebuggerTargetService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait TargetPublicationListener {}

/// Placeholder for `ghidra.app.util.viewer.format.FormatManager`, referenced by
/// [`CodeFormatService`](crate::app::services::CodeFormatService) before the real class is
/// ported. `CodeFormatService` only ever returns this type, so no members are needed yet.
pub trait FormatManager {}

/// Placeholder for `ghidra.app.plugin.core.datamgr.archive.Archive`, referenced by
/// [`DataTypeArchiveService`](crate::app::services::DataTypeArchiveService) before the real
/// class is ported. `DataTypeArchiveService` only ever returns this type, so no members are
/// needed yet.
pub trait Archive {}

/// Placeholder for `ghidra.app.nav.Navigatable`, referenced by
/// [`MemorySearchService`](crate::app::services::MemorySearchService) (which only ever passes
/// this type through as a parameter) and by
/// [`NavigatableActionContext`](crate::app::context::NavigatableActionContext) (whose
/// `is_active_program` default method mirrors `NavigatableActionContext.isActiveProgram()`,
/// which calls `Navigatable.isConnected()`) before the real class is ported.
pub trait Navigatable {
    /// Stands in for `Navigatable.isConnected()`.
    fn is_connected(&self) -> bool;
}

/// Placeholder for `ghidra.features.base.memsearch.gui.SearchSettings`, referenced by
/// [`MemorySearchService`](crate::app::services::MemorySearchService) before the real class is
/// ported. `MemorySearchService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait SearchSettings {}

/// Placeholder for `ghidra.app.services.ViewService`, the base interface extended by
/// [`ViewManagerService`](crate::app::services::ViewManagerService) before the real class is
/// ported. `ViewManagerService` does not itself call any `ViewService` members, so no members
/// are needed yet.
pub trait ViewService {}

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

/// Placeholder for `ghidra.debug.api.emulation.EmulatorFactory`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService) before the real
/// class is ported. `DebuggerEmulationService` only ever passes this type through as a
/// parameter/return value, so no members are needed yet.
pub trait EmulatorFactory {}

/// Placeholder for `ghidra.pcode.emu.PcodeMachine`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService) and its nested
/// `CachedEmulator` before the real class is ported. Java's `PcodeMachine<?>` wildcard is
/// dropped, since this crate has no generic parameter to substitute yet.
/// `DebuggerEmulationService` only ever passes this type through as a parameter/return value, so
/// no members are needed yet.
pub trait PcodeMachine {}

/// Placeholder for `ghidra.trace.model.time.schedule.TraceSchedule`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService) and
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService) before the
/// real class is ported. Both services only ever pass this type through as a parameter/return
/// value, so no members are needed yet.
// `Send` so an `EmulationResult` holding a `Box<dyn TraceSchedule>` can cross threads,
// as required by the `+ Send` `RunFuture` (ports Java's `CompletableFuture<EmulationResult>`).
pub trait TraceSchedule: Send {}

/// Placeholder for `ghidra.trace.model.time.schedule.Scheduler`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService) before the real
/// class is ported. `DebuggerEmulationService` only ever passes this type through as a
/// parameter, so no members are needed yet.
pub trait Scheduler {}

/// Placeholder for `ghidra.trace.model.guest.TracePlatform`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService) and
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService) before the
/// real class is ported. Both services only ever pass this type through as a parameter/return
/// value, so no members are needed yet.
pub trait TracePlatform {}

/// Placeholder for `ghidra.trace.model.thread.TraceThread`, referenced by
/// [`DebuggerTraceManagerService`](crate::app::services::DebuggerTraceManagerService) before the
/// real class is ported. `DebuggerTraceManagerService` only ever passes this type through as a
/// parameter/return value, so no members are needed yet.
pub trait TraceThread {}

/// Placeholder for `ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer`, referenced by
/// [`DebuggerEmulationService`](crate::app::services::DebuggerEmulationService)'s nested
/// `CachedEmulator` before the real class is ported. `CachedEmulator` only ever stores and
/// returns this type opaquely, so no members are needed yet.
pub trait Writer {}

/// Placeholder for `ghidra.trace.model.time.schedule.Scheduler.RunResult`, the base interface
/// extended by `DebuggerEmulationService.EmulationResult` before the real `Scheduler` class is
/// ported. Models the two accessors that `EmulationResult` and `RecordEmulationResult`
/// (both in [`debugger_emulation_service`](crate::app::services::debugger_emulation_service))
/// build on.
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
/// are needed yet.
pub trait GoToOverrideService {}

/// Placeholder for `ghidra.service.graph.GraphDisplayProvider`, referenced by
/// [`GraphDisplayBroker`](crate::app::services::GraphDisplayBroker) before the real class is
/// ported. `GraphDisplayBroker` only ever passes this type through as a parameter/return value,
/// so no members are needed yet.
pub trait GraphDisplayProvider {}

/// Placeholder for `ghidra.service.graph.GraphDisplay`, referenced by
/// [`GraphDisplayBroker`](crate::app::services::GraphDisplayBroker) before the real class is
/// ported. `GraphDisplayBroker` only ever returns this type, so no members are needed yet.
pub trait GraphDisplay {}

/// Placeholder for `ghidra.program.model.block.CodeBlockModel`, referenced by
/// [`BlockModelService`](crate::app::services::BlockModelService) before the real class is
/// ported. `BlockModelService` only ever passes/returns this type opaquely (and registers
/// factories for it), so no members are needed yet.
pub trait CodeBlockModel {}

/// Placeholder for `ghidra.debug.api.modules.DebuggerAddressTranslator`, the base interface
/// extended by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real interface is ported. `DebuggerStaticMappingService` does not itself call any
/// `DebuggerAddressTranslator` members, so no members are needed yet.
pub trait DebuggerAddressTranslator {}

/// Placeholder for `ghidra.trace.model.TraceLocation`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through as
/// a parameter, so no members are needed yet.
pub trait TraceLocation {}

/// Placeholder for `ghidra.trace.model.modules.TraceConflictedMappingException`, thrown by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. Extends `std::error::Error` so it can stand in for the Java checked
/// exception as a boxed `Result` error.
pub trait TraceConflictedMappingException: std::error::Error {}

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

/// Placeholder for `ghidra.trace.model.modules.TraceModule`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through
/// as a parameter, so no members are needed yet.
pub trait TraceModule {}

/// Placeholder for `ghidra.trace.model.modules.TraceSection`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through
/// as a parameter, so no members are needed yet.
pub trait TraceSection {}

/// Placeholder for `ghidra.trace.model.memory.TraceMemoryRegion`, referenced by
/// [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService) before
/// the real class is ported. `DebuggerStaticMappingService` only ever passes this type through
/// as a parameter, so no members are needed yet.
pub trait TraceMemoryRegion {}

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

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver`, referenced by
/// [`AssemblyResolvedBackfill::solve`](crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill::solve)
/// before the real class is ported. `AssemblyResolvedBackfill::solve` only ever passes this type
/// through as a parameter, so no members are needed yet.
pub trait RecursiveDescentSolver {}

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

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns`, referenced by
/// [`AssemblyResolvedBackfill::solve`](crate::app::plugin::assembler::sleigh::sem::AssemblyResolvedBackfill::solve)
/// and by [`AssemblySelector`](crate::app::plugin::assembler::AssemblySelector) before the real
/// class is ported. Extends the crate's already-ported
/// [`AssemblyResolution`](crate::app::plugin::assembler::sleigh::sem::AssemblyResolution) trait,
/// mirroring the Java interface's `extends AssemblyResolution`. `AssemblyResolvedBackfill::solve`
/// only ever passes this type through as a parameter, so it needed no further members;
/// `AssemblySelector` additionally sorts resolutions by encoded length/bits and re-masks the
/// chosen one, so it needs `getInstructionLength()`, `getInstruction()`, and `getContext()` too.
pub trait AssemblyResolvedPatterns:
    crate::app::plugin::assembler::sleigh::sem::AssemblyResolution
{
    /// Mirrors `AssemblyResolvedPatterns.getInstructionLength()`.
    fn get_instruction_length(&self) -> i32;

    /// Mirrors `AssemblyResolvedPatterns.getInstruction()`.
    fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock>;

    /// Mirrors `AssemblyResolvedPatterns.getContext()`.
    fn get_context(&self) -> Box<dyn AssemblyPatternBlock>;
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock`, referenced by
/// [`AssemblyResolvedPatterns`] and by
/// [`AssemblySelector`](crate::app::plugin::assembler::AssemblySelector) before the real class is
/// ported. `AssemblySelector` only ever reads the raw instruction bytes (to compare two candidate
/// encodings by length, then lexicographically) and asks for a fully-masked copy of the chosen
/// encoding, so only `getVals()` and `fillMask()` are needed.
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
    Patterns(Box<dyn AssemblyResolvedPatterns>),
}

/// Placeholder for `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults`, referenced
/// by [`AssemblySelector`](crate::app::plugin::assembler::AssemblySelector) before the real class
/// is ported. Java's version is a `Set<AssemblyResolution>` decorator; `AssemblySelector` only
/// ever iterates it, so this stub exposes that as a single method returning already-discriminated
/// [`AssemblyResolutionEntry`] values (see its docs for why).
pub trait AssemblyResolutionResults {
    /// Mirrors iterating `AssemblyResolutionResults` (a `Set<AssemblyResolution>`).
    fn resolutions(&self) -> Vec<AssemblyResolutionEntry>;
}

/// Placeholder for `ghidra.app.plugin.assembler.AssemblySyntaxException`, thrown by
/// [`AssemblySelector::filter_parse`](crate::app::plugin::assembler::AssemblySelector::filter_parse)'s
/// default implementation before the real class is ported. Extends `std::error::Error` so it can
/// stand in for the Java checked exception as a boxed `Result` error, mirroring
/// [`TraceConflictedMappingException`].
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
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) before the
/// real class is ported. Distinct from
/// [`crate::program::model::lang::sleigh::constructor::Constructor`] (a port of the unrelated
/// `ghidra.pcodeCPort.slghsymbol.Constructor` backend class). `AssemblyGrammar` only ever passes
/// this type through as a parameter, so no members are needed yet.
pub trait Constructor {}

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
