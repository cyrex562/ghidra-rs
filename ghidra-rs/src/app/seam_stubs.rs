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

/// Placeholder for `ghidra.program.util.ProgramLocation`, referenced by
/// [`StringTranslationService`](crate::app::services::StringTranslationService) before the real
/// class is ported. `StringTranslationService` only ever passes this type through as a
/// parameter, so no members are needed yet.
pub trait ProgramLocation {}

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
/// [`MemorySearchService`](crate::app::services::MemorySearchService) before the real class is
/// ported. `MemorySearchService` only ever passes this type through as a parameter, so no
/// members are needed yet.
pub trait Navigatable {}

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
