//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.framework.options.ToolOptions`, referenced by
/// [`EclipseIntegrationService`](crate::app::services::EclipseIntegrationService) before the
/// real class is ported. `EclipseIntegrationService` only ever returns this type, so no members
/// are needed yet.
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
/// `StateEditor` before the real class is ported. `DebuggerControlService` only ever passes this
/// type through as a parameter/return value, so no members are needed yet.
pub trait DebuggerCoordinates {}
