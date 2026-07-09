//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.framework.options.ToolOptions`, referenced by
/// [`EclipseIntegrationService`](crate::app::services::EclipseIntegrationService) before the
/// real class is ported. `EclipseIntegrationService` only ever returns this type, so no members
/// are needed yet.
pub trait ToolOptions {}
