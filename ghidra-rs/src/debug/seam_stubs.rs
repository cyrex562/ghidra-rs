//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.debug.api.action.LocationTrackingSpec`, referenced by
/// [`DebuggerListing`](crate::debug::api::listing::DebuggerListing) before the real class is
/// ported. `DebuggerListing` only ever passes this type through as a parameter (`setTrackingSpec`),
/// so no members are needed yet.
pub trait LocationTrackingSpec {}
