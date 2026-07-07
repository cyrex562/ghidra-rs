//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.docking.settings.StringSettingsDefinition`, referenced by
/// [`Settings`](crate::docking::settings::settings::Settings)
/// before the real interface is ported.
pub trait StringSettingsDefinition {}
