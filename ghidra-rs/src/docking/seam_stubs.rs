//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::docking::settings::string_settings_definition::StringSettingsDefinition;

/// Placeholder for `docking.ComponentProvider`, referenced by [`crate::docking::action_context`].
pub trait ComponentProvider {}

/// Placeholder for `docking.action.ActionContextProvider`, referenced by
/// [`crate::docking::action_context`].
pub trait ActionContextProvider {}

/// Placeholder for `java.awt.event.MouseEvent`, referenced by
/// [`crate::docking::action_context`].
pub trait MouseEvent {}

/// Placeholder for `java.awt.Component`, referenced by [`crate::docking::action_context`].
pub trait Component {}
