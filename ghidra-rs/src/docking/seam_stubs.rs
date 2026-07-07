//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
/// Placeholder for `javax.swing.KeyStroke`. Already stubbed for
/// [`Options`](crate::framework::options::Options); re-exported here so
/// [`crate::docking::action::docking_action_if`] can reference the same placeholder rather than
/// defining a second, incompatible one.
pub use crate::framework::seam_stubs::KeyStroke;

/// Placeholder for `docking.ComponentProvider`, referenced by [`crate::docking::action_context`].
pub trait ComponentProvider {}

/// Placeholder for `docking.action.ActionContextProvider`, referenced by
/// [`crate::docking::action_context`].
pub trait ActionContextProvider {}

/// Placeholder for `java.awt.event.MouseEvent`, referenced by
/// [`crate::docking::action_context`].
pub trait MouseEvent {}

/// Placeholder for `java.awt.Component`, referenced by [`crate::docking::action_context`] and
/// [`crate::docking::action::docking_action_if`].
pub trait Component {}

/// Placeholder for `help.HelpDescriptor`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] (which extends it). That trait
/// never calls `getHelpObject`/`getHelpInfo` itself, so no members are needed yet.
pub trait HelpDescriptor {}

/// Placeholder for `java.beans.PropertyChangeListener`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before a Rust equivalent
/// exists. `DockingActionIf` only ever registers/unregisters this listener, never calls
/// `propertyChange` on it, so no members are needed yet.
pub trait PropertyChangeListener {}

/// Placeholder for `docking.action.MenuData`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before the real class is
/// ported. `DockingActionIf` only ever passes this type through as an opaque value, so no
/// members are needed yet.
pub trait MenuData {}

/// Placeholder for `docking.action.ToolBarData`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before the real class is
/// ported. `DockingActionIf` only ever passes this type through as an opaque value, so no
/// members are needed yet.
pub trait ToolBarData {}

/// Placeholder for `docking.action.KeyBindingData`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before the real class is
/// ported. `DockingActionIf` only ever passes this type through as an opaque value, so no
/// members are needed yet.
pub trait KeyBindingData {}

/// Placeholder for `docking.action.KeyBindingType`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before the real (Java `enum`)
/// type is ported. `DockingActionIf` only ever passes this type through as an opaque value, so
/// no members are needed yet.
pub trait KeyBindingType {}

/// Placeholder for `javax.swing.JButton`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before a Rust equivalent
/// exists. `DockingActionIf` only ever returns this type, so no members are needed yet.
pub trait JButton {}

/// Placeholder for `javax.swing.JMenuItem`, referenced by
/// [`crate::docking::action::docking_action_if::DockingActionIf`] before a Rust equivalent
/// exists. `DockingActionIf` only ever returns this type, so no members are needed yet.
pub trait JMenuItem {}
