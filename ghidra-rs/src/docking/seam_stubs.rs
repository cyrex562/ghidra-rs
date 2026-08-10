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

/// Placeholder for `java.awt.Color`, referenced by [`AttributedString`] before the real class is
/// ported. Carries no channel data -- callers only ever pass an existing `Color` value through to
/// a new `AttributedString`, they never inspect it -- so this is an opaque marker rather than an
/// RGBA struct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Color;

/// Placeholder for `java.awt.FontMetrics`, referenced by [`AttributedString`] before the real
/// class is ported. Carries no metric data for the same reason as [`Color`] above.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FontMetrics;

/// Placeholder for `docking.widgets.fieldpanel.field.AttributedString`, referenced by
/// [`AnnotatedStringHandler`](crate::app::util::viewer::field::annotated_string_handler::AnnotatedStringHandler)
/// and by
/// [`AddressAnnotatedStringHandler`](crate::app::util::viewer::field::address_annotated_string_handler::AddressAnnotatedStringHandler)
/// before the real class is ported. Java's version is a concrete container class (not an
/// interface), so this is a plain struct rather than a `dyn`-dispatched trait. Grown with a
/// `text` field plus the two constructors and two accessors `AddressAnnotatedStringHandler`
/// needs; `color`/`font_metrics`/`underline` are accepted (mirroring the Java constructor
/// signatures) but not stored, since no caller reads them back yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributedString {
    text: String,
}

impl AttributedString {
    /// Mirrors the 3-arg `AttributedString(String, Color, FontMetrics)` constructor.
    pub fn new(text: impl Into<String>, _color: Color, _font_metrics: FontMetrics) -> Self {
        Self { text: text.into() }
    }

    /// Mirrors the 5-arg `AttributedString(String, Color, FontMetrics, boolean, Color)`
    /// constructor.
    pub fn with_underline(
        text: impl Into<String>,
        _color: Color,
        _font_metrics: FontMetrics,
        _underline: bool,
        _underline_color: Option<Color>,
    ) -> Self {
        Self { text: text.into() }
    }

    /// Mirrors `AttributedString.getText()` (called `text()` per this crate's accessor
    /// convention).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Mirrors `AttributedString.getFontMetrics(int)`.
    pub fn get_font_metrics(&self, _char_index: i32) -> FontMetrics {
        FontMetrics
    }

    /// Mirrors `AttributedString.getColor(int)`.
    pub fn get_color(&self, _char_index: i32) -> Color {
        Color
    }
}
