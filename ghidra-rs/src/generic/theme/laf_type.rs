//! Port of the value side of `generic.theme.LafType`: the look-and-feel identities that
//! theme property files name as custom sections (`[Metal]`, `[Flat Dark]`, ...).
//!
//! Java's `isSupported()` (queries Swing's `UIManager`) and `getLookAndFeelManager()`
//! (Swing look-and-feel installation) are toolkit work and are not ported here.

use std::fmt;

/// A look and feel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LafType {
    /// "Metal"
    Metal,
    /// "Nimbus"
    Nimbus,
    /// "GTK+"
    Gtk,
    /// "CDE/Motif"
    Motif,
    /// "Flat Light"
    FlatLight,
    /// "Flat Dark" (uses dark defaults)
    FlatDark,
    /// "Windows"
    Windows,
    /// "Windows Classic"
    WindowsClassic,
    /// "Mac OS X"
    Mac,
}

impl LafType {
    /// `values()`, in declaration order.
    pub const ALL: [LafType; 9] = [
        LafType::Metal,
        LafType::Nimbus,
        LafType::Gtk,
        LafType::Motif,
        LafType::FlatLight,
        LafType::FlatDark,
        LafType::Windows,
        LafType::WindowsClassic,
        LafType::Mac,
    ];

    /// `getName()`: the Swing look-and-feel name, also the theme file section name.
    pub fn name(self) -> &'static str {
        match self {
            LafType::Metal => "Metal",
            LafType::Nimbus => "Nimbus",
            LafType::Gtk => "GTK+",
            LafType::Motif => "CDE/Motif",
            LafType::FlatLight => "Flat Light",
            LafType::FlatDark => "Flat Dark",
            LafType::Windows => "Windows",
            LafType::WindowsClassic => "Windows Classic",
            LafType::Mac => "Mac OS X",
        }
    }

    /// `getDisplayString()`: the name, except "Motif" for [`LafType::Motif`].
    pub fn display_string(self) -> &'static str {
        match self {
            LafType::Motif => "Motif",
            other => other.name(),
        }
    }

    /// `usesDarkDefaults()`
    pub fn uses_dark_defaults(self) -> bool {
        self == LafType::FlatDark
    }

    /// `fromName(name)`: exact (case-sensitive) name match.
    pub fn from_name(name: &str) -> Option<LafType> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }
}

impl fmt::Display for LafType {
    /// Java's `toString()` returns the display string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name_matches_java_names() {
        assert_eq!(LafType::from_name("Metal"), Some(LafType::Metal));
        assert_eq!(LafType::from_name("CDE/Motif"), Some(LafType::Motif));
        assert_eq!(LafType::from_name("GTK+"), Some(LafType::Gtk));
        assert_eq!(LafType::from_name("Mac OS X"), Some(LafType::Mac));
        assert_eq!(LafType::from_name("metal"), None);
        assert_eq!(LafType::from_name("Bogus"), None);
        for t in LafType::ALL {
            assert_eq!(LafType::from_name(t.name()), Some(t));
        }
    }

    #[test]
    fn display_and_dark_defaults() {
        assert_eq!(LafType::Motif.display_string(), "Motif");
        assert_eq!(LafType::Nimbus.display_string(), "Nimbus");
        assert_eq!(LafType::Motif.to_string(), "Motif");
        assert_eq!(LafType::Gtk.to_string(), "GTK+");
        assert!(LafType::FlatDark.uses_dark_defaults());
        assert!(!LafType::FlatLight.uses_dark_defaults());
    }
}
