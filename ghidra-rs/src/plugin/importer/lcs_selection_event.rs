//! Port of `ghidra.plugin.importer.LcsSelectionEvent`.

use std::fmt;

use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;

/// The kind of selection event, mirroring the nested `LcsSelectionEvent.Type` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    /// A language was selected in the UI.
    Selected,
    /// A language was picked (e.g., double-clicked) in the UI.
    Picked,
}

/// An event describing a language/compiler-spec selection made in the importer UI.
///
/// Port of `ghidra.plugin.importer.LcsSelectionEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcsSelectionEvent {
    lcs: LanguageCompilerSpecPair,
    event_type: Type,
}

impl LcsSelectionEvent {
    /// Port of `LcsSelectionEvent(LanguageCompilerSpecPair, Type)`.
    pub fn new(selection: LanguageCompilerSpecPair, event_type: Type) -> Self {
        LcsSelectionEvent { lcs: selection, event_type }
    }

    /// Port of `LcsSelectionEvent.getLcs()`.
    pub fn get_lcs(&self) -> &LanguageCompilerSpecPair {
        &self.lcs
    }

    /// Port of `LcsSelectionEvent.getType()`.
    pub fn get_type(&self) -> Type {
        self.event_type
    }
}

impl fmt::Display for LcsSelectionEvent {
    /// Port of `LcsSelectionEvent.toString()`: `"LSE{" + lcs + "}"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LSE{{{}}}", self.lcs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new("x86:LE:32:default", "gcc")
    }

    #[test]
    fn get_lcs_and_get_type_return_constructor_arguments() {
        let event = LcsSelectionEvent::new(pair(), Type::Selected);
        assert_eq!(event.get_lcs(), &pair());
        assert_eq!(event.get_type(), Type::Selected);
    }

    #[test]
    fn picked_type_is_distinguishable_from_selected() {
        let event = LcsSelectionEvent::new(pair(), Type::Picked);
        assert_eq!(event.get_type(), Type::Picked);
        assert_ne!(event.get_type(), Type::Selected);
    }

    #[test]
    fn to_string_matches_java_format() {
        let event = LcsSelectionEvent::new(pair(), Type::Selected);
        assert_eq!(event.to_string(), "LSE{x86:LE:32:default:gcc}");
    }

    #[test]
    fn equality_compares_lcs_and_type() {
        let a = LcsSelectionEvent::new(pair(), Type::Selected);
        let b = LcsSelectionEvent::new(pair(), Type::Selected);
        let c = LcsSelectionEvent::new(pair(), Type::Picked);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
