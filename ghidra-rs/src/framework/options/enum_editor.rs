use std::collections::HashSet;
use std::fmt;

/// Trait for enum-like types whose complete set of variants can be listed and whose current
/// variant can report its declared name.
///
/// Stands in for the reflection the Java `EnumEditor` performs (`value.getClass().getMethod(
/// "values")`) to discover the constants of whatever `Enum<?>` subclass it currently holds.
/// Rust has no such runtime reflection, but it also doesn't need it: the concrete enum type is
/// known statically as [`EnumEditor`]'s type parameter, so implementing this trait for a
/// concrete enum plays the role that `Class.getMethod("values")` played in Java.
pub trait EnumValues: Sized {
    /// All variants of this enum, in declaration order. Mirrors `Enum.values()`.
    fn all_values() -> &'static [Self];

    /// This variant's declared name. Mirrors `Enum.name()`.
    fn variant_name(&self) -> &'static str;
}

/// A property editor for enum values.
///
/// Port of `ghidra.framework.options.EnumEditor`.
///
/// The Java implementation extends `PropertyEditorSupport` and stores its value as an untyped
/// `Enum<?>`, using reflection to invoke the static `values()` method of whatever enum class it
/// currently holds; reflection failures are caught and logged via `Msg.error`. This port is
/// generic over an [`EnumValues`] implementation instead, so the enum type is fixed at compile
/// time and the reflection failure path has no Rust equivalent. As a consequence
/// [`EnumEditor::get_tags`] and [`EnumEditor::get_enums`] no longer depend on a value having
/// been set first (in Java both would throw a `NullPointerException` if `value` was `null`, since
/// `value.getClass()` requires a non-null receiver).
///
/// `firePropertyChange()`, part of the JavaBeans event system, has no Rust equivalent and is
/// omitted, matching the other editors in this module (e.g. `StringWithChoicesEditor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumEditor<T> {
    value: Option<T>,
}

impl<T> Default for EnumEditor<T> {
    fn default() -> Self {
        Self { value: None }
    }
}

impl<T> EnumEditor<T>
where
    T: EnumValues + Clone + fmt::Display + 'static,
{
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current value, or `None` if no value has been set.
    pub fn get_value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Sets the current value.
    pub fn set_value(&mut self, value: T) {
        self.value = Some(value);
    }

    /// Returns a display label for every variant of `T`, in declaration order.
    ///
    /// A variant's `Display` output is used unless it collides with an earlier variant's label,
    /// in which case the variant's declared name is used instead.
    pub fn get_tags(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut choices = Vec::new();
        for variant in T::all_values() {
            let mut label = variant.to_string();
            if seen.contains(&label) {
                label = variant.variant_name().to_owned();
            }
            seen.insert(label.clone());
            choices.push(label);
        }
        choices
    }

    /// Returns every variant of `T`, in declaration order.
    pub fn get_enums(&self) -> &'static [T] {
        T::all_values()
    }

    /// Returns the current value's display text, or `None` if no value has been set.
    pub fn get_as_text(&self) -> Option<String> {
        self.value.as_ref().map(|v| v.to_string())
    }

    /// Sets the current value to the variant whose `Display` output equals `text`.
    ///
    /// Leaves the current value unchanged if no variant matches, matching the Java
    /// implementation (which only assigns `value` inside the matching branch of its loop).
    pub fn set_as_text(&mut self, text: &str) {
        if let Some(found) = T::all_values().iter().find(|v| v.to_string() == text) {
            self.value = Some(found.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Suit {
        Clubs,
        Diamonds,
        Hearts,
        Spades,
    }

    impl EnumValues for Suit {
        fn all_values() -> &'static [Self] {
            &[Suit::Clubs, Suit::Diamonds, Suit::Hearts, Suit::Spades]
        }

        fn variant_name(&self) -> &'static str {
            match self {
                Suit::Clubs => "Clubs",
                Suit::Diamonds => "Diamonds",
                Suit::Hearts => "Hearts",
                Suit::Spades => "Spades",
            }
        }
    }

    impl fmt::Display for Suit {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.variant_name())
        }
    }

    /// An enum whose `Display` output collides across variants, exercising the
    /// dedup-via-`variant_name` fallback in [`EnumEditor::get_tags`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Confusable {
        A,
        B,
    }

    impl EnumValues for Confusable {
        fn all_values() -> &'static [Self] {
            &[Confusable::A, Confusable::B]
        }

        fn variant_name(&self) -> &'static str {
            match self {
                Confusable::A => "A",
                Confusable::B => "B",
            }
        }
    }

    impl fmt::Display for Confusable {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("same")
        }
    }

    #[test]
    fn new_editor_has_no_value() {
        let editor: EnumEditor<Suit> = EnumEditor::new();
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn set_and_get_value() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_value(Suit::Hearts);
        assert_eq!(editor.get_value(), Some(&Suit::Hearts));
    }

    #[test]
    fn set_value_overwrites_previous() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_value(Suit::Clubs);
        editor.set_value(Suit::Spades);
        assert_eq!(editor.get_value(), Some(&Suit::Spades));
    }

    #[test]
    fn get_tags_lists_all_variants_in_order() {
        let editor: EnumEditor<Suit> = EnumEditor::new();
        assert_eq!(
            editor.get_tags(),
            vec!["Clubs", "Diamonds", "Hearts", "Spades"]
        );
    }

    #[test]
    fn get_tags_available_without_a_value_set() {
        let editor: EnumEditor<Suit> = EnumEditor::new();
        assert!(editor.get_value().is_none());
        assert_eq!(editor.get_tags().len(), 4);
    }

    #[test]
    fn get_tags_falls_back_to_variant_name_on_collision() {
        let editor: EnumEditor<Confusable> = EnumEditor::new();
        assert_eq!(editor.get_tags(), vec!["same", "B"]);
    }

    #[test]
    fn get_enums_returns_all_variants() {
        let editor: EnumEditor<Suit> = EnumEditor::new();
        assert_eq!(
            editor.get_enums(),
            &[Suit::Clubs, Suit::Diamonds, Suit::Hearts, Suit::Spades]
        );
    }

    #[test]
    fn get_as_text_none_when_no_value() {
        let editor: EnumEditor<Suit> = EnumEditor::new();
        assert_eq!(editor.get_as_text(), None);
    }

    #[test]
    fn get_as_text_with_value() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_value(Suit::Diamonds);
        assert_eq!(editor.get_as_text(), Some("Diamonds".to_owned()));
    }

    #[test]
    fn set_as_text_matches_variant() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_as_text("Spades");
        assert_eq!(editor.get_value(), Some(&Suit::Spades));
    }

    #[test]
    fn set_as_text_no_match_leaves_value_unchanged() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_value(Suit::Clubs);
        editor.set_as_text("NotASuit");
        assert_eq!(editor.get_value(), Some(&Suit::Clubs));
    }

    #[test]
    fn set_as_text_no_match_on_unset_editor_stays_unset() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_as_text("NotASuit");
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn default_has_no_value() {
        let editor: EnumEditor<Suit> = EnumEditor::default();
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn clone_preserves_value() {
        let mut editor: EnumEditor<Suit> = EnumEditor::new();
        editor.set_value(Suit::Hearts);
        let cloned = editor.clone();
        assert_eq!(cloned.get_value(), editor.get_value());
    }
}
