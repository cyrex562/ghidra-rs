/// A property editor for Boolean values.
///
/// Corresponds to `docking.options.editor.BooleanEditor`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BooleanEditor {
    value: Option<bool>,
}

impl BooleanEditor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current boolean value, or `None` if no value has been set.
    pub fn get_value(&self) -> Option<bool> {
        self.value
    }

    /// Sets the current boolean value.
    pub fn set_value(&mut self, value: bool) {
        self.value = Some(value);
    }

    /// Returns the string representation of the current value (`"true"` or `"false"`),
    /// or an empty string if no value is set.
    pub fn get_as_text(&self) -> &str {
        match self.value {
            Some(true) => "true",
            Some(false) => "false",
            None => "",
        }
    }

    /// Sets the value by parsing a string. Accepts `"true"` (case-insensitive) as `true`,
    /// anything else as `false`.
    pub fn set_as_text(&mut self, text: &str) {
        self.value = Some(text.eq_ignore_ascii_case("true"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_editor_has_no_value() {
        let editor = BooleanEditor::new();
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn set_and_get_true() {
        let mut editor = BooleanEditor::new();
        editor.set_value(true);
        assert_eq!(editor.get_value(), Some(true));
    }

    #[test]
    fn set_and_get_false() {
        let mut editor = BooleanEditor::new();
        editor.set_value(false);
        assert_eq!(editor.get_value(), Some(false));
    }

    #[test]
    fn get_as_text_true() {
        let mut editor = BooleanEditor::new();
        editor.set_value(true);
        assert_eq!(editor.get_as_text(), "true");
    }

    #[test]
    fn get_as_text_false() {
        let mut editor = BooleanEditor::new();
        editor.set_value(false);
        assert_eq!(editor.get_as_text(), "false");
    }

    #[test]
    fn get_as_text_no_value() {
        let editor = BooleanEditor::new();
        assert_eq!(editor.get_as_text(), "");
    }

    #[test]
    fn set_as_text_true_lowercase() {
        let mut editor = BooleanEditor::new();
        editor.set_as_text("true");
        assert_eq!(editor.get_value(), Some(true));
    }

    #[test]
    fn set_as_text_true_uppercase() {
        let mut editor = BooleanEditor::new();
        editor.set_as_text("TRUE");
        assert_eq!(editor.get_value(), Some(true));
    }

    #[test]
    fn set_as_text_false() {
        let mut editor = BooleanEditor::new();
        editor.set_as_text("false");
        assert_eq!(editor.get_value(), Some(false));
    }

    #[test]
    fn set_as_text_arbitrary_string_is_false() {
        let mut editor = BooleanEditor::new();
        editor.set_as_text("yes");
        assert_eq!(editor.get_value(), Some(false));
    }

    #[test]
    fn default_matches_new() {
        let a = BooleanEditor::new();
        let b = BooleanEditor::default();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_preserves_value() {
        let mut editor = BooleanEditor::new();
        editor.set_value(true);
        let cloned = editor.clone();
        assert_eq!(cloned.get_value(), Some(true));
    }
}
