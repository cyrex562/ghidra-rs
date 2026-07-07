/// A property editor for `String` values restricted to a fixed set of choices.
///
/// Corresponds to `docking.options.editor.StringWithChoicesEditor`.
///
/// The Java implementation extends `PropertyEditorSupport` and uses `getTags()` to
/// expose the allowed choices to the UI. `firePropertyChange()` is part of the
/// JavaBeans event system and has no Rust equivalent here.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StringWithChoicesEditor {
    choices: Vec<String>,
    value: Option<String>,
}

impl StringWithChoicesEditor {
    pub fn new(choices: Vec<String>) -> Self {
        Self {
            choices,
            value: None,
        }
    }

    /// Returns the current string value, or `None` if no value has been set.
    pub fn get_value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Sets the current string value.
    pub fn set_value(&mut self, value: String) {
        self.value = Some(value);
    }

    /// Returns the allowed choices for this editor.
    pub fn get_tags(&self) -> &[String] {
        &self.choices
    }

    /// Returns the current value as text, or an empty string if no value is set.
    pub fn get_as_text(&self) -> &str {
        self.value.as_deref().unwrap_or("")
    }

    /// Sets the value from the given text.
    pub fn set_as_text(&mut self, text: &str) {
        self.value = Some(text.to_owned());
    }

    /// Replaces the set of allowed choices.
    pub fn set_choices(&mut self, choices: Vec<String>) {
        self.choices = choices;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choices() -> Vec<String> {
        vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()]
    }

    #[test]
    fn new_editor_has_no_value() {
        let editor = StringWithChoicesEditor::new(choices());
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn new_editor_exposes_choices_via_get_tags() {
        let editor = StringWithChoicesEditor::new(choices());
        assert_eq!(editor.get_tags(), &["alpha", "beta", "gamma"]);
    }

    #[test]
    fn set_and_get_value() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_value("beta".to_owned());
        assert_eq!(editor.get_value(), Some("beta"));
    }

    #[test]
    fn set_value_overwrites_previous() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_value("alpha".to_owned());
        editor.set_value("gamma".to_owned());
        assert_eq!(editor.get_value(), Some("gamma"));
    }

    #[test]
    fn get_as_text_with_value() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_value("alpha".to_owned());
        assert_eq!(editor.get_as_text(), "alpha");
    }

    #[test]
    fn get_as_text_no_value() {
        let editor = StringWithChoicesEditor::new(choices());
        assert_eq!(editor.get_as_text(), "");
    }

    #[test]
    fn set_as_text_on_empty_editor() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_as_text("beta");
        assert_eq!(editor.get_value(), Some("beta"));
    }

    #[test]
    fn set_as_text_replaces_existing_value() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_value("alpha".to_owned());
        editor.set_as_text("gamma");
        assert_eq!(editor.get_value(), Some("gamma"));
    }

    #[test]
    fn set_choices_replaces_tags() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_choices(vec!["x".to_owned(), "y".to_owned()]);
        assert_eq!(editor.get_tags(), &["x", "y"]);
    }

    #[test]
    fn set_choices_does_not_clear_value() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_value("alpha".to_owned());
        editor.set_choices(vec!["x".to_owned()]);
        assert_eq!(editor.get_value(), Some("alpha"));
    }

    #[test]
    fn default_has_empty_choices_and_no_value() {
        let editor = StringWithChoicesEditor::default();
        assert_eq!(editor.get_tags(), &[] as &[String]);
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn clone_preserves_choices_and_value() {
        let mut editor = StringWithChoicesEditor::new(choices());
        editor.set_value("beta".to_owned());
        let cloned = editor.clone();
        assert_eq!(cloned.get_tags(), editor.get_tags());
        assert_eq!(cloned.get_value(), editor.get_value());
    }
}
