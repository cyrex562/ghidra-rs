/// A property editor for `String` values.
///
/// Corresponds to `docking.options.editor.StringEditor`.
///
/// The Java implementation extends `PropertyEditorSupport` and overrides `setAsText`
/// to guard against the case where the internal value has been set to a non-`String`
/// object (which Java's untyped `Object` storage allows). Rust's type system makes
/// that case impossible, so `set_as_text` always succeeds here.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StringEditor {
    value: Option<String>,
}

impl StringEditor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current string value, or `None` if no value has been set.
    pub fn get_value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Sets the current string value.
    pub fn set_value(&mut self, value: String) {
        self.value = Some(value);
    }

    /// Returns the current value as text, or an empty string if no value is set.
    pub fn get_as_text(&self) -> &str {
        self.value.as_deref().unwrap_or("")
    }

    /// Sets the value from the given text.
    ///
    /// Always succeeds; any `&str` is a valid `String` value.
    pub fn set_as_text(&mut self, text: &str) {
        self.value = Some(text.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_editor_has_no_value() {
        let editor = StringEditor::new();
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn set_and_get_value() {
        let mut editor = StringEditor::new();
        editor.set_value("hello".to_owned());
        assert_eq!(editor.get_value(), Some("hello"));
    }

    #[test]
    fn set_value_overwrites_previous() {
        let mut editor = StringEditor::new();
        editor.set_value("first".to_owned());
        editor.set_value("second".to_owned());
        assert_eq!(editor.get_value(), Some("second"));
    }

    #[test]
    fn get_as_text_with_value() {
        let mut editor = StringEditor::new();
        editor.set_value("world".to_owned());
        assert_eq!(editor.get_as_text(), "world");
    }

    #[test]
    fn get_as_text_no_value() {
        let editor = StringEditor::new();
        assert_eq!(editor.get_as_text(), "");
    }

    #[test]
    fn set_as_text_on_empty_editor() {
        let mut editor = StringEditor::new();
        editor.set_as_text("foo");
        assert_eq!(editor.get_value(), Some("foo"));
    }

    #[test]
    fn set_as_text_replaces_existing_string_value() {
        let mut editor = StringEditor::new();
        editor.set_value("old".to_owned());
        editor.set_as_text("new");
        assert_eq!(editor.get_value(), Some("new"));
    }

    #[test]
    fn set_as_text_empty_string() {
        let mut editor = StringEditor::new();
        editor.set_as_text("");
        assert_eq!(editor.get_value(), Some(""));
    }

    #[test]
    fn default_matches_new() {
        let a = StringEditor::new();
        let b = StringEditor::default();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_preserves_value() {
        let mut editor = StringEditor::new();
        editor.set_value("cloned".to_owned());
        let cloned = editor.clone();
        assert_eq!(cloned.get_value(), Some("cloned"));
    }
}
