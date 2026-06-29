/// A property editor for integer values.
///
/// Corresponds to `docking.options.editor.IntEditor`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IntEditor {
    value: Option<i32>,
}

impl IntEditor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current integer value, or `None` if no value has been set.
    pub fn get_value(&self) -> Option<i32> {
        self.value
    }

    /// Sets the current integer value.
    pub fn set_value(&mut self, value: i32) {
        self.value = Some(value);
    }

    /// Returns the string representation of the current value, or an empty string if none is set.
    pub fn get_as_text(&self) -> String {
        match self.value {
            Some(v) => v.to_string(),
            None => String::new(),
        }
    }

    /// Parses `text` as a decimal integer and sets the value.
    ///
    /// Returns `Err` with a descriptive message if `text` is not a valid integer,
    /// mirroring the `IllegalArgumentException` thrown by the Java source.
    pub fn set_as_text(&mut self, text: &str) -> Result<(), String> {
        match text.trim().parse::<i32>() {
            Ok(v) => {
                self.value = Some(v);
                Ok(())
            }
            Err(_) => Err(format!("Invalid integer: {}", text)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_editor_has_no_value() {
        let editor = IntEditor::new();
        assert_eq!(editor.get_value(), None);
    }

    #[test]
    fn set_and_get_value() {
        let mut editor = IntEditor::new();
        editor.set_value(42);
        assert_eq!(editor.get_value(), Some(42));
    }

    #[test]
    fn set_and_get_negative_value() {
        let mut editor = IntEditor::new();
        editor.set_value(-7);
        assert_eq!(editor.get_value(), Some(-7));
    }

    #[test]
    fn get_as_text_with_value() {
        let mut editor = IntEditor::new();
        editor.set_value(100);
        assert_eq!(editor.get_as_text(), "100");
    }

    #[test]
    fn get_as_text_no_value() {
        let editor = IntEditor::new();
        assert_eq!(editor.get_as_text(), "");
    }

    #[test]
    fn set_as_text_valid() {
        let mut editor = IntEditor::new();
        assert!(editor.set_as_text("123").is_ok());
        assert_eq!(editor.get_value(), Some(123));
    }

    #[test]
    fn set_as_text_negative() {
        let mut editor = IntEditor::new();
        assert!(editor.set_as_text("-99").is_ok());
        assert_eq!(editor.get_value(), Some(-99));
    }

    #[test]
    fn set_as_text_invalid_returns_err() {
        let mut editor = IntEditor::new();
        let result = editor.set_as_text("not_a_number");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Invalid integer"));
        assert!(msg.contains("not_a_number"));
    }

    #[test]
    fn set_as_text_empty_returns_err() {
        let mut editor = IntEditor::new();
        assert!(editor.set_as_text("").is_err());
    }

    #[test]
    fn set_as_text_does_not_change_value_on_error() {
        let mut editor = IntEditor::new();
        editor.set_value(5);
        let _ = editor.set_as_text("bad");
        assert_eq!(editor.get_value(), Some(5));
    }

    #[test]
    fn default_matches_new() {
        let a = IntEditor::new();
        let b = IntEditor::default();
        assert_eq!(a, b);
    }

    #[test]
    fn clone_preserves_value() {
        let mut editor = IntEditor::new();
        editor.set_value(77);
        let cloned = editor.clone();
        assert_eq!(cloned.get_value(), Some(77));
    }
}
