/// A single line of Java source text that tracks mutations against the original.
///
/// Port of `ghidra.util.JavaSourceLine`.
pub struct JavaSourceLine {
    line_number: i32,
    line_text: String,
    original_text: String,
    is_deleted: bool,
}

impl JavaSourceLine {
    /// Creates a new `JavaSourceLine` with the given text and line number.
    pub fn new(line: impl Into<String>, line_number: i32) -> Self {
        let text = line.into();
        Self {
            line_number,
            line_text: text.clone(),
            original_text: text,
            is_deleted: false,
        }
    }

    /// Returns the line number.
    pub fn line_number(&self) -> i32 {
        self.line_number
    }

    /// Clears the line text and marks this line as deleted.
    pub fn delete(&mut self) {
        self.line_text = String::new();
        self.is_deleted = true;
    }

    /// Returns the leading whitespace characters from the current line text.
    pub fn leading_whitespace(&self) -> &str {
        let end = self
            .line_text
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(self.line_text.len());
        &self.line_text[..end]
    }

    /// Returns `true` if this line has been deleted.
    pub fn is_deleted(&self) -> bool {
        self.is_deleted
    }

    /// Returns the current line text.
    pub fn text(&self) -> &str {
        &self.line_text
    }

    /// Prepends `text` to the current line text and clears the deleted flag.
    pub fn prepend(&mut self, text: &str) {
        let mut new_text = text.to_string();
        new_text.push_str(&self.line_text);
        self.line_text = new_text;
        self.is_deleted = false;
    }

    /// Appends `text` to the current line text and clears the deleted flag.
    pub fn append(&mut self, text: &str) {
        self.line_text.push_str(text);
        self.is_deleted = false;
    }

    /// Replaces the current line text and clears the deleted flag.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.line_text = text.into();
        self.is_deleted = false;
    }

    /// Returns `true` if the current line text differs from the original.
    pub fn has_changes(&self) -> bool {
        self.original_text != self.line_text
    }

    /// Returns the original (unmodified) line text.
    pub fn original_text(&self) -> &str {
        &self.original_text
    }

    /// Creates a new `JavaSourceLine` from this line's original unmodified text.
    pub(crate) fn create_original_clone(&self) -> Self {
        Self::new(self.original_text.clone(), self.line_number)
    }
}

impl std::fmt::Display for JavaSourceLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.line_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_text_and_line_number() {
        let line = JavaSourceLine::new("    int x = 0;", 42);
        assert_eq!(line.text(), "    int x = 0;");
        assert_eq!(line.line_number(), 42);
        assert!(!line.is_deleted());
    }

    #[test]
    fn delete_clears_text_and_sets_deleted() {
        let mut line = JavaSourceLine::new("foo", 1);
        line.delete();
        assert_eq!(line.text(), "");
        assert!(line.is_deleted());
    }

    #[test]
    fn leading_whitespace_empty_string() {
        let line = JavaSourceLine::new("", 1);
        assert_eq!(line.leading_whitespace(), "");
    }

    #[test]
    fn leading_whitespace_no_whitespace() {
        let line = JavaSourceLine::new("int x;", 1);
        assert_eq!(line.leading_whitespace(), "");
    }

    #[test]
    fn leading_whitespace_spaces_and_tabs() {
        let line = JavaSourceLine::new("  \t  code", 1);
        assert_eq!(line.leading_whitespace(), "  \t  ");
    }

    #[test]
    fn leading_whitespace_all_whitespace() {
        let line = JavaSourceLine::new("   ", 1);
        assert_eq!(line.leading_whitespace(), "   ");
    }

    #[test]
    fn prepend_adds_text_and_clears_deleted() {
        let mut line = JavaSourceLine::new("bar", 1);
        line.delete();
        line.prepend("foo");
        assert_eq!(line.text(), "foobar");
        assert!(!line.is_deleted());
    }

    #[test]
    fn append_adds_text_and_clears_deleted() {
        let mut line = JavaSourceLine::new("foo", 1);
        line.delete();
        line.append("bar");
        assert_eq!(line.text(), "bar");
        assert!(!line.is_deleted());
    }

    #[test]
    fn set_text_replaces_text_and_clears_deleted() {
        let mut line = JavaSourceLine::new("original", 5);
        line.delete();
        line.set_text("replaced");
        assert_eq!(line.text(), "replaced");
        assert!(!line.is_deleted());
    }

    #[test]
    fn has_changes_false_when_unmodified() {
        let line = JavaSourceLine::new("abc", 1);
        assert!(!line.has_changes());
    }

    #[test]
    fn has_changes_true_after_delete() {
        let mut line = JavaSourceLine::new("abc", 1);
        line.delete();
        assert!(line.has_changes());
    }

    #[test]
    fn has_changes_true_after_append() {
        let mut line = JavaSourceLine::new("abc", 1);
        line.append("x");
        assert!(line.has_changes());
    }

    #[test]
    fn has_changes_true_after_set_text() {
        let mut line = JavaSourceLine::new("abc", 1);
        line.set_text("xyz");
        assert!(line.has_changes());
    }

    #[test]
    fn original_text_unchanged_after_mutations() {
        let mut line = JavaSourceLine::new("original", 3);
        line.append(" extra");
        assert_eq!(line.original_text(), "original");
        assert_eq!(line.text(), "original extra");
    }

    #[test]
    fn create_original_clone_restores_initial_state() {
        let mut line = JavaSourceLine::new("hello", 7);
        line.append(" world");
        let clone = line.create_original_clone();
        assert_eq!(clone.text(), "hello");
        assert_eq!(clone.line_number(), 7);
        assert!(!clone.is_deleted());
        assert!(!clone.has_changes());
    }

    #[test]
    fn display_shows_current_text() {
        let mut line = JavaSourceLine::new("original", 1);
        line.set_text("modified");
        assert_eq!(line.to_string(), "modified");
    }

    #[test]
    fn display_after_delete_shows_empty() {
        let mut line = JavaSourceLine::new("data", 1);
        line.delete();
        assert_eq!(line.to_string(), "");
    }

    #[test]
    fn append_to_deleted_line_restores_only_appended_text() {
        let mut line = JavaSourceLine::new("foo", 1);
        line.delete();
        line.append("bar");
        assert_eq!(line.text(), "bar");
        assert!(!line.is_deleted());
    }
}
