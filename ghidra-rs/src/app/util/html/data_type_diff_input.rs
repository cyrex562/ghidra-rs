use super::{PlaceHolderLine, ValidatableLine};

/// A provider of lines for diff operations, with the ability to create placeholder lines.
///
/// Mirrors `ghidra.app.util.html.diff.DataTypeDiffInput`.
pub trait DataTypeDiffInput {
    /// Returns the list of lines to be used in a diff.
    fn get_lines(&self) -> Vec<Box<dyn ValidatableLine>>;

    /// Creates a specialized placeholder line that corresponds to `opposite_line`.
    fn create_placeholder(&self, opposite_line: &dyn ValidatableLine) -> Box<dyn PlaceHolderLine>;
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::html::{EmptyTextLine, TextLine, PlaceHolderLine};

    // Mock implementation for testing
    struct MockDiffInput {
        lines: Vec<Box<dyn ValidatableLine>>,
    }

    impl MockDiffInput {
        fn new(texts: Vec<&str>) -> Self {
            let lines = texts
                .into_iter()
                .map(|t| Box::new(TextLine::new(t)) as Box<dyn ValidatableLine>)
                .collect();
            Self { lines }
        }
    }

    impl DataTypeDiffInput for MockDiffInput {
        fn get_lines(&self) -> Vec<Box<dyn ValidatableLine>> {
            self.lines
                .iter()
                .map(|line| line.copy())
                .collect()
        }

        fn create_placeholder(&self, _opposite_line: &dyn ValidatableLine) -> Box<dyn PlaceHolderLine> {
            Box::new(EmptyTextLine::new(3))
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let input: &dyn DataTypeDiffInput = &MockDiffInput::new(vec!["test"]);
        let lines = input.get_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].get_text(), "test");
    }

    #[test]
    fn get_lines_empty() {
        let input = MockDiffInput::new(vec![]);
        let lines = input.get_lines();
        assert!(lines.is_empty());
    }

    #[test]
    fn get_lines_single_line() {
        let input = MockDiffInput::new(vec!["hello"]);
        let lines = input.get_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].get_text(), "hello");
    }

    #[test]
    fn get_lines_multiple_lines() {
        let input = MockDiffInput::new(vec!["line1", "line2", "line3"]);
        let lines = input.get_lines();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].get_text(), "line1");
        assert_eq!(lines[1].get_text(), "line2");
        assert_eq!(lines[2].get_text(), "line3");
    }

    #[test]
    fn get_lines_returns_copies() {
        let input = MockDiffInput::new(vec!["test"]);
        let lines1 = input.get_lines();
        let lines2 = input.get_lines();
        // Both should have the same content but be different instances
        assert_eq!(lines1[0].get_text(), lines2[0].get_text());
    }

    #[test]
    fn create_placeholder_returns_valid_line() {
        let input = MockDiffInput::new(vec!["test"]);
        let opposite = TextLine::new("opposite");
        let placeholder = input.create_placeholder(&opposite);
        assert_eq!(placeholder.get_text(), "   ");
    }

    #[test]
    fn create_placeholder_is_placeholder_line() {
        let input = MockDiffInput::new(vec![]);
        let opposite = TextLine::new("test");
        let placeholder = input.create_placeholder(&opposite);
        // Verify it's a PlaceHolderLine by using it as one
        let _ph: &dyn PlaceHolderLine = &*placeholder;
    }
}
