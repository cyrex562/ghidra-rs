use super::DiffLines;

/// A container for diff results between two data types.
///
/// Holds the left and right sides of a diff comparison, each represented as
/// a sequence of validatable lines.
///
/// Mirrors `ghidra.app.util.html.diff.DataTypeDiff`.
pub struct DataTypeDiff {
    left_lines: DiffLines,
    right_lines: DiffLines,
}

impl DataTypeDiff {
    /// Creates a new `DataTypeDiff` with the given left and right line sets.
    pub(crate) fn new(left_lines: DiffLines, right_lines: DiffLines) -> Self {
        Self { left_lines, right_lines }
    }

    /// Returns a reference to the left side of the diff.
    pub fn get_left_lines(&self) -> &DiffLines {
        &self.left_lines
    }

    /// Returns a reference to the right side of the diff.
    pub fn get_right_lines(&self) -> &DiffLines {
        &self.right_lines
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::html::DataTypeDiffInput;
    use std::rc::Rc;

    struct MockInput;

    impl DataTypeDiffInput for MockInput {
        fn get_lines(&self) -> Vec<Box<dyn crate::app::util::html::ValidatableLine>> {
            vec![]
        }

        fn create_placeholder(
            &self,
            _opposite_line: &dyn crate::app::util::html::ValidatableLine,
        ) -> Box<dyn crate::app::util::html::PlaceHolderLine> {
            unimplemented!()
        }
    }

    #[test]
    fn new_stores_lines() {
        let mock = Rc::new(MockInput);
        let left = DiffLines::new(mock.clone());
        let right = DiffLines::new(mock);

        let diff = DataTypeDiff::new(left, right);
        assert_eq!(diff.get_left_lines().len(), 0);
        assert_eq!(diff.get_right_lines().len(), 0);
    }

    #[test]
    fn get_left_lines_returns_reference() {
        let mock = Rc::new(MockInput);
        let left = DiffLines::new(mock.clone());
        let right = DiffLines::new(mock);

        let diff = DataTypeDiff::new(left, right);
        let left_ref = diff.get_left_lines();
        assert_eq!(left_ref.len(), 0);
    }

    #[test]
    fn get_right_lines_returns_reference() {
        let mock = Rc::new(MockInput);
        let left = DiffLines::new(mock.clone());
        let right = DiffLines::new(mock);

        let diff = DataTypeDiff::new(left, right);
        let right_ref = diff.get_right_lines();
        assert_eq!(right_ref.len(), 0);
    }
}
