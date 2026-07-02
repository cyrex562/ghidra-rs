use std::rc::Rc;

use crate::util::exception::AssertException;

use super::{DataTypeDiffInput, PlaceHolderLine, ValidatableLine};

/// An entry in a [`DiffLines`] list.
///
/// Java identifies placeholder lines via `instanceof PlaceHolderLine`; a boxed
/// `dyn ValidatableLine` cannot be downcast back to `dyn PlaceHolderLine` in Rust, so
/// `DiffLines` tracks the flag itself at the point of insertion (only
/// [`DiffLines::insert_placeholder`] / [`DiffLines::insert_placeholder_at`] ever produce one).
struct DiffEntry {
    line: Box<dyn ValidatableLine>,
    is_place_holder: bool,
}

impl DiffEntry {
    fn line(line: Box<dyn ValidatableLine>) -> Self {
        Self { line, is_place_holder: false }
    }

    fn place_holder(line: Box<dyn PlaceHolderLine>) -> Self {
        Self { line, is_place_holder: true }
    }
}

/// A class that holds lines that will be used to generate diffs. It also has a reference to
/// the source of the data so that it can create the correct type of empty lines as needed.
///
/// Mirrors `ghidra.app.util.html.diff.DiffLines`.
pub struct DiffLines {
    input: Rc<dyn DataTypeDiffInput>,
    lines: Vec<DiffEntry>,
}

impl DiffLines {
    /// Creates a new `DiffLines` populated with `input`'s lines.
    pub fn new(input: Rc<dyn DataTypeDiffInput>) -> Self {
        let lines = input.get_lines().into_iter().map(DiffEntry::line).collect();
        Self { input, lines }
    }

    /// Creates a new `DiffLines` with the given already-validated lines.
    pub fn with_validated_lines(
        input: Rc<dyn DataTypeDiffInput>,
        validated_lines: Vec<Box<dyn ValidatableLine>>,
    ) -> Self {
        let lines = validated_lines.into_iter().map(DiffEntry::line).collect();
        Self { input, lines }
    }

    /// Returns the number of lines.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Returns `true` if there are no lines.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Returns the line at `index`.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn get(&self, index: usize) -> &dyn ValidatableLine {
        self.lines[index].line.as_ref()
    }

    /// Returns an iterator over the lines, in order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn ValidatableLine> {
        self.lines.iter().map(|entry| entry.line.as_ref())
    }

    /// Removes leading placeholder lines, stopping at the first non-placeholder line.
    pub(crate) fn remove_leading_empty_rows(&mut self) {
        while let Some(entry) = self.lines.first() {
            if entry.is_place_holder {
                self.lines.remove(0);
            } else {
                return; // stop at the first real line
            }
        }
    }

    /// Creates a new, empty `DiffLines` that shares this instance's input.
    pub(crate) fn create_empty_clone(&self) -> DiffLines {
        DiffLines::with_validated_lines(Rc::clone(&self.input), Vec::new())
    }

    /// Replaces the content of this diff with the given content.
    ///
    /// # Panics
    /// Panics with an [`AssertException`] unless `new_lines` was created from a clone of
    /// this instance's input.
    pub(crate) fn install_new_lines(&mut self, new_lines: DiffLines) {
        if !Rc::ptr_eq(&self.input, &new_lines.input) {
            panic!(
                "{}",
                AssertException::with_message(
                    "Can only install new diff lines from a clone of the original"
                )
            );
        }

        self.lines = new_lines.lines;
    }

    fn create_place_holder_line(&self, opposite_line: &dyn ValidatableLine) -> Box<dyn PlaceHolderLine> {
        self.input.create_placeholder(opposite_line)
    }

    /// Appends a placeholder line paired with `opposite_line`.
    pub(crate) fn insert_placeholder(&mut self, opposite_line: &dyn ValidatableLine) {
        self.insert_placeholder_at(self.lines.len(), opposite_line);
    }

    /// Inserts a placeholder line at `index`, paired with `opposite_line`.
    pub(crate) fn insert_placeholder_at(&mut self, index: usize, opposite_line: &dyn ValidatableLine) {
        let placeholder = self.create_place_holder_line(opposite_line);
        self.lines.insert(index, DiffEntry::place_holder(placeholder));
    }
}

impl std::fmt::Display for DiffLines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[")?;
        for entry in &self.lines {
            writeln!(f, "{}", entry.line.get_text())?;
        }
        write!(f, "]")
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::html::{EmptyTextLine, TextLine};

    struct MockDiffInput {
        lines: Vec<&'static str>,
    }

    impl MockDiffInput {
        fn new(lines: Vec<&'static str>) -> Rc<Self> {
            Rc::new(Self { lines })
        }
    }

    impl DataTypeDiffInput for MockDiffInput {
        fn get_lines(&self) -> Vec<Box<dyn ValidatableLine>> {
            self.lines
                .iter()
                .map(|t| Box::new(TextLine::new(*t)) as Box<dyn ValidatableLine>)
                .collect()
        }

        fn create_placeholder(&self, _opposite_line: &dyn ValidatableLine) -> Box<dyn PlaceHolderLine> {
            Box::new(EmptyTextLine::new(0))
        }
    }

    #[test]
    fn new_populates_lines_from_input() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let diff_lines = DiffLines::new(input);
        assert_eq!(diff_lines.len(), 2);
        assert_eq!(diff_lines.get(0).get_text(), "one");
        assert_eq!(diff_lines.get(1).get_text(), "two");
    }

    #[test]
    fn new_with_empty_input_is_empty() {
        let input = MockDiffInput::new(vec![]);
        let diff_lines = DiffLines::new(input);
        assert!(diff_lines.is_empty());
    }

    #[test]
    fn with_validated_lines_uses_given_lines() {
        let input = MockDiffInput::new(vec!["ignored"]);
        let validated = vec![Box::new(TextLine::new("custom")) as Box<dyn ValidatableLine>];
        let diff_lines = DiffLines::with_validated_lines(input, validated);
        assert_eq!(diff_lines.len(), 1);
        assert_eq!(diff_lines.get(0).get_text(), "custom");
    }

    #[test]
    fn create_empty_clone_is_empty() {
        let input = MockDiffInput::new(vec!["one"]);
        let diff_lines = DiffLines::new(input);
        let clone = diff_lines.create_empty_clone();
        assert!(clone.is_empty());
    }

    #[test]
    fn install_new_lines_replaces_content() {
        let input = MockDiffInput::new(vec!["one"]);
        let mut diff_lines = DiffLines::new(input);
        let mut clone = diff_lines.create_empty_clone();
        clone.insert_placeholder(diff_lines.get(0));

        diff_lines.install_new_lines(clone);

        assert_eq!(diff_lines.len(), 1);
    }

    #[test]
    #[should_panic(expected = "Can only install new diff lines from a clone of the original")]
    fn install_new_lines_panics_for_unrelated_input() {
        let input_a = MockDiffInput::new(vec!["one"]);
        let input_b = MockDiffInput::new(vec!["two"]);
        let mut diff_lines = DiffLines::new(input_a);
        let unrelated = DiffLines::new(input_b);

        diff_lines.install_new_lines(unrelated);
    }

    #[test]
    fn insert_placeholder_appends_to_end() {
        let input = MockDiffInput::new(vec!["one"]);
        let mut diff_lines = DiffLines::new(input);
        let opposite = TextLine::new("opposite");
        diff_lines.insert_placeholder(&opposite);

        assert_eq!(diff_lines.len(), 2);
        assert_eq!(diff_lines.get(1).get_text(), "");
    }

    #[test]
    fn insert_placeholder_at_inserts_at_index() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let mut diff_lines = DiffLines::new(input);
        let opposite = TextLine::new("opposite");
        diff_lines.insert_placeholder_at(1, &opposite);

        assert_eq!(diff_lines.len(), 3);
        assert_eq!(diff_lines.get(0).get_text(), "one");
        assert_eq!(diff_lines.get(1).get_text(), "");
        assert_eq!(diff_lines.get(2).get_text(), "two");
    }

    #[test]
    fn remove_leading_empty_rows_strips_only_leading_placeholders() {
        let input = MockDiffInput::new(vec!["one"]);
        let mut diff_lines = DiffLines::new(input);
        let opposite = TextLine::new("opposite");
        diff_lines.insert_placeholder_at(0, &opposite);
        diff_lines.insert_placeholder_at(0, &opposite);
        diff_lines.insert_placeholder(&opposite); // trailing placeholder, should survive

        diff_lines.remove_leading_empty_rows();

        assert_eq!(diff_lines.len(), 2);
        assert_eq!(diff_lines.get(0).get_text(), "one");
        assert_eq!(diff_lines.get(1).get_text(), "");
    }

    #[test]
    fn remove_leading_empty_rows_no_placeholders_is_noop() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let mut diff_lines = DiffLines::new(input);
        diff_lines.remove_leading_empty_rows();
        assert_eq!(diff_lines.len(), 2);
    }

    #[test]
    fn remove_leading_empty_rows_all_placeholders_empties_list() {
        let input = MockDiffInput::new(vec![]);
        let mut diff_lines = DiffLines::new(input);
        let opposite = TextLine::new("opposite");
        diff_lines.insert_placeholder(&opposite);
        diff_lines.insert_placeholder(&opposite);

        diff_lines.remove_leading_empty_rows();

        assert!(diff_lines.is_empty());
    }

    #[test]
    fn iter_yields_lines_in_order() {
        let input = MockDiffInput::new(vec!["one", "two", "three"]);
        let diff_lines = DiffLines::new(input);
        let texts: Vec<&str> = diff_lines.iter().map(|l| l.get_text()).collect();
        assert_eq!(texts, vec!["one", "two", "three"]);
    }

    #[test]
    fn display_formats_lines_bracketed() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let diff_lines = DiffLines::new(input);
        let s = diff_lines.to_string();
        assert_eq!(s, "[\none\ntwo\n]");
    }

    #[test]
    fn display_empty_list() {
        let input = MockDiffInput::new(vec![]);
        let diff_lines = DiffLines::new(input);
        assert_eq!(diff_lines.to_string(), "[\n]");
    }
}
