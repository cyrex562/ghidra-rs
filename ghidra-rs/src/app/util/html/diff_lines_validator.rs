use std::fmt;
use std::rc::Rc;

use crate::util::exception::AssertException;

use super::{DataTypeDiffInput, DiffLines, PlaceHolderLine, ValidatableLine};

/// An entry tracked by [`DiffLinesValidator`].
///
/// Java tells placeholder lines apart via `instanceof PlaceHolderLine`; a boxed
/// `dyn ValidatableLine` cannot be downcast back to `dyn PlaceHolderLine` in Rust, so the
/// placeholder flag is tracked here instead, mirroring `DiffLines`'s `DiffEntry`.
struct Entry {
    line: Box<dyn ValidatableLine>,
    is_place_holder: bool,
}

impl Entry {
    fn line(line: Box<dyn ValidatableLine>) -> Self {
        Self { line, is_place_holder: false }
    }

    fn place_holder(line: Box<dyn PlaceHolderLine>) -> Self {
        Self { line, is_place_holder: true }
    }
}

/// Knows how to traverse a set of lines that are being used to generate a diff.
///
/// Mirrors `ghidra.app.util.html.diff.DiffLinesValidator`.
pub(crate) struct DiffLinesValidator {
    my_lines: Vec<Entry>,
    marker: usize,
    input: Rc<dyn DataTypeDiffInput>,
    is_left: bool,
}

impl DiffLinesValidator {
    pub(crate) fn new(input: Rc<dyn DataTypeDiffInput>, is_left: bool) -> Self {
        let my_lines = input.get_lines().into_iter().map(Entry::line).collect();
        Self { my_lines, marker: 0, input, is_left }
    }

    /// # Panics
    /// Panics with an [`AssertException`] if validation has not finished.
    pub(crate) fn get_validated_lines(self) -> DiffLines {
        if !self.is_done() {
            panic!(
                "{}",
                AssertException::with_message(
                    "Cannot get validated lines before validation is finished"
                )
            );
        }

        let lines = self.my_lines.into_iter().map(|entry| entry.line).collect();
        DiffLines::with_validated_lines(self.input, lines)
    }

    /// Creates a placeholder line paired with `opposite_line` and inserts it at `index`.
    ///
    /// Returns the index of the inserted placeholder. Java returns the `PlaceHolderLine`
    /// object itself, relying on shared object aliasing that Rust's ownership model does not
    /// allow; callers can look the line back up via [`DiffLinesValidator::get_line_at`] /
    /// [`DiffLinesValidator::get_line_at_mut`].
    pub(crate) fn insert_mismatch_placeholder(
        &mut self,
        index: usize,
        opposite_line: &dyn ValidatableLine,
    ) -> usize {
        let place_holder = self.input.create_placeholder(opposite_line);
        self.my_lines.insert(index, Entry::place_holder(place_holder));
        index
    }

    pub(crate) fn get_marker_position(&self) -> usize {
        self.marker
    }

    /// Push forward the current marker position. The marker starts at the beginning and
    /// only moves forward past validated lines.
    pub(crate) fn increment(&mut self) {
        self.marker += 1;

        // keep walking our list until we find an unvalidated line
        while self.marker < self.my_lines.len() {
            if !self.my_lines[self.marker].line.is_validated() {
                return;
            }
            self.marker += 1;
        }
    }

    pub(crate) fn get_line(&self) -> Option<&dyn ValidatableLine> {
        let mut marker = self.marker;
        while marker < self.my_lines.len() {
            let entry = &self.my_lines[marker];
            if !entry.is_place_holder {
                return Some(entry.line.as_ref());
            }
            if !entry.line.is_validated() {
                return Some(entry.line.as_ref());
            }
            marker += 1; // skip over place holder lines
        }

        None
    }

    pub(crate) fn find_next_match(&self, line: &dyn ValidatableLine) -> Option<usize> {
        for (search_position, entry) in self.my_lines.iter().enumerate() {
            if line.matches_line(entry.line.as_ref()) {
                return Some(search_position);
            }
        }
        None
    }

    pub(crate) fn is_done(&self) -> bool {
        self.marker >= self.my_lines.len()
    }

    pub(crate) fn get_line_at(&self, index: usize) -> &dyn ValidatableLine {
        self.my_lines[index].line.as_ref()
    }

    pub(crate) fn get_line_at_mut(&mut self, index: usize) -> &mut dyn ValidatableLine {
        self.my_lines[index].line.as_mut()
    }

    pub(crate) fn size(&self) -> usize {
        self.my_lines.len()
    }

    fn markup(&self, line_number: usize, text: &str) -> String {
        if line_number != self.marker {
            return text.to_string();
        }

        let mut flag = " ****** ".to_string();
        let mut buffy = String::new();
        for line in text.split('\n') {
            if line.trim().is_empty() {
                buffy.push_str(line);
                buffy.push('\n');
                continue;
            }
            buffy.push_str(&flag);
            buffy.push_str(line);
            buffy.push_str(&flag);
            buffy.push('\n');
            flag = "        ".to_string();
        }

        buffy
    }
}

impl fmt::Display for DiffLinesValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Diff Validator ({})", if self.is_left { "left" } else { "right" })?;

        write!(f, "[ ")?;
        for (i, entry) in self.my_lines.iter().enumerate() {
            write!(f, "{}", self.markup(i, entry.line.get_text()))?;
            if i + 1 < self.my_lines.len() {
                write!(f, ", ")?;
            }
        }
        write!(f, " ]")
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
        let validator = DiffLinesValidator::new(input, true);
        assert_eq!(validator.size(), 2);
        assert_eq!(validator.get_line_at(0).get_text(), "one");
        assert_eq!(validator.get_line_at(1).get_text(), "two");
    }

    #[test]
    fn new_marker_starts_at_zero() {
        let input = MockDiffInput::new(vec!["one"]);
        let validator = DiffLinesValidator::new(input, true);
        assert_eq!(validator.get_marker_position(), 0);
    }

    #[test]
    fn is_done_false_when_lines_remain() {
        let input = MockDiffInput::new(vec!["one"]);
        let validator = DiffLinesValidator::new(input, true);
        assert!(!validator.is_done());
    }

    #[test]
    fn is_done_true_for_empty_input() {
        let input = MockDiffInput::new(vec![]);
        let validator = DiffLinesValidator::new(input, true);
        assert!(validator.is_done());
    }

    #[test]
    fn increment_advances_marker() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let mut validator = DiffLinesValidator::new(input, true);
        validator.increment();
        assert_eq!(validator.get_marker_position(), 1);
    }

    #[test]
    fn increment_skips_validated_lines() {
        let input = MockDiffInput::new(vec!["one", "two", "three"]);
        let mut validator = DiffLinesValidator::new(input, true);
        validator.get_line_at_mut(1).set_validation_line(&mut TextLine::new("two"));
        validator.increment();
        assert_eq!(validator.get_marker_position(), 2);
    }

    #[test]
    fn increment_past_end_marks_done() {
        let input = MockDiffInput::new(vec!["one"]);
        let mut validator = DiffLinesValidator::new(input, true);
        validator.increment();
        assert!(validator.is_done());
    }

    #[test]
    fn get_line_returns_current_line() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let validator = DiffLinesValidator::new(input, true);
        assert_eq!(validator.get_line().unwrap().get_text(), "one");
    }

    #[test]
    fn get_line_returns_none_when_done() {
        let input = MockDiffInput::new(vec![]);
        let validator = DiffLinesValidator::new(input, true);
        assert!(validator.get_line().is_none());
    }

    #[test]
    fn get_line_skips_validated_placeholder() {
        let input = MockDiffInput::new(vec!["one"]);
        let mut validator = DiffLinesValidator::new(input, true);
        let opposite = TextLine::new("opposite");
        validator.insert_mismatch_placeholder(0, &opposite);
        validator.get_line_at_mut(0).set_validation_line(&mut TextLine::new("opposite"));

        // index 0 is a validated placeholder, so get_line should skip to index 1 ("one")
        assert_eq!(validator.get_line().unwrap().get_text(), "one");
        assert_eq!(validator.get_marker_position(), 1);
    }

    #[test]
    fn get_line_returns_unvalidated_placeholder() {
        let input = MockDiffInput::new(vec!["one"]);
        let mut validator = DiffLinesValidator::new(input, true);
        let opposite = TextLine::new("opposite");
        validator.insert_mismatch_placeholder(0, &opposite);

        // unvalidated placeholder at the marker position is returned as-is
        assert_eq!(validator.get_line().unwrap().get_text(), "");
        assert_eq!(validator.get_marker_position(), 0);
    }

    #[test]
    fn insert_mismatch_placeholder_inserts_at_index() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let mut validator = DiffLinesValidator::new(input, true);
        let opposite = TextLine::new("opposite");
        let index = validator.insert_mismatch_placeholder(1, &opposite);

        assert_eq!(index, 1);
        assert_eq!(validator.size(), 3);
        assert_eq!(validator.get_line_at(0).get_text(), "one");
        assert_eq!(validator.get_line_at(1).get_text(), "");
        assert_eq!(validator.get_line_at(2).get_text(), "two");
    }

    #[test]
    fn find_next_match_finds_matching_index() {
        let input = MockDiffInput::new(vec!["one", "two", "three"]);
        let validator = DiffLinesValidator::new(input, true);
        let needle = TextLine::new("two");
        assert_eq!(validator.find_next_match(&needle), Some(1));
    }

    #[test]
    fn find_next_match_returns_none_when_absent() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let validator = DiffLinesValidator::new(input, true);
        let needle = TextLine::new("missing");
        assert_eq!(validator.find_next_match(&needle), None);
    }

    #[test]
    fn get_validated_lines_returns_diff_lines() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let mut validator = DiffLinesValidator::new(input, true);
        validator.increment();
        validator.increment();

        let diff_lines = validator.get_validated_lines();
        assert_eq!(diff_lines.len(), 2);
        assert_eq!(diff_lines.get(0).get_text(), "one");
        assert_eq!(diff_lines.get(1).get_text(), "two");
    }

    #[test]
    #[should_panic(expected = "Cannot get validated lines before validation is finished")]
    fn get_validated_lines_panics_when_not_done() {
        let input = MockDiffInput::new(vec!["one"]);
        let validator = DiffLinesValidator::new(input, true);
        validator.get_validated_lines();
    }

    #[test]
    fn display_shows_side_and_marked_line() {
        let input = MockDiffInput::new(vec!["one", "two"]);
        let validator = DiffLinesValidator::new(input, true);
        let s = validator.to_string();
        assert!(s.starts_with("Diff Validator (left)\n"));
        assert!(s.contains("****** one ******"));
        assert!(s.contains("two"));
    }

    #[test]
    fn display_shows_right_side() {
        let input = MockDiffInput::new(vec!["one"]);
        let validator = DiffLinesValidator::new(input, false);
        let s = validator.to_string();
        assert!(s.starts_with("Diff Validator (right)\n"));
    }
}
