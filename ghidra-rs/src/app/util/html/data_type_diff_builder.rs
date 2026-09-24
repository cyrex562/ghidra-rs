//! Builds line-by-line diffs between two [`DataTypeDiffInput`]s.
//!
//! Mirrors `ghidra.app.util.html.diff.DataTypeDiffBuilder`, a statics-only Java factory class;
//! in Rust it is a module of free functions and constants.

use std::rc::Rc;

use crate::util::exception::AssertException;

use super::diff_lines_validator::DiffLinesValidator;
use super::{validate_pair, DataTypeDiff, DataTypeDiffInput, DiffLines, TextLine, ValidatableLine};

/// HACK: for some reason when opening the HTML document with `&#47;`, all text until the
/// next HTML tag is not displayed. So, we put in a dummy tag and all is well.
/// (Java 1.5.0_12)
pub const EMPTY_TAG: &str = "<I></I>";

/// HTML line break used as padding text.
pub const BR: &str = "<BR>";

/// Creates a diff of the lines of `left` and `right`, padding the shorter side and pairing
/// lines positionally.
pub fn diff_lines(left: Rc<dyn DataTypeDiffInput>, right: Rc<dyn DataTypeDiffInput>) -> DataTypeDiff {
    let mut left_lines = DiffLines::new(left);
    let mut right_lines = DiffLines::new(right);

    pad_lines(&mut left_lines, &mut right_lines);

    highlight_diff_line_differences(&mut left_lines, &mut right_lines);

    DataTypeDiff::new(left_lines, right_lines)
}

/// Creates a diff of the header lines of `left` and `right` (same as [`diff_lines`]).
pub fn diff_header(left: Rc<dyn DataTypeDiffInput>, right: Rc<dyn DataTypeDiffInput>) -> DataTypeDiff {
    diff_lines(left, right)
}

/// Pads the shorter of the two lists with text lines so that both have the same length.
///
/// The first padding line (index 0) uses [`EMPTY_TAG`]; the rest use [`BR`].
pub fn pad_lines(left_lines: &mut DiffLines, right_lines: &mut DiffLines) {
    let length = left_lines.len();
    let other_length = right_lines.len();

    if length == other_length {
        return;
    }

    let max_length = length.max(other_length);
    for i in 0..max_length {
        // special case (see docs for EMPTY_TAG)
        let padding_text = if i == 0 { EMPTY_TAG } else { BR };

        if i >= length {
            left_lines.add(Box::new(TextLine::new(padding_text)));
        } else if i >= other_length {
            right_lines.add(Box::new(TextLine::new(padding_text)));
        }
    }
}

/// Creates a diff of the body lines of `left` and `right`, aligning matching lines (inserting
/// placeholder lines where one side has lines the other does not) and coloring mismatches.
pub fn diff_body(left: Rc<dyn DataTypeDiffInput>, right: Rc<dyn DataTypeDiffInput>) -> DataTypeDiff {
    let mut left_diff = DiffLinesValidator::new(left, true);
    let mut right_diff = DiffLinesValidator::new(right, false);

    align_rows(&mut left_diff, &mut right_diff);

    let mut left_lines = left_diff.get_validated_lines();
    let mut right_lines = right_diff.get_validated_lines();

    remove_excess_empty_rows(&mut left_lines, &mut right_lines);

    DataTypeDiff::new(left_lines, right_lines)
}

/// Walks both lists, processing the lines and adding blank lines to align the data.
fn align_rows(left_validator: &mut DiffLinesValidator, right_validator: &mut DiffLinesValidator) {
    while !left_validator.is_done() || !right_validator.is_done() {
        // process the next line in the first list
        validate_next_line(left_validator, right_validator);
        validate_next_line(right_validator, left_validator);
    }
}

/// Pairs line `index1` of `validator1` with line `index2` of `validator2`.
fn pair(
    validator1: &mut DiffLinesValidator,
    index1: usize,
    validator2: &mut DiffLinesValidator,
    index2: usize,
) {
    validate_pair(validator1.get_line_at_mut(index1), validator2.get_line_at_mut(index2));
}

fn validate_next_line(validator1: &mut DiffLinesValidator, validator2: &mut DiffLinesValidator) {
    if validator1.is_done() {
        return;
    }

    // None means no lines or nothing left but empty lines
    if validator1.get_line().is_none() {
        return;
    }
    let index1 = validator1.get_marker_position();

    if validator2.get_line().is_none() {
        // the other state is shorter than this one and has run out of lines
        let position = validator2.get_marker_position();
        let placeholder =
            validator2.insert_mismatch_placeholder(position, validator1.get_line_at(index1));

        pair(validator1, index1, validator2, placeholder);
        validator1.increment(); // done with this line, move the state forward
        return;
    }
    let index2 = validator2.get_marker_position();

    if validator1.get_line_at(index1).matches_line(validator2.get_line_at(index2)) {
        pair(validator1, index1, validator2, index2);

        // since they matched, mark the other line as valid too
        validator2.increment();
        validator1.increment();
        return;
    }

    //
    // No match at the current position; we need to decide if there is any match...
    //
    if let Some(list2_match_for_line1) = find_next_match(validator1, index1, validator2) {
        pair(validator1, index1, validator2, list2_match_for_line1);

        // ...there is an upcoming match; that match will be handled later; mark this line done
        validator1.increment();
        return;
    }

    match find_next_match(validator2, index2, validator1) {
        None => {
            // neither line has a match in the other list, treat them as
            // two different values in the same position
            pair(validator1, index1, validator2, index2);
            validator2.increment();
        }
        Some(_) => {
            // list 1 has a match for line2, so they will sync up later
            let position = validator1.get_marker_position();
            let placeholder =
                validator2.insert_mismatch_placeholder(position, validator1.get_line_at(index1));

            pair(validator1, index1, validator2, placeholder);
        }
    }

    validator1.increment(); // done with this line, move the state forward
}

/// Returns the index in `other` of a line matching `source`'s line at `source_index`, or `None`.
///
/// The goal is to find a match for an item that was pushed down because a new item was
/// inserted, NOT for an item that was changed. Matching lines at the same offset between the
/// source line and the candidate match signal that the sought item cannot exist.
///
/// Java recovers the source line's position with `source.indexOf(sourceLine)` (an `equals`
/// search); here the caller passes the line's actual position.
fn find_next_match(
    source: &DiffLinesValidator,
    source_index: usize,
    other: &DiffLinesValidator,
) -> Option<usize> {
    let source_line = source.get_line_at(source_index);
    // no other match for the item at all in the list
    let index = other.find_next_match(source_line)?;

    //
    // Starting after the index of the current line, see if there is a match in the structures,
    // at the same index.  If so, then we don't want to use the match from another
    // offset that we found above.
    //
    let start = source_index + 1;
    let end = source.size().min(index);
    for i in start..end {
        let next_other = other.get_line_at(i);
        let next_source = source.get_line_at(i);

        if next_source.matches_line(next_other) {
            return None;
        }
    }

    Some(index)
}

/// A source line awaiting relocation: the line plus its placeholder flag, or `None` once moved.
type Slot = Option<(Box<dyn ValidatableLine>, bool)>;

fn slot_line(slots: &[Slot], index: usize) -> &dyn ValidatableLine {
    slots[index]
        .as_ref()
        .map(|(line, _)| line.as_ref())
        .expect("source line was already moved")
}

/// Removes empty rows that are no longer necessary for alignment (it may add new empty rows).
fn remove_excess_empty_rows(left_lines: &mut DiffLines, right_lines: &mut DiffLines) {
    let mut new_left_lines = left_lines.create_empty_clone();
    let mut new_right_lines = right_lines.create_empty_clone();

    left_lines.remove_leading_empty_rows();
    right_lines.remove_leading_empty_rows();

    let mut left: Vec<Slot> = left_lines.take_lines().into_iter().map(Some).collect();
    let mut right: Vec<Slot> = right_lines.take_lines().into_iter().map(Some).collect();

    //
    // For the lists, condense areas with empty rows by adjusting the blocks with empty rows
    // so that the empty rows are at the bottom.  This seems to be aesthetically more pleasing
    // when viewing the diff.
    //
    let end = left.len().min(right.len());
    condense_shared_range(&mut left, &mut right, &mut new_left_lines, &mut new_right_lines, 0, end);

    // handle remaining list elements from the longer list
    let left_len = left.len();
    copy_real_lines(&mut left, &mut new_left_lines, end, left_len);
    let right_len = right.len();
    copy_real_lines(&mut right, &mut new_right_lines, end, right_len);

    // reset the contents with the new layout
    left_lines.install_new_lines(new_left_lines);
    right_lines.install_new_lines(new_right_lines);
}

fn condense_shared_range(
    left: &mut [Slot],
    right: &mut [Slot],
    new_left: &mut DiffLines,
    new_right: &mut DiffLines,
    start: usize,
    end: usize,
) {
    let mut i = start;
    while i < end {
        if slot_line(left, i).matches_line(slot_line(right, i)) {
            copy_line(left, new_left, i);
            copy_line(right, new_right, i);
            i += 1;
            continue;
        }

        let end_of_range = find_end_of_distinct_lines(left, right, i);
        condense_sub_range(left, right, new_left, new_right, i, end_of_range);

        // setup the next range match (end_of_range is exclusive)
        i = end_of_range;
    }
}

fn find_end_of_distinct_lines(left: &[Slot], right: &[Slot], start: usize) -> usize {
    let end = left.len().min(right.len());
    (start..end)
        .find(|&i| slot_line(left, i).matches_line(slot_line(right, i)))
        .unwrap_or(end)
}

/// Copies from the source to the destination all lines that are not placeholders. If the
/// two destination lists are not the same size after the copy, then the smaller list is padded
/// with placeholder lines.
fn condense_sub_range(
    left_source: &mut [Slot],
    right_source: &mut [Slot],
    left_destination: &mut DiffLines,
    right_destination: &mut DiffLines,
    start: usize,
    end: usize,
) {
    let safe_end_index = end.min(left_source.len());
    copy_real_lines(left_source, left_destination, start, safe_end_index);

    let safe_end_index = end.min(right_source.len());
    copy_real_lines(right_source, right_destination, start, safe_end_index);

    pad_smaller(left_destination, right_destination);
}

/// # Panics
/// Panics with an [`AssertException`] if the line at `index` is a placeholder.
fn copy_line(from: &mut [Slot], to: &mut DiffLines, index: usize) {
    let (line, is_place_holder) = from[index].take().expect("source line was already moved");
    if is_place_holder {
        panic!(
            "{}",
            AssertException::with_message(
                "copyLine() is meant to copy only real lines, not placeholders"
            )
        );
    }
    to.add(line);
}

fn copy_real_lines(from: &mut [Slot], to: &mut DiffLines, start: usize, end: usize) {
    for slot in &mut from[start..end] {
        let (line, is_place_holder) = slot.take().expect("source line was already moved");
        if is_place_holder {
            // the final list only has placeholders in between items, not at the end
            continue;
        }
        to.add(line);
    }
}

fn pad_smaller(left_destination: &mut DiffLines, right_destination: &mut DiffLines) {
    // for the bigger list, we need to pad, for the other, we don't need the empty rows
    let (smaller_list, larger_list) = if left_destination.len() <= right_destination.len() {
        (left_destination, right_destination)
    } else {
        // right is the small list
        (right_destination, left_destination)
    };

    let size_difference = larger_list.len() - smaller_list.len();
    for _ in 0..size_difference {
        let size = smaller_list.len();

        // get the line opposite of the empty line we are adding
        let opposite_line = larger_list.get(size);
        smaller_list.insert_placeholder(opposite_line);
    }
}

fn highlight_diff_line_differences(left: &mut DiffLines, right: &mut DiffLines) {
    highlight_differences(left, right);
}

/// Pairs each line of `left` with the line at the same position in `right`, coloring lines
/// that do not match.
///
/// # Panics
/// Panics (Java's `IllegalArgumentException`) if the two lists differ in size.
pub fn highlight_differences(left: &mut DiffLines, right: &mut DiffLines) {
    if left.len() != right.len() {
        // update this method to handle different sizes if there is a use case (see the
        // history)
        panic!("Line list size must be the same");
    }

    let shared_length = left.len().min(right.len());
    for i in 0..shared_length {
        validate_pair(left.get_mut(i), right.get_mut(i));
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Ported from `ghidra.app.util.html.DataTypeDifferTest`.
    use super::*;
    use crate::app::util::html::{EmptyTextLine, PlaceHolderLine};

    struct DiffInputTestStub {
        lines: Vec<&'static str>,
    }

    impl DataTypeDiffInput for DiffInputTestStub {
        fn get_lines(&self) -> Vec<Box<dyn ValidatableLine>> {
            self.lines
                .iter()
                .map(|t| Box::new(TextLine::new(*t)) as Box<dyn ValidatableLine>)
                .collect()
        }

        fn create_placeholder(&self, _opposite_line: &dyn ValidatableLine) -> Box<dyn PlaceHolderLine> {
            Box::new(EmptyTextLine::new(1))
        }
    }

    fn input(lines: Vec<&'static str>) -> Rc<dyn DataTypeDiffInput> {
        Rc::new(DiffInputTestStub { lines })
    }

    /// A placeholder means that it is different than the opposite side.
    fn is_diff_colored(lines: &DiffLines, index: usize) -> bool {
        lines.is_place_holder(index) || lines.get(index).is_diff_colored()
    }

    fn index_of(lines: &DiffLines, text: &str) -> usize {
        (0..lines.len())
            .find(|&i| !lines.is_place_holder(i) && lines.get(i).get_text() == text)
            .unwrap_or_else(|| panic!("no line '{text}' in {lines}"))
    }

    fn assert_colored(lines: &DiffLines, texts: &[&str], colored: bool) {
        for text in texts {
            let i = index_of(lines, text);
            assert_eq!(is_diff_colored(lines, i), colored, "line '{text}' in {lines}");
        }
    }

    fn assert_all_colored(lines: &DiffLines, colored: bool) {
        for i in 0..lines.len() {
            assert_eq!(is_diff_colored(lines, i), colored, "line {i} in {lines}");
        }
    }

    fn body(left: Vec<&'static str>, right: Vec<&'static str>) -> DataTypeDiff {
        diff_body(input(left), input(right))
    }

    #[test]
    fn diff_body_empty_inputs() {
        let diff = body(vec![], vec![]);
        assert!(diff.get_left_lines().is_empty());
        assert!(diff.get_right_lines().is_empty());
    }

    #[test]
    fn diff_body_single_input_same() {
        let diff = body(vec!["Line One"], vec!["Line One"]);
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_all_colored(left, false);
        assert_all_colored(right, false);
    }

    #[test]
    fn diff_body_single_input_different() {
        let diff = body(vec!["Left One"], vec!["Right One"]);
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_all_colored(left, true);
        assert_all_colored(right, true);
    }

    #[test]
    fn diff_body_different_size_same_start() {
        let diff = body(vec!["Line One"], vec!["Line One", "Line Two"]);
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_colored(right, &["Line One"], false);
        assert_colored(right, &["Line Two"], true);
        assert!(left.is_place_holder(1));
    }

    #[test]
    fn diff_body_triple_input_all_different_but_last() {
        let diff = body(
            vec!["Left One", "Left Two", "Same"],
            vec!["Right One", "Right Two", "Same"],
        );
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_colored(left, &["Left One", "Left Two"], true);
        assert_colored(right, &["Right One", "Right Two"], true);
        assert_colored(left, &["Same"], false);
        assert_colored(right, &["Same"], false);
    }

    #[test]
    fn diff_body_different_size_same_top_and_bottom() {
        let diff = body(
            vec!["Line One", "Line Two", "Line Three"],
            vec!["Line One", "Insert A", "Line Two", "Insert B", "Line Three"],
        );
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        // inserted lines are different; other should be matched
        assert_colored(right, &["Insert A", "Insert B"], true);
        assert_colored(left, &["Line One", "Line Two", "Line Three"], false);
        assert_colored(right, &["Line One", "Line Two", "Line Three"], false);
        // aligned: placeholders sit opposite the inserted lines
        assert!(left.is_place_holder(1));
        assert!(left.is_place_holder(3));
    }

    #[test]
    fn diff_body_different_size_all_different() {
        let diff = body(
            vec!["Left One", "Left Two"],
            vec!["Right One", "Right Two", "Right Three", "Right Four", "Right Five"],
        );
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_all_colored(left, true);
        assert_all_colored(right, true);
    }

    #[test]
    fn diff_body_same_initial_lines_inserts_to_both_at_different_offsets() {
        let diff = body(
            vec![
                "Line One",
                "Left One - A",
                "Left One - B",
                "Left One - C",
                "Line Two",
                "Line Three",
                "Line Four",
            ],
            vec![
                "Line One",
                "Line Two",
                "Right Two - A",
                "Right Two - B",
                "Line Three",
                "Line Four",
            ],
        );
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(
            left.len() as isize - right.len() as isize,
            1,
            "Expected left side to be 1 larger due to conflicting inserted items"
        );

        let matched = ["Line One", "Line Two", "Line Three", "Line Four"];
        assert_colored(left, &matched, false);
        assert_colored(right, &matched, false);
        assert_colored(left, &["Left One - A", "Left One - B", "Left One - C"], true);
        assert_colored(right, &["Right Two - A", "Right Two - B"], true);

        // no duplicates: every real line appears exactly once
        for lines in [left, right] {
            let texts: Vec<&str> = (0..lines.len())
                .filter(|&i| !lines.is_place_holder(i))
                .map(|i| lines.get(i).get_text())
                .collect();
            let mut deduped = texts.clone();
            deduped.sort_unstable();
            deduped.dedup();
            assert_eq!(texts.len(), deduped.len(), "duplicate lines in {lines}");
        }
    }

    #[test]
    fn header_lines_same() {
        let diff = body(vec!["Line One", "Line Two"], vec!["Line One", "Line Two"]);
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_all_colored(left, false);
        assert_all_colored(right, false);
    }

    #[test]
    fn header_lines_different_same_size() {
        let diff = body(vec!["Line One", "Left Two"], vec!["Line One", "Right Two"]);
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_colored(left, &["Line One"], false);
        assert_colored(right, &["Line One"], false);
        assert_colored(left, &["Left Two"], true);
        assert_colored(right, &["Right Two"], true);
    }

    #[test]
    fn header_lines_different_different_size() {
        let diff = body(
            vec!["Line One", "Left Two"],
            vec!["Line One", "Right Two", "Right Three", "Right Four"],
        );
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(left.len(), right.len());
        assert_colored(left, &["Line One"], false);
        assert_colored(right, &["Line One"], false);
        assert_colored(left, &["Left Two"], true);
        assert_colored(right, &["Right Two", "Right Three", "Right Four"], true);
    }

    fn lines_of(texts: &[&'static str]) -> DiffLines {
        DiffLines::new(input(texts.to_vec()))
    }

    #[test]
    fn highlight_differences_same() {
        let mut left = lines_of(&["Line One", "Line Two"]);
        let mut right = lines_of(&["Line One", "Line Two"]);
        highlight_differences(&mut left, &mut right);
        assert_all_colored(&left, false);
        assert_all_colored(&right, false);
    }

    #[test]
    fn highlight_differences_different() {
        let mut left = lines_of(&["Line One", "Left Two"]);
        let mut right = lines_of(&["Line One", "Right Two"]);
        highlight_differences(&mut left, &mut right);
        assert!(!left.get(0).is_diff_colored());
        assert!(!right.get(0).is_diff_colored());
        assert!(left.get(1).is_diff_colored());
        assert!(right.get(1).is_diff_colored());
    }

    #[test]
    #[should_panic(expected = "Line list size must be the same")]
    fn highlight_differences_different_sizes() {
        let mut left = lines_of(&["Line One"]);
        let mut right = lines_of(&["Line One", "Right Two"]);
        highlight_differences(&mut left, &mut right);
    }

    #[test]
    fn pad_lines_pads_shorter_side_with_empty_tag_then_br() {
        let mut left = lines_of(&[]);
        let mut right = lines_of(&["a", "b", "c"]);
        pad_lines(&mut left, &mut right);
        let texts: Vec<&str> = left.iter().map(|l| l.get_text()).collect();
        assert_eq!(texts, vec![EMPTY_TAG, BR, BR]);
        assert_eq!(right.len(), 3);
    }

    #[test]
    fn pad_lines_equal_sizes_is_noop() {
        let mut left = lines_of(&["a"]);
        let mut right = lines_of(&["b"]);
        pad_lines(&mut left, &mut right);
        assert_eq!(left.len(), 1);
        assert_eq!(right.len(), 1);
    }

    #[test]
    fn diff_lines_pads_and_highlights_positionally() {
        let diff = diff_lines(input(vec!["same", "left"]), input(vec!["same"]));
        let (left, right) = (diff.get_left_lines(), diff.get_right_lines());
        assert_eq!(right.len(), 2);
        assert_eq!(right.get(1).get_text(), BR);
        assert!(!left.get(0).is_diff_colored());
        assert!(left.get(1).is_diff_colored());
        assert!(right.get(1).is_diff_colored());

        let header = diff_header(input(vec!["x"]), input(vec!["x"]));
        assert!(!header.get_left_lines().get(0).is_diff_colored());
    }
}
