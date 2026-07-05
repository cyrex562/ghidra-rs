use crate::generic::algorithms::{DummyMonitor, ReducingListBasedLcs};

use super::StringDiff;

/// Minimum size used to determine whether a new [`StringDiff`] object will be
/// created just using a string (no positions) in [`get_line_diffs`].
const MINIMUM_DIFF_SIZE: i32 = 100;

/// Returns the list of [`StringDiff`]s that, if applied to `s1`, would result in `s2`. The
/// given text will look only for whole lines using `'\n'`.
///
/// # Arguments
/// * `s1` - the original string
/// * `s2` - the result string
pub(crate) fn get_line_diffs(s1: &str, s2: &str) -> Vec<StringDiff> {
    get_line_diffs_with_minimum(s1, s2, MINIMUM_DIFF_SIZE)
}

pub(crate) fn get_line_diffs_with_minimum(
    s1: &str,
    s2: &str,
    minimum_diff_size: i32,
) -> Vec<StringDiff> {
    if (s2.len() as i32) < minimum_diff_size {
        return vec![StringDiff::all_text_replaced(s2)];
    }

    let a_list = split(s1);
    let b_list = split(s2);
    let lcs = ReducingListBasedLcs::new(a_list.clone(), b_list.clone());
    let commons = lcs
        .get_lcs(&DummyMonitor)
        .expect("DummyMonitor never cancels");
    if commons.is_empty() {
        // no common text--complete replacement
        return vec![StringDiff::all_text_replaced(s2)];
    }

    let mut a_last_index = 0usize;
    let mut b_last_index = 0usize;
    let mut results: Vec<StringDiff> = Vec::new();

    for common in &commons {
        let a_index = index_of(&a_list, common, a_last_index);
        let b_index = index_of(&b_list, common, b_last_index);

        let a_previous = &a_list[a_last_index..a_index];
        if let Some(delete) = create_delete(a_previous) {
            results.push(delete);
        }

        let b_previous = &b_list[b_last_index..b_index];
        if let Some(insert) = create_insert(b_previous, char_offset(&a_list, a_index)) {
            results.push(insert);
        }

        // note: nothing is needed for the 'common' string, since we don't track unchanged text

        a_last_index = a_index + 1;
        b_last_index = b_index + 1;
    }

    // grab remainder
    if let Some(trailing_deleted) = create_delete_at_end(&a_list, a_last_index, a_list.len()) {
        results.push(trailing_deleted);
    }

    if let Some(trailing_inserted) =
        create_insert_at_end(&b_list, b_last_index, b_list.len(), s1.len() as i32)
    {
        results.push(trailing_inserted);
    }

    results
}

fn char_offset(list: &[Line], index: usize) -> i32 {
    list[index].start
}

fn create_insert_at_end(
    list: &[Line],
    start: usize,
    end: usize,
    insert_index: i32,
) -> Option<StringDiff> {
    if start == end + 1 {
        return None;
    }

    let to_do = &list[start..end];
    let newline_needed = true; // we are at the end--need a newline
    create_insert_impl(to_do, insert_index, newline_needed)
}

fn create_insert(lines: &[Line], insert_index: i32) -> Option<StringDiff> {
    create_insert_impl(lines, insert_index, false)
}

fn create_insert_impl(lines: &[Line], insert_index: i32, is_at_end: bool) -> Option<StringDiff> {
    if lines.is_empty() {
        return None;
    }

    let mut buffy = String::new();

    // special case: if this insert is for the end of the line, then we want to add
    //               a newline before the remaining text is added since the original text
    //               did not have this newline
    if is_at_end {
        buffy.push('\n');
    }

    for line in lines {
        buffy.push_str(&line.get_text());
    }

    Some(StringDiff::text_inserted(buffy, insert_index))
}

fn create_delete_at_end(list: &[Line], start: usize, end: usize) -> Option<StringDiff> {
    if start == end + 1 {
        return None;
    }

    let to_do = &list[start..end];
    let include_last_newline = false; // we are at the end--do not include artificial newline
    create_delete_impl(to_do, include_last_newline)
}

fn create_delete(lines: &[Line]) -> Option<StringDiff> {
    create_delete_impl(lines, true)
}

fn create_delete_impl(lines: &[Line], include_last_newline: bool) -> Option<StringDiff> {
    if lines.is_empty() {
        return None;
    }

    let mut start = 0i32;
    let mut end = 0i32;
    for line in lines {
        start = line.start;
        end = line.start + line.text.len() as i32;
    }

    // special case: if this delete is for the last line, then we want to remove the remaining
    //               trailing newline
    let last = &lines[lines.len() - 1];
    if !include_last_newline && last.is_last_line {
        start -= 1; // remove previous newline
    }

    Some(StringDiff::text_deleted(start, end))
}

fn index_of(list: &[Line], line: &Line, from: usize) -> usize {
    for (i, candidate) in list.iter().enumerate().skip(from) {
        if candidate.text_matches(line) {
            return i;
        }
    }
    list.len() // should not get here since 's' is known to be in list
}

fn split(s: &str) -> Vec<Line> {
    let tokens: Vec<&str> = if s.is_empty() {
        Vec::new()
    } else {
        s.split('\n').collect()
    };

    let mut result: Vec<Line> = Vec::new();
    let mut start = 0i32;
    for line in tokens {
        let l = Line::new(format!("{line}\n"), start);
        start += l.text.len() as i32;
        result.push(l);
    }

    if result.is_empty() {
        result.push(Line::new(String::new(), 0));
    }

    if let Some(last) = result.last_mut() {
        last.mark_as_last(); // this will signal to remove the trailing newline for the last line
    }

    result
}

/// Applies the list of [`StringDiff`]s to the string `s` to produce a new string.
///
/// Warning: the diff objects cannot be applied to an arbitrary string, the strings must be
/// the original string used to compute the diffs.
///
/// # Arguments
/// * `s` - the original string
/// * `diffs` - the diffs to apply
pub(crate) fn apply_diffs(s: &str, diffs: &[StringDiff]) -> String {
    if diffs.is_empty() {
        return s.to_string();
    }

    if diffs[0].start < 0 {
        // all replaced or all deleted
        return diffs[0].text.clone().unwrap_or_default();
    }

    let mut pos = 0usize;
    let mut buf = String::with_capacity(s.len());
    for element in diffs {
        if element.start > pos as i32 {
            buf.push_str(&s[pos..element.start as usize]);
            pos = element.start as usize;
        }

        match &element.text {
            Some(data) => buf.push_str(data),
            None => pos = element.end as usize, // null data is a delete; move to the end of the delete
        }
    }

    if pos < s.len() {
        buf.push_str(&s[pos..]);
    }

    buf
}

#[derive(Debug, Clone)]
struct Line {
    text: String,
    start: i32,
    is_last_line: bool,
}

impl Line {
    fn new(text: String, start: i32) -> Self {
        Self { text, start, is_last_line: false }
    }

    fn get_text(&self) -> String {
        if self.is_last_line {
            self.text_without_newline()
        }
        else {
            self.text.clone()
        }
    }

    fn mark_as_last(&mut self) {
        self.is_last_line = true;
    }

    fn text_without_newline(&self) -> String {
        if let Some(stripped) = self.text.strip_suffix('\n') {
            stripped.to_string()
        }
        else {
            self.text.clone()
        }
    }

    fn text_matches(&self, other: &Line) -> bool {
        self.text == other.text
    }
}

// The Java `LineLcs` overrides `matches` to compare only the line text, ignoring position;
// mirror that here since equality is only ever used to drive the LCS match.
impl PartialEq for Line {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_result_is_all_text_replaced() {
        let diffs = get_line_diffs_with_minimum("hello", "world", 100);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].start, -1);
        assert_eq!(diffs[0].end, -1);
        assert_eq!(diffs[0].text.as_deref(), Some("world"));
    }

    #[test]
    fn identical_strings_produce_no_diffs() {
        let s1 = "a\n".repeat(60);
        let s2 = s1.clone();
        let diffs = get_line_diffs_with_minimum(&s1, &s2, 10);
        assert!(diffs.is_empty());
        assert_eq!(apply_diffs(&s1, &diffs), s2);
    }

    #[test]
    fn no_common_lines_is_full_replacement() {
        let s1 = "x\n".repeat(60);
        let s2 = "y\n".repeat(60);
        let diffs = get_line_diffs_with_minimum(&s1, &s2, 10);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].start, -1);
        assert_eq!(diffs[0].text.as_deref(), Some(s2.as_str()));
    }

    #[test]
    fn inserted_line_round_trips() {
        let s1 = "line1\nline2\nline3\n".repeat(10);
        let mut s2 = String::new();
        let mut first = true;
        for line in s1.split_inclusive('\n') {
            s2.push_str(line);
            if first {
                s2.push_str("inserted\n");
                first = false;
            }
        }

        let diffs = get_line_diffs_with_minimum(&s1, &s2, 10);
        assert!(!diffs.is_empty());
        assert_eq!(apply_diffs(&s1, &diffs), s2);
    }

    #[test]
    fn deleted_line_round_trips() {
        let s1 = "line1\nline2\nline3\nline4\n".repeat(10);
        let s2: String = s1
            .split_inclusive('\n')
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .map(|(_, l)| l)
            .collect();

        let diffs = get_line_diffs_with_minimum(&s1, &s2, 10);
        assert!(!diffs.is_empty());
        assert_eq!(apply_diffs(&s1, &diffs), s2);
    }

    #[test]
    fn trailing_newline_difference_round_trips() {
        let s1 = "line1\nline2\n".repeat(15);
        let s2 = format!("{}extra", s1);

        let diffs = get_line_diffs_with_minimum(&s1, &s2, 10);
        assert_eq!(apply_diffs(&s1, &diffs), s2);
    }

    #[test]
    fn apply_diffs_with_no_diffs_returns_original() {
        assert_eq!(apply_diffs("unchanged", &[]), "unchanged");
    }

    #[test]
    fn apply_diffs_all_text_replaced() {
        let diffs = vec![StringDiff::all_text_replaced("new text")];
        assert_eq!(apply_diffs("old text", &diffs), "new text");
    }

    #[test]
    fn apply_diffs_delete_only() {
        let diffs = vec![StringDiff::text_deleted(0, -1)];
        assert_eq!(apply_diffs("anything", &diffs), "");
    }

    #[test]
    fn split_empty_string_yields_single_empty_line() {
        let lines = split("");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].get_text(), "");
        assert!(lines[0].is_last_line);
    }

    #[test]
    fn split_preserves_trailing_newline_as_extra_line() {
        let lines = split("a\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].get_text(), "a\n");
        assert_eq!(lines[1].get_text(), "");
    }

    #[test]
    fn split_without_trailing_newline() {
        let lines = split("a\nb");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].get_text(), "a\n");
        assert_eq!(lines[1].get_text(), "b");
    }

    #[test]
    fn line_equality_ignores_start_position() {
        let a = Line::new("same\n".to_string(), 0);
        let b = Line::new("same\n".to_string(), 42);
        assert_eq!(a, b);
    }
}
