//! Port of `ghidra.app.plugin.core.terminal.vt.VtLine`.

use crate::app::seam_stubs::VtAttributes;

/// A line of text in the terminal's `VtBuffer`.
///
/// Port of `ghidra.app.plugin.core.terminal.vt.VtLine`. Columns are 0-up. The character and
/// attribute buffers may be longer than [`cols`](Self::cols): shrinking a line does not forget the
/// characters beyond the new width, so they come back if the terminal is widened again.
///
/// As in Java, out-of-range column arguments are a caller error; where Java would throw
/// `ArrayIndexOutOfBoundsException`, this port panics on the slice index.
#[derive(Debug, Clone)]
pub struct VtLine {
    cols: usize,
    len: usize,
    chars: Vec<char>,
    /// Whether this line wrapped onto the next. Mirrors Java's `protected` field of the same name;
    /// every edit to the line clears it.
    pub wrapped_to_next: bool,
    /// Per-cell attributes; `None` (Java's `null`) reads back as [`VtAttributes::DEFAULTS`].
    cell_attrs: Vec<Option<VtAttributes>>,
}

impl VtLine {
    /// Create a line with the given maximum number of characters.
    pub fn new(cols: usize) -> Self {
        VtLine {
            cols,
            len: 0,
            chars: vec!['\0'; cols],
            wrapped_to_next: false,
            cell_attrs: vec![None; cols],
        }
    }

    /// Get the character in the given column.
    pub fn get_char(&self, x: usize) -> char {
        self.chars[x]
    }

    /// Get the full character buffer.
    ///
    /// This is the buffer itself, which is useful when rendering. It may be longer than
    /// [`cols`](Self::cols) and contains stale characters past [`length`](Self::length).
    pub fn get_char_buffer(&self) -> &[char] {
        &self.chars
    }

    /// Get the attributes for the character in the given column, or
    /// [`VtAttributes::DEFAULTS`] if that cell was never assigned any.
    pub fn get_cell_attrs(&self, x: usize) -> VtAttributes {
        match &self.cell_attrs[x] {
            Some(attrs) => attrs.clone(),
            None => VtAttributes::DEFAULTS,
        }
    }

    /// Place the given character with attributes into the given column.
    ///
    /// Any gap between the previous end of the line and `x` is filled with default-attributed
    /// spaces. When `attrs` is `None` the cell keeps whatever attributes it already had, as Java
    /// does for a `null` argument.
    pub fn put_char(&mut self, x: usize, c: char, attrs: Option<VtAttributes>) {
        let old_len = self.len;
        self.len = self.len.max(x + 1);
        self.wrapped_to_next = false;
        for i in old_len..x {
            self.chars[i] = ' ';
            self.cell_attrs[i] = Some(VtAttributes::DEFAULTS);
        }
        self.chars[x] = c;
        if let Some(attrs) = attrs {
            self.cell_attrs[x] = Some(attrs);
        }
    }

    /// Resize the line to the given maximum character count.
    ///
    /// The buffers only ever grow: characters beyond a smaller width are kept so that resizing
    /// back restores them.
    pub fn resize(&mut self, cols: usize) {
        self.cols = cols;
        if cols <= self.chars.len() {
            return;
        }
        self.chars.resize(cols, '\0');
        self.cell_attrs.resize(cols, None);
    }

    /// Reset the line.
    ///
    /// Java assigns `cols` before testing whether it changed, so an existing buffer is never
    /// reallocated here; only the column count, length and wrap flag are reset. That behavior is
    /// preserved.
    pub fn reset(&mut self, cols: usize) {
        self.cols = cols;
        self.len = 0;
        self.wrapped_to_next = false;
    }

    /// Get the length of the line, excluding trailing cleared characters.
    pub fn length(&self) -> usize {
        self.len.min(self.cols)
    }

    /// Get the number of columns in the line.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Clear the full line.
    pub fn clear(&mut self) {
        self.len = 0;
        self.wrapped_to_next = false;
    }

    /// Clear characters at and after the given column.
    pub fn clear_to_end(&mut self, x: usize) {
        self.len = self.len.min(x);
        self.wrapped_to_next = false;
    }

    /// Clear characters before and at the given column, giving the cleared (space) characters the
    /// given attributes.
    pub fn clear_to_start(&mut self, x: usize, attrs: VtAttributes) {
        if self.len <= x {
            self.len = 0;
            self.wrapped_to_next = false;
            return;
        }
        for i in 0..=x {
            self.chars[i] = ' ';
            self.cell_attrs[i] = Some(attrs.clone());
        }
    }

    /// Delete characters in the given range (`end` exclusive), shifting remaining characters to
    /// the left.
    ///
    /// Faithful to Java, only the `end - start` cells of the deleted range are overwritten from
    /// the cells `end - start` to their right.
    pub fn delete(&mut self, start: usize, end: usize) {
        if self.len <= end {
            self.len = self.len.min(start);
            self.wrapped_to_next = false;
            return;
        }
        let shift = end - start;
        self.len -= shift;
        for x in start..end {
            self.chars[x] = self.chars[x + shift];
            self.cell_attrs[x] = self.cell_attrs[x + shift].clone();
        }
    }

    /// Replace characters in the given range (`end` exclusive) with spaces having the given
    /// attributes.
    ///
    /// If the last column is erased, this instead clears from `start` to the end, so the trailing
    /// spaces are not reported as part of the line's text.
    pub fn erase(&mut self, start: usize, end: usize, attrs: VtAttributes) {
        if self.len <= end {
            self.len = self.len.min(start);
            self.wrapped_to_next = false;
            return;
        }
        for x in start..end {
            self.chars[x] = ' ';
            self.cell_attrs[x] = Some(attrs.clone());
        }
    }

    /// Insert `n` (space) characters at and after the given column.
    ///
    /// Shifted characters that fall off the end of the line are lost rather than wrapped, and the
    /// inserted spaces keep the attributes already in their cells, as in Java.
    pub fn insert(&mut self, start: usize, n: usize) {
        let end = self.cols.min(start + n);
        let mut x = self.cols;
        while x > end {
            x -= 1;
            self.chars[x] = self.chars[x - n];
            self.cell_attrs[x] = self.cell_attrs[x - n].clone();
        }
        for x in start..end {
            self.chars[x] = ' ';
        }
        self.len = self.cols.min(self.len + n);
        self.wrapped_to_next = false;
    }

    /// Execute an action on each run of contiguous characters having the same attributes, from
    /// left to right. The action receives the run's shared attributes, its first column and its
    /// last column (exclusive).
    ///
    /// Port of `forEachRun(RunConsumer)`; Java's single-method `RunConsumer` callback interface
    /// is a closure here. For an empty line Java reports an empty run with the default attributes
    /// and then, because it does not return early, a second empty run with the attributes of
    /// column 0; both calls are preserved.
    pub fn for_each_run<F>(&self, mut action: F)
    where
        F: FnMut(&VtAttributes, usize, usize),
    {
        let length = self.length();
        if length == 0 {
            action(&VtAttributes::DEFAULTS, 0, 0);
        }
        let mut first = 0;
        let mut attrs = self.get_cell_attrs(0);
        for x in 1..length {
            let cell = self.get_cell_attrs(x);
            if attrs != cell {
                action(&attrs, first, x);
                first = x;
                attrs = cell;
            }
        }
        action(&attrs, first, length);
    }

    /// Append a portion of this line's text (`end` exclusive) to the given string. Both bounds are
    /// clamped to the line's current length.
    pub fn gather_text(&self, sb: &mut String, start: usize, end: usize) {
        let start = start.min(self.len);
        let end = end.min(self.len);
        sb.extend(&self.chars[start..end]);
    }

    /// Check if the given character is considered part of a word.
    ///
    /// This is used both when selecting words, and when requiring search to find whole words.
    pub fn is_word_char(ch: char) -> bool {
        ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '@'
    }

    /// Find the boundaries for the word at the given column.
    ///
    /// Returns the word's first column when `forward` is false, or its last column (exclusive)
    /// when `forward` is true.
    pub fn find_word(&self, x: usize, forward: bool) -> usize {
        if forward {
            for i in x..self.len {
                if !Self::is_word_char(self.chars[i]) {
                    return i;
                }
            }
            self.len
        } else {
            if x < self.len {
                for i in (0..=x).rev() {
                    if !Self::is_word_char(self.chars[i]) {
                        return i + 1;
                    }
                }
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_with(text: &str, cols: usize) -> VtLine {
        let mut line = VtLine::new(cols);
        for (i, c) in text.chars().enumerate() {
            line.put_char(i, c, None);
        }
        line
    }

    fn text(line: &VtLine) -> String {
        let mut sb = String::new();
        line.gather_text(&mut sb, 0, line.cols());
        sb
    }

    #[test]
    fn new_line_is_empty() {
        let line = VtLine::new(10);
        assert_eq!(line.cols(), 10);
        assert_eq!(line.length(), 0);
        assert_eq!(line.get_char_buffer().len(), 10);
        assert!(!line.wrapped_to_next);
        assert_eq!(line.get_cell_attrs(3), VtAttributes::DEFAULTS);
    }

    #[test]
    fn put_char_pads_gap_with_spaces_and_clears_wrap() {
        let mut line = VtLine::new(10);
        line.wrapped_to_next = true;
        line.put_char(3, 'x', Some(VtAttributes::DEFAULTS));
        assert_eq!(line.length(), 4);
        assert_eq!(text(&line), "   x");
        assert_eq!(line.get_char(3), 'x');
        assert!(!line.wrapped_to_next);
        // Writing before the end does not shrink the line.
        line.put_char(1, 'y', None);
        assert_eq!(line.length(), 4);
        assert_eq!(text(&line), " y x");
    }

    #[test]
    fn resize_keeps_characters_beyond_new_width() {
        let mut line = line_with("abcdef", 6);
        line.resize(3);
        assert_eq!(line.cols(), 3);
        assert_eq!(line.length(), 3);
        assert_eq!(line.get_char_buffer().len(), 6);
        line.resize(6);
        assert_eq!(line.length(), 6);
        assert_eq!(text(&line), "abcdef");
        line.resize(8);
        assert_eq!(line.get_char_buffer().len(), 8);
        assert_eq!(text(&line), "abcdef");
    }

    #[test]
    fn reset_keeps_existing_buffer() {
        let mut line = line_with("abc", 4);
        line.wrapped_to_next = true;
        line.reset(2);
        assert_eq!(line.cols(), 2);
        assert_eq!(line.length(), 0);
        assert!(!line.wrapped_to_next);
        assert_eq!(line.get_char_buffer().len(), 4);
        assert_eq!(line.get_char(0), 'a');
    }

    #[test]
    fn clear_and_clear_to_end() {
        let mut line = line_with("hello", 10);
        line.clear_to_end(2);
        assert_eq!(text(&line), "he");
        line.clear_to_end(4);
        assert_eq!(text(&line), "he");
        line.clear();
        assert_eq!(line.length(), 0);
    }

    #[test]
    fn clear_to_start_blanks_prefix_or_clears_short_line() {
        let mut line = line_with("hello", 10);
        line.clear_to_start(1, VtAttributes::DEFAULTS);
        assert_eq!(text(&line), "  llo");
        assert_eq!(line.length(), 5);
        // Clearing at or past the end clears the whole line.
        line.clear_to_start(5, VtAttributes::DEFAULTS);
        assert_eq!(line.length(), 0);
    }

    #[test]
    fn delete_shifts_left_or_truncates() {
        let mut line = line_with("abcdefgh", 10);
        line.delete(1, 3);
        assert_eq!(line.length(), 6);
        // Java copies only end-start cells: [1]=d, [2]=e; the rest are left as they were.
        assert_eq!(text(&line), "adedef");

        let mut line = line_with("abcdef", 10);
        line.delete(2, 6);
        assert_eq!(text(&line), "ab");
    }

    #[test]
    fn erase_blanks_range_or_truncates_at_end() {
        let mut line = line_with("abcdef", 10);
        line.erase(1, 3, VtAttributes::DEFAULTS);
        assert_eq!(text(&line), "a  def");
        line.erase(4, 6, VtAttributes::DEFAULTS);
        assert_eq!(text(&line), "a  d");
    }

    #[test]
    fn insert_shifts_right_and_drops_overflow() {
        let mut line = line_with("abcdef", 8);
        line.insert(1, 2);
        assert_eq!(line.length(), 8);
        assert_eq!(text(&line), "a  bcdef");
        line.insert(6, 5);
        // end is capped at cols, so nothing shifts; columns 6..8 become spaces.
        assert_eq!(text(&line), "a  bcd  ");
        assert_eq!(line.length(), 8);
    }

    #[test]
    fn for_each_run_reports_single_run_for_uniform_line() {
        let line = line_with("abc", 5);
        let mut runs = Vec::new();
        line.for_each_run(|a, s, e| runs.push((a.clone(), s, e)));
        assert_eq!(runs, vec![(VtAttributes::DEFAULTS, 0, 3)]);
    }

    #[test]
    fn for_each_run_on_empty_line_reports_two_empty_runs() {
        let line = VtLine::new(5);
        let mut runs = Vec::new();
        line.for_each_run(|a, s, e| runs.push((a.clone(), s, e)));
        assert_eq!(
            runs,
            vec![(VtAttributes::DEFAULTS, 0, 0), (VtAttributes::DEFAULTS, 0, 0)]
        );
    }

    #[test]
    fn gather_text_clamps_to_length() {
        let line = line_with("hello", 10);
        let mut sb = String::from(">");
        line.gather_text(&mut sb, 1, 99);
        assert_eq!(sb, ">ello");
        let mut sb = String::new();
        line.gather_text(&mut sb, 7, 9);
        assert_eq!(sb, "");
    }

    #[test]
    fn word_chars_match_java() {
        for c in ['a', 'Z', '0', '_', '-', '@', 'é'] {
            assert!(VtLine::is_word_char(c), "{c}");
        }
        for c in [' ', '.', '/', ':', '\t'] {
            assert!(!VtLine::is_word_char(c), "{c}");
        }
    }

    #[test]
    fn find_word_boundaries() {
        let line = line_with("ls foo_bar.txt", 20);
        // "foo_bar" spans columns 3..10.
        assert_eq!(line.find_word(5, true), 10);
        assert_eq!(line.find_word(5, false), 3);
        // Word running to the end / start of the line.
        assert_eq!(line.find_word(12, true), 14);
        assert_eq!(line.find_word(1, false), 0);
        // Starting on a non-word character returns that column (forward) or the next (backward).
        assert_eq!(line.find_word(2, true), 2);
        assert_eq!(line.find_word(2, false), 3);
        // Past the end of the line.
        assert_eq!(line.find_word(15, true), 14);
        assert_eq!(line.find_word(15, false), 0);
    }
}
