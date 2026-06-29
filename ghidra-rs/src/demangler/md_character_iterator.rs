/// Returned when the iterator reaches the beginning or end of the text.
///
/// Mirrors `MDCharacterIterator.DONE` (`'\u{FFFF}'`).
pub const DONE: char = '\u{FFFF}';

/// Bidirectional character iterator over a string, from the `mdemangler` package.
///
/// Maintains a current index over the range `0..=get_length()`. [`peek`] reads at the
/// current index without advancing; [`next`] advances first then reads; [`get_and_increment`]
/// reads then advances; [`previous`] retreats first then reads.
///
/// Port of `mdemangler.MDCharacterIterator`.
pub struct MdCharacterIterator {
    string: String,
    chars: Vec<char>,
    index: usize,
}

impl MdCharacterIterator {
    /// Sentinel returned when the iterator is exhausted.
    pub const DONE: char = DONE;

    /// Creates a new iterator over `s`, positioned at index 0.
    pub fn new(s: impl Into<String>) -> Self {
        let string = s.into();
        let chars = string.chars().collect();
        Self { string, chars, index: 0 }
    }

    /// Returns the underlying string.
    pub fn get_string(&self) -> &str {
        &self.string
    }

    /// Returns the current index.
    pub fn get_index(&self) -> usize {
        self.index
    }

    /// Returns the number of characters in the underlying string.
    pub fn get_length(&self) -> usize {
        self.chars.len()
    }

    /// Sets the current index to the given position.
    ///
    /// The index may be set to `get_length()` to represent the iterator positioned just past
    /// the end of the text.
    ///
    /// # Panics
    /// Panics if `index > get_length()` (mirrors Java `IllegalArgumentException`).
    pub fn set_index(&mut self, index: usize) {
        assert!(
            index <= self.chars.len(),
            "index out of bounds: {} for length {}",
            index,
            self.chars.len()
        );
        self.index = index;
    }

    /// Returns `true` if [`next`] would return a valid character (not [`DONE`]).
    ///
    /// Mirrors Java `index < string.length() - 1`.
    pub fn has_next(&self) -> bool {
        self.index < self.chars.len().saturating_sub(1)
    }

    /// Returns the character at the current index without advancing.
    ///
    /// Returns [`DONE`] if the current index is out of range.
    pub fn peek(&self) -> char {
        self.chars.get(self.index).copied().unwrap_or(Self::DONE)
    }

    /// Returns the character at `current_index + look_ahead` without advancing.
    ///
    /// Returns [`DONE`] if the computed position is out of range.
    pub fn peek_ahead(&self, look_ahead: usize) -> char {
        self.index
            .checked_add(look_ahead)
            .and_then(|i| self.chars.get(i))
            .copied()
            .unwrap_or(Self::DONE)
    }

    /// Advances the index by one and returns the character at the **new** position.
    ///
    /// Returns [`DONE`] and clamps the index to `get_length()` when advancing would exceed
    /// the string.
    pub fn next(&mut self) -> char {
        self.index = self.index.saturating_add(1);
        if self.index < self.chars.len() {
            self.chars[self.index]
        } else {
            self.index = self.chars.len();
            Self::DONE
        }
    }

    /// Returns the character at the **current** index, then advances by one.
    ///
    /// Returns [`DONE`] and clamps the index to `get_length()` when the current index is
    /// out of range.
    pub fn get_and_increment(&mut self) -> char {
        match self.chars.get(self.index).copied() {
            Some(c) => {
                self.index += 1;
                c
            }
            None => {
                self.index = self.chars.len();
                Self::DONE
            }
        }
    }

    /// Increments the current index by one without bounds checking.
    pub fn increment(&mut self) {
        self.index += 1;
    }

    /// Increments the current index by `count` without bounds checking.
    pub fn increment_by(&mut self, count: usize) {
        self.index += count;
    }

    /// Decrements the current index by one and returns the character at the **new** position.
    ///
    /// Returns [`DONE`] (leaving the index at 0) when already at the beginning.
    pub fn previous(&mut self) -> char {
        if self.index == 0 {
            return Self::DONE;
        }
        self.index -= 1;
        self.chars[self.index]
    }

    /// Returns `true` if `substring` begins at the current index position.
    ///
    /// Mirrors `String.regionMatches` from Java.
    pub fn position_starts_with(&self, substring: &str) -> bool {
        let safe_index = self.index.min(self.chars.len());
        let byte_offset: usize = self.chars[..safe_index].iter().map(|c| c.len_utf8()).sum();
        self.string[byte_offset..].starts_with(substring)
    }
}

impl std::fmt::Display for MdCharacterIterator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n{}^", self.string, " ".repeat(self.index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_index_zero() {
        let it = MdCharacterIterator::new("hello");
        assert_eq!(it.get_index(), 0);
        assert_eq!(it.get_length(), 5);
    }

    #[test]
    fn get_string_returns_original() {
        let it = MdCharacterIterator::new("abc");
        assert_eq!(it.get_string(), "abc");
    }

    #[test]
    fn done_constant_is_u_ffff() {
        assert_eq!(MdCharacterIterator::DONE, '\u{FFFF}');
        assert_eq!(DONE, '\u{FFFF}');
    }

    #[test]
    fn set_index_to_length_is_valid() {
        let mut it = MdCharacterIterator::new("abc");
        it.set_index(3); // == get_length(), just past the end
        assert_eq!(it.get_index(), 3);
        assert_eq!(it.peek(), DONE);
    }

    #[test]
    fn set_index_mid_string() {
        let mut it = MdCharacterIterator::new("hello");
        it.set_index(2);
        assert_eq!(it.peek(), 'l');
    }

    #[test]
    #[should_panic]
    fn set_index_beyond_length_panics() {
        let mut it = MdCharacterIterator::new("hi");
        it.set_index(3); // length is 2, so 3 > length → panic
    }

    // has_next: returns true only when next() would yield a valid char
    // i.e., index < length - 1
    #[test]
    fn has_next_true_when_more_than_one_char_remains() {
        let it = MdCharacterIterator::new("ab");
        assert!(it.has_next()); // index=0, length=2 → 0 < 1
    }

    #[test]
    fn has_next_false_at_last_char() {
        let mut it = MdCharacterIterator::new("ab");
        it.get_and_increment(); // index=1
        assert!(!it.has_next()); // 1 < 1 is false
    }

    #[test]
    fn has_next_false_for_single_char_string() {
        let it = MdCharacterIterator::new("x");
        assert!(!it.has_next()); // length=1, saturating_sub(1)=0 → 0 < 0 is false
    }

    #[test]
    fn has_next_false_for_empty_string() {
        let it = MdCharacterIterator::new("");
        assert!(!it.has_next());
    }

    #[test]
    fn peek_at_start() {
        let it = MdCharacterIterator::new("hello");
        assert_eq!(it.peek(), 'h');
    }

    #[test]
    fn peek_past_end_returns_done() {
        let mut it = MdCharacterIterator::new("a");
        it.get_and_increment(); // index=1, past end
        assert_eq!(it.peek(), DONE);
    }

    #[test]
    fn peek_empty_string_returns_done() {
        let it = MdCharacterIterator::new("");
        assert_eq!(it.peek(), DONE);
    }

    #[test]
    fn peek_ahead_looks_forward() {
        let it = MdCharacterIterator::new("abcd");
        assert_eq!(it.peek_ahead(2), 'c');
    }

    #[test]
    fn peek_ahead_zero_is_same_as_peek() {
        let it = MdCharacterIterator::new("xyz");
        assert_eq!(it.peek_ahead(0), it.peek());
    }

    #[test]
    fn peek_ahead_out_of_range_returns_done() {
        let it = MdCharacterIterator::new("ab");
        assert_eq!(it.peek_ahead(10), DONE);
    }

    #[test]
    fn next_increments_first_returns_new_char() {
        let mut it = MdCharacterIterator::new("abcd");
        // index=0; next() → index=1, returns 'b'
        assert_eq!(it.next(), 'b');
        assert_eq!(it.get_index(), 1);
    }

    #[test]
    fn next_at_last_char_returns_done() {
        let mut it = MdCharacterIterator::new("ab");
        it.get_and_increment(); // 'a', index=1
        assert_eq!(it.next(), DONE); // advance to 2, out of range
        assert_eq!(it.get_index(), 2);
    }

    #[test]
    fn next_clamps_index_at_length() {
        let mut it = MdCharacterIterator::new("a");
        it.next(); // index becomes 1 == length
        it.next(); // should stay at 1, return DONE
        assert_eq!(it.get_index(), 1);
    }

    #[test]
    fn get_and_increment_traverses_all() {
        let mut it = MdCharacterIterator::new("abc");
        assert_eq!(it.get_and_increment(), 'a');
        assert_eq!(it.get_and_increment(), 'b');
        assert_eq!(it.get_and_increment(), 'c');
        assert_eq!(it.get_and_increment(), DONE);
        assert_eq!(it.get_index(), 3);
    }

    #[test]
    fn get_and_increment_empty_returns_done() {
        let mut it = MdCharacterIterator::new("");
        assert_eq!(it.get_and_increment(), DONE);
    }

    #[test]
    fn increment_moves_forward_one() {
        let mut it = MdCharacterIterator::new("abc");
        it.increment();
        assert_eq!(it.get_index(), 1);
        assert_eq!(it.peek(), 'b');
    }

    #[test]
    fn increment_by_moves_forward_n() {
        let mut it = MdCharacterIterator::new("hello");
        it.increment_by(3);
        assert_eq!(it.get_index(), 3);
        assert_eq!(it.peek(), 'l');
    }

    #[test]
    fn increment_by_zero_is_noop() {
        let mut it = MdCharacterIterator::new("abc");
        it.increment_by(0);
        assert_eq!(it.get_index(), 0);
    }

    #[test]
    fn previous_retreats_and_returns_char() {
        let mut it = MdCharacterIterator::new("abc");
        it.get_and_increment(); // 'a', index=1
        it.get_and_increment(); // 'b', index=2
        assert_eq!(it.previous(), 'b'); // retreat to 1, return chars[1]='b'
        assert_eq!(it.get_index(), 1);
    }

    #[test]
    fn previous_at_start_returns_done() {
        let mut it = MdCharacterIterator::new("abc");
        assert_eq!(it.previous(), DONE);
        assert_eq!(it.get_index(), 0);
    }

    #[test]
    fn position_starts_with_match() {
        let it = MdCharacterIterator::new("hello world");
        assert!(it.position_starts_with("hello"));
    }

    #[test]
    fn position_starts_with_no_match() {
        let it = MdCharacterIterator::new("hello world");
        assert!(!it.position_starts_with("world"));
    }

    #[test]
    fn position_starts_with_after_advance() {
        let mut it = MdCharacterIterator::new("hello world");
        it.increment_by(6); // position at 'w'
        assert!(it.position_starts_with("world"));
    }

    #[test]
    fn position_starts_with_at_end_returns_false() {
        let mut it = MdCharacterIterator::new("abc");
        it.set_index(3); // past end
        assert!(!it.position_starts_with("x"));
    }

    #[test]
    fn position_starts_with_empty_substring_always_true() {
        let it = MdCharacterIterator::new("abc");
        assert!(it.position_starts_with(""));
    }

    #[test]
    fn display_format() {
        let it = MdCharacterIterator::new("hello");
        assert_eq!(it.to_string(), "hello\n^");
    }

    #[test]
    fn display_format_after_advance() {
        let mut it = MdCharacterIterator::new("hello");
        it.increment_by(2);
        assert_eq!(it.to_string(), "hello\n  ^");
    }
}
