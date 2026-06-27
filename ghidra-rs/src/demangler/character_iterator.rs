/// Returned when the iterator reaches the beginning or end of the text.
///
/// Mirrors `CharacterIterator.DONE` (`'￿'`).
pub const DONE: char = '\u{FFFF}';

/// Bidirectional character iterator over a string.
///
/// Maintains a current index (valid range `0..string.len()`). [`peek`] reads
/// without advancing; [`get_and_increment`] reads and advances; [`next`]
/// advances first then reads; [`previous`] retreats first then reads.
///
/// Port of `ghidra.app.util.demangler.CharacterIterator`.
pub struct CharacterIterator {
    string: String,
    chars: Vec<char>,
    index: usize,
}

impl CharacterIterator {
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
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the number of characters in the underlying string.
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Returns `true` if the underlying string is empty.
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Sets the current index.
    ///
    /// # Panics
    /// Panics if `index` is out of range `0..=self.len()-1` (mirrors Java
    /// `IllegalArgumentException`).
    pub fn set_index(&mut self, index: usize) {
        assert!(
            !self.chars.is_empty() && index < self.chars.len(),
            "index out of bounds: {} for length {}",
            index,
            self.chars.len()
        );
        self.index = index;
    }

    /// Returns `true` if there are more characters to read at or after the current index.
    pub fn has_next(&self) -> bool {
        self.index < self.chars.len()
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
    /// Returns [`DONE`] and clamps the index to `len()` when advancing would exceed the string.
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
    /// Returns [`DONE`] and clamps the index to `len()` when the current index is out of range.
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

    /// Retreats the index by one and returns the character at the **new** position.
    ///
    /// Returns [`DONE`] (leaving the index at 0) when already at the beginning.
    pub fn previous(&mut self) -> char {
        if self.index == 0 {
            return Self::DONE;
        }
        self.index -= 1;
        self.chars[self.index]
    }

    /// Returns the next `len` characters as a `String` and advances the index by `len`.
    ///
    /// # Panics
    /// Panics if `current_index + len` exceeds `self.len()`.
    pub fn next_string(&mut self, len: usize) -> String {
        let s: String = self.chars[self.index..self.index + len].iter().collect();
        self.index += len;
        s
    }

    /// Reads and returns the next decimal integer.
    ///
    /// Consumes all consecutive ASCII digit characters starting at the current index.
    /// If no digits are consumed, returns `(current_char as i32) - ('0' as i32)` without
    /// advancing (mirrors Java edge-case behavior).
    ///
    /// # Errors
    /// Returns a `ParseIntError` if the consumed digits overflow `i32`; the index is
    /// restored to its pre-call value on error.
    pub fn next_integer(&mut self) -> Result<i32, std::num::ParseIntError> {
        let orig_index = self.index;
        while self.peek().is_ascii_digit() {
            self.get_and_increment();
        }
        if orig_index == self.index {
            // No digits consumed — mirrors Java's charAt(index) - '0' (may panic if OOB)
            let c = self.chars[self.index];
            return Ok((c as i32) - ('0' as i32));
        }
        let s: String = self.chars[orig_index..self.index].iter().collect();
        match s.parse::<i32>() {
            Ok(n) => Ok(n),
            Err(e) => {
                self.index = orig_index;
                Err(e)
            }
        }
    }

    /// Returns the position of the next occurrence of `c` at or after the current index,
    /// or `None` if `c` is not found.
    pub fn find(&self, c: char) -> Option<usize> {
        self.chars[self.index..]
            .iter()
            .position(|&ch| ch == c)
            .map(|p| p + self.index)
    }
}

impl std::fmt::Display for CharacterIterator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // "currnt" is the original Java spelling; preserved for parity.
        write!(f, "currnt = {}; next = {}", self.peek(), self.peek_ahead(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_index_zero() {
        let it = CharacterIterator::new("hello");
        assert_eq!(it.index(), 0);
        assert_eq!(it.len(), 5);
    }

    #[test]
    fn get_string_returns_original() {
        let it = CharacterIterator::new("abc");
        assert_eq!(it.get_string(), "abc");
    }

    #[test]
    fn peek_at_start() {
        let it = CharacterIterator::new("hello");
        assert_eq!(it.peek(), 'h');
    }

    #[test]
    fn peek_past_end_returns_done() {
        let mut it = CharacterIterator::new("a");
        it.get_and_increment(); // advance past 'a'
        assert_eq!(it.peek(), DONE);
    }

    #[test]
    fn peek_ahead_looks_forward() {
        let it = CharacterIterator::new("abcd");
        assert_eq!(it.peek_ahead(2), 'c');
    }

    #[test]
    fn peek_ahead_out_of_range_returns_done() {
        let it = CharacterIterator::new("ab");
        assert_eq!(it.peek_ahead(10), DONE);
    }

    #[test]
    fn has_next_true_when_chars_remain() {
        let it = CharacterIterator::new("x");
        assert!(it.has_next());
    }

    #[test]
    fn has_next_false_when_exhausted() {
        let mut it = CharacterIterator::new("x");
        it.get_and_increment();
        assert!(!it.has_next());
    }

    #[test]
    fn get_and_increment_traverses_all() {
        let mut it = CharacterIterator::new("abc");
        assert_eq!(it.get_and_increment(), 'a');
        assert_eq!(it.get_and_increment(), 'b');
        assert_eq!(it.get_and_increment(), 'c');
        assert_eq!(it.get_and_increment(), DONE);
        assert_eq!(it.index(), 3);
    }

    #[test]
    fn next_skips_current_and_returns_following() {
        let mut it = CharacterIterator::new("abcd");
        // index=0; next() increments to 1, returns 'b'
        assert_eq!(it.next(), 'b');
        assert_eq!(it.index(), 1);
    }

    #[test]
    fn next_at_last_char_returns_done() {
        let mut it = CharacterIterator::new("ab");
        it.get_and_increment(); // skip 'a'; index=1
        assert_eq!(it.next(), DONE); // advance to 2, out of range
        assert_eq!(it.index(), 2);
    }

    #[test]
    fn previous_retreats() {
        let mut it = CharacterIterator::new("abc");
        it.get_and_increment(); // 'a', index=1
        it.get_and_increment(); // 'b', index=2
        assert_eq!(it.previous(), 'b'); // retreat to 1, return 'b'
        assert_eq!(it.index(), 1);
    }

    #[test]
    fn previous_at_start_returns_done() {
        let mut it = CharacterIterator::new("abc");
        assert_eq!(it.previous(), DONE);
        assert_eq!(it.index(), 0);
    }

    #[test]
    fn set_index_moves_position() {
        let mut it = CharacterIterator::new("hello");
        it.set_index(3);
        assert_eq!(it.peek(), 'l');
    }

    #[test]
    #[should_panic]
    fn set_index_out_of_range_panics() {
        let mut it = CharacterIterator::new("hi");
        it.set_index(5);
    }

    #[test]
    fn next_string_reads_and_advances() {
        let mut it = CharacterIterator::new("hello world");
        assert_eq!(it.next_string(5), "hello");
        assert_eq!(it.index(), 5);
    }

    #[test]
    fn next_integer_reads_decimal() {
        let mut it = CharacterIterator::new("123abc");
        assert_eq!(it.next_integer().unwrap(), 123);
        assert_eq!(it.index(), 3);
    }

    #[test]
    fn next_integer_single_digit() {
        let mut it = CharacterIterator::new("7xyz");
        assert_eq!(it.next_integer().unwrap(), 7);
        assert_eq!(it.index(), 1);
    }

    #[test]
    fn find_locates_char() {
        let it = CharacterIterator::new("hello");
        assert_eq!(it.find('l'), Some(2));
    }

    #[test]
    fn find_from_current_index() {
        let mut it = CharacterIterator::new("hello");
        it.get_and_increment(); // skip 'h', index=1
        it.get_and_increment(); // skip 'e', index=2
        it.get_and_increment(); // skip first 'l', index=3
        assert_eq!(it.find('l'), Some(3));
    }

    #[test]
    fn find_missing_char_returns_none() {
        let it = CharacterIterator::new("hello");
        assert_eq!(it.find('z'), None);
    }

    #[test]
    fn display_shows_current_and_next() {
        let it = CharacterIterator::new("ab");
        assert_eq!(it.to_string(), "currnt = a; next = b");
    }

    #[test]
    fn empty_string_has_next_is_false() {
        let it = CharacterIterator::new("");
        assert!(!it.has_next());
        assert_eq!(it.peek(), DONE);
    }

    #[test]
    fn done_constant_is_u_ffff() {
        assert_eq!(CharacterIterator::DONE, '\u{FFFF}');
    }
}
