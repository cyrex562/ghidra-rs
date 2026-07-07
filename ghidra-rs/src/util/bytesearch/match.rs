use std::fmt;
use std::hash::{Hash, Hasher};

/// Represents a match of a pattern at a given offset in a byte sequence.
///
/// # Type Parameters
/// - `T`: The specific implementation of the byte pattern that produced this match.
#[derive(Debug, Clone)]
pub struct Match<T> {
    pattern: T,
    start: u64,
    length: usize,
}

impl<T> Match<T> {
    /// Constructs a `Match` of a byte pattern that matched at a position in the
    /// input byte sequence.
    ///
    /// - `pattern`: the byte pattern that matched.
    /// - `start`: the location in the input byte sequence where the match begins.
    /// - `length`: the length in bytes of the matching sequence.
    pub fn new(pattern: T, start: u64, length: usize) -> Self {
        Self { pattern, start, length }
    }

    /// Returns the length in bytes of the matched pattern.
    pub fn get_length(&self) -> usize {
        self.length
    }

    /// Returns the offset of the match in the byte sequence.
    pub fn get_start(&self) -> u64 {
        self.start
    }

    /// Returns the pattern that was matched.
    pub fn get_pattern(&self) -> &T {
        &self.pattern
    }
}

impl<T: fmt::Display> fmt::Display for Match<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {}", self.pattern, self.start)
    }
}

impl<T: PartialEq> PartialEq for Match<T> {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.start == other.start && self.length == other.length
    }
}

impl<T: Eq> Eq for Match<T> {}

impl<T: Hash> Hash for Match<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
        self.start.hash(state);
        self.length.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::Match;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut h = DefaultHasher::new();
        val.hash(&mut h);
        h.finish()
    }

    #[test]
    fn getters_return_correct_fields() {
        let m = Match::new("pat", 42u64, 3usize);
        assert_eq!(m.get_pattern(), &"pat");
        assert_eq!(m.get_start(), 42);
        assert_eq!(m.get_length(), 3);
    }

    #[test]
    fn display_formats_pattern_at_start() {
        let m = Match::new("hello", 100u64, 5usize);
        assert_eq!(m.to_string(), "hello @ 100");
    }

    #[test]
    fn equal_matches_are_equal() {
        let a = Match::new(0xDEADu32, 0u64, 2usize);
        let b = Match::new(0xDEADu32, 0u64, 2usize);
        assert_eq!(a, b);
    }

    #[test]
    fn different_pattern_not_equal() {
        let a = Match::new(0x01u32, 0u64, 1usize);
        let b = Match::new(0x02u32, 0u64, 1usize);
        assert_ne!(a, b);
    }

    #[test]
    fn different_start_not_equal() {
        let a = Match::new(0x01u32, 0u64, 1usize);
        let b = Match::new(0x01u32, 1u64, 1usize);
        assert_ne!(a, b);
    }

    #[test]
    fn different_length_not_equal() {
        let a = Match::new(0x01u32, 0u64, 1usize);
        let b = Match::new(0x01u32, 0u64, 2usize);
        assert_ne!(a, b);
    }

    #[test]
    fn equal_matches_have_equal_hashes() {
        let a = Match::new(0xABu32, 7u64, 4usize);
        let b = Match::new(0xABu32, 7u64, 4usize);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn zero_length_match_is_valid() {
        let m = Match::new("x", 0u64, 0usize);
        assert_eq!(m.get_length(), 0);
        assert_eq!(m.get_start(), 0);
    }

    #[test]
    fn large_start_offset_preserved() {
        let start = u64::MAX;
        let m = Match::new(1u8, start, 1usize);
        assert_eq!(m.get_start(), u64::MAX);
    }
}
