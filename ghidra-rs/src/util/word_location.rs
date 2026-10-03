//! Port of `ghidra.util.WordLocation`.
//!
//! A simple immutable value object representing a word as found within some surrounding context
//! string (e.g. by `StringUtilities.findWord(String, int)`), plus the word's starting offset
//! within that context.
//!
//! `WordLocation` does not implement [`crate::util::location::Location`] in Java (no `implements`
//! clause) despite the similar name -- they are unrelated types that both happen to live in
//! `ghidra.util`. This port keeps them as two independent types accordingly (composition/wrapping
//! was not applicable here since there is no such relationship to preserve).

/// A word found within a context string, plus its starting offset within that context.
///
/// Port of `ghidra.util.WordLocation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordLocation {
    context: String,
    word: String,
    start: i64,
}

impl WordLocation {
    /// Returns an empty `WordLocation` for the given context (empty word, start of `-1`).
    ///
    /// Port of `WordLocation.empty(String)`.
    pub fn empty(context: impl Into<String>) -> Self {
        WordLocation::new(context, String::new(), -1)
    }

    /// Constructs a `WordLocation` for `word`, found at offset `start` within `context`.
    pub fn new(context: impl Into<String>, word: impl Into<String>, start: i64) -> Self {
        WordLocation {
            context: context.into(),
            word: word.into(),
            start,
        }
    }

    /// Returns `true` if the word is blank (empty or all whitespace), matching Java's
    /// `StringUtils.isBlank(word)` (which also treats a `null` string as blank; Rust's `String`
    /// has no such state, so the empty/whitespace-only checks cover every reachable case here).
    pub fn is_empty(&self) -> bool {
        self.word.trim().is_empty()
    }

    /// Returns the surrounding context string the word was found in.
    pub fn get_context(&self) -> &str {
        &self.context
    }

    /// Returns the word itself.
    pub fn get_word(&self) -> &str {
        &self.word
    }

    /// Returns the word's starting offset within its context, or `-1` for an empty location.
    pub fn get_start(&self) -> i64 {
        self.start
    }
}

impl std::fmt::Display for WordLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Matches Java's `toString()` exactly, including its literal tab/newline layout.
        write!(
            f,
            "{{\n\tword: {},\n\tstart: {}\n}}",
            self.word, self.start
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_blank_word_and_negative_start() {
        let loc = WordLocation::empty("some context string");
        assert!(loc.is_empty());
        assert_eq!(loc.get_word(), "");
        assert_eq!(loc.get_start(), -1);
        assert_eq!(loc.get_context(), "some context string");
    }

    #[test]
    fn non_empty_word_reports_not_empty() {
        let loc = WordLocation::new("the quick fox", "quick", 4);
        assert!(!loc.is_empty());
        assert_eq!(loc.get_word(), "quick");
        assert_eq!(loc.get_start(), 4);
        assert_eq!(loc.get_context(), "the quick fox");
    }

    #[test]
    fn whitespace_only_word_counts_as_blank() {
        // Matches Java's `StringUtils.isBlank`, which treats whitespace-only strings as blank
        // too, not merely the empty string.
        let loc = WordLocation::new("ctx", "   ", 2);
        assert!(loc.is_empty());
    }

    #[test]
    fn display_matches_java_tostring_layout() {
        let loc = WordLocation::new("ctx", "quick", 4);
        assert_eq!(loc.to_string(), "{\n\tword: quick,\n\tstart: 4\n}");
    }

    #[test]
    fn equality_compares_all_fields() {
        let a = WordLocation::new("ctx", "word", 1);
        let b = WordLocation::new("ctx", "word", 1);
        let c = WordLocation::new("ctx", "word", 2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
