//! Port of `ghidra.features.base.memsearch.matcher.InvalidByteMatcher`.
//!
//! Objects of this type are the result of a `SearchFormat` not being able to fully parse input
//! text. There are two cases: the user typed an illegal character for the selected search format
//! (both an invalid search and invalid input, with the description explaining the error), or the
//! input is valid but incomplete so a fully valid byte matcher could not be created (the search is
//! still invalid, but the input is valid).

use crate::feature::base::memsearch::matcher::ByteMatcher;
use crate::feature::seam_stubs::{SearchData, UserInputByteMatcher, UserInputByteMatcherBase};
use crate::util::bytesearch::{ExtendedByteSequence, Match};

/// Port of `ghidra.features.base.memsearch.matcher.InvalidByteMatcher`.
pub struct InvalidByteMatcher {
    base: UserInputByteMatcherBase,
    error_message: String,
    is_valid_input: bool,
}

impl InvalidByteMatcher {
    /// Java: `InvalidByteMatcher(String errorMessage)`, which delegates to the two-argument
    /// constructor with `isValidInput = false`.
    pub fn new(error_message: impl Into<String>) -> Self {
        Self::with_valid_input(error_message, false)
    }

    /// Java: `InvalidByteMatcher(String errorMessage, boolean isValidInput)`. `isValidInput`
    /// should be `true` when the reason this is invalid is simply that the input text is not
    /// complete (e.g. the user typed "-" as they start to enter a negative number).
    pub fn with_valid_input(error_message: impl Into<String>, is_valid_input: bool) -> Self {
        Self {
            // Java: `super("Invalid", "", null)`.
            base: UserInputByteMatcherBase::new("Invalid", "", None),
            error_message: error_message.into(),
            is_valid_input,
        }
    }
}

impl ByteMatcher<SearchData> for InvalidByteMatcher {
    fn match_bytes(&self, _bytes: &ExtendedByteSequence) -> Vec<Match<SearchData>> {
        Vec::new()
    }

    fn get_description(&self) -> String {
        self.error_message.clone()
    }
}

impl UserInputByteMatcher for InvalidByteMatcher {
    fn base(&self) -> &UserInputByteMatcherBase {
        &self.base
    }

    fn get_tool_tip(&self) -> Option<String> {
        None
    }

    fn is_valid_input(&self) -> bool {
        self.is_valid_input
    }

    fn is_valid_search(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::base::memsearch::bytesequence::ByteArrayByteSequence;

    /// Java: `new InvalidByteMatcher("bad input").getDescription()` returns the error message.
    #[test]
    fn description_is_the_error_message() {
        let matcher = InvalidByteMatcher::new("bad input");
        assert_eq!(matcher.get_description(), "bad input");
    }

    /// Java: single-arg constructor delegates `isValidInput = false`.
    #[test]
    fn single_arg_constructor_is_not_valid_input() {
        let matcher = InvalidByteMatcher::new("bad input");
        assert!(!matcher.is_valid_input());
    }

    /// Java: two-arg constructor lets the caller mark the input valid-but-incomplete.
    #[test]
    fn two_arg_constructor_honors_valid_input_flag() {
        let matcher = InvalidByteMatcher::with_valid_input("incomplete", true);
        assert!(matcher.is_valid_input());
    }

    /// Java: `isValidSearch()` is always `false`, regardless of `isValidInput`.
    #[test]
    fn is_never_a_valid_search() {
        assert!(!InvalidByteMatcher::new("bad").is_valid_search());
        assert!(!InvalidByteMatcher::with_valid_input("incomplete", true).is_valid_search());
    }

    /// Java: `getToolTip()` returns `null`.
    #[test]
    fn tool_tip_is_none() {
        let matcher = InvalidByteMatcher::new("bad input");
        assert_eq!(matcher.get_tool_tip(), None);
    }

    /// Java: `match(ExtendedByteSequence)` returns an empty iterable, regardless of input bytes.
    #[test]
    fn match_bytes_is_always_empty() {
        let matcher = InvalidByteMatcher::new("bad input");
        let main = Box::new(ByteArrayByteSequence::new(&[0xDE, 0xAD, 0xBE, 0xEF]));
        let bytes = ExtendedByteSequence::new(main, None, None, 0);
        assert!(matcher.match_bytes(&bytes).is_empty());
    }
}
