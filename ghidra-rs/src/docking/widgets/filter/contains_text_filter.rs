use std::any::Any;
use std::cell::RefCell;

use regex::{Regex, RegexBuilder};

use crate::util::UserSearchUtils;

use super::{AbstractPatternTextFilter, MatchesPatternTextFilter, TextFilter};

/// A text filter that matches text containing the filter text.
///
/// Corresponds to `docking.widgets.filter.ContainsTextFilter`.
pub struct ContainsTextFilter {
    filter_text: String,
    pattern_cache: RefCell<Option<Regex>>,
    case_sensitive: bool,
    allow_globbing: bool,
}

impl ContainsTextFilter {
    /// Creates a new filter that matches text containing the given filter text.
    ///
    /// # Parameters
    /// - `filter_text`: the text that matched text must contain.
    /// - `case_sensitive`: whether matching is case-sensitive.
    /// - `allow_globbing`: whether glob-style wildcards (`*`, `?`) are allowed.
    pub fn new(filter_text: &str, case_sensitive: bool, allow_globbing: bool) -> Self {
        Self {
            filter_text: filter_text.to_owned(),
            pattern_cache: RefCell::new(None),
            case_sensitive,
            allow_globbing,
        }
    }
}

impl AbstractPatternTextFilter for ContainsTextFilter {
    fn filter_text(&self) -> &str {
        &self.filter_text
    }

    fn pattern_cache(&self) -> &RefCell<Option<Regex>> {
        &self.pattern_cache
    }

    fn create_pattern(&self) -> Option<Regex> {
        let options = if self.case_sensitive {
            UserSearchUtils::CASE_SENSITIVE
        } else {
            UserSearchUtils::CASE_INSENSITIVE
        };

        // Java's ContainsTextFilter compiles with Pattern.DOTALL so the `.*` padding
        // produced by createContainsPattern can span newlines. UserSearchUtils does not
        // expose DOTALL, so rebuild the compiled pattern's source with
        // `dot_matches_new_line(true)` (preserving any inline case-insensitivity flag).
        let base =
            UserSearchUtils::create_contains_pattern(&self.filter_text, self.allow_globbing, options)
                .ok()?;
        RegexBuilder::new(base.as_str())
            .dot_matches_new_line(true)
            .build()
            .ok()
    }

    fn pattern_matches(&self, text: &str, pattern: &Regex) -> bool {
        self.matches_pattern(text, pattern)
    }
}

impl MatchesPatternTextFilter for ContainsTextFilter {
    fn case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    fn allow_globbing(&self) -> bool {
        self.allow_globbing
    }
}

impl TextFilter for ContainsTextFilter {
    fn matches(&self, text: &str) -> bool {
        self.matches_text(text)
    }

    fn get_filter_text(&self) -> &str {
        self.filter_text()
    }

    fn is_sub_filter_of(&self, filter: &dyn TextFilter) -> bool {
        let any_filter: &dyn Any = filter;
        let other = match any_filter.downcast_ref::<ContainsTextFilter>() {
            Some(other) => other,
            None => return false,
        };

        if self.case_sensitive != other.case_sensitive || self.allow_globbing != other.allow_globbing {
            return false;
        }

        if self.parent_is_glob_escape(other) {
            return false;
        }

        self.filter_text.contains(other.filter_text.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_when_text_contains_filter() {
        let filter = ContainsTextFilter::new("cat", true, false);
        assert!(filter.matches("the cat sat"));
        assert!(filter.matches("cat"));
        assert!(filter.matches("concatenate"));
    }

    #[test]
    fn does_not_match_when_text_does_not_contain_filter() {
        let filter = ContainsTextFilter::new("cat", true, false);
        assert!(!filter.matches("dog"));
        assert!(!filter.matches(""));
    }

    #[test]
    fn matches_respects_case_sensitivity() {
        let filter_sensitive = ContainsTextFilter::new("Cat", true, false);
        let filter_insensitive = ContainsTextFilter::new("Cat", false, false);

        assert!(filter_sensitive.matches("the Cat"));
        assert!(!filter_sensitive.matches("the cat"));

        assert!(filter_insensitive.matches("the Cat"));
        assert!(filter_insensitive.matches("the cat"));
    }

    #[test]
    fn matches_across_newlines() {
        // The literal filter text "ab" appears after a newline. Java compiles the contains
        // pattern with DOTALL, so the surrounding `.*` padding spans the newlines. (The '.'
        // in filter text is escaped to a literal, so it is not usable for newline spanning.)
        let filter = ContainsTextFilter::new("ab", true, false);
        assert!(filter.matches("x\nab\ny"));
    }

    #[test]
    fn matches_with_glob_wildcard_star() {
        let filter = ContainsTextFilter::new("c*t", true, true);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cart"));
        assert!(filter.matches("concatenate"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn matches_with_glob_wildcard_question() {
        let filter = ContainsTextFilter::new("c?t", true, true);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cot"));
        assert!(!filter.matches("cart"));
    }

    #[test]
    fn get_filter_text_returns_constructor_value() {
        let filter = ContainsTextFilter::new("hello", true, false);
        assert_eq!(filter.get_filter_text(), "hello");
    }

    #[test]
    fn is_sub_filter_of_true_when_filter_text_contains_parent_text() {
        let parent = ContainsTextFilter::new("cat", true, false);
        let child = ContainsTextFilter::new("concatenate", true, false);
        assert!(child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_when_filter_text_does_not_contain_parent_text() {
        let parent = ContainsTextFilter::new("cat", true, false);
        let child = ContainsTextFilter::new("dog", true, false);
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_different_case_sensitivity() {
        let parent = ContainsTextFilter::new("cat", true, false);
        let child = ContainsTextFilter::new("concatenate", false, false);
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_different_allow_globbing() {
        let parent = ContainsTextFilter::new("cat", true, false);
        let child = ContainsTextFilter::new("concatenate", true, true);
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_non_contains_filter() {
        struct OtherFilter;
        impl TextFilter for OtherFilter {
            fn matches(&self, _text: &str) -> bool {
                true
            }
            fn get_filter_text(&self) -> &str {
                "cat"
            }
            fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
                false
            }
        }

        let child = ContainsTextFilter::new("concatenate", true, false);
        let other = OtherFilter;
        assert!(!child.is_sub_filter_of(&other));
    }

    #[test]
    fn is_sub_filter_of_true_when_texts_are_equal() {
        let parent = ContainsTextFilter::new("cat", true, false);
        let child = ContainsTextFilter::new("cat", true, false);
        assert!(child.is_sub_filter_of(&parent));
    }
}
