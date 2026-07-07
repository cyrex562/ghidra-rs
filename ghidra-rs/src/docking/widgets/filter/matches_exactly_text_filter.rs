use std::any::Any;
use std::cell::RefCell;

use regex::Regex;

use crate::util::UserSearchUtils;

use super::{AbstractPatternTextFilter, MatchesPatternTextFilter, TextFilter};

/// A text filter that matches text when it matches exactly.
///
/// Corresponds to `docking.widgets.filter.MatchesExactlyTextFilter`.
pub struct MatchesExactlyTextFilter {
    filter_text: String,
    pattern_cache: RefCell<Option<Regex>>,
    case_sensitive: bool,
    allow_globbing: bool,
}

impl MatchesExactlyTextFilter {
    /// Creates a new filter that matches text exactly.
    ///
    /// # Parameters
    /// - `filter_text`: the text that text must match exactly.
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

impl AbstractPatternTextFilter for MatchesExactlyTextFilter {
    fn filter_text(&self) -> &str {
        &self.filter_text
    }

    fn pattern_cache(&self) -> &RefCell<Option<Regex>> {
        &self.pattern_cache
    }

    fn create_pattern(&self) -> Option<Regex> {
        let mut options = if self.case_sensitive {
            UserSearchUtils::CASE_SENSITIVE
        } else {
            UserSearchUtils::CASE_INSENSITIVE
        };

        UserSearchUtils::create_pattern(&self.filter_text, self.allow_globbing, options).ok()
    }

    fn pattern_matches(&self, text: &str, pattern: &Regex) -> bool {
        self.matches_pattern(text, pattern)
    }
}

impl MatchesPatternTextFilter for MatchesExactlyTextFilter {
    fn case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    fn allow_globbing(&self) -> bool {
        self.allow_globbing
    }
}

impl TextFilter for MatchesExactlyTextFilter {
    fn matches(&self, text: &str) -> bool {
        self.matches_text(text)
    }

    fn get_filter_text(&self) -> &str {
        self.filter_text()
    }

    fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_text() {
        let filter = MatchesExactlyTextFilter::new("hello", true, false);
        assert!(filter.matches("hello"));
        assert!(!filter.matches("hello world"));
        assert!(!filter.matches("world hello"));
    }

    #[test]
    fn does_not_match_partial_text() {
        let filter = MatchesExactlyTextFilter::new("cat", true, false);
        assert!(!filter.matches("concatenate"));
        assert!(!filter.matches("the cat"));
        assert!(!filter.matches("cat sat"));
    }

    #[test]
    fn matches_respects_case_sensitivity() {
        let filter_sensitive = MatchesExactlyTextFilter::new("Cat", true, false);
        let filter_insensitive = MatchesExactlyTextFilter::new("Cat", false, false);

        assert!(filter_sensitive.matches("Cat"));
        assert!(!filter_sensitive.matches("cat"));

        assert!(filter_insensitive.matches("Cat"));
        assert!(filter_insensitive.matches("cat"));
    }

    #[test]
    fn empty_filter_matches_empty_string() {
        let filter = MatchesExactlyTextFilter::new("", true, false);
        assert!(filter.matches(""));
        assert!(!filter.matches("anything"));
    }

    #[test]
    fn get_filter_text_returns_constructor_value() {
        let filter = MatchesExactlyTextFilter::new("test", true, false);
        assert_eq!(filter.get_filter_text(), "test");
    }

    #[test]
    fn is_sub_filter_of_always_returns_false() {
        let filter = MatchesExactlyTextFilter::new("cat", true, false);
        let parent = MatchesExactlyTextFilter::new("c", true, false);
        assert!(!filter.is_sub_filter_of(&parent));
    }

    #[test]
    fn matches_with_glob_wildcard_star() {
        let filter = MatchesExactlyTextFilter::new("c*t", true, true);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cart"));
        assert!(filter.matches("ct"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn matches_with_glob_wildcard_question() {
        let filter = MatchesExactlyTextFilter::new("c?t", true, true);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cot"));
        assert!(!filter.matches("cart"));
        assert!(!filter.matches("ct"));
    }
}
