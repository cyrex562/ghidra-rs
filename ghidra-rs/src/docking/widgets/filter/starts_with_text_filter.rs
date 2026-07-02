use std::any::Any;
use std::cell::RefCell;

use regex::Regex;

use crate::util::UserSearchUtils;

use super::{AbstractPatternTextFilter, MatchesPatternTextFilter, TextFilter};

/// A text filter that matches text when it starts with the filter text.
///
/// Corresponds to `docking.widgets.filter.StartsWithTextFilter`.
pub struct StartsWithTextFilter {
    filter_text: String,
    pattern_cache: RefCell<Option<Regex>>,
    case_sensitive: bool,
    allow_globbing: bool,
}

impl StartsWithTextFilter {
    /// Creates a new filter that matches text starting with the given filter text.
    ///
    /// # Parameters
    /// - `filter_text`: the text that matched text must start with.
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

impl AbstractPatternTextFilter for StartsWithTextFilter {
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

        UserSearchUtils::create_starts_with_pattern(&self.filter_text, self.allow_globbing, options)
            .ok()
    }

    fn pattern_matches(&self, text: &str, pattern: &Regex) -> bool {
        self.matches_pattern(text, pattern)
    }
}

impl MatchesPatternTextFilter for StartsWithTextFilter {
    fn case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    fn allow_globbing(&self) -> bool {
        self.allow_globbing
    }
}

impl TextFilter for StartsWithTextFilter {
    fn matches(&self, text: &str) -> bool {
        self.matches_text(text)
    }

    fn get_filter_text(&self) -> &str {
        self.filter_text()
    }

    fn is_sub_filter_of(&self, filter: &dyn TextFilter) -> bool {
        let any_filter: &dyn Any = filter;
        let other = match any_filter.downcast_ref::<StartsWithTextFilter>() {
            Some(other) => other,
            None => return false,
        };

        if self.case_sensitive != other.case_sensitive || self.allow_globbing != other.allow_globbing {
            return false;
        }

        if self.parent_is_glob_escape(other) {
            return false;
        }

        self.filter_text.starts_with(other.filter_text.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_when_text_starts_with_filter() {
        let filter = StartsWithTextFilter::new("cat", true, false);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cats"));
        assert!(filter.matches("category"));
    }

    #[test]
    fn does_not_match_when_text_does_not_start_with_filter() {
        let filter = StartsWithTextFilter::new("cat", true, false);
        assert!(!filter.matches("dog"));
        assert!(!filter.matches("the cat"));
        assert!(!filter.matches("concatenate"));
    }

    #[test]
    fn matches_respects_case_sensitivity() {
        let filter_sensitive = StartsWithTextFilter::new("Cat", true, false);
        let filter_insensitive = StartsWithTextFilter::new("Cat", false, false);

        assert!(filter_sensitive.matches("Cat"));
        assert!(!filter_sensitive.matches("cat"));

        assert!(filter_insensitive.matches("Cat"));
        assert!(filter_insensitive.matches("cat"));
    }

    #[test]
    fn empty_filter_matches_any_text() {
        let filter = StartsWithTextFilter::new("", true, false);
        assert!(filter.matches(""));
        assert!(filter.matches("anything"));
    }

    #[test]
    fn get_filter_text_returns_constructor_value() {
        let filter = StartsWithTextFilter::new("hello", true, false);
        assert_eq!(filter.get_filter_text(), "hello");
    }

    #[test]
    fn is_sub_filter_of_true_when_filter_text_starts_with_parent_text() {
        let parent = StartsWithTextFilter::new("cat", true, false);
        let child = StartsWithTextFilter::new("category", true, false);
        assert!(child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_when_filter_text_does_not_start_with_parent_text() {
        let parent = StartsWithTextFilter::new("cat", true, false);
        let child = StartsWithTextFilter::new("dog", true, false);
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_different_case_sensitivity() {
        let parent = StartsWithTextFilter::new("cat", true, false);
        let child = StartsWithTextFilter::new("category", false, false);
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_different_allow_globbing() {
        let parent = StartsWithTextFilter::new("cat", true, false);
        let child = StartsWithTextFilter::new("category", true, true);
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn is_sub_filter_of_false_for_non_starts_with_filter() {
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

        let child = StartsWithTextFilter::new("category", true, false);
        let other = OtherFilter;
        assert!(!child.is_sub_filter_of(&other));
    }

    #[test]
    fn is_sub_filter_of_true_when_texts_are_equal() {
        let parent = StartsWithTextFilter::new("cat", true, false);
        let child = StartsWithTextFilter::new("cat", true, false);
        assert!(child.is_sub_filter_of(&parent));
    }

    #[test]
    fn matches_with_glob_wildcard_star() {
        let filter = StartsWithTextFilter::new("c*t", true, true);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cart"));
        assert!(filter.matches("ct"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn matches_with_glob_wildcard_question() {
        let filter = StartsWithTextFilter::new("c?t", true, true);
        assert!(filter.matches("cat"));
        assert!(filter.matches("cot"));
        assert!(!filter.matches("cart"));
        assert!(!filter.matches("dog"));
    }
}
