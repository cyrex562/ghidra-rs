use regex::Regex;

use super::AbstractPatternTextFilter;

/// A text filter that uses a pattern and performs a 'matches' using that pattern.
///
/// Corresponds to `docking.widgets.filter.MatchesPatternTextFilter`. Implementors must also
/// implement [`AbstractPatternTextFilter`] (`create_pattern` in particular is still left to a
/// concrete filter, e.g. one matching exactly or matching a "starts with" pattern); this trait
/// supplies the shared full-text match behavior, glob-escape detection, and equality comparison
/// on top.
pub trait MatchesPatternTextFilter: AbstractPatternTextFilter {
    /// Returns true if this filter's pattern matching should be case sensitive.
    fn case_sensitive(&self) -> bool;

    /// Returns true if this filter allows glob-style wildcard characters (`*`, `?`).
    fn allow_globbing(&self) -> bool;

    /// Returns true if `self`'s filter text ends with an escaped glob character that `parent`
    /// does not account for, meaning `self` cannot safely be treated as a sub-filter of
    /// `parent`.
    ///
    /// If the user types slowly enough (to let the update manager run) in the filter field, the
    /// parent filter will end with a backslash. If the user types fast or pastes, this will not
    /// be the case.
    fn parent_is_glob_escape(&self, parent: &dyn MatchesPatternTextFilter) -> bool {
        if self.allow_globbing() {
            let filter_text = self.filter_text();
            let ends_with_escaped_glob =
                filter_text.ends_with("\\?") || filter_text.ends_with("\\*");
            if ends_with_escaped_glob && parent.filter_text().ends_with('\\') {
                return true;
            }
        }

        false
    }

    /// Returns true if `pattern` matches the entirety of `text`, mirroring Java's
    /// `Matcher.matches()`.
    fn matches_pattern(&self, text: &str, pattern: &Regex) -> bool {
        match pattern.find(text) {
            Some(found) => found.start() == 0 && found.end() == text.len(),
            None => false,
        }
    }

    /// Returns true if `self` and `other` have equivalent case-sensitivity, glob-allowance,
    /// and pattern/filter-text state, mirroring Java's `equals`.
    fn matches_pattern_filter_eq(&self, other: &dyn MatchesPatternTextFilter) -> bool {
        self.allow_globbing() == other.allow_globbing()
            && self.case_sensitive() == other.case_sensitive()
            && self.pattern_filter_eq(other)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct StubFilter {
        filter_text: String,
        pattern_cache: RefCell<Option<Regex>>,
        case_sensitive: bool,
        allow_globbing: bool,
    }

    impl StubFilter {
        fn new(filter_text: &str, case_sensitive: bool, allow_globbing: bool) -> Self {
            Self {
                filter_text: filter_text.to_owned(),
                pattern_cache: RefCell::new(None),
                case_sensitive,
                allow_globbing,
            }
        }
    }

    impl AbstractPatternTextFilter for StubFilter {
        fn filter_text(&self) -> &str {
            &self.filter_text
        }

        fn pattern_cache(&self) -> &RefCell<Option<Regex>> {
            &self.pattern_cache
        }

        fn create_pattern(&self) -> Option<Regex> {
            Regex::new(&self.filter_text).ok()
        }

        fn pattern_matches(&self, text: &str, pattern: &Regex) -> bool {
            self.matches_pattern(text, pattern)
        }
    }

    impl MatchesPatternTextFilter for StubFilter {
        fn case_sensitive(&self) -> bool {
            self.case_sensitive
        }

        fn allow_globbing(&self) -> bool {
            self.allow_globbing
        }
    }

    #[test]
    fn matches_pattern_requires_full_text_match() {
        let filter = StubFilter::new("ab", true, false);
        let pattern = Regex::new("ab").unwrap();

        assert!(filter.matches_pattern("ab", &pattern));
        assert!(!filter.matches_pattern("abc", &pattern));
        assert!(!filter.matches_pattern("xab", &pattern));
    }

    #[test]
    fn matches_text_delegates_through_pattern_matches() {
        let filter = StubFilter::new("ca.", true, false);
        assert!(filter.matches_text("cat"));
        assert!(!filter.matches_text("caterpillar"));
    }

    #[test]
    fn parent_is_glob_escape_true_when_globbing_and_parent_ends_with_backslash() {
        let filter = StubFilter::new("foo\\*", true, true);
        let parent = StubFilter::new("foo\\", true, true);
        assert!(filter.parent_is_glob_escape(&parent));
    }

    #[test]
    fn parent_is_glob_escape_false_when_globbing_disallowed() {
        let filter = StubFilter::new("foo\\*", true, false);
        let parent = StubFilter::new("foo\\", true, false);
        assert!(!filter.parent_is_glob_escape(&parent));
    }

    #[test]
    fn parent_is_glob_escape_false_when_parent_does_not_end_with_backslash() {
        let filter = StubFilter::new("foo\\*", true, true);
        let parent = StubFilter::new("foo", true, true);
        assert!(!filter.parent_is_glob_escape(&parent));
    }

    #[test]
    fn parent_is_glob_escape_false_when_filter_text_not_escaped_glob() {
        let filter = StubFilter::new("foo*", true, true);
        let parent = StubFilter::new("foo\\", true, true);
        assert!(!filter.parent_is_glob_escape(&parent));
    }

    #[test]
    fn matches_pattern_filter_eq_true_for_equivalent_filters() {
        let a = StubFilter::new("ca.", true, false);
        let b = StubFilter::new("ca.", true, false);
        assert!(a.matches_pattern_filter_eq(&b));
    }

    #[test]
    fn matches_pattern_filter_eq_false_for_different_case_sensitivity() {
        let a = StubFilter::new("ca.", true, false);
        let b = StubFilter::new("ca.", false, false);
        assert!(!a.matches_pattern_filter_eq(&b));
    }

    #[test]
    fn matches_pattern_filter_eq_false_for_different_globbing() {
        let a = StubFilter::new("ca.", true, false);
        let b = StubFilter::new("ca.", true, true);
        assert!(!a.matches_pattern_filter_eq(&b));
    }

    #[test]
    fn matches_pattern_filter_eq_false_for_different_filter_text() {
        let a = StubFilter::new("ca.", true, false);
        let b = StubFilter::new("do.", true, false);
        assert!(!a.matches_pattern_filter_eq(&b));
    }
}
