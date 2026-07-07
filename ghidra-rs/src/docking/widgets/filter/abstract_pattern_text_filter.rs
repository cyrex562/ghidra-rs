use std::cell::RefCell;

use regex::Regex;

/// Shared behavior for text filters that lazily compile and cache a [`Regex`] pattern.
///
/// Corresponds to `docking.widgets.filter.AbstractPatternTextFilter`. Implementors supply the
/// filter text, a cache slot for the compiled pattern, how to build the pattern
/// ([`create_pattern`](Self::create_pattern)), and how to apply it
/// ([`pattern_matches`](Self::pattern_matches)); this trait supplies the shared matching,
/// equality, and display behavior on top.
///
/// The Java type overrides `hashCode` to throw `UnsupportedOperationException`, since its
/// `equals` is based on data that can change over time. This trait mirrors that intent simply by
/// not implementing `Hash`.
pub trait AbstractPatternTextFilter {
    /// Returns the filter text used to construct this filter.
    fn filter_text(&self) -> &str;

    /// Returns the cache slot used to store the lazily created pattern.
    fn pattern_cache(&self) -> &RefCell<Option<Regex>>;

    /// Creates the pattern that will be used by this filter. Implementors must provide this.
    fn create_pattern(&self) -> Option<Regex>;

    /// Implementors provide their usage of the given pattern (find vs. matches).
    fn pattern_matches(&self, text: &str, pattern: &Regex) -> bool;

    /// Returns the lazily-computed filter pattern, creating and caching it on first access.
    ///
    /// If `create_pattern` returns `None`, nothing is cached and the next call retries this,
    /// mirroring the Java implementation's use of a `null` field value as its "not yet computed"
    /// sentinel.
    fn get_filter_pattern(&self) -> Option<Regex> {
        let mut cache = self.pattern_cache().borrow_mut();
        if cache.is_none() {
            *cache = self.create_pattern();
        }
        cache.clone()
    }

    /// Returns true if the given text matches this filter's pattern; false if there is no
    /// usable pattern.
    fn matches_text(&self, text: &str) -> bool {
        match self.get_filter_pattern() {
            Some(pattern) => self.pattern_matches(text, &pattern),
            None => false,
        }
    }

    /// Returns true if this filter and `other` were built from equivalent patterns and filter
    /// text.
    ///
    /// Corresponds to Java's `equals`, minus the `Pattern` flags comparison: the `regex` crate
    /// does not expose compiled flags the way `java.util.regex.Pattern` does, so only the
    /// pattern source text is compared.
    fn pattern_filter_eq(&self, other: &dyn AbstractPatternTextFilter) -> bool {
        let p1 = self.create_pattern();
        let p2 = other.create_pattern();
        let s1 = p1.as_ref().map(Regex::as_str).unwrap_or("");
        let s2 = p2.as_ref().map(Regex::as_str).unwrap_or("");
        s1 == s2 && self.filter_text() == other.filter_text()
    }

    /// Renders this filter as `{ filter: ..., pattern: ... }`, mirroring Java's `toString`.
    fn to_display_string(&self) -> String {
        let pattern_display = match self.get_filter_pattern() {
            Some(p) => p.as_str().to_string(),
            None => "null".to_string(),
        };
        format!("{{\n\tfilter: {},\n\tpattern: {},\n}}", self.filter_text(), pattern_display)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FindsFilter {
        filter_text: String,
        pattern_cache: RefCell<Option<Regex>>,
    }

    impl FindsFilter {
        fn new(filter_text: &str) -> Self {
            Self { filter_text: filter_text.to_owned(), pattern_cache: RefCell::new(None) }
        }
    }

    impl AbstractPatternTextFilter for FindsFilter {
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
            pattern.is_match(text)
        }
    }

    struct InvalidPatternFilter {
        filter_text: String,
        pattern_cache: RefCell<Option<Regex>>,
        create_pattern_calls: RefCell<usize>,
    }

    impl InvalidPatternFilter {
        fn new(filter_text: &str) -> Self {
            Self {
                filter_text: filter_text.to_owned(),
                pattern_cache: RefCell::new(None),
                create_pattern_calls: RefCell::new(0),
            }
        }
    }

    impl AbstractPatternTextFilter for InvalidPatternFilter {
        fn filter_text(&self) -> &str {
            &self.filter_text
        }

        fn pattern_cache(&self) -> &RefCell<Option<Regex>> {
            &self.pattern_cache
        }

        fn create_pattern(&self) -> Option<Regex> {
            *self.create_pattern_calls.borrow_mut() += 1;
            None
        }

        fn pattern_matches(&self, _text: &str, _pattern: &Regex) -> bool {
            true
        }
    }

    #[test]
    fn matches_delegates_to_pattern_matches() {
        let filter = FindsFilter::new("ca.");
        assert!(filter.matches_text("cat"));
        assert!(!filter.matches_text("dog"));
    }

    #[test]
    fn get_filter_pattern_caches_result() {
        let filter = FindsFilter::new("a+");
        assert!(filter.pattern_cache().borrow().is_none());
        filter.get_filter_pattern();
        assert!(filter.pattern_cache().borrow().is_some());
    }

    #[test]
    fn invalid_pattern_matches_returns_false() {
        let filter = InvalidPatternFilter::new("[");
        assert!(!filter.matches_text("anything"));
    }

    #[test]
    fn invalid_pattern_is_recomputed_each_time() {
        let filter = InvalidPatternFilter::new("[");
        filter.get_filter_pattern();
        filter.get_filter_pattern();
        assert_eq!(*filter.create_pattern_calls.borrow(), 2);
    }

    #[test]
    fn filter_text_returns_constructor_value() {
        let filter = FindsFilter::new("hello");
        assert_eq!(filter.filter_text(), "hello");
    }

    #[test]
    fn pattern_filter_eq_true_for_same_pattern_and_text() {
        let a = FindsFilter::new("ca.");
        let b = FindsFilter::new("ca.");
        assert!(a.pattern_filter_eq(&b));
    }

    #[test]
    fn pattern_filter_eq_false_for_different_text() {
        let a = FindsFilter::new("ca.");
        let b = FindsFilter::new("do.");
        assert!(!a.pattern_filter_eq(&b));
    }

    #[test]
    fn to_display_string_includes_filter_and_pattern() {
        let filter = FindsFilter::new("ca.");
        let s = filter.to_display_string();
        assert!(s.contains("filter: ca."));
        assert!(s.contains("pattern: ca."));
    }

    #[test]
    fn to_display_string_shows_null_for_invalid_pattern() {
        let filter = InvalidPatternFilter::new("[");
        let s = filter.to_display_string();
        assert!(s.contains("pattern: null"));
    }
}
