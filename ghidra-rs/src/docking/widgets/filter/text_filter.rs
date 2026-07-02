use std::any::Any;

/// A filter that operates on string text values.
///
/// Corresponds to `docking.widgets.filter.TextFilter`.
///
/// `Any` is a supertrait so that implementors of [`is_sub_filter_of`](Self::is_sub_filter_of)
/// can downcast a `&dyn TextFilter` to a concrete type, mirroring Java's `instanceof` checks
/// (e.g. `FindsPatternTextFilter` only treats another `FindsPatternTextFilter` as a candidate
/// parent filter).
pub trait TextFilter: Any {
    /// Returns true if the given text matches this filter.
    fn matches(&self, text: &str) -> bool;

    /// Returns the filter text used to construct this filter.
    fn get_filter_text(&self) -> &str;

    /// Returns true if this filter is a more specific version of the given filter.
    ///
    /// Whether sub-filtering is supported depends on the implementation. For example,
    /// a "starts with" filter treating `"cat"` as a sub-filter of `"ca"` is valid,
    /// while an exact-match filter typically cannot be a sub-filter of anything.
    fn is_sub_filter_of(&self, filter: &dyn TextFilter) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StartsWithFilter {
        text: String,
    }

    impl TextFilter for StartsWithFilter {
        fn matches(&self, text: &str) -> bool {
            text.starts_with(self.text.as_str())
        }

        fn get_filter_text(&self) -> &str {
            &self.text
        }

        fn is_sub_filter_of(&self, filter: &dyn TextFilter) -> bool {
            self.text.starts_with(filter.get_filter_text())
        }
    }

    struct ExactFilter {
        text: String,
    }

    impl TextFilter for ExactFilter {
        fn matches(&self, text: &str) -> bool {
            text == self.text.as_str()
        }

        fn get_filter_text(&self) -> &str {
            &self.text
        }

        fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
            false
        }
    }

    #[test]
    fn starts_with_matches() {
        let f = StartsWithFilter { text: "ca".to_owned() };
        assert!(f.matches("cat"));
        assert!(f.matches("ca"));
        assert!(!f.matches("dog"));
    }

    #[test]
    fn get_filter_text_returns_text() {
        let f = StartsWithFilter { text: "hello".to_owned() };
        assert_eq!(f.get_filter_text(), "hello");
    }

    #[test]
    fn starts_with_sub_filter() {
        let parent = StartsWithFilter { text: "ca".to_owned() };
        let child = StartsWithFilter { text: "cat".to_owned() };
        assert!(child.is_sub_filter_of(&parent));
        assert!(!parent.is_sub_filter_of(&child));
    }

    #[test]
    fn starts_with_not_sub_filter_of_unrelated() {
        let parent = StartsWithFilter { text: "dog".to_owned() };
        let child = StartsWithFilter { text: "cat".to_owned() };
        assert!(!child.is_sub_filter_of(&parent));
    }

    #[test]
    fn exact_filter_never_sub_filter() {
        let parent = StartsWithFilter { text: "ca".to_owned() };
        let exact = ExactFilter { text: "cat".to_owned() };
        assert!(!exact.is_sub_filter_of(&parent));
    }

    #[test]
    fn exact_filter_matches_only_equal() {
        let f = ExactFilter { text: "cat".to_owned() };
        assert!(f.matches("cat"));
        assert!(!f.matches("cats"));
        assert!(!f.matches("ca"));
    }
}
