use super::TextFilter;

/// A text filter that inverts the matching logic of another filter.
///
/// For any given text, this filter returns the opposite of what its wrapped filter would return.
/// This filter can never be a sub-filter of another, since it inverts the matching logic.
///
/// Corresponds to `docking.widgets.filter.InvertedTextFilter`.
pub struct InvertedTextFilter {
    filter: Box<dyn TextFilter>,
}

impl InvertedTextFilter {
    /// Creates a new inverted filter that wraps the given filter.
    pub fn new(filter: Box<dyn TextFilter>) -> Self {
        Self { filter }
    }
}

impl TextFilter for InvertedTextFilter {
    fn matches(&self, text: &str) -> bool {
        !self.filter.matches(text)
    }

    fn get_filter_text(&self) -> &str {
        self.filter.get_filter_text()
    }

    fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
        // Inverted filters can't add back data that has already been filtered out
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleFilter {
        text: String,
    }

    impl TextFilter for SimpleFilter {
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

    struct StartsWithFilter {
        prefix: String,
    }

    impl TextFilter for StartsWithFilter {
        fn matches(&self, text: &str) -> bool {
            text.starts_with(self.prefix.as_str())
        }

        fn get_filter_text(&self) -> &str {
            &self.prefix
        }

        fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
            false
        }
    }

    #[test]
    fn inverts_exact_match() {
        let inner = Box::new(SimpleFilter {
            text: "test".to_owned(),
        });
        let inverted = InvertedTextFilter::new(inner);

        assert!(!inverted.matches("test"));
        assert!(inverted.matches("other"));
        assert!(inverted.matches(""));
    }

    #[test]
    fn inverts_starts_with() {
        let inner = Box::new(StartsWithFilter {
            prefix: "prefix".to_owned(),
        });
        let inverted = InvertedTextFilter::new(inner);

        assert!(!inverted.matches("prefix"));
        assert!(!inverted.matches("prefixsuffix"));
        assert!(inverted.matches("other"));
        assert!(inverted.matches("prefi"));
    }

    #[test]
    fn get_filter_text_delegates_to_inner() {
        let inner = Box::new(SimpleFilter {
            text: "mytext".to_owned(),
        });
        let inverted = InvertedTextFilter::new(inner);

        assert_eq!(inverted.get_filter_text(), "mytext");
    }

    #[test]
    fn is_sub_filter_of_always_false() {
        let inner = Box::new(SimpleFilter {
            text: "test".to_owned(),
        });
        let inverted = InvertedTextFilter::new(inner);
        let another = Box::new(SimpleFilter {
            text: "other".to_owned(),
        });

        assert!(!inverted.is_sub_filter_of(another.as_ref()));
    }

    #[test]
    fn multiple_inversions() {
        let inner = Box::new(SimpleFilter {
            text: "match".to_owned(),
        });
        let inverted1: Box<dyn TextFilter> = Box::new(InvertedTextFilter::new(inner));
        let inverted2 = InvertedTextFilter::new(inverted1);

        // Double inversion: not(not(match)) = match
        assert!(inverted2.matches("match"));
        assert!(!inverted2.matches("other"));
    }
}
