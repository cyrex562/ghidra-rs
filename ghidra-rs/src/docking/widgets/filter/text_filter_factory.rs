use super::TextFilter;

/// Factory for creating TextFilter instances.
///
/// Corresponds to `docking.widgets.filter.TextFilterFactory`.
pub trait TextFilterFactory {
    /// Creates a text filter from the given text.
    ///
    /// # Arguments
    /// * `text` - The text used to create the filter
    ///
    /// # Returns
    /// A new TextFilter instance based on the provided text
    fn get_text_filter(&self, text: &str) -> Box<dyn TextFilter>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::widgets::filter::TextFilter as _;

    struct MockTextFilter {
        text: String,
    }

    impl TextFilter for MockTextFilter {
        fn matches(&self, text: &str) -> bool {
            text == self.text
        }

        fn get_filter_text(&self) -> &str {
            &self.text
        }

        fn is_sub_filter_of(&self, _filter: &dyn TextFilter) -> bool {
            false
        }
    }

    struct MockFactory;

    impl TextFilterFactory for MockFactory {
        fn get_text_filter(&self, text: &str) -> Box<dyn TextFilter> {
            Box::new(MockTextFilter {
                text: text.to_string(),
            })
        }
    }

    #[test]
    fn factory_creates_filter_with_text() {
        let factory = MockFactory;
        let filter = factory.get_text_filter("test");
        assert_eq!(filter.get_filter_text(), "test");
    }

    #[test]
    fn factory_creates_filter_that_matches() {
        let factory = MockFactory;
        let filter = factory.get_text_filter("hello");
        assert!(filter.matches("hello"));
        assert!(!filter.matches("world"));
    }

    #[test]
    fn factory_creates_distinct_filters() {
        let factory = MockFactory;
        let filter1 = factory.get_text_filter("foo");
        let filter2 = factory.get_text_filter("bar");
        assert_eq!(filter1.get_filter_text(), "foo");
        assert_eq!(filter2.get_filter_text(), "bar");
    }

    #[test]
    fn factory_handles_empty_text() {
        let factory = MockFactory;
        let filter = factory.get_text_filter("");
        assert_eq!(filter.get_filter_text(), "");
    }
}
