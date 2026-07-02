use super::{StartsWithTextFilter, TextFilter, TextFilterFactory};

/// Factory for creating StartsWithTextFilter instances.
///
/// Corresponds to `docking.widgets.filter.StartsWithTextFilterFactory`.
pub struct StartsWithTextFilterFactory {
    case_sensitive: bool,
    allow_globbing: bool,
}

impl StartsWithTextFilterFactory {
    /// Creates a new factory with the specified options.
    ///
    /// # Arguments
    /// * `case_sensitive` - Whether filters created by this factory should be case-sensitive
    /// * `allow_globbing` - Whether filters created by this factory should allow glob patterns
    pub fn new(case_sensitive: bool, allow_globbing: bool) -> Self {
        Self {
            case_sensitive,
            allow_globbing,
        }
    }
}

impl TextFilterFactory for StartsWithTextFilterFactory {
    fn get_text_filter(&self, text: &str) -> Box<dyn TextFilter> {
        Box::new(StartsWithTextFilter::new(
            text,
            self.case_sensitive,
            self.allow_globbing,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_filter_with_given_text() {
        let factory = StartsWithTextFilterFactory::new(true, false);
        let filter = factory.get_text_filter("test");
        assert_eq!(filter.get_filter_text(), "test");
    }

    #[test]
    fn creates_filter_that_matches_starts_with() {
        let factory = StartsWithTextFilterFactory::new(true, false);
        let filter = factory.get_text_filter("cat");
        assert!(filter.matches("cat"));
        assert!(filter.matches("cats"));
        assert!(filter.matches("category"));
        assert!(!filter.matches("the cat"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn respects_case_sensitive_flag() {
        let factory_sensitive = StartsWithTextFilterFactory::new(true, false);
        let factory_insensitive = StartsWithTextFilterFactory::new(false, false);

        let filter_sensitive = factory_sensitive.get_text_filter("Cat");
        let filter_insensitive = factory_insensitive.get_text_filter("Cat");

        assert!(filter_sensitive.matches("Cat"));
        assert!(!filter_sensitive.matches("cat"));

        assert!(filter_insensitive.matches("Cat"));
        assert!(filter_insensitive.matches("cat"));
    }

    #[test]
    fn respects_allow_globbing_flag() {
        let factory_with_globbing = StartsWithTextFilterFactory::new(true, true);
        let factory_without_globbing = StartsWithTextFilterFactory::new(true, false);

        let filter_with = factory_with_globbing.get_text_filter("c*t");
        let filter_without = factory_without_globbing.get_text_filter("c*t");

        assert!(filter_with.matches("cat"));
        assert!(filter_with.matches("cart"));
        assert!(filter_with.matches("ct"));

        assert!(!filter_without.matches("cat"));
        assert!(filter_without.matches("c*t"));
    }

    #[test]
    fn factory_with_different_configurations() {
        let factory1 = StartsWithTextFilterFactory::new(true, true);
        let factory2 = StartsWithTextFilterFactory::new(false, false);

        let filter1 = factory1.get_text_filter("test");
        let filter2 = factory2.get_text_filter("test");

        assert_eq!(filter1.get_filter_text(), "test");
        assert_eq!(filter2.get_filter_text(), "test");
    }

    #[test]
    fn creates_distinct_filter_instances() {
        let factory = StartsWithTextFilterFactory::new(true, false);
        let filter1 = factory.get_text_filter("foo");
        let filter2 = factory.get_text_filter("bar");

        assert_eq!(filter1.get_filter_text(), "foo");
        assert_eq!(filter2.get_filter_text(), "bar");
    }

    #[test]
    fn handles_empty_text() {
        let factory = StartsWithTextFilterFactory::new(true, false);
        let filter = factory.get_text_filter("");
        assert_eq!(filter.get_filter_text(), "");
    }

    #[test]
    fn creates_filter_with_globbing_enabled() {
        let factory = StartsWithTextFilterFactory::new(false, true);
        let filter = factory.get_text_filter("h*llo");
        assert!(filter.matches("hello"));
        assert!(filter.matches("hallo"));
        assert!(filter.matches("hllo"));
    }
}
