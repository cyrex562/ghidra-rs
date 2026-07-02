use super::{ContainsTextFilter, TextFilter, TextFilterFactory};

/// Factory for creating ContainsTextFilter instances.
///
/// Corresponds to `docking.widgets.filter.ContainsTextFilterFactory`.
pub struct ContainsTextFilterFactory {
    case_sensitive: bool,
    allow_globbing: bool,
}

impl ContainsTextFilterFactory {
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

impl TextFilterFactory for ContainsTextFilterFactory {
    fn get_text_filter(&self, text: &str) -> Box<dyn TextFilter> {
        Box::new(ContainsTextFilter::new(
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
        let factory = ContainsTextFilterFactory::new(true, false);
        let filter = factory.get_text_filter("test");
        assert_eq!(filter.get_filter_text(), "test");
    }

    #[test]
    fn creates_filter_that_matches() {
        let factory = ContainsTextFilterFactory::new(true, false);
        let filter = factory.get_text_filter("cat");
        assert!(filter.matches("the cat sat"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn respects_case_sensitive_flag() {
        let factory_sensitive = ContainsTextFilterFactory::new(true, false);
        let factory_insensitive = ContainsTextFilterFactory::new(false, false);

        let filter_sensitive = factory_sensitive.get_text_filter("Cat");
        let filter_insensitive = factory_insensitive.get_text_filter("Cat");

        assert!(filter_sensitive.matches("the Cat"));
        assert!(!filter_sensitive.matches("the cat"));

        assert!(filter_insensitive.matches("the Cat"));
        assert!(filter_insensitive.matches("the cat"));
    }

    #[test]
    fn respects_allow_globbing_flag() {
        let factory_with_globbing = ContainsTextFilterFactory::new(true, true);
        let factory_without_globbing = ContainsTextFilterFactory::new(true, false);

        let filter_with = factory_with_globbing.get_text_filter("c*t");
        let filter_without = factory_without_globbing.get_text_filter("c*t");

        assert!(filter_with.matches("cat"));
        assert!(filter_with.matches("cart"));

        assert!(!filter_without.matches("cat"));
        assert!(filter_without.matches("c*t"));
    }

    #[test]
    fn factory_with_different_configurations() {
        let factory1 = ContainsTextFilterFactory::new(true, true);
        let factory2 = ContainsTextFilterFactory::new(false, false);

        let filter1 = factory1.get_text_filter("test");
        let filter2 = factory2.get_text_filter("test");

        assert_eq!(filter1.get_filter_text(), "test");
        assert_eq!(filter2.get_filter_text(), "test");
    }

    #[test]
    fn creates_distinct_filter_instances() {
        let factory = ContainsTextFilterFactory::new(true, false);
        let filter1 = factory.get_text_filter("foo");
        let filter2 = factory.get_text_filter("bar");

        assert_eq!(filter1.get_filter_text(), "foo");
        assert_eq!(filter2.get_filter_text(), "bar");
    }

    #[test]
    fn handles_empty_text() {
        let factory = ContainsTextFilterFactory::new(true, false);
        let filter = factory.get_text_filter("");
        assert_eq!(filter.get_filter_text(), "");
    }
}
