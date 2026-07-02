use super::{FindsPatternTextFilter, TextFilter, TextFilterFactory};

/// Factory for creating FindsPatternTextFilter instances (regex-based).
///
/// Corresponds to `docking.widgets.filter.RegularExpressionTextFilterFactory`.
pub struct RegularExpressionTextFilterFactory;

impl TextFilterFactory for RegularExpressionTextFilterFactory {
    fn get_text_filter(&self, text: &str) -> Box<dyn TextFilter> {
        Box::new(FindsPatternTextFilter::new(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_filter_from_text() {
        let factory = RegularExpressionTextFilterFactory;
        let filter = factory.get_text_filter("test");
        assert_eq!(filter.get_filter_text(), "test");
    }

    #[test]
    fn creates_regex_filter_that_matches() {
        let factory = RegularExpressionTextFilterFactory;
        let filter = factory.get_text_filter("ca.");
        assert!(filter.matches("cat"));
        assert!(filter.matches("car"));
        assert!(!filter.matches("dog"));
    }

    #[test]
    fn creates_distinct_filter_instances() {
        let factory = RegularExpressionTextFilterFactory;
        let filter1 = factory.get_text_filter("foo");
        let filter2 = factory.get_text_filter("bar");
        assert_eq!(filter1.get_filter_text(), "foo");
        assert_eq!(filter2.get_filter_text(), "bar");
    }

    #[test]
    fn handles_empty_text() {
        let factory = RegularExpressionTextFilterFactory;
        let filter = factory.get_text_filter("");
        assert_eq!(filter.get_filter_text(), "");
    }

    #[test]
    fn handles_invalid_regex() {
        let factory = RegularExpressionTextFilterFactory;
        let filter = factory.get_text_filter("[");
        assert!(!filter.matches("anything"));
    }
}
