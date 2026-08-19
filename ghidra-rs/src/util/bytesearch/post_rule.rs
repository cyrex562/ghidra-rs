use crate::util::bytesearch::PatternFactory;
use crate::util::seam_stubs::{Pattern, XmlPullParser};

/// Trait for post match rules that are checked after a match is identified.
///
/// A post rule is applied after a pattern match is found to validate or process the match.
/// Implementations can inspect the matched pattern and its offset to determine if the match
/// should be accepted, or to perform additional processing on the matched data.
pub trait PostRule: Send + Sync {
    /// Apply a post rule given the matching pattern and offset into the byte stream.
    ///
    /// # Arguments
    /// * `pat` - pattern that matched
    /// * `matchoffset` - offset of the match
    ///
    /// # Returns
    /// true if the PostRule is satisfied, false otherwise
    fn apply(&self, pat: &dyn Pattern, matchoffset: i64) -> bool;

    /// Can restore state of instance PostRule from XML.
    ///
    /// # Arguments
    /// * `parser` - XML pull parser
    fn restore_xml(&self, parser: &dyn XmlPullParser);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A concrete test implementation that records calls for verification.
    struct TestPostRule {
        apply_called: Arc<Mutex<usize>>,
        apply_result: Arc<Mutex<bool>>,
        restore_xml_called: Arc<Mutex<usize>>,
    }

    impl TestPostRule {
        fn new() -> Self {
            Self {
                apply_called: Arc::new(Mutex::new(0)),
                apply_result: Arc::new(Mutex::new(true)),
                restore_xml_called: Arc::new(Mutex::new(0)),
            }
        }

        fn with_result(result: bool) -> Self {
            Self {
                apply_called: Arc::new(Mutex::new(0)),
                apply_result: Arc::new(Mutex::new(result)),
                restore_xml_called: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl PostRule for TestPostRule {
        fn apply(&self, _pat: &dyn Pattern, _matchoffset: i64) -> bool {
            *self.apply_called.lock().unwrap() += 1;
            *self.apply_result.lock().unwrap()
        }

        fn restore_xml(&self, _parser: &dyn XmlPullParser) {
            *self.restore_xml_called.lock().unwrap() += 1;
        }
    }

    #[test]
    fn trait_object_can_be_created() {
        let rule: Box<dyn PostRule> = Box::new(TestPostRule::new());
        assert!(true); // Just verify we can create a trait object
    }

    #[test]
    fn apply_returns_true_by_default() {
        let rule = TestPostRule::new();
        let result = rule.apply(&MockPattern, 0);
        assert_eq!(result, true);
    }

    #[test]
    fn apply_returns_false_when_configured() {
        let rule = TestPostRule::with_result(false);
        let result = rule.apply(&MockPattern, 0);
        assert_eq!(result, false);
    }

    #[test]
    fn apply_can_be_called_through_trait_object() {
        let rule: Box<dyn PostRule> = Box::new(TestPostRule::new());
        let result = rule.apply(&MockPattern, 42);
        assert_eq!(result, true);
    }

    #[test]
    fn restore_xml_can_be_called_through_trait_object() {
        let rule: Box<dyn PostRule> = Box::new(TestPostRule::new());
        rule.restore_xml(&MockXmlPullParser);
        assert!(true);
    }

    #[test]
    fn multiple_implementations_can_coexist() {
        let _rule1: Box<dyn PostRule> = Box::new(TestPostRule::new());
        let _rule2: Box<dyn PostRule> = Box::new(TestPostRule::with_result(false));
        assert!(true);
    }

    /// Mock implementation of Pattern for testing.
    struct MockPattern;

    impl Pattern for MockPattern {
        fn get_post_rules(&self) -> Vec<Box<dyn PostRule>> {
            Vec::new()
        }

        fn get_match_actions(&self) -> Vec<Box<dyn crate::util::bytesearch::MatchAction>> {
            Vec::new()
        }

        fn set_match_actions(&self, _actions: &[Box<dyn crate::util::bytesearch::MatchAction>]) {}

        fn get_mark_offset(&self) -> i32 {
            0
        }

        fn restore_xml_attributes(
            &self,
            _postrulelist: Vec<Box<dyn PostRule>>,
            _actionlist: Vec<Box<dyn crate::util::bytesearch::MatchAction>>,
            _parser: &dyn XmlPullParser,
            _pfactory: &dyn PatternFactory,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn restore_xml(
            &self,
            _parser: &dyn XmlPullParser,
            _pfactory: &dyn PatternFactory,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn read_patterns(
            &self,
            _file: &dyn crate::util::seam_stubs::ResourceFile,
            _patlist: Vec<Box<dyn Pattern>>,
            _pfactory: &dyn PatternFactory,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn error(&self, _exception: &dyn crate::util::seam_stubs::SAXParseException) -> std::io::Result<()> {
            Ok(())
        }

        fn fatal_error(&self, _exception: &dyn crate::util::seam_stubs::SAXParseException) -> std::io::Result<()> {
            Ok(())
        }

        fn warning(&self, _exception: &dyn crate::util::seam_stubs::SAXParseException) -> std::io::Result<()> {
            Ok(())
        }

        fn read_post_patterns(
            &self,
            _file: &dyn crate::util::seam_stubs::FileMarker,
            _pattern_list: Vec<Box<dyn Pattern>>,
            _pfactory: &dyn PatternFactory,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn check_post_rules(&self, _offset: i64) -> bool {
            true
        }

        fn get_pre_sequence_length(&self) -> i32 {
            0
        }
    }

    /// Mock implementation of XmlPullParser for testing.
    struct MockXmlPullParser;

    impl XmlPullParser for MockXmlPullParser {
        fn start(&self, _name: &str) {}
        fn end(&self) {}
    }
}
