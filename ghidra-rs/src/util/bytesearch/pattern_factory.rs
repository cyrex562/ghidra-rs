use super::match_action::MatchAction;
use super::post_rule::PostRule;

/// Factory for creating Match Pattern classes and retrieving named actions and rules.
///
/// This trait serves as a factory interface for obtaining named match actions and post rules
/// that are associated with pattern matching. Implementations provide access to predefined
/// actions and rules by name.
pub trait PatternFactory: Send + Sync {
    /// Get a named match action.
    ///
    /// # Arguments
    /// * `nm` - name of the action to find
    ///
    /// # Returns
    /// A match action with the given name, or None if not found
    fn get_match_action_by_name(&self, nm: &str) -> Option<Box<dyn MatchAction>>;

    /// Get a named post match rule.
    ///
    /// # Arguments
    /// * `nm` - name of the post rule to find
    ///
    /// # Returns
    /// A post rule with the given name, or None if not found
    fn get_post_rule_by_name(&self, nm: &str) -> Option<Box<dyn PostRule>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A concrete test implementation that records calls for verification.
    struct TestPatternFactory {
        match_action_names: Arc<Mutex<Vec<String>>>,
        post_rule_names: Arc<Mutex<Vec<String>>>,
    }

    impl TestPatternFactory {
        fn new() -> Self {
            Self {
                match_action_names: Arc::new(Mutex::new(Vec::new())),
                post_rule_names: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl PatternFactory for TestPatternFactory {
        fn get_match_action_by_name(&self, nm: &str) -> Option<Box<dyn MatchAction>> {
            self.match_action_names.lock().unwrap().push(nm.to_string());
            None
        }

        fn get_post_rule_by_name(&self, nm: &str) -> Option<Box<dyn PostRule>> {
            self.post_rule_names.lock().unwrap().push(nm.to_string());
            None
        }
    }

    #[test]
    fn trait_object_can_be_created() {
        let factory: Box<dyn PatternFactory> = Box::new(TestPatternFactory::new());
        assert!(true); // Just verify we can create a trait object
    }

    #[test]
    fn get_match_action_by_name_returns_none_by_default() {
        let factory = TestPatternFactory::new();
        let result = factory.get_match_action_by_name("test_action");
        assert!(result.is_none());
    }

    #[test]
    fn get_post_rule_by_name_returns_none_by_default() {
        let factory = TestPatternFactory::new();
        let result = factory.get_post_rule_by_name("test_rule");
        assert!(result.is_none());
    }

    #[test]
    fn get_match_action_by_name_tracks_calls() {
        let factory = TestPatternFactory::new();
        factory.get_match_action_by_name("action1");
        factory.get_match_action_by_name("action2");
        let names = factory.match_action_names.lock().unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], "action1");
        assert_eq!(names[1], "action2");
    }

    #[test]
    fn get_post_rule_by_name_tracks_calls() {
        let factory = TestPatternFactory::new();
        factory.get_post_rule_by_name("rule1");
        factory.get_post_rule_by_name("rule2");
        let names = factory.post_rule_names.lock().unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], "rule1");
        assert_eq!(names[1], "rule2");
    }

    #[test]
    fn can_call_both_methods_through_trait_object() {
        let factory: Box<dyn PatternFactory> = Box::new(TestPatternFactory::new());
        let _action = factory.get_match_action_by_name("action");
        let _rule = factory.get_post_rule_by_name("rule");
        assert!(true);
    }

    #[test]
    fn multiple_implementations_can_coexist() {
        let _factory1: Box<dyn PatternFactory> = Box::new(TestPatternFactory::new());
        let _factory2: Box<dyn PatternFactory> = Box::new(TestPatternFactory::new());
        assert!(true);
    }
}
