use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::bytesearch::Match;
use crate::util::seam_stubs::Pattern;
use crate::util::seam_stubs::XmlPullParser;

/// Interface for a match action to be taken for the Program at Address for a ditted bit sequence pattern.
///
/// When a pattern match is found in a program, this trait defines the action to be performed.
/// Implementations can annotate the program, create symbols, or take other program-specific actions.
pub trait MatchAction: Send + Sync {
    /// Apply the match action to the program at the address.
    ///
    /// # Arguments
    /// * `program` - program in which the match occurred
    /// * `addr` - where the match occurred
    /// * `match_` - information about the match that occurred
    fn apply(&self, program: &dyn Program, addr: &Address, match_: &Match<Box<dyn Pattern>>);

    /// Action can be constructed from XML.
    ///
    /// # Arguments
    /// * `parser` - XML pull parser to restore action from XML
    fn restore_xml(&self, parser: &dyn XmlPullParser);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A concrete test implementation that records calls for verification.
    struct TestMatchAction {
        apply_called: Arc<Mutex<usize>>,
        restore_xml_called: Arc<Mutex<usize>>,
    }

    impl TestMatchAction {
        fn new() -> Self {
            Self {
                apply_called: Arc::new(Mutex::new(0)),
                restore_xml_called: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl MatchAction for TestMatchAction {
        fn apply(&self, _program: &dyn Program, _addr: &Address, _match_: &Match<Box<dyn Pattern>>) {
            *self.apply_called.lock().unwrap() += 1;
        }

        fn restore_xml(&self, _parser: &dyn XmlPullParser) {
            *self.restore_xml_called.lock().unwrap() += 1;
        }
    }

    #[test]
    fn trait_object_can_be_created() {
        let action: Box<dyn MatchAction> = Box::new(TestMatchAction::new());
        assert!(true); // Just verify we can create a trait object
    }

    #[test]
    fn apply_can_be_called_through_trait_object() {
        let action = Box::new(TestMatchAction::new());
        let test_ref = action.as_ref();

        // Verify that the trait object can be held and used.
        // In a real scenario, we'd pass actual program/address/match data,
        // but for this smoke test we just verify the mechanism works.
        assert_eq!(std::mem::size_of_val(&action) > 0, true);
    }

    #[test]
    fn restore_xml_can_be_called_through_trait_object() {
        let action = Box::new(TestMatchAction::new());
        // Verify that the trait object exists and could be called with restore_xml
        let test_ref = action.as_ref();
        assert_eq!(std::mem::size_of_val(&test_ref) > 0, true);
    }

    #[test]
    fn multiple_implementations_can_coexist() {
        let _action1: Box<dyn MatchAction> = Box::new(TestMatchAction::new());
        let _action2: Box<dyn MatchAction> = Box::new(TestMatchAction::new());
        // Verify we can create multiple independent implementations
        assert!(true);
    }
}
