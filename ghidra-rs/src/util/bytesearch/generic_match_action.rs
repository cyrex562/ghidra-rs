use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::bytesearch::dummy_match_action::DummyMatchAction;
use crate::util::bytesearch::match_action::MatchAction;
use crate::util::bytesearch::Match;
use crate::util::seam_stubs::Pattern;
use crate::util::seam_stubs::XmlPullParser;

/// Template for a generic match action attached to a match sequence. Used to store an
/// associated value on the matching sequence; the associated value can be retrieved when the
/// sequence is matched.
///
/// Port of `ghidra.util.bytesearch.GenericMatchAction<T>`.
///
/// Java's `GenericMatchAction<T> extends DummyMatchAction`, inheriting `apply`/`restoreXml`
/// unchanged (it overrides neither) and adding only the `matchValue` field and its getter. Per
/// this crate's composition-over-inheritance convention, the inherited behavior is captured by
/// composing a [`DummyMatchAction`] field and delegating [`MatchAction::apply`]/
/// [`MatchAction::restore_xml`] to it, rather than attempting to fake `extends` with a trait
/// default or a blanket impl.
#[derive(Debug, Clone, Copy)]
pub struct GenericMatchAction<T> {
    inner: DummyMatchAction,
    match_value: T,
}

impl<T> GenericMatchAction<T> {
    /// Constructs a match action used when a match occurs for some `GenericByteSequence`.
    ///
    /// Port of `GenericMatchAction(T matchValue)`.
    pub fn new(match_value: T) -> Self {
        Self {
            inner: DummyMatchAction::new(),
            match_value,
        }
    }

    /// The specialized object associated with this match action.
    ///
    /// Port of `GenericMatchAction.getMatchValue()`.
    pub fn get_match_value(&self) -> &T {
        &self.match_value
    }
}

impl<T: Send + Sync> MatchAction for GenericMatchAction<T> {
    /// Inherited unchanged from `DummyMatchAction.apply` -- Java's `GenericMatchAction` does not
    /// override it, so applying this action is still a no-op.
    fn apply(&self, program: &dyn Program, addr: &Address, match_: &Match<Box<dyn Pattern>>) {
        self.inner.apply(program, addr, match_);
    }

    /// Inherited unchanged from `DummyMatchAction.restoreXml` -- Java's `GenericMatchAction`
    /// does not override it either, so this still just discards the (nonexistent) subtree
    /// rather than restoring `matchValue` from XML.
    fn restore_xml(&self, parser: &dyn XmlPullParser) {
        self.inner.restore_xml(parser);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::util::bytesearch::{PatternFactory, PostRule};
    use std::sync::{Arc, Mutex};

    struct MockProgram {
        factory: Arc<dyn AddressFactory>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    fn mock_program() -> MockProgram {
        MockProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![])) as Arc<dyn AddressFactory>,
        }
    }

    fn some_address() -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, 0x1000)
    }

    struct MockPattern;

    impl Pattern for MockPattern {
        fn get_post_rules(&self) -> Vec<Box<dyn PostRule>> {
            Vec::new()
        }

        fn get_match_actions(&self) -> Vec<Box<dyn MatchAction>> {
            Vec::new()
        }

        fn set_match_actions(&self, _actions: &[Box<dyn MatchAction>]) {}

        fn get_mark_offset(&self) -> i32 {
            0
        }

        fn restore_xml_attributes(
            &self,
            _postrulelist: Vec<Box<dyn PostRule>>,
            _actionlist: Vec<Box<dyn MatchAction>>,
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

    fn some_match() -> Match<Box<dyn Pattern>> {
        Match::new(Box::new(MockPattern) as Box<dyn Pattern>, 0, 1)
    }

    #[derive(Default)]
    struct RecordingParser {
        discard_calls: Mutex<usize>,
    }

    impl XmlPullParser for RecordingParser {
        fn start(&self, _name: &str) {}
        fn end(&self) {}
        fn discard_sub_tree(&self) {
            *self.discard_calls.lock().unwrap() += 1;
        }
    }

    #[test]
    fn new_stores_the_match_value() {
        // Java: the constructor just assigns `this.matchValue = matchValue`.
        let action = GenericMatchAction::new(42);
        assert_eq!(*action.get_match_value(), 42);
    }

    #[test]
    fn get_match_value_returns_the_exact_stored_object() {
        let action = GenericMatchAction::new("payload".to_string());
        assert_eq!(action.get_match_value(), "payload");
    }

    #[test]
    fn apply_is_inherited_as_a_true_no_op() {
        // Java: `GenericMatchAction` does not override `apply`, so `DummyMatchAction.apply`'s
        // empty body runs -- nothing observable happens to the program/address/match.
        let action = GenericMatchAction::new(7);
        let program = mock_program();
        let addr = some_address();
        let m = some_match();
        action.apply(&program, &addr, &m);
    }

    #[test]
    fn restore_xml_is_inherited_and_discards_subtree() {
        // Java: `GenericMatchAction` does not override `restoreXml` either, so
        // `DummyMatchAction.restoreXml`'s `parser.discardSubTree()` call runs, and
        // `matchValue` is never touched by XML restoration.
        let action = GenericMatchAction::new(99);
        let parser = RecordingParser::default();
        action.restore_xml(&parser);
        assert_eq!(*parser.discard_calls.lock().unwrap(), 1);
        assert_eq!(*action.get_match_value(), 99);
    }

    #[test]
    fn implements_match_action_trait_object() {
        let action: Box<dyn MatchAction> = Box::new(GenericMatchAction::new(5i32));
        let program = mock_program();
        let addr = some_address();
        let m = some_match();
        action.apply(&program, &addr, &m);
        let parser = RecordingParser::default();
        action.restore_xml(&parser);
        assert_eq!(*parser.discard_calls.lock().unwrap(), 1);
    }

    #[test]
    fn distinct_generic_match_actions_hold_independent_values() {
        let a = GenericMatchAction::new(1);
        let b = GenericMatchAction::new(2);
        assert_eq!(*a.get_match_value(), 1);
        assert_eq!(*b.get_match_value(), 2);
    }
}
