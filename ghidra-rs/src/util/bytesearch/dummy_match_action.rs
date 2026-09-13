use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::bytesearch::match_action::MatchAction;
use crate::util::bytesearch::Match;
use crate::util::seam_stubs::Pattern;
use crate::util::seam_stubs::XmlPullParser;

/// Dummy action attached to a match sequence. Action is not restored from XML.
///
/// Port of `ghidra.util.bytesearch.DummyMatchAction`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DummyMatchAction;

impl DummyMatchAction {
    /// Creates a new `DummyMatchAction`.
    pub fn new() -> Self {
        Self
    }
}

impl MatchAction for DummyMatchAction {
    /// Java: `apply(Program, Address, Match)`. The body is empty: this action performs no work
    /// when a match is found.
    fn apply(&self, _program: &dyn Program, _addr: &Address, _match_: &Match<Box<dyn Pattern>>) {}

    /// Java: `restoreXml(XmlPullParser)`, which discards the (nonexistent) subtree since this
    /// action carries no XML-configurable state.
    fn restore_xml(&self, parser: &dyn XmlPullParser) {
        parser.discard_sub_tree();
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
        MockProgram { factory: Arc::new(DefaultAddressFactory::new(vec![])) as Arc<dyn AddressFactory> }
    }

    fn some_address() -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, 0x1000)
    }

    /// Minimal `Pattern` implementation, just enough to build a `Match<Box<dyn Pattern>>` for
    /// exercising `apply`.
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
    fn apply_is_a_true_no_op() {
        // Java: `apply(Program, Address, Match)` has an empty body -- it must not touch the
        // program, address, or match in any observable way. There is nothing to assert on the
        // program/address/match themselves (DummyMatchAction never reads them), so this test
        // just confirms the call completes without panicking for a real match value.
        let action = DummyMatchAction::new();
        let program = mock_program();
        let addr = some_address();
        let m = some_match();
        action.apply(&program, &addr, &m);
    }

    #[test]
    fn restore_xml_discards_subtree() {
        // Java: `restoreXml(XmlPullParser parser)` calls `parser.discardSubTree()` and nothing
        // else -- action state is never populated from XML.
        let action = DummyMatchAction::new();
        let parser = RecordingParser::default();
        action.restore_xml(&parser);
        assert_eq!(*parser.discard_calls.lock().unwrap(), 1);
    }

    #[test]
    fn restore_xml_discards_subtree_exactly_once_per_call() {
        let action = DummyMatchAction::new();
        let parser = RecordingParser::default();
        action.restore_xml(&parser);
        action.restore_xml(&parser);
        assert_eq!(*parser.discard_calls.lock().unwrap(), 2);
    }

    #[test]
    fn implements_match_action_trait_object() {
        let action: Box<dyn MatchAction> = Box::new(DummyMatchAction::new());
        let program = mock_program();
        let addr = some_address();
        let m = some_match();
        action.apply(&program, &addr, &m);
        let parser = RecordingParser::default();
        action.restore_xml(&parser);
        assert_eq!(*parser.discard_calls.lock().unwrap(), 1);
    }

    #[test]
    fn default_and_new_are_equivalent() {
        let a = DummyMatchAction::default();
        let b = DummyMatchAction::new();
        // Both are unit structs; this just confirms both construction paths compile and are
        // usable interchangeably.
        let program = mock_program();
        let addr = some_address();
        let m = some_match();
        a.apply(&program, &addr, &m);
        b.apply(&program, &addr, &m);
    }
}
