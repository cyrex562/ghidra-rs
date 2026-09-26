//! Port of `ghidra.xml.XmlMessageLog`.

use std::ops::{Deref, DerefMut};

use super::xml_pull_parser::XmlPullParser;
use crate::app::util::importer::message_log::MessageLog;

/// A sub-class of [`MessageLog`] to handle appending messages from the XML parser.
///
/// Port of `ghidra.xml.XmlMessageLog`. Java's `extends MessageLog` becomes composition here (a
/// `base: MessageLog` field plus [`Deref`]/[`DerefMut`] so every other `MessageLog` method --
/// `append_msg_from`, `has_messages`, `clear`, `set_status`, ... -- remains reachable unchanged
/// through this type); only `appendMsg(String)` is actually overridden, as an inherent method
/// that shadows the `Deref`-reached one.
///
/// Generic over the concrete parser type `P`: [`XmlPullParser`] declares an associated `Element`
/// type (see that trait's own module docs), which makes it non-object-safe, so `parser` can't be
/// stored as a `dyn XmlPullParser`.
pub(crate) struct XmlMessageLog<P: XmlPullParser> {
    base: MessageLog,
    parser: Option<P>,
}

impl<P: XmlPullParser> XmlMessageLog<P> {
    /// Constructs a new XML message log.
    ///
    /// Port of `XmlMessageLog()`.
    pub fn new() -> Self {
        XmlMessageLog {
            base: MessageLog::new(),
            parser: None,
        }
    }

    /// Sets the XML parser.
    ///
    /// Port of `XmlMessageLog.setParser(XmlPullParser)`.
    pub fn set_parser(&mut self, parser: P) {
        self.parser = Some(parser);
    }

    /// Appends the message to the log, prefixed with the parser's current line number when one
    /// is available and positive.
    ///
    /// Port of `XmlMessageLog.appendMsg(String)`, overriding `MessageLog.appendMsg(String)`.
    pub fn append_msg(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        let line_num = match &self.parser {
            Some(parser) => parser.get_line_number(),
            None => 0,
        };
        if line_num > 0 {
            self.base.append_msg_at_line(line_num, &msg);
        } else {
            self.base.append_msg(msg);
        }
    }
}

impl<P: XmlPullParser> Default for XmlMessageLog<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: XmlPullParser> Deref for XmlMessageLog<P> {
    type Target = MessageLog;

    fn deref(&self) -> &MessageLog {
        &self.base
    }
}

impl<P: XmlPullParser> DerefMut for XmlMessageLog<P> {
    fn deref_mut(&mut self) -> &mut MessageLog {
        &mut self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element::XmlElement;
    use std::collections::HashMap;

    /// A trivial [`XmlElement`] whose only behavior this module's tests rely on is
    /// `get_line_number`.
    #[derive(Clone)]
    struct MockElement {
        line: i32,
    }

    impl XmlElement for MockElement {
        fn get_level(&self) -> i32 {
            0
        }
        fn is_start(&self) -> bool {
            true
        }
        fn is_end(&self) -> bool {
            false
        }
        fn is_content(&self) -> bool {
            false
        }
        fn get_name(&self) -> &str {
            "mock"
        }
        fn get_attributes(&self) -> HashMap<String, String> {
            HashMap::new()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(std::iter::empty())
        }
        fn has_attribute(&self, _key: &str) -> bool {
            false
        }
        fn get_attribute(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_text(&self) -> &str {
            ""
        }
        fn get_column_number(&self) -> i32 {
            0
        }
        fn get_line_number(&self) -> i32 {
            self.line
        }
        fn set_attribute(&mut self, _key: impl Into<String>, _value: impl Into<String>) {}
        fn is_start_with(&self, _name: &str) -> bool {
            false
        }
    }

    /// A minimal [`XmlPullParser`] that either has one element queued (reporting `line`) or is
    /// already exhausted (`has_next() == false`, so `get_line_number()`'s default falls back to
    /// -1, exactly like a real parser positioned at EOF).
    struct MockParser {
        has_next: bool,
        line: i32,
    }

    impl MockParser {
        fn at_line(line: i32) -> Self {
            MockParser { has_next: true, line }
        }

        fn exhausted() -> Self {
            MockParser { has_next: false, line: 0 }
        }
    }

    impl XmlPullParser for MockParser {
        type Element = MockElement;

        fn get_name(&self) -> &str {
            "mock"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn is_pulling_content(&self) -> bool {
            false
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn has_next(&self) -> bool {
            self.has_next
        }

        fn peek(&self) -> MockElement {
            MockElement { line: self.line }
        }

        fn next(&mut self) -> MockElement {
            MockElement { line: self.line }
        }

        fn dispose(&mut self) {}
    }

    #[test]
    fn new_log_has_no_messages() {
        let log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        assert!(!log.has_messages());
    }

    #[test]
    fn append_msg_without_parser_is_bare() {
        let mut log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        log.append_msg("no parser attached");
        assert_eq!(log.to_string(), "no parser attached\n");
    }

    #[test]
    fn append_msg_with_parser_prefixes_line_number() {
        let mut log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        log.set_parser(MockParser::at_line(42));
        log.append_msg("bad token");
        assert_eq!(log.to_string(), "Line #42 - bad token\n");
    }

    #[test]
    fn append_msg_with_exhausted_parser_is_bare() {
        // Mirrors the Java `if (lineNum > 0)` guard: `getLineNumber()`'s default implementation
        // returns -1 when the parser has no next element, so the message falls back to the bare
        // `super.appendMsg(msg)` path even though a parser is attached.
        let mut log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        log.set_parser(MockParser::exhausted());
        log.append_msg("eof");
        assert_eq!(log.to_string(), "eof\n");
    }

    #[test]
    fn append_msg_with_zero_line_is_bare() {
        let mut log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        log.set_parser(MockParser::at_line(0));
        log.append_msg("zero line");
        assert_eq!(log.to_string(), "zero line\n");
    }

    #[test]
    fn other_message_log_methods_reach_through_deref() {
        let mut log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        log.set_status("uh oh");
        assert_eq!(log.get_status(), "uh oh");
        log.append_msg_from(Some("Loader"), "could not parse");
        assert!(log.has_messages());
        log.clear();
        assert!(!log.has_messages());
    }

    #[test]
    fn multiple_appends_accumulate_in_order() {
        let mut log: XmlMessageLog<MockParser> = XmlMessageLog::new();
        log.set_parser(MockParser::at_line(1));
        log.append_msg("first");
        log.set_parser(MockParser::at_line(2));
        log.append_msg("second");
        assert_eq!(log.to_string(), "Line #1 - first\nLine #2 - second\n");
    }
}
