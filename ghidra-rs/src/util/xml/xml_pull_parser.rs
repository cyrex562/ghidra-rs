use super::xml_element::XmlElement;
use super::xml_exception::XmlException;

/// Interface describing the API for the XML pull parsing system.
///
/// Port of `ghidra.xml.XmlPullParser`. This is similar to `XmlParser`, except that it
/// has slightly different methods and IS case sensitive, conforming to the XML spec.
///
/// [`XmlElement`] takes a generic setter (`set_attribute`), which makes it unusable as a
/// `dyn` trait object; `XmlPullParser` therefore exposes its element type as an associated
/// type rather than boxing it.
pub(crate) trait XmlPullParser {
    /// The concrete [`XmlElement`] type produced by this parser.
    type Element: XmlElement;

    /// Returns the name of this parser.
    fn get_name(&self) -> &str;

    /// Returns the value of the attribute of the processing instruction.
    ///
    /// For example, `<?program_dtd version="1"?>`.
    fn get_processing_instruction(&self, name: &str, attribute: &str) -> Option<String>;

    /// Returns the current line number where the parser is (note that this may actually be
    /// ahead of where you think it is because of look-ahead and caching).
    fn get_line_number(&self) -> i32;

    /// Returns the current column number where the parser is (note that this may actually be
    /// ahead of where you think it is because of look-ahead and caching).
    fn get_column_number(&self) -> i32;

    /// Returns whether the parser will return content elements as well as start and end
    /// elements (they're always accumulated and provided in the appropriate end element).
    fn is_pulling_content(&self) -> bool;

    /// Sets whether the parser will return content elements. Note that this may fail if the
    /// parser cannot comply with the setting (usually when setting to `true`).
    fn set_pulling_content(&mut self, pulling_content: bool);

    /// The current element level, as if the XML document was a tree. The root element is at
    /// level 0. Each child is at a level one higher than its parent.
    ///
    /// Note that this is the same as `peek().get_level()`.
    fn get_current_level(&self) -> i32;

    /// Returns whether there is a next element.
    fn has_next(&self) -> bool;

    /// Returns the next element, without removing it from the queue (assuming there is such a
    /// next element). This is very useful for examining the next item to decide who should
    /// handle the subtree, and then delegating to a subordinate with the parser state intact.
    fn peek(&self) -> Self::Element;

    /// Returns the next element, removing it from the queue (assuming there is such a next
    /// element). This method should be used RARELY. Typically, when you're reading XML, you
    /// almost always at least know that you're either starting or ending a subtree, so
    /// `start()` or `end()` should be used instead. The only time you really might need to use
    /// this is if you don't really know where you are and you need to pop elements off until
    /// you synchronize back into a sane state.
    fn next(&mut self) -> Self::Element;

    /// Returns the next element, which must be a start element, and must be one of the
    /// supplied names (if any are provided). This method is very useful for starting a
    /// subtree, and returns an [`XmlException`] if the next element does not conform to your
    /// specification.
    fn start(&mut self, names: &[&str]) -> Result<Self::Element, XmlException>;

    /// Returns the next element, which must be an end element. The name doesn't matter. This
    /// method returns an [`XmlException`] if the next element is not an end element. Use this
    /// method when you really know you're matching the right end and want to avoid extra
    /// constraint checks.
    fn end(&mut self) -> Result<Self::Element, XmlException>;

    /// Returns the next element, which must be an end element, and must match the supplied
    /// element's name (presumably the start element of the subtree). This method returns an
    /// [`XmlException`] if the next element is not an end element, or if the name doesn't
    /// match.
    ///
    /// Port of the `end(XmlElement)` overload.
    fn end_matching(&mut self, element: &Self::Element) -> Result<Self::Element, XmlException>;

    /// Returns the next element, which must be a start element, and must be one of the
    /// supplied names (if any are provided). This method is very useful for starting a
    /// subtree, but differs from `start(...)` in that failures are soft. This means that if
    /// the next element isn't a start element, or doesn't match one of the optional provided
    /// names, `None` is returned (instead of raising an [`XmlException`]).
    fn soft_start(&mut self, names: &[&str]) -> Option<Self::Element>;

    /// Discards the current subtree. If the current element (`peek()`) is a content or end
    /// element, then just that element is discarded. If it's a start element, then the entire
    /// subtree starting with the start element is discarded (i.e. `next()` is called until the
    /// current element is now the element after the subtree's end element).
    ///
    /// Returns the number of elements discarded.
    fn discard_sub_tree(&mut self) -> i32;

    /// Discards the current subtree. The current element must be a start element, and must be
    /// named `name`, otherwise an [`XmlException`] is returned.
    ///
    /// Returns the number of elements discarded.
    ///
    /// Port of the `discardSubTree(String)` overload.
    fn discard_sub_tree_named(&mut self, name: &str) -> Result<i32, XmlException>;

    /// Discards a subtree. The element provided is used as the "start" of the subtree
    /// (although it doesn't actually have to be a start element; only its name and level are
    /// used). The queue of elements is discarded such that the last element discarded is an
    /// end element, has the same name as the provided element, and is the same level as the
    /// provided element. If the provided element's level is higher than the current level,
    /// then nothing is discarded.
    ///
    /// Returns the number of elements discarded.
    ///
    /// Port of the `discardSubTree(XmlElement)` overload.
    fn discard_sub_tree_element(&mut self, element: &Self::Element) -> i32;

    /// Disposes all resources of the parser. It's important that this is called when a client
    /// is finished with the parser, because this allows files to be closed, threads to be
    /// stopped, etc.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Clone)]
    struct MockElement {
        name: String,
        level: i32,
        is_start: bool,
        is_end: bool,
    }

    impl MockElement {
        fn start(name: &str, level: i32) -> Self {
            Self { name: name.to_string(), level, is_start: true, is_end: false }
        }

        fn end(name: &str, level: i32) -> Self {
            Self { name: name.to_string(), level, is_start: false, is_end: true }
        }
    }

    impl XmlElement for MockElement {
        fn get_level(&self) -> i32 {
            self.level
        }

        fn is_start(&self) -> bool {
            self.is_start
        }

        fn is_end(&self) -> bool {
            self.is_end
        }

        fn is_content(&self) -> bool {
            !self.is_start && !self.is_end
        }

        fn get_name(&self) -> &str {
            &self.name
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
            0
        }

        fn set_attribute(&mut self, _key: impl Into<String>, _value: impl Into<String>) {}

        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    /// Minimal queue-backed parser exercising the same contract as
    /// `AbstractXmlPullParser`, used to validate the trait's method shapes.
    struct QueueParser {
        elements: Vec<MockElement>,
        pos: usize,
        pulling_content: bool,
        disposed: bool,
    }

    impl QueueParser {
        fn new(elements: Vec<MockElement>) -> Self {
            Self { elements, pos: 0, pulling_content: false, disposed: false }
        }
    }

    fn collapse(names: &[&str]) -> String {
        if names.is_empty() {
            "[  ]".to_string()
        } else {
            format!("[ {} ]", names.join(", "))
        }
    }

    impl XmlPullParser for QueueParser {
        type Element = MockElement;

        fn get_name(&self) -> &str {
            "queue"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn get_line_number(&self) -> i32 {
            if self.has_next() {
                self.peek().get_line_number()
            } else {
                -1
            }
        }

        fn get_column_number(&self) -> i32 {
            if self.has_next() {
                self.peek().get_column_number()
            } else {
                -1
            }
        }

        fn is_pulling_content(&self) -> bool {
            self.pulling_content
        }

        fn set_pulling_content(&mut self, pulling_content: bool) {
            self.pulling_content = pulling_content;
        }

        fn get_current_level(&self) -> i32 {
            if self.has_next() {
                self.peek().get_level()
            } else {
                -1
            }
        }

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> MockElement {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> MockElement {
            let elem = self.elements[self.pos].clone();
            self.pos += 1;
            elem
        }

        fn start(&mut self, names: &[&str]) -> Result<MockElement, XmlException> {
            if !self.has_next() {
                return Err(XmlException::with_message(format!(
                    "at EOF but expected start element {}",
                    collapse(names)
                )));
            }
            let next = self.next();
            if !next.is_start() {
                return Err(XmlException::with_message(format!(
                    "got {} element but expected start element {}",
                    if next.is_end() { "end" } else { "content" },
                    collapse(names)
                )));
            }
            let found = names.is_empty() || names.iter().any(|n| *n == next.get_name());
            if !found {
                return Err(XmlException::with_message(format!(
                    "got element {} but expected start element {}",
                    next.get_name(),
                    collapse(names)
                )));
            }
            Ok(next)
        }

        fn end(&mut self) -> Result<MockElement, XmlException> {
            if !self.has_next() {
                return Err(XmlException::with_message("at EOF but expected end element"));
            }
            let next = self.next();
            if !next.is_end() {
                return Err(XmlException::with_message(format!(
                    "got {} element but expected end element",
                    if next.is_start() { "start" } else { "content" }
                )));
            }
            Ok(next)
        }

        fn end_matching(&mut self, element: &MockElement) -> Result<MockElement, XmlException> {
            let name = element.get_name();
            if !self.has_next() {
                return Err(XmlException::with_message(format!(
                    "at EOF but expected end element {}",
                    name
                )));
            }
            let next = self.next();
            if next.get_name() != name {
                return Err(XmlException::with_message(format!(
                    "got element {} but expected end element {}",
                    next.get_name(),
                    name
                )));
            }
            if !next.is_end() {
                return Err(XmlException::with_message(format!(
                    "got {} element but expected end element {}",
                    if next.is_start() { "start" } else { "content" },
                    name
                )));
            }
            Ok(next)
        }

        fn soft_start(&mut self, names: &[&str]) -> Option<MockElement> {
            if !self.has_next() {
                return None;
            }
            let peek = self.peek();
            if !peek.is_start() {
                return None;
            }
            let found = names.is_empty() || names.iter().any(|n| *n == peek.get_name());
            if !found {
                return None;
            }
            Some(self.next())
        }

        fn discard_sub_tree(&mut self) -> i32 {
            let front = self.peek();
            self.discard_sub_tree_element(&front)
        }

        fn discard_sub_tree_named(&mut self, name: &str) -> Result<i32, XmlException> {
            let start = self.start(&[name])?;
            Ok(self.discard_sub_tree_element(&start) + 1)
        }

        fn discard_sub_tree_element(&mut self, element: &MockElement) -> i32 {
            let element_name = element.get_name().to_string();
            let element_level = element.get_level();
            let mut count = 0;
            if self.has_next() {
                let front = self.peek();
                if front.is_start()
                    && front.get_level() == element_level
                    && front.get_name() == element_name
                {
                    self.next();
                    count += 1;
                }
            }
            while self.has_next() {
                let next = self.next();
                count += 1;
                if next.is_end() && next.get_level() == element_level
                    && next.get_name() == element_name
                {
                    break;
                }
            }
            count
        }

        fn dispose(&mut self) {
            self.disposed = true;
        }
    }

    fn sample_parser() -> QueueParser {
        QueueParser::new(vec![
            MockElement::start("root", 0),
            MockElement::start("child", 1),
            MockElement::end("child", 1),
            MockElement::end("root", 0),
        ])
    }

    #[test]
    fn has_next_true_before_exhausted() {
        let parser = sample_parser();
        assert!(parser.has_next());
    }

    #[test]
    fn peek_does_not_advance() {
        let parser = sample_parser();
        assert_eq!(parser.peek().get_name(), "root");
        assert_eq!(parser.peek().get_name(), "root");
    }

    #[test]
    fn next_advances_the_queue() {
        let mut parser = sample_parser();
        assert_eq!(parser.next().get_name(), "root");
        assert_eq!(parser.peek().get_name(), "child");
    }

    #[test]
    fn start_returns_matching_start_element() {
        let mut parser = sample_parser();
        let elem = parser.start(&["root"]).unwrap();
        assert_eq!(elem.get_name(), "root");
    }

    #[test]
    fn start_rejects_wrong_name() {
        let mut parser = sample_parser();
        assert!(parser.start(&["notroot"]).is_err());
    }

    #[test]
    fn start_at_eof_errors() {
        let mut parser = QueueParser::new(Vec::new());
        assert!(parser.start(&[]).is_err());
    }

    #[test]
    fn end_returns_matching_end_element() {
        let mut parser = sample_parser();
        parser.next();
        parser.next();
        parser.next();
        let elem = parser.end().unwrap();
        assert_eq!(elem.get_name(), "child");
    }

    #[test]
    fn end_rejects_non_end_element() {
        let mut parser = sample_parser();
        assert!(parser.end().is_err());
    }

    #[test]
    fn end_matching_checks_name() {
        let mut parser = sample_parser();
        let start = parser.start(&["root"]).unwrap();
        parser.next();
        parser.next();
        let end = parser.end_matching(&start).unwrap();
        assert_eq!(end.get_name(), "root");
    }

    #[test]
    fn end_matching_rejects_mismatched_name() {
        let mut parser = sample_parser();
        parser.next(); // root start
        parser.next(); // child start
        parser.next(); // child end
        let wrong = MockElement::start("wrong", 0);
        assert!(parser.end_matching(&wrong).is_err());
    }

    #[test]
    fn soft_start_returns_none_when_not_start() {
        let mut parser = sample_parser();
        parser.next();
        parser.next();
        assert!(parser.soft_start(&["child"]).is_none());
    }

    #[test]
    fn soft_start_returns_some_when_matched() {
        let mut parser = sample_parser();
        let elem = parser.soft_start(&["root"]).unwrap();
        assert_eq!(elem.get_name(), "root");
    }

    #[test]
    fn soft_start_returns_none_on_name_mismatch() {
        let mut parser = sample_parser();
        assert!(parser.soft_start(&["notroot"]).is_none());
    }

    #[test]
    fn discard_sub_tree_skips_entire_subtree() {
        let mut parser = sample_parser();
        let count = parser.discard_sub_tree();
        assert_eq!(count, 4);
        assert!(!parser.has_next());
    }

    #[test]
    fn discard_sub_tree_named_requires_matching_start() {
        let mut parser = sample_parser();
        let count = parser.discard_sub_tree_named("root").unwrap();
        assert_eq!(count, 4);
        assert!(!parser.has_next());
    }

    #[test]
    fn discard_sub_tree_named_errors_on_mismatch() {
        let mut parser = sample_parser();
        assert!(parser.discard_sub_tree_named("notroot").is_err());
    }

    #[test]
    fn set_and_get_pulling_content() {
        let mut parser = sample_parser();
        assert!(!parser.is_pulling_content());
        parser.set_pulling_content(true);
        assert!(parser.is_pulling_content());
    }

    #[test]
    fn get_current_level_reflects_next_element() {
        let mut parser = sample_parser();
        assert_eq!(parser.get_current_level(), 0);
        parser.next();
        assert_eq!(parser.get_current_level(), 1);
    }

    #[test]
    fn get_current_level_is_negative_one_at_eof() {
        let parser = QueueParser::new(Vec::new());
        assert_eq!(parser.get_current_level(), -1);
    }

    #[test]
    fn dispose_marks_parser_disposed() {
        let mut parser = sample_parser();
        parser.dispose();
        assert!(parser.disposed);
    }

    #[test]
    fn generic_usage_via_trait_bound() {
        fn drive<P: XmlPullParser>(parser: &mut P) -> i32 {
            let mut count = 0;
            while parser.has_next() {
                parser.next();
                count += 1;
            }
            count
        }

        let mut parser = sample_parser();
        assert_eq!(drive(&mut parser), 4);
    }
}
