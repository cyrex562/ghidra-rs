//! A pull parser that replays a captured element sequence.
//!
//! Not the port of a Ghidra class. [`XmlPullParser`] has an associated element type and generic
//! provided methods, so it cannot be used as a trait object; code that must hand "the rest of
//! this element" to a `dyn` implementor (a p-code inject library extension's custom payload, for
//! instance) captures the subtree with [`ElementReplayParser::capture_subtree`] and passes this
//! one concrete parser type instead.

use super::xml_element::XmlElement;
use super::xml_element_impl::XmlElementImpl;
use super::xml_exception::XmlException;
use super::xml_pull_parser::XmlPullParser;

/// An [`XmlPullParser`] over an owned list of elements.
#[derive(Debug, Clone)]
pub(crate) struct ElementReplayParser {
    name: String,
    elements: Vec<XmlElementImpl>,
    pos: usize,
}

impl ElementReplayParser {
    /// A parser named `name` replaying `elements` in order.
    pub(crate) fn new(name: impl Into<String>, elements: Vec<XmlElementImpl>) -> Self {
        ElementReplayParser { name: name.into(), elements, pos: 0 }
    }

    /// Consumes the next element of `parser` (which must be a start element) and everything up to
    /// and including its matching end element, returning a parser that replays them.
    ///
    /// # Errors
    /// If the next element is not a start element, or `parser` ends before the matching end.
    pub(crate) fn capture_subtree<P: XmlPullParser>(parser: &mut P) -> Result<Self, XmlException> {
        if !parser.has_next() || !parser.peek().is_start() {
            return Err(XmlException::with_message("expected a start element to capture"));
        }
        let mut elements = Vec::new();
        let mut depth = 0usize;
        loop {
            if !parser.has_next() {
                return Err(XmlException::with_message("at EOF before the captured element ended"));
            }
            let el = parser.next();
            if el.is_start() {
                depth += 1;
            } else if el.is_end() {
                depth -= 1;
            }
            elements.push(Self::copy_element(&el)?);
            if depth == 0 {
                break;
            }
        }
        Ok(ElementReplayParser::new(parser.get_name().to_string(), elements))
    }

    fn copy_element<E: XmlElement>(el: &E) -> Result<XmlElementImpl, XmlException> {
        let text = if el.is_start() { None } else { Some(el.get_text().to_string()) };
        XmlElementImpl::new(
            el.is_start(),
            el.is_end(),
            el.get_name(),
            el.get_level(),
            el.get_attribute_iter().collect(),
            text,
            el.get_column_number(),
            el.get_line_number(),
        )
    }
}

impl XmlPullParser for ElementReplayParser {
    type Element = XmlElementImpl;

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
        None
    }

    fn is_pulling_content(&self) -> bool {
        false
    }

    fn set_pulling_content(&mut self, _pulling_content: bool) {}

    fn has_next(&self) -> bool {
        self.pos < self.elements.len()
    }

    /// # Panics
    /// At the end of the replayed elements.
    fn peek(&self) -> XmlElementImpl {
        self.elements[self.pos].clone()
    }

    /// # Panics
    /// At the end of the replayed elements.
    fn next(&mut self) -> XmlElementImpl {
        let el = self.elements[self.pos].clone();
        self.pos += 1;
        el
    }

    fn dispose(&mut self) {
        self.pos = self.elements.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_pull_parser_factory;

    #[test]
    fn captures_exactly_one_subtree_and_replays_it() {
        let xml = r#"<root><a k="v"><b/>text</a><c/></root>"#;
        let mut parser = xml_pull_parser_factory::create_from_str(xml, "doc", None, false).unwrap();
        parser.start(&["root"]).unwrap();
        let mut replay = ElementReplayParser::capture_subtree(&mut parser).unwrap();
        // The source parser is left at <c>.
        assert!(parser.peek().is_start_with("c"));

        assert_eq!(replay.get_name(), "doc");
        let a = replay.start(&["a"]).unwrap();
        assert_eq!(a.get_attribute("k").as_deref(), Some("v"));
        replay.start(&["b"]).unwrap();
        replay.end().unwrap();
        let end = replay.end_matching(&a).unwrap();
        assert_eq!(end.get_text(), "text");
        assert!(!replay.has_next());
    }

    #[test]
    fn capture_requires_a_start_element() {
        let mut parser = xml_pull_parser_factory::create_from_str("<r/>", "doc", None, false).unwrap();
        parser.start(&["r"]).unwrap();
        assert!(ElementReplayParser::capture_subtree(&mut parser).is_err());
    }
}
