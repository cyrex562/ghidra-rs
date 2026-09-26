//! Port of `ghidra.features.bsim.query.protocol.ResponseError`.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A response carrying an error message, used when a query could not be answered normally.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseError`.
pub struct ResponseError {
    /// The error message. `None` mirrors Java's `errorMessage == null` (the field is never
    /// initialized by the constructor).
    pub error_message: Option<String>,

    base: QueryResponseRecordBase,
}

impl ResponseError {
    /// Java: `ResponseError()`.
    pub fn new() -> Self {
        Self { error_message: None, base: QueryResponseRecordBase::new("error") }
    }

    /// Serializes this response as an `<error>message</error>` element.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a real Java bug:
    /// `errorMessage` starts out `null` (never assigned by the constructor -- see
    /// [`new`](Self::new)) and `saveXml` calls `SpecXmlUtils.xmlEscapeWriter(fwrite,
    /// errorMessage)` unconditionally, with no null check, so calling this before
    /// `error_message` is populated throws a `NullPointerException` in the real Ghidra code, and
    /// panics here for the same reason (see [`tests::save_xml_panics_when_error_message_is_unset`]).
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.base.get_name())?;
        let message = self.error_message.as_deref().expect(
            "Java: ResponseError.saveXml calls SpecXmlUtils.xmlEscapeWriter(fwrite, errorMessage) \
             unconditionally; errorMessage is null until explicitly set, so this throws a \
             NullPointerException in the real Ghidra code too",
        );
        let mut escaped = String::new();
        spec_xml_utils::xml_escape(&mut escaped, message);
        write!(fwrite, "{escaped}")?;
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseError` from an `<error>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`. Java matches the closing tag against
    /// the previously read start element (`parser.end(el)`), which this mirrors via
    /// [`XmlPullParser::end_matching`].
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        let el = parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        let text = parser.end_matching(&el).map_err(xml_err)?.get_text().to_string();
        self.error_message = Some(text);
        Ok(())
    }
}

impl Default for ResponseError {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseError {
    fn base(&self) -> &QueryResponseRecordBase {
        &self.base
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        Self::save_xml(self, fwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;

    struct VecParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl XmlPullParser for VecParser {
        type Element = XmlElementImpl;

        fn get_name(&self) -> &str {
            "VecParser"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn is_pulling_content(&self) -> bool {
            true
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> Self::Element {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> Self::Element {
            let el = self.elements[self.pos].clone();
            self.pos += 1;
            el
        }

        fn dispose(&mut self) {}
    }

    fn start(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0).unwrap()
    }

    #[test]
    fn new_starts_with_no_message() {
        let r = ResponseError::new();
        assert!(r.error_message.is_none());
        assert_eq!(r.base.get_name(), "error");
    }

    #[test]
    fn save_xml_panics_when_error_message_is_unset() {
        let r = ResponseError::new();
        let mut buf = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.save_xml(&mut buf)));
        assert!(result.is_err());
    }

    #[test]
    fn save_xml_writes_escaped_message() {
        let r = ResponseError { error_message: Some("bad <input>".to_string()), base: QueryResponseRecordBase::new("error") };
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<error>\nbad &lt;input&gt;</error>\n");
    }

    #[test]
    fn restore_xml_reads_message() {
        let mut parser = VecParser { elements: vec![start("error"), end_with_text("error", "something broke")], pos: 0 };
        let mut r = ResponseError::new();
        r.restore_xml(&mut parser).unwrap();
        assert_eq!(r.error_message.as_deref(), Some("something broke"));
    }

    #[test]
    fn restore_xml_rejects_mismatched_end_element() {
        let mut parser = VecParser { elements: vec![start("error"), end_with_text("wrong", "x")], pos: 0 };
        let mut r = ResponseError::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }

    #[test]
    fn restore_xml_rejects_wrong_start_element() {
        let mut parser = VecParser { elements: vec![start("wrong")], pos: 0 };
        let mut r = ResponseError::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
