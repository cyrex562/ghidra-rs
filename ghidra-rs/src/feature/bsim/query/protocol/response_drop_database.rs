//! Port of `ghidra.features.bsim.query.protocol.ResponseDropDatabase`.
//!
//! Response of server indicating whether a drop-database request succeeded.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response of server indicating whether a drop-database request succeeded.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseDropDatabase`.
pub struct ResponseDropDatabase {
    /// True if the back-end supports this operation.
    ///
    /// Java declares and default-initializes this field but, per the faithfully reproduced
    /// `saveXml`/`restoreXml` below, never actually serializes or deserializes it: it is only
    /// ever observed at its constructor default (`true`) by any code that round-trips a
    /// `ResponseDropDatabase` through XML.
    pub operation_supported: bool,
    /// True if the drop was successful.
    pub drop_successful: bool,
    /// Error message if the drop was not successful.
    pub error_message: Option<String>,

    base: QueryResponseRecordBase,
}

impl ResponseDropDatabase {
    /// Java: `ResponseDropDatabase()`.
    pub fn new() -> Self {
        Self {
            operation_supported: true,
            drop_successful: false,
            error_message: None,
            base: QueryResponseRecordBase::new("responsedropdatabase"),
        }
    }

    /// Serializes this response as a `<responsedropdatabase success="...">message</responsedropdatabase>`
    /// element.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a bug in the original Java:
    /// `SpecXmlUtils.encodeBoolean(dropSuccessful)` is called for its side-effect-free return
    /// value, which is never appended to `fwrite`, so the `success` attribute always serializes
    /// as the empty string regardless of `drop_successful`. `operation_supported` is never
    /// written at all (no attribute or element corresponds to it in the real Java source).
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{} success=\"\">", self.base.get_name())?;
        if let Some(msg) = &self.error_message {
            let mut escaped = String::new();
            spec_xml_utils::xml_escape(&mut escaped, msg);
            write!(fwrite, "{escaped}")?;
        }
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseDropDatabase` from a `<responsedropdatabase>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`. As in the real Java,
    /// `operation_supported` is left untouched (it is not part of the serialized form).
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        let el = parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        self.drop_successful =
            spec_xml_utils::decode_boolean(el.get_attribute("success").as_deref().unwrap_or(""));
        let text = parser.end().map_err(xml_err)?.get_text().to_string();
        self.error_message = if text.is_empty() { None } else { Some(text) };
        Ok(())
    }
}

impl Default for ResponseDropDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseDropDatabase {
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

    fn start(name: &str, attrs: &[(&str, &str)]) -> XmlElementImpl {
        XmlElementImpl::new(
            true,
            false,
            name,
            0,
            attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            None,
            0,
            0,
        )
        .unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0).unwrap()
    }

    #[test]
    fn new_defaults() {
        let r = ResponseDropDatabase::new();
        assert!(r.operation_supported);
        assert!(!r.drop_successful);
        assert!(r.error_message.is_none());
    }

    #[test]
    fn save_xml_success_attribute_is_always_empty_bug() {
        let mut r = ResponseDropDatabase::new();
        r.drop_successful = true;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<responsedropdatabase success=\"\"></responsedropdatabase>\n"
        );
    }

    #[test]
    fn save_xml_never_emits_operation_supported() {
        let mut r = ResponseDropDatabase::new();
        r.operation_supported = false;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(!xml.contains("support"));
    }

    #[test]
    fn restore_xml_never_touches_operation_supported() {
        let mut parser = VecParser {
            elements: vec![
                start("responsedropdatabase", &[("success", "true")]),
                end_with_text("responsedropdatabase", ""),
            ],
            pos: 0,
        };
        let mut r = ResponseDropDatabase::new();
        r.operation_supported = false;
        r.restore_xml(&mut parser).unwrap();
        assert!(r.drop_successful);
        // Untouched by restore_xml, exactly as in the real Java.
        assert!(!r.operation_supported);
    }

    #[test]
    fn restore_xml_reads_error_message() {
        let mut parser = VecParser {
            elements: vec![
                start("responsedropdatabase", &[("success", "false")]),
                end_with_text("responsedropdatabase", "table missing"),
            ],
            pos: 0,
        };
        let mut r = ResponseDropDatabase::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(!r.drop_successful);
        assert_eq!(r.error_message.as_deref(), Some("table missing"));
    }

    #[test]
    fn restore_xml_rejects_wrong_element() {
        let mut parser = VecParser { elements: vec![start("wrong", &[])], pos: 0 };
        let mut r = ResponseDropDatabase::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
