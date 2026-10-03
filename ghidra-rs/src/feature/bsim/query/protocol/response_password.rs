//! Port of `ghidra.features.bsim.query.protocol.ResponsePassword`.
//!
//! Response of server indicating whether a password change request (`PasswordChange`)
//! succeeded.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response of server indicating whether a password change request succeeded.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponsePassword`.
pub struct ResponsePassword {
    /// True if the password change was successful.
    pub change_successful: bool,
    /// Error message if the change was not successful.
    pub error_message: Option<String>,

    base: QueryResponseRecordBase,
}

impl ResponsePassword {
    /// Java: `ResponsePassword()`.
    pub fn new() -> Self {
        Self {
            change_successful: false,
            error_message: None,
            base: QueryResponseRecordBase::new("responsepassword"),
        }
    }

    /// Serializes this response as a `<responsepassword success="...">message</responsepassword>`
    /// element.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a bug in the original Java:
    /// `SpecXmlUtils.encodeBoolean(changeSuccessful)` is called for its side-effect-free return
    /// value, which is never appended to `fwrite` (the statement is missing a chained `.append(...)`
    /// like the sibling attribute writes elsewhere in this package have). The `success` attribute
    /// therefore always serializes as the empty string, regardless of `change_successful`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{} success=\"\">", self.base.get_name())?;
        if let Some(msg) = &self.error_message {
            let mut escaped = String::new();
            spec_xml_utils::xml_escape(&mut escaped, msg);
            write!(fwrite, "{escaped}")?;
        }
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponsePassword` from a `<responsepassword>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        let el = parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        self.change_successful =
            spec_xml_utils::decode_boolean(el.get_attribute("success").as_deref().unwrap_or(""));
        let text = parser.end().map_err(xml_err)?.get_text().to_string();
        self.error_message = if text.is_empty() { None } else { Some(text) };
        Ok(())
    }
}

impl Default for ResponsePassword {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponsePassword {
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
        let r = ResponsePassword::new();
        assert!(!r.change_successful);
        assert!(r.error_message.is_none());
        assert_eq!(r.base.get_name(), "responsepassword");
    }

    #[test]
    fn save_xml_success_attribute_is_always_empty_bug() {
        // Java: SpecXmlUtils.encodeBoolean(changeSuccessful) is computed but never appended.
        let mut r = ResponsePassword::new();
        r.change_successful = true;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<responsepassword success=\"\"></responsepassword>\n");
    }

    #[test]
    fn save_xml_writes_escaped_error_message() {
        let r = ResponsePassword {
            change_successful: false,
            error_message: Some("bad <password>".to_string()),
            base: QueryResponseRecordBase::new("responsepassword"),
        };
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "<responsepassword success=\"\">bad &lt;password&gt;</responsepassword>\n"
        );
    }

    #[test]
    fn restore_xml_reads_success_attribute_and_message() {
        let mut parser = VecParser {
            elements: vec![start("responsepassword", &[("success", "true")]), end_with_text("responsepassword", "oops")],
            pos: 0,
        };
        let mut r = ResponsePassword::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(r.change_successful);
        assert_eq!(r.error_message.as_deref(), Some("oops"));
    }

    #[test]
    fn restore_xml_empty_text_becomes_none() {
        let mut parser = VecParser {
            elements: vec![start("responsepassword", &[("success", "false")]), end_with_text("responsepassword", "")],
            pos: 0,
        };
        let mut r = ResponsePassword::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(!r.change_successful);
        assert!(r.error_message.is_none());
    }

    #[test]
    fn restore_xml_rejects_wrong_element() {
        let mut parser = VecParser { elements: vec![start("wrong", &[])], pos: 0 };
        let mut r = ResponsePassword::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
