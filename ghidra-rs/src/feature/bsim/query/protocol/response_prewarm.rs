//! Port of `ghidra.features.bsim.query.protocol.ResponsePrewarm`.
//!
//! Response to a prewarm request, indicating the number of database blocks that were preloaded.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response to a prewarm request, indicating the number of database blocks that were preloaded.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponsePrewarm`.
pub struct ResponsePrewarm {
    /// Number of blocks in the main index that were read.
    pub block_count: i32,
    /// True if the back-end supports this operation.
    pub operation_supported: bool,

    base: QueryResponseRecordBase,
}

impl ResponsePrewarm {
    /// Java: `ResponsePrewarm()`.
    pub fn new() -> Self {
        Self {
            block_count: -1,
            operation_supported: true,
            base: QueryResponseRecordBase::new("responseprewarm"),
        }
    }

    /// Serializes this response as a `<responseprewarm support="...">...</responseprewarm>`
    /// element.
    ///
    /// Java: `saveXml(Writer)`. Note this faithfully reproduces a bug in the original Java:
    /// `Integer.toString(blockCount)` is called for its side-effect-free return value, which is
    /// never appended to `fwrite`, so `block_count` is never written into the element body
    /// (unlike `operation_supported`'s `support` attribute, which the original code does append
    /// correctly).
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(
            fwrite,
            "<{} support=\"{}\">\n</{}>\n",
            self.base.get_name(),
            spec_xml_utils::encode_boolean(self.operation_supported),
            self.base.get_name()
        )
    }

    /// Deserializes a `ResponsePrewarm` from a `<responseprewarm>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        let el = parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        self.operation_supported =
            spec_xml_utils::decode_boolean(el.get_attribute("support").as_deref().unwrap_or(""));
        let text = parser.end().map_err(xml_err)?.get_text().to_string();
        self.block_count = spec_xml_utils::decode_int(Some(&text));
        Ok(())
    }
}

impl Default for ResponsePrewarm {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponsePrewarm {
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
        let r = ResponsePrewarm::new();
        assert_eq!(r.block_count, -1);
        assert!(r.operation_supported);
    }

    #[test]
    fn save_xml_never_emits_block_count_bug() {
        // Java: `Integer.toString(blockCount)` return value is discarded.
        let mut r = ResponsePrewarm::new();
        r.block_count = 42;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<responseprewarm support=\"true\">\n</responseprewarm>\n");
    }

    #[test]
    fn save_xml_writes_support_attribute_correctly() {
        let mut r = ResponsePrewarm::new();
        r.operation_supported = false;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("support=\"false\""));
    }

    #[test]
    fn restore_xml_reads_support_and_body_text() {
        let mut parser = VecParser {
            elements: vec![
                start("responseprewarm", &[("support", "false")]),
                end_with_text("responseprewarm", "17"),
            ],
            pos: 0,
        };
        let mut r = ResponsePrewarm::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(!r.operation_supported);
        assert_eq!(r.block_count, 17);
    }

    #[test]
    fn restore_xml_round_trip_of_buggy_save_xml_always_yields_zero_block_count() {
        // Because save_xml never writes block_count, restoring the buggy output always yields 0.
        let mut r = ResponsePrewarm::new();
        r.block_count = 99;
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();

        let mut parser = VecParser {
            elements: vec![start("responseprewarm", &[("support", "true")]), end_with_text("responseprewarm", "")],
            pos: 0,
        };
        let mut restored = ResponsePrewarm::new();
        restored.restore_xml(&mut parser).unwrap();
        assert_eq!(restored.block_count, 0);
    }

    #[test]
    fn restore_xml_rejects_wrong_element() {
        let mut parser = VecParser { elements: vec![start("wrong", &[])], pos: 0 };
        let mut r = ResponsePrewarm::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }
}
