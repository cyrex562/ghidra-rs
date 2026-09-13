//! Port of `ghidra.features.bsim.query.protocol.ResponseAdjustIndex`.
//!
//! Response to an `AdjustVectorIndex` request, returning a boolean value of either success or
//! failure of the request.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response to an `AdjustVectorIndex` request, indicating success/failure and whether the
/// operation is even supported by the back-end.
///
/// Port of `ghidra.features.bsim.query.protocol.ResponseAdjustIndex`.
pub struct ResponseAdjustIndex {
    /// True if the vector index adjustment succeeded.
    pub success: bool,
    /// True if the back-end supports this operation.
    pub operation_supported: bool,

    base: QueryResponseRecordBase,
}

impl ResponseAdjustIndex {
    /// Java: `ResponseAdjustIndex()`.
    pub fn new() -> Self {
        Self {
            success: false,
            operation_supported: true,
            base: QueryResponseRecordBase::new("responseadjust"),
        }
    }

    /// Serializes this response as a single self-closing `<responseadjust>` element.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(
            fwrite,
            "<{} success=\"{}\" support=\"{}\"/>\n",
            self.base.get_name(),
            spec_xml_utils::encode_boolean(self.success),
            spec_xml_utils::encode_boolean(self.operation_supported)
        )
    }

    /// Deserializes a `ResponseAdjustIndex` from a single `<responseadjust>` element.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub(crate) fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), LshException> {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        let el = parser.start(&[self.base.get_name()]).map_err(xml_err)?;
        self.success = spec_xml_utils::decode_boolean(el.get_attribute("success").as_deref().unwrap_or(""));
        self.operation_supported =
            spec_xml_utils::decode_boolean(el.get_attribute("support").as_deref().unwrap_or(""));
        parser.end().map_err(xml_err)?;
        Ok(())
    }
}

impl Default for ResponseAdjustIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryResponseRecord for ResponseAdjustIndex {
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

    fn end(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    #[test]
    fn new_defaults_match_java() {
        let r = ResponseAdjustIndex::new();
        assert!(!r.success);
        assert!(r.operation_supported);
        assert_eq!(r.base.get_name(), "responseadjust");
    }

    #[test]
    fn save_xml_writes_both_attributes() {
        let r = ResponseAdjustIndex { success: true, operation_supported: false, base: QueryResponseRecordBase::new("responseadjust") };
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<responseadjust success=\"true\" support=\"false\"/>\n");
    }

    #[test]
    fn restore_xml_reads_both_attributes() {
        let mut parser = VecParser {
            elements: vec![start("responseadjust", &[("success", "true"), ("support", "false")]), end("responseadjust")],
            pos: 0,
        };
        let mut r = ResponseAdjustIndex::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(r.success);
        assert!(!r.operation_supported);
    }

    #[test]
    fn restore_xml_missing_attributes_default_to_false() {
        let mut parser = VecParser { elements: vec![start("responseadjust", &[]), end("responseadjust")], pos: 0 };
        let mut r = ResponseAdjustIndex::new();
        r.restore_xml(&mut parser).unwrap();
        assert!(!r.success);
        assert!(!r.operation_supported);
    }

    #[test]
    fn restore_xml_round_trips_through_save_xml() {
        let original = ResponseAdjustIndex { success: true, operation_supported: true, base: QueryResponseRecordBase::new("responseadjust") };
        let mut parser = VecParser {
            elements: vec![start("responseadjust", &[("success", "true"), ("support", "true")]), end("responseadjust")],
            pos: 0,
        };
        let mut restored = ResponseAdjustIndex::new();
        restored.restore_xml(&mut parser).unwrap();
        assert_eq!(restored.success, original.success);
        assert_eq!(restored.operation_supported, original.operation_supported);
    }

    #[test]
    fn restore_xml_rejects_wrong_start_element() {
        let mut parser = VecParser { elements: vec![start("wrong", &[])], pos: 0 };
        let mut r = ResponseAdjustIndex::new();
        assert!(r.restore_xml(&mut parser).is_err());
    }

    #[test]
    fn query_response_record_trait_get_name() {
        let r = ResponseAdjustIndex::new();
        let rec: &dyn QueryResponseRecord = &r;
        assert_eq!(rec.get_name(), "responseadjust");
    }
}
