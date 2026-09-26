//! Port of `ghidra.program.model.lang.InjectPayloadJumpAssist`.
//!
//! One p-code snippet of a jump-assist table (`<jumpassist>` in a `.pspec`/`.cspec`/sleigh
//! language file): the caller (`SleighLanguage.initParser`) constructs a fresh
//! `InjectPayloadJumpAssist` for each child element of `<jumpassist name="...">` --
//! `<case_pcode>`, `<addr_pcode>`, `<size_pcode>`, or a "default" element -- and this payload's
//! `restoreXml` derives its formal name from the child element's tag name before delegating to
//! the base `<pcode>` parsing (which, like Java's, doesn't check the wrapping element's own name
//! at all: it just consumes whatever start tag is next).
//!
//! Unlike `InjectPayloadCallother`/`InjectPayloadSegment`, Java's `InjectPayloadJumpAssist` does
//! *not* override `encode`, so it reuses the base `InjectPayloadSleigh.encode()` unwrapped
//! `<pcode>` element -- this port does the same.

use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{
    InjectParameter, InjectPayload, InjectPayloadError, EXECUTABLEPCODE_TYPE,
};
use crate::program::model::lang::inject_payload_sleigh::{InjectPayloadSleigh, InjectPayloadSleighImpl};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Concrete port of `InjectPayloadJumpAssist`.
#[derive(Clone)]
pub struct InjectPayloadJumpAssist {
    base: InjectPayloadSleighImpl,
    base_name: String,
}

impl InjectPayloadJumpAssist {
    /// Port of `InjectPayloadJumpAssist(String, String)`.
    pub fn new(b_name: impl Into<String>, source_name: impl Into<String>) -> Self {
        let mut base = InjectPayloadSleighImpl::new_source(source_name);
        base.set_type(EXECUTABLEPCODE_TYPE);
        InjectPayloadJumpAssist { base, base_name: b_name.into() }
    }

    /// Port of `InjectPayloadJumpAssist.restoreXml(XmlPullParser, SleighLanguage)`.
    ///
    /// Java reads `subel.getName().charAt(0)`, which would throw `StringIndexOutOfBounds` on an
    /// empty element name; this instead falls back to the "default" branch on an empty/absent
    /// name rather than panicking, a deliberate (and inert in practice, since XML parsers never
    /// hand back an empty tag name) safety deviation from that edge case.
    ///
    /// # Errors
    /// Returns an error for badly formed XML (see
    /// [`InjectPayloadSleighImpl::restore_xml_pcode_element`]).
    pub fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let subel = parser.peek();
        let suffix = match subel.get_name().chars().next() {
            Some('c') => "_index2case",
            Some('a') => "_index2addr",
            Some('s') => "_calcsize",
            _ => "_defaultaddr",
        };
        self.base.set_name(format!("{}{}", self.base_name, suffix));
        self.base.restore_xml_pcode_element(parser)
    }

    /// Port of `InjectPayloadJumpAssist.isEquivalent(InjectPayload)`.
    ///
    /// See [`InjectPayloadSleighImpl::is_equivalent_base`]'s doc comment for why this takes a
    /// concrete `&InjectPayloadJumpAssist` rather than `&dyn InjectPayload`.
    pub fn is_equivalent_typed(&self, other: &InjectPayloadJumpAssist) -> bool {
        if self.base_name != other.base_name {
            return false;
        }
        self.base.is_equivalent_base(&other.base)
    }
}

impl InjectPayload for InjectPayloadJumpAssist {
    fn get_name(&self) -> String {
        self.base.get_name()
    }
    fn get_type(&self) -> i32 {
        self.base.get_type()
    }
    fn get_source(&self) -> String {
        self.base.get_source()
    }
    fn get_param_shift(&self) -> i32 {
        self.base.get_param_shift()
    }
    fn get_input(&self) -> Vec<InjectParameter> {
        self.base.get_input()
    }
    fn get_output(&self) -> Vec<InjectParameter> {
        self.base.get_output()
    }
    fn is_error_placeholder(&self) -> bool {
        false
    }
    fn inject(
        &self,
        context: &InjectContext,
        emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
    ) -> Result<(), InjectPayloadError> {
        self.base.inject(context, emit)
    }
    fn get_pcode(
        &self,
        program: &dyn crate::program::model::listing::program::Program,
        context: &InjectContext,
    ) -> Result<Vec<crate::program::model::pcode::PcodeOp>, InjectPayloadError> {
        self.base.get_pcode(program, context)
    }
    fn is_fall_thru(&self) -> bool {
        self.base.is_fall_thru()
    }
    fn is_incidental_copy(&self) -> bool {
        self.base.is_incidental_copy()
    }
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        // No override in Java: reuses the base `<pcode>` element, unwrapped.
        self.base.encode_pcode_element(encoder)
    }
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        InjectPayloadJumpAssist::restore_xml(self, parser)
    }
    fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
        self.base.get_name() == other.get_name()
            && self.get_input() == other.get_input()
            && self.get_output() == other.get_output()
            && self.is_incidental_copy() == other.is_incidental_copy()
            && self.get_param_shift() == other.get_param_shift()
            && self.get_type() == other.get_type()
    }
}

impl InjectPayloadSleigh for InjectPayloadJumpAssist {
    fn release_parse_string(&mut self) -> Option<String> {
        self.base.release_parse_string()
    }
    fn set_template(&mut self, template: ConstructTpl) {
        self.base.set_template(template)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
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
        attrs: HashMap<String, String>,
    }
    impl MockElement {
        fn start(name: &str, level: i32, attrs: &[(&str, &str)]) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: true,
                is_end: false,
                attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            }
        }
        fn end(name: &str, level: i32) -> Self {
            Self { name: name.to_string(), level, is_start: false, is_end: true, attrs: HashMap::new() }
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
            self.attrs.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attrs.clone().into_iter())
        }
        fn has_attribute(&self, key: &str) -> bool {
            self.attrs.contains_key(key)
        }
        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attrs.get(key).cloned()
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
        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attrs.insert(key.into(), value.into());
        }
        fn is_start_with(&self, name: &str) -> bool {
            self.is_start && self.name == name
        }
    }

    struct QueueParser {
        elements: Vec<MockElement>,
        pos: usize,
        pulling_content: bool,
    }
    impl QueueParser {
        fn new(elements: Vec<MockElement>) -> Self {
            Self { elements, pos: 0, pulling_content: false }
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
        fn is_pulling_content(&self) -> bool {
            self.pulling_content
        }
        fn set_pulling_content(&mut self, pulling_content: bool) {
            self.pulling_content = pulling_content;
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
        fn dispose(&mut self) {}
    }

    fn pcode_dynamic(tag: &str) -> Vec<MockElement> {
        vec![MockElement::start(tag, 0, &[("dynamic", "true")]), MockElement::end(tag, 0)]
    }

    #[test]
    fn restore_xml_derives_name_from_first_letter_of_child_tag() {
        for (tag, expected_suffix) in [
            ("case_pcode", "_index2case"),
            ("addr_pcode", "_index2addr"),
            ("size_pcode", "_calcsize"),
            ("default_pcode", "_defaultaddr"),
            ("other_pcode", "_defaultaddr"),
        ] {
            let mut parser = QueueParser::new(pcode_dynamic(tag));
            let mut payload = InjectPayloadJumpAssist::new("jt1", "src.pspec");
            payload.restore_xml(&mut parser).unwrap_or_else(|e| panic!("tag {tag}: {e}"));
            assert_eq!(payload.get_name(), format!("jt1{expected_suffix}"), "tag {tag}");
        }
    }

    #[test]
    fn get_type_is_executablepcode() {
        let payload = InjectPayloadJumpAssist::new("jt1", "src.pspec");
        assert_eq!(payload.get_type(), EXECUTABLEPCODE_TYPE);
    }

    #[test]
    fn is_equivalent_typed_compares_base_name() {
        let mut a = InjectPayloadJumpAssist::new("jt1", "src");
        a.restore_xml(&mut QueueParser::new(pcode_dynamic("case_pcode"))).unwrap();
        let mut b = InjectPayloadJumpAssist::new("jt1", "src2");
        b.restore_xml(&mut QueueParser::new(pcode_dynamic("case_pcode"))).unwrap();
        assert!(a.is_equivalent_typed(&b));

        let mut c = InjectPayloadJumpAssist::new("jt2", "src");
        c.restore_xml(&mut QueueParser::new(pcode_dynamic("case_pcode"))).unwrap();
        assert!(!a.is_equivalent_typed(&c));
    }

    #[test]
    fn usable_as_trait_object() {
        let payload: Box<dyn InjectPayload> = Box::new(InjectPayloadJumpAssist::new("jt1", "src"));
        assert!(!payload.is_error_placeholder());
        assert_eq!(payload.get_type(), EXECUTABLEPCODE_TYPE);
    }
}
