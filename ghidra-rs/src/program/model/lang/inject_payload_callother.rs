//! Port of `ghidra.program.model.lang.InjectPayloadCallother`.
//!
//! A payload of p-code that substitutes for a userop (`CALLOTHER`) invocation, wrapped in a
//! `<callotherfixup targetop="...">` XML element. Embeds an
//! [`InjectPayloadSleighImpl`] (standing in for `extends InjectPayloadSleigh`) with no extra
//! fields of its own -- the only overrides are `encode`/`restoreXml`'s outer-element wrapping.

use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{
    InjectParameter, InjectPayload, InjectPayloadError, CALLOTHERFIXUP_TYPE,
};
use crate::program::model::lang::inject_payload_sleigh::{
    xml_err, InjectPayloadSleigh, InjectPayloadSleighImpl,
};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::ids::{ATTRIB_TARGETOP, ELEM_CALLOTHERFIXUP};
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Concrete port of `InjectPayloadCallother`.
#[derive(Clone)]
pub struct InjectPayloadCallother {
    base: InjectPayloadSleighImpl,
}

impl InjectPayloadCallother {
    /// Constructor for a partial clone of a payload whose p-code failed to parse.
    ///
    /// Port of the protected `InjectPayloadCallother(ConstructTpl, InjectPayloadCallother)`.
    pub fn new_partial_clone(pcode: ConstructTpl, failed: &InjectPayloadCallother) -> Self {
        InjectPayloadCallother { base: InjectPayloadSleighImpl::new_partial_clone(pcode, &failed.base) }
    }

    /// Constructor for a dummy payload.
    ///
    /// Port of the protected `InjectPayloadCallother(ConstructTpl, String)`.
    pub fn new_dummy(pcode: ConstructTpl, nm: impl Into<String>) -> Self {
        InjectPayloadCallother { base: InjectPayloadSleighImpl::new_dummy(pcode, CALLOTHERFIXUP_TYPE, nm) }
    }

    /// Port of the public `InjectPayloadCallother(String)`.
    pub fn new(source_name: impl Into<String>) -> Self {
        let mut base = InjectPayloadSleighImpl::new_source(source_name);
        base.set_type(CALLOTHERFIXUP_TYPE);
        InjectPayloadCallother { base }
    }

    /// Port of `InjectPayloadCallother.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_CALLOTHERFIXUP)?;
        encoder.write_string(ATTRIB_TARGETOP, &self.base.get_name())?;
        self.base.encode_pcode_element(encoder)?;
        encoder.close_element(ELEM_CALLOTHERFIXUP)
    }

    /// Port of `InjectPayloadCallother.restoreXml(XmlPullParser, SleighLanguage)`.
    ///
    /// # Errors
    /// Returns an error for badly formed XML, or if the `<callotherfixup>` element does not
    /// contain a `<pcode>` child.
    pub fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let fixup_el = parser.start(&["callotherfixup"]).map_err(xml_err)?;
        self.base.set_name(fixup_el.get_attribute("targetop").unwrap_or_default());
        let next = parser.peek();
        if !next.is_start() || next.get_name() != "pcode" {
            return Err(XmlParseException::new("<callotherfixup> does not contain a <pcode> tag"));
        }
        self.base.restore_xml_pcode_element(parser)?;
        parser.end_matching(&fixup_el).map_err(xml_err)?;
        Ok(())
    }
}

impl InjectPayload for InjectPayloadCallother {
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
        InjectPayloadCallother::encode(self, encoder)
    }
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        InjectPayloadCallother::restore_xml(self, parser)
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

impl InjectPayloadSleigh for InjectPayloadCallother {
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
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::inject_payload_sleigh::get_dummy_pcode;
    use std::collections::HashMap;

    fn factory() -> DefaultAddressFactory {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2);
        let constant = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 3);
        DefaultAddressFactory::new(vec![ram, unique, constant])
    }

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

    struct RecordingEncoder {
        events: Vec<String>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: bool) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: i64) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: u64) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: &str) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, index: i32, val: &str) -> std::io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, val));
            Ok(())
        }
        fn write_space(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, spc: &AddressSpace) -> std::io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, index: i32, name: &str) -> std::io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, name));
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn constructors_set_type_and_source() {
        let via_public = InjectPayloadCallother::new("src.pspec");
        assert_eq!(via_public.get_type(), CALLOTHERFIXUP_TYPE);
        assert_eq!(via_public.get_source(), "src.pspec");

        let dummy = InjectPayloadCallother::new_dummy(get_dummy_pcode(&factory()), "dummyOp");
        assert_eq!(dummy.get_type(), CALLOTHERFIXUP_TYPE);
        assert!(dummy.is_fall_thru());
    }

    #[test]
    fn restore_xml_reads_targetop_as_name_and_parses_pcode() {
        let elements = vec![
            MockElement::start("callotherfixup", 0, &[("targetop", "my_userop")]),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callotherfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallother::new("src.pspec");
        payload.restore_xml(&mut parser).expect("restore_xml should succeed");
        assert_eq!(payload.get_name(), "my_userop");
    }

    #[test]
    fn restore_xml_requires_pcode_child() {
        let elements = vec![
            MockElement::start("callotherfixup", 0, &[("targetop", "my_userop")]),
            MockElement::end("callotherfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallother::new("src.pspec");
        let err = payload.restore_xml(&mut parser).unwrap_err();
        assert!(err.to_string().contains("does not contain a <pcode> tag"));
    }

    #[test]
    fn encode_writes_targetop_attribute_from_name() {
        let elements = vec![
            MockElement::start("callotherfixup", 0, &[("targetop", "my_userop")]),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callotherfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallother::new("src.pspec");
        payload.restore_xml(&mut parser).unwrap();

        let mut enc = RecordingEncoder { events: Vec::new() };
        payload.encode(&mut enc).unwrap();
        assert_eq!(enc.events[0], "open:callotherfixup");
        assert!(enc.events.iter().any(|e| e == "attr:targetop=my_userop"));
        assert_eq!(enc.events.last().unwrap(), "close:callotherfixup");
    }

    #[test]
    fn usable_as_trait_object() {
        let payload: Box<dyn InjectPayload> = Box::new(InjectPayloadCallother::new("src.pspec"));
        assert!(!payload.is_error_placeholder());
        assert_eq!(payload.get_type(), CALLOTHERFIXUP_TYPE);
    }
}
