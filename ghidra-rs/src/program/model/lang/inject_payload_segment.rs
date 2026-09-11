//! Port of `ghidra.program.model.lang.InjectPayloadSegment`.
//!
//! A p-code payload describing a processor's segment/far-pointer handling (`<segmentop>` in a
//! sleigh language file), including how a constant should be resolved when used to construct a
//! segmented address (the optional `<constresolve>` child).
//!
//! # Gaps
//!
//! `AddressXML.restoreXml(XmlElement, Language)` (used by Java's `restoreXml` to parse the
//! `<constresolve>` address) is not reused here: it requires `&dyn Language`, but this crate's
//! [`SleighLanguage`] is a partial, `.sla`-only port that does not implement the `Language`
//! trait (see `address_xml.rs`'s module docs). [`InjectPayloadSegment::restore_xml`] instead
//! parses the `space`/`offset`/`size` attributes directly against
//! [`SleighLanguage::get_address_factory`], covering the common (non-register, non-join) case;
//! the "register name" address form (`AddressXML.restoreXml`'s `<register name="...">` branch)
//! is not supported, since `SleighLanguage` has no register-name lookup to resolve it against --
//! attempting to restore a `<constresolve>` using that form returns a precise
//! [`XmlParseException`] rather than silently producing a wrong address.

use crate::program::model::address::factory::AddressFactory;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{
    InjectParameter, InjectPayload, InjectPayloadError, EXECUTABLEPCODE_TYPE,
};
use crate::program::model::lang::inject_payload_sleigh::{
    xml_err, InjectPayloadSleigh, InjectPayloadSleighImpl,
};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::ids::{
    ATTRIB_FARPOINTER, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_USEROP, ELEM_CONSTRESOLVE,
    ELEM_SEGMENTOP, ELEM_VARNODE,
};
use crate::program::model::pcode::Encoder;
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int, decode_long};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use std::sync::Arc;

/// Concrete port of `InjectPayloadSegment`.
#[derive(Clone)]
pub struct InjectPayloadSegment {
    base: InjectPayloadSleighImpl,
    space: Option<Arc<AddressSpace>>,
    supports_far_pointer: bool,
    const_resolve_space: Option<Arc<AddressSpace>>,
    const_resolve_offset: i64,
    const_resolve_size: i32,
}

impl InjectPayloadSegment {
    /// Port of `InjectPayloadSegment(String)`.
    pub fn new(source: impl Into<String>) -> Self {
        let mut base = InjectPayloadSleighImpl::new_source(source);
        base.set_type(EXECUTABLEPCODE_TYPE);
        InjectPayloadSegment {
            base,
            space: None,
            supports_far_pointer: false,
            const_resolve_space: None,
            const_resolve_offset: 0,
            const_resolve_size: 0,
        }
    }

    /// Port of `InjectPayloadSegment.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    ///
    /// Java writes `encoder.writeSpace(ATTRIB_SPACE, space)` unconditionally -- if `restoreXml`
    /// was never called (`space` is still `null`), that's a Java `NullPointerException`; this
    /// instead skips writing the attribute when `space` is `None`, a deliberate safety deviation
    /// from that edge case.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_SEGMENTOP)?;
        let name = self.base.get_name();
        let sub_name = match name.find('_') {
            Some(pos) if pos > 0 => &name[..pos],
            _ => name.as_str(),
        };
        if sub_name != "segment" {
            encoder.write_string(ATTRIB_USEROP, sub_name)?;
        }
        if let Some(space) = &self.space {
            encoder.write_space(ATTRIB_SPACE, space.as_ref())?;
        }
        if self.supports_far_pointer {
            encoder.write_bool(ATTRIB_FARPOINTER, self.supports_far_pointer)?;
        }
        self.base.encode_pcode_element(encoder)?;
        if let Some(cr_space) = &self.const_resolve_space {
            encoder.open_element(ELEM_CONSTRESOLVE)?;
            encoder.open_element(ELEM_VARNODE)?;
            encoder.write_space(ATTRIB_SPACE, cr_space.as_ref())?;
            encoder.write_unsigned_integer(ATTRIB_OFFSET, self.const_resolve_offset as u64)?;
            encoder.write_signed_integer(ATTRIB_SIZE, self.const_resolve_size as i64)?;
            encoder.close_element(ELEM_VARNODE)?;
            encoder.close_element(ELEM_CONSTRESOLVE)?;
        }
        encoder.close_element(ELEM_SEGMENTOP)
    }

    /// Port of `InjectPayloadSegment.restoreXml(XmlPullParser, SleighLanguage)`.
    ///
    /// # Errors
    /// Returns an error for badly formed XML, an unknown address space, a missing `<pcode>`
    /// child, or (see the module docs) a `<constresolve>` address given by register name.
    pub fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        language: &SleighLanguage,
    ) -> Result<(), XmlParseException> {
        let el = parser.start(&[]).map_err(xml_err)?;
        let mut name = el.get_attribute("userop").unwrap_or_else(|| "segment".to_string());
        name.push_str("_pcode");
        self.base.set_name(name);

        let space_string = el.get_attribute("space").unwrap_or_default();
        let space = language
            .get_address_factory()
            .get_address_space_by_name(&space_string)
            .ok_or_else(|| XmlParseException::new(format!("Unknown address space: {space_string}")))?;
        self.space = Some(space);

        self.supports_far_pointer =
            decode_boolean(el.get_attribute("farpointer").as_deref().unwrap_or(""));

        if parser.peek().is_start() {
            let peeked = parser.peek();
            if peeked.get_name() == "pcode" {
                self.base.restore_xml_pcode_element(parser)?;
            } else {
                return Err(XmlParseException::new("Missing <pcode> child for <segmentop> tag"));
            }
        }

        if parser.peek().is_start() {
            let subel = parser.start(&["constresolve"]).map_err(xml_err)?;
            let subsubel = parser.start(&[]).map_err(xml_err)?;
            if subsubel.get_name() == "register" {
                return Err(XmlParseException::new(
                    "InjectPayloadSegment::restore_xml: <constresolve> by register name is not \
                     supported by this port (SleighLanguage has no register-name lookup)",
                ));
            }
            let cr_space_name = subsubel.get_attribute("space").unwrap_or_default();
            let cr_space = language
                .get_address_factory()
                .get_address_space_by_name(&cr_space_name)
                .ok_or_else(|| {
                    XmlParseException::new(format!("Unknown address space: {cr_space_name}"))
                })?;
            let cr_offset = decode_long(subsubel.get_attribute("offset").as_deref());
            let cr_size = decode_int(subsubel.get_attribute("size").as_deref());
            // Java also calls `addrSize.getFirstAddress()` here purely to "fail fast" (throws
            // AddressOutOfBoundsException for an invalid offset); this crate's Address
            // construction performs no such validation, so there is nothing to replicate.
            self.const_resolve_space = Some(cr_space);
            self.const_resolve_offset = cr_offset;
            self.const_resolve_size = cr_size;
            parser.end_matching(&subsubel).map_err(xml_err)?;
            parser.end_matching(&subel).map_err(xml_err)?;
        }

        parser.end_matching(&el).map_err(xml_err)?;
        Ok(())
    }

    /// Port of `InjectPayloadSegment.isEquivalent(InjectPayload)`.
    ///
    /// See [`InjectPayloadSleighImpl::is_equivalent_base`]'s doc comment for why this takes a
    /// concrete `&InjectPayloadSegment` rather than `&dyn InjectPayload`. Java's `space.equals(...)`
    /// is unconditional (a potential NPE if `restoreXml` was never called); comparing the
    /// `Option<Arc<AddressSpace>>`s directly instead treats "neither has been restored yet" as
    /// equivalent rather than crashing.
    pub fn is_equivalent_typed(&self, other: &InjectPayloadSegment) -> bool {
        if self.const_resolve_offset != other.const_resolve_offset {
            return false;
        }
        if self.const_resolve_size != other.const_resolve_size {
            return false;
        }
        if self.const_resolve_space != other.const_resolve_space {
            return false;
        }
        if self.space != other.space {
            return false;
        }
        if self.supports_far_pointer != other.supports_far_pointer {
            return false;
        }
        self.base.is_equivalent_base(&other.base)
    }
}

impl InjectPayload for InjectPayloadSegment {
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
        InjectPayloadSegment::encode(self, encoder)
    }
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        InjectPayloadSegment::restore_xml(self, parser, language)
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

impl InjectPayloadSleigh for InjectPayloadSegment {
    fn release_parse_string(&mut self) -> Option<String> {
        self.base.release_parse_string()
    }
    fn set_template(&mut self, template: crate::program::model::lang::sleigh::template::ConstructTpl) {
        self.base.set_template(template)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::PackedDecode;
    use std::collections::HashMap;

    /// Builds a real [`SleighLanguage`] (with a "ram" address space) via its `decode` entry
    /// point -- its only public constructor -- from the same known-good packed-binary byte
    /// sequence used by `program_modifier_listener.rs`'s own `make_language` test helper.
    fn test_language() -> SleighLanguage {
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).expect("test language should decode")
    }

    fn pcode_dynamic() -> Vec<(&'static str, &'static str)> {
        vec![("dynamic", "true")]
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
    fn restore_xml_defaults_userop_name_to_segment() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "ram")]),
            MockElement::start("pcode", 1, &pcode_dynamic()),
            MockElement::end("pcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        payload.restore_xml(&mut parser, &lang).expect("restore_xml should succeed");
        assert_eq!(payload.get_name(), "segment_pcode");
    }

    #[test]
    fn restore_xml_uses_userop_attribute_when_present() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("userop", "myseg"), ("space", "ram")]),
            MockElement::start("pcode", 1, &pcode_dynamic()),
            MockElement::end("pcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        payload.restore_xml(&mut parser, &lang).unwrap();
        assert_eq!(payload.get_name(), "myseg_pcode");
    }

    #[test]
    fn restore_xml_rejects_unknown_address_space() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "nosuchspace")]),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        let err = payload.restore_xml(&mut parser, &lang).unwrap_err();
        assert!(err.to_string().contains("Unknown address space"));
    }

    #[test]
    fn restore_xml_requires_pcode_child_when_a_child_is_present() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "ram")]),
            MockElement::start("notpcode", 1, &[]),
            MockElement::end("notpcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        let err = payload.restore_xml(&mut parser, &lang).unwrap_err();
        assert!(err.to_string().contains("Missing <pcode> child"));
    }

    #[test]
    fn restore_xml_parses_constresolve() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "ram"), ("farpointer", "true")]),
            MockElement::start("pcode", 1, &pcode_dynamic()),
            MockElement::end("pcode", 1),
            MockElement::start("constresolve", 1, &[]),
            MockElement::start("addr", 2, &[("space", "ram"), ("offset", "0x10"), ("size", "4")]),
            MockElement::end("addr", 2),
            MockElement::end("constresolve", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        payload.restore_xml(&mut parser, &lang).expect("restore_xml should succeed");

        // No direct getter for constResolve* (Java doesn't expose one either); exercise it
        // indirectly through encode(), which is the only other place that reads it.
        let mut enc = RecordingEncoder { events: Vec::new() };
        payload.encode(&mut enc).unwrap();
        assert!(enc.events.iter().any(|e| e == "open:constresolve"));
        assert!(enc.events.iter().any(|e| e == "open:varnode"));
        assert!(enc.events.iter().any(|e| e == "attr:offset=16"));
        assert!(enc.events.iter().any(|e| e == "attr:size=4"));
        assert!(enc.events.iter().any(|e| e == "attr:farpointer=true"));
    }

    #[test]
    fn restore_xml_rejects_constresolve_by_register_name() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "ram")]),
            MockElement::start("pcode", 1, &pcode_dynamic()),
            MockElement::end("pcode", 1),
            MockElement::start("constresolve", 1, &[]),
            MockElement::start("register", 2, &[("name", "SP")]),
            MockElement::end("register", 2),
            MockElement::end("constresolve", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        let err = payload.restore_xml(&mut parser, &lang).unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn encode_omits_userop_attribute_when_subname_is_segment() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("space", "ram")]),
            MockElement::start("pcode", 1, &pcode_dynamic()),
            MockElement::end("pcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        payload.restore_xml(&mut parser, &lang).unwrap(); // name becomes "segment_pcode"

        let mut enc = RecordingEncoder { events: Vec::new() };
        payload.encode(&mut enc).unwrap();
        assert_eq!(enc.events[0], "open:segmentop");
        assert!(!enc.events.iter().any(|e| e.starts_with("attr:userop")));
        assert!(enc.events.iter().any(|e| e == "attr:space=ram"));
        assert_eq!(enc.events.last().unwrap(), "close:segmentop");
    }

    #[test]
    fn encode_writes_userop_attribute_when_subname_is_not_segment() {
        let lang = test_language();
        let elements = vec![
            MockElement::start("segmentop", 0, &[("userop", "myseg"), ("space", "ram")]),
            MockElement::start("pcode", 1, &pcode_dynamic()),
            MockElement::end("pcode", 1),
            MockElement::end("segmentop", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadSegment::new("src.pspec");
        payload.restore_xml(&mut parser, &lang).unwrap(); // name becomes "myseg_pcode"

        let mut enc = RecordingEncoder { events: Vec::new() };
        payload.encode(&mut enc).unwrap();
        assert!(enc.events.iter().any(|e| e == "attr:userop=myseg"));
    }

    #[test]
    fn is_equivalent_typed_compares_space_farpointer_and_constresolve() {
        let lang = test_language();
        let base_elements = || {
            vec![
                MockElement::start("segmentop", 0, &[("space", "ram")]),
                MockElement::start("pcode", 1, &pcode_dynamic()),
                MockElement::end("pcode", 1),
                MockElement::end("segmentop", 0),
            ]
        };
        let mut a = InjectPayloadSegment::new("src");
        a.restore_xml(&mut QueueParser::new(base_elements()), &lang).unwrap();
        let mut b = InjectPayloadSegment::new("src2");
        b.restore_xml(&mut QueueParser::new(base_elements()), &lang).unwrap();
        assert!(a.is_equivalent_typed(&b));

        let mut c = InjectPayloadSegment::new("src");
        c.restore_xml(
            &mut QueueParser::new(vec![
                MockElement::start("segmentop", 0, &[("space", "ram"), ("farpointer", "true")]),
                MockElement::start("pcode", 1, &pcode_dynamic()),
                MockElement::end("pcode", 1),
                MockElement::end("segmentop", 0),
            ]),
            &lang,
        )
        .unwrap();
        assert!(!a.is_equivalent_typed(&c));
    }

    #[test]
    fn usable_as_trait_object() {
        let payload: Box<dyn InjectPayload> = Box::new(InjectPayloadSegment::new("src.pspec"));
        assert!(!payload.is_error_placeholder());
        assert_eq!(payload.get_type(), EXECUTABLEPCODE_TYPE);
    }
}
