//! Port of `ghidra.program.model.lang.InjectPayloadCallfixup`.
//!
//! `InjectPayloadCallfixup` was selected as a dependency-cycle cut-point: `CallFixupAnalyzer`
//! (not yet ported) downcasts a `PcodeInjectLibrary`-provided `InjectPayloadSleigh` to
//! `InjectPayloadCallfixup` purely to call `getTargets()`, while `ProgramCompilerSpec` and
//! `SpecExtension` (not yet ported) construct and pattern-match on the concrete class when
//! wiring `<callfixup>` XML into a `PcodeInjectLibrary`. Modeling it as a trait over
//! [`InjectPayloadSleigh`] lets those consumers depend on the trait object instead of the
//! concrete class, breaking the cycle.
//!
//! The extra constructors (partial clone of a failed payload, dummy payload) are Java
//! construction patterns rather than API surface, so -- consistent with
//! [`InjectPayloadSleigh`](super::inject_payload_sleigh) -- they are left out of the trait.
//! Likewise `encode`, `restoreXml`, and `isEquivalent` are overrides of methods already declared
//! on [`InjectPayload`], not new API surface, so they are not redeclared here.

use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{InjectParameter, InjectPayload, InjectPayloadError};
use crate::program::model::lang::inject_payload_sleigh::{
    xml_err, InjectPayloadSleigh, InjectPayloadSleighImpl,
};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::ids::{ATTRIB_NAME, ELEM_CALLFIXUP, ELEM_TARGET};
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A call fixup: a payload of p-code that substitutes for a subroutine call to specific target
/// symbols (see [`InjectPayloadSleigh`]).
///
/// Port of `ghidra.program.model.lang.InjectPayloadCallfixup`.
pub trait InjectPayloadCallfixup: InjectPayloadSleigh {
    /// Returns the names of symbols that trigger this call fixup when called.
    ///
    /// Port of `InjectPayloadCallfixup.getTargets()`.
    fn get_targets(&self) -> Vec<String>;
}

/// Concrete port of `InjectPayloadCallfixup`. Embeds an [`InjectPayloadSleighImpl`] (standing in
/// for `extends InjectPayloadSleigh`) plus the `targetSymbolNames` this subclass adds.
#[derive(Clone)]
pub struct InjectPayloadCallfixupImpl {
    base: InjectPayloadSleighImpl,
    target_symbol_names: Vec<String>,
}

impl InjectPayloadCallfixupImpl {
    /// Constructor for a partial clone of a payload whose p-code failed to parse.
    ///
    /// Port of the protected `InjectPayloadCallfixup(ConstructTpl, InjectPayloadCallfixup)`.
    pub fn new_partial_clone(pcode: ConstructTpl, failed: &InjectPayloadCallfixupImpl) -> Self {
        InjectPayloadCallfixupImpl {
            base: InjectPayloadSleighImpl::new_partial_clone(pcode, &failed.base),
            target_symbol_names: failed.target_symbol_names.clone(),
        }
    }

    /// Constructor for a dummy payload.
    ///
    /// Port of the protected `InjectPayloadCallfixup(ConstructTpl, String)`.
    pub fn new_dummy(pcode: ConstructTpl, nm: impl Into<String>) -> Self {
        InjectPayloadCallfixupImpl {
            base: InjectPayloadSleighImpl::new_dummy(
                pcode,
                crate::program::model::lang::inject_payload::CALLFIXUP_TYPE,
                nm,
            ),
            target_symbol_names: Vec::new(),
        }
    }

    /// Port of the public `InjectPayloadCallfixup(String)`.
    pub fn new(source_name: impl Into<String>) -> Self {
        InjectPayloadCallfixupImpl {
            base: {
                let mut base = InjectPayloadSleighImpl::new_source(source_name);
                base.set_type(crate::program::model::lang::inject_payload::CALLFIXUP_TYPE);
                base
            },
            target_symbol_names: Vec::new(),
        }
    }

    /// Port of `InjectPayloadCallfixup.getTargets()`.
    pub fn get_targets(&self) -> Vec<String> {
        self.target_symbol_names.clone()
    }

    /// Port of `InjectPayloadCallfixup.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_CALLFIXUP)?;
        encoder.write_string(ATTRIB_NAME, &self.base.get_name())?;
        for nm in &self.target_symbol_names {
            encoder.open_element(ELEM_TARGET)?;
            encoder.write_string(ATTRIB_NAME, nm)?;
            encoder.close_element(ELEM_TARGET)?;
        }
        self.base.encode_pcode_element(encoder)?;
        encoder.close_element(ELEM_CALLFIXUP)
    }

    /// Port of `InjectPayloadCallfixup.restoreXml(XmlPullParser, SleighLanguage)`.
    ///
    /// # Errors
    /// Returns an error for badly formed XML, an unrecognized child tag, a `<target>` missing its
    /// `name` attribute, or a missing `<pcode>` subtag.
    pub fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlParseException> {
        let fixup_el = parser.start(&["callfixup"]).map_err(xml_err)?;
        self.base.set_name(fixup_el.get_attribute("name").unwrap_or_default());
        let mut pcode_subtag = false;
        while parser.peek().is_start() {
            let elname = parser.peek().get_name().to_string();
            if elname == "target" {
                let subel = parser.start(&[]).map_err(xml_err)?;
                let target_name = subel.get_attribute("name").ok_or_else(|| {
                    XmlParseException::new("Invalid callfixup target, missing target name")
                })?;
                self.target_symbol_names.push(target_name);
                parser.end_matching(&subel).map_err(xml_err)?;
            } else if elname == "pcode" {
                self.base.restore_xml_pcode_element(parser)?;
                pcode_subtag = true;
            } else {
                return Err(XmlParseException::new(format!("Unknown callfixup tag: {elname}")));
            }
        }
        if !pcode_subtag {
            return Err(XmlParseException::new(format!(
                "<callfixup> missing <pcode> subtag: {}",
                self.base.get_name()
            )));
        }
        parser.end_matching(&fixup_el).map_err(xml_err)?;
        Ok(())
    }

    /// Port of `InjectPayloadCallfixup.isEquivalent(InjectPayload)`.
    ///
    /// See [`InjectPayloadSleighImpl::is_equivalent_base`]'s doc comment for why this takes a
    /// concrete `&InjectPayloadCallfixupImpl` (a same-type comparison) rather than `&dyn
    /// InjectPayload` -- there is no `getClass()`-equivalent downcast available through the
    /// trait object.
    pub fn is_equivalent_typed(&self, other: &InjectPayloadCallfixupImpl) -> bool {
        if self.target_symbol_names != other.target_symbol_names {
            return false;
        }
        self.base.is_equivalent_base(&other.base)
    }
}

impl InjectPayload for InjectPayloadCallfixupImpl {
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
        InjectPayloadCallfixupImpl::encode(self, encoder)
    }
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        InjectPayloadCallfixupImpl::restore_xml(self, parser)
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

impl InjectPayloadSleigh for InjectPayloadCallfixupImpl {
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

impl InjectPayloadCallfixup for InjectPayloadCallfixupImpl {
    fn get_targets(&self) -> Vec<String> {
        InjectPayloadCallfixupImpl::get_targets(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::inject_payload::{
        InjectParameter, InjectPayload, InjectPayloadError, CALLFIXUP_TYPE,
    };
    use crate::program::model::lang::inject_payload_sleigh::compute_fall_thru;
    use crate::program::model::lang::sleigh::template::ConstructTpl;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::listing::program::Program;
    use crate::program::model::pcode::{Encoder, PcodeOp};
    use crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit;
    use crate::program::model::lang::inject_context::InjectContext;
    use crate::util::xml::xml_parse_exception::XmlParseException;
    use crate::util::xml::xml_pull_parser::XmlPullParser;

    struct MockCallfixup {
        name: String,
        targets: Vec<String>,
        parse_string: Option<String>,
        is_fallthru: bool,
    }

    impl InjectPayload for MockCallfixup {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_type(&self) -> i32 {
            CALLFIXUP_TYPE
        }

        fn get_source(&self) -> String {
            "mock".to_string()
        }

        fn get_param_shift(&self) -> i32 {
            0
        }

        fn get_input(&self) -> Vec<InjectParameter> {
            Vec::new()
        }

        fn get_output(&self) -> Vec<InjectParameter> {
            Vec::new()
        }

        fn is_error_placeholder(&self) -> bool {
            false
        }

        fn inject(
            &self,
            _context: &InjectContext,
            _emit: &mut dyn PcodeEmit,
        ) -> Result<(), InjectPayloadError> {
            Ok(())
        }

        fn get_pcode(
            &self,
            _program: &dyn Program,
            _context: &InjectContext,
        ) -> Result<Vec<PcodeOp>, InjectPayloadError> {
            Ok(Vec::new())
        }

        fn is_fall_thru(&self) -> bool {
            self.is_fallthru
        }

        fn is_incidental_copy(&self) -> bool {
            false
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _language: &SleighLanguage,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }

        fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
            self.name == other.get_name()
        }
    }

    impl InjectPayloadSleigh for MockCallfixup {
        fn release_parse_string(&mut self) -> Option<String> {
            self.parse_string.take()
        }

        fn set_template(&mut self, template: ConstructTpl) {
            self.is_fallthru = compute_fall_thru(&template.vec);
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl InjectPayloadCallfixup for MockCallfixup {
        fn get_targets(&self) -> Vec<String> {
            self.targets.clone()
        }
    }

    #[test]
    fn usable_as_trait_object_and_exposes_targets() {
        let mut payload: Box<dyn InjectPayloadCallfixup> = Box::new(MockCallfixup {
            name: "memcpy_fixup".to_string(),
            targets: vec!["memcpy".to_string(), "__memcpy_chk".to_string()],
            parse_string: Some("local tmp:1 = 0;".to_string()),
            is_fallthru: false,
        });

        assert_eq!(payload.get_name(), "memcpy_fixup");
        assert_eq!(
            payload.get_targets(),
            vec!["memcpy".to_string(), "__memcpy_chk".to_string()]
        );

        assert!(payload.release_parse_string().is_some());
        assert!(payload.release_parse_string().is_none());
    }

    // --- InjectPayloadCallfixupImpl ---

    #[derive(Clone)]
    struct MockElement {
        name: String,
        level: i32,
        is_start: bool,
        is_end: bool,
        attrs: std::collections::HashMap<String, String>,
        text: String,
    }
    impl MockElement {
        fn start(name: &str, level: i32, attrs: &[(&str, &str)]) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: true,
                is_end: false,
                attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                text: String::new(),
            }
        }
        fn end(name: &str, level: i32) -> Self {
            Self {
                name: name.to_string(),
                level,
                is_start: false,
                is_end: true,
                attrs: std::collections::HashMap::new(),
                text: String::new(),
            }
        }
        fn end_with_text(name: &str, level: i32, text: &str) -> Self {
            let mut e = Self::end(name, level);
            e.text = text.to_string();
            e
        }
    }
    impl crate::util::xml::xml_element::XmlElement for MockElement {
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
        fn get_attributes(&self) -> std::collections::HashMap<String, String> {
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
            &self.text
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
    impl crate::util::xml::xml_pull_parser::XmlPullParser for QueueParser {
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
    impl crate::program::model::pcode::Encoder for RecordingEncoder {
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
        fn write_space(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, spc: &crate::program::model::address::AddressSpace) -> std::io::Result<()> {
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
    fn restore_xml_parses_targets_and_pcode_subtag() {
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "memcpy_fixup")]),
            MockElement::start("target", 1, &[("name", "memcpy")]),
            MockElement::end("target", 1),
            MockElement::start("target", 1, &[("name", "__memcpy_chk")]),
            MockElement::end("target", 1),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallfixupImpl::new("src.pspec");
        payload.restore_xml(&mut parser).expect("restore_xml should succeed");

        assert_eq!(payload.get_name(), "memcpy_fixup");
        assert_eq!(payload.get_targets(), vec!["memcpy".to_string(), "__memcpy_chk".to_string()]);
    }

    #[test]
    fn restore_xml_requires_pcode_subtag() {
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("target", 1, &[("name", "memcpy")]),
            MockElement::end("target", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallfixupImpl::new("src.pspec");
        let err = payload.restore_xml(&mut parser).unwrap_err();
        assert!(err.to_string().contains("missing <pcode> subtag"));
    }

    #[test]
    fn restore_xml_rejects_target_missing_name() {
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("target", 1, &[]),
            MockElement::end("target", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallfixupImpl::new("src.pspec");
        let err = payload.restore_xml(&mut parser).unwrap_err();
        assert!(err.to_string().contains("missing target name"));
    }

    #[test]
    fn restore_xml_rejects_unknown_child_tag() {
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("bogus", 1, &[]),
            MockElement::end("bogus", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallfixupImpl::new("src.pspec");
        let err = payload.restore_xml(&mut parser).unwrap_err();
        assert!(err.to_string().contains("Unknown callfixup tag"));
    }

    #[test]
    fn encode_writes_name_targets_and_pcode() {
        let elements = vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("target", 1, &[("name", "memcpy")]),
            MockElement::end("target", 1),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut payload = InjectPayloadCallfixupImpl::new("src.pspec");
        payload.restore_xml(&mut parser).unwrap();

        let mut enc = RecordingEncoder { events: Vec::new() };
        payload.encode(&mut enc).unwrap();

        assert_eq!(enc.events[0], "open:callfixup");
        assert!(enc.events.iter().any(|e| e == "attr:name=f"));
        assert!(enc.events.iter().any(|e| e == "open:target"));
        assert!(enc.events.iter().any(|e| e == "attr:name=memcpy"));
        assert!(enc.events.iter().any(|e| e == "open:pcode"));
        assert_eq!(enc.events.last().unwrap(), "close:callfixup");
    }

    #[test]
    fn is_equivalent_typed_compares_targets_and_base_fields() {
        let mut a = InjectPayloadCallfixupImpl::new("src");
        a.restore_xml(&mut QueueParser::new(vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("target", 1, &[("name", "memcpy")]),
            MockElement::end("target", 1),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ]))
        .unwrap();

        let mut b = InjectPayloadCallfixupImpl::new("src2");
        b.restore_xml(&mut QueueParser::new(vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("target", 1, &[("name", "memcpy")]),
            MockElement::end("target", 1),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ]))
        .unwrap();
        assert!(a.is_equivalent_typed(&b));

        let mut c = InjectPayloadCallfixupImpl::new("src");
        c.restore_xml(&mut QueueParser::new(vec![
            MockElement::start("callfixup", 0, &[("name", "f")]),
            MockElement::start("target", 1, &[("name", "differentTarget")]),
            MockElement::end("target", 1),
            MockElement::start("pcode", 1, &[("dynamic", "true")]),
            MockElement::end("pcode", 1),
            MockElement::end("callfixup", 0),
        ]))
        .unwrap();
        assert!(!a.is_equivalent_typed(&c));
    }
}
