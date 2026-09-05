//! Port of `ghidra.program.model.data.BitFieldPackingImpl`, the one concrete
//! [`BitFieldPacking`] implementation.
//!
//! `BitFieldPackingImpl.save`/`restore` (Java's package-private static helpers that persist
//! bitfield-packing settings into a `DBStringMapAdapter`-backed options map) are **not** ported
//! here: `ghidra.program.database.DBStringMapAdapter` is still `TODO` in `PORT_MANIFEST.tsv`, so
//! there is nothing real to serialize into. `encode`/`restore_xml` *are* ported, since their real
//! dependencies ([`Encoder`], [`XmlPullParser`], `SpecXmlUtils`) are already real.
//!
//! This crate's existing `MockBitFieldPacking`/similar test doubles for the [`BitFieldPacking`]
//! trait scattered across `program::model::data` are left untouched -- this type is landed
//! alongside them, not as a replacement.

use std::io;

use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_VALUE, ELEM_BITFIELD_PACKING, ELEM_TYPE_ALIGNMENT_ENABLED, ELEM_USE_MS_CONVENTION,
    ELEM_ZERO_LENGTH_BOUNDARY,
};
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Port of `BitFieldPackingImpl.DEFAULT_USE_MS_CONVENTION`.
pub const DEFAULT_USE_MS_CONVENTION: bool = false;
/// Port of `BitFieldPackingImpl.DEFAULT_TYPE_ALIGNMENT_ENABLED`.
pub const DEFAULT_TYPE_ALIGNMENT_ENABLED: bool = true;
/// Port of `BitFieldPackingImpl.DEFAULT_ZERO_LENGTH_BOUNDARY`.
pub const DEFAULT_ZERO_LENGTH_BOUNDARY: i32 = 0;

/// Controls how bit-fields are packed and aligned within composite data types.
///
/// Port of `ghidra.program.model.data.BitFieldPackingImpl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitFieldPackingImpl {
    use_ms_convention: bool,
    type_alignment_enabled: bool,
    zero_length_boundary: i32,
}

impl Default for BitFieldPackingImpl {
    fn default() -> Self {
        BitFieldPackingImpl {
            use_ms_convention: DEFAULT_USE_MS_CONVENTION,
            type_alignment_enabled: DEFAULT_TYPE_ALIGNMENT_ENABLED,
            zero_length_boundary: DEFAULT_ZERO_LENGTH_BOUNDARY,
        }
    }
}

impl BitFieldPackingImpl {
    /// Creates a new `BitFieldPackingImpl` with the default settings, mirroring the Java
    /// no-argument constructor (which relies on the field initializers).
    pub fn new() -> Self {
        Self::default()
    }

    /// Control if the alignment and packing of bit-fields follows MSVC conventions. When this is
    /// enabled it takes precedence over all other bit-field packing controls.
    pub fn set_use_ms_convention(&mut self, use_ms_convention: bool) {
        self.use_ms_convention = use_ms_convention;
    }

    /// Control whether the alignment of bit-field types is respected when laying out structures.
    /// Corresponds to `PCC_BITFIELD_TYPE_MATTERS` in gcc.
    pub fn set_type_alignment_enabled(&mut self, type_alignment_enabled: bool) {
        self.type_alignment_enabled = type_alignment_enabled;
    }

    /// Indicate a fixed alignment size in bytes which should be used for zero-length bit-fields.
    /// A value of `0` causes the zero-length type size to be used.
    pub fn set_zero_length_boundary(&mut self, zero_length_boundary: i32) {
        self.zero_length_boundary = zero_length_boundary;
    }

    /// Port of `BitFieldPackingImpl.encode(Encoder)`.
    ///
    /// Outputs the details of this bitfield packing to an encoded document formatter, writing
    /// nothing at all if every setting is still at its default value.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        if self.use_ms_convention == DEFAULT_USE_MS_CONVENTION
            && self.type_alignment_enabled == DEFAULT_TYPE_ALIGNMENT_ENABLED
            && self.zero_length_boundary == DEFAULT_ZERO_LENGTH_BOUNDARY
        {
            return Ok(()); // All defaults
        }
        encoder.open_element(ELEM_BITFIELD_PACKING)?;
        if self.use_ms_convention != DEFAULT_USE_MS_CONVENTION {
            encoder.open_element(ELEM_USE_MS_CONVENTION)?;
            encoder.write_bool(ATTRIB_VALUE, true)?;
            encoder.close_element(ELEM_USE_MS_CONVENTION)?;
        }
        if self.type_alignment_enabled != DEFAULT_TYPE_ALIGNMENT_ENABLED {
            encoder.open_element(ELEM_TYPE_ALIGNMENT_ENABLED)?;
            encoder.write_bool(ATTRIB_VALUE, false)?;
            encoder.close_element(ELEM_TYPE_ALIGNMENT_ENABLED)?;
        }
        if self.zero_length_boundary != DEFAULT_ZERO_LENGTH_BOUNDARY {
            encoder.open_element(ELEM_ZERO_LENGTH_BOUNDARY)?;
            encoder.write_signed_integer(ATTRIB_VALUE, self.zero_length_boundary as i64)?;
            encoder.close_element(ELEM_ZERO_LENGTH_BOUNDARY)?;
        }
        encoder.close_element(ELEM_BITFIELD_PACKING)?;
        Ok(())
    }

    /// Port of `BitFieldPackingImpl.restoreXml(XmlPullParser)`.
    ///
    /// Restores settings from a `<bitfield_packing>` tag in an XML stream. The XML is designed to
    /// override existing settings from the default constructor, so callers should generally start
    /// from [`BitFieldPackingImpl::default`] before calling this.
    ///
    /// # Errors
    /// Returns an [`XmlException`] if the parser is out of sync with the expected element
    /// structure.
    pub fn restore_xml<P: XmlPullParser>(&mut self, parser: &mut P) -> Result<(), XmlException> {
        parser.start(&[])?;
        while parser.has_next() && parser.peek().is_start() {
            let subel = parser.start(&[])?;
            let name = subel.get_name().to_string();
            let value = subel.get_attribute(ATTRIB_VALUE.name);

            if name == ELEM_USE_MS_CONVENTION.name {
                self.use_ms_convention = decode_boolean(value.as_deref().unwrap_or(""));
            } else if name == ELEM_TYPE_ALIGNMENT_ENABLED.name {
                self.type_alignment_enabled = decode_boolean(value.as_deref().unwrap_or(""));
            } else if name == ELEM_ZERO_LENGTH_BOUNDARY.name {
                self.zero_length_boundary = decode_int(value.as_deref());
            }

            parser.end()?;
        }
        parser.end()?;
        Ok(())
    }
}

impl BitFieldPacking for BitFieldPackingImpl {
    fn use_ms_convention(&self) -> bool {
        self.use_ms_convention
    }

    fn is_type_alignment_enabled(&self) -> bool {
        // same as PCC_BITFIELD_TYPE_MATTERS
        self.use_ms_convention || self.type_alignment_enabled
    }

    fn get_zero_length_boundary(&self) -> i32 {
        if self.use_ms_convention {
            0
        } else {
            self.zero_length_boundary
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockEncoder {
        writes: Vec<String>,
    }

    impl Encoder for MockEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }

        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.push(format!("close:{}", elem_id.name));
            Ok(())
        }

        fn write_bool(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: bool,
        ) -> io::Result<()> {
            self.writes.push(format!("bool:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.writes.push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: u64,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
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
            Self {
                name: name.to_string(),
                level,
                is_start: false,
                is_end: true,
                attrs: HashMap::new(),
            }
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

    #[test]
    fn defaults_match_java_constants() {
        let bfp = BitFieldPackingImpl::new();
        assert!(!bfp.use_ms_convention());
        assert!(bfp.is_type_alignment_enabled());
        assert_eq!(bfp.get_zero_length_boundary(), 0);
    }

    #[test]
    fn is_type_alignment_enabled_true_when_ms_convention_set() {
        let mut bfp = BitFieldPackingImpl::new();
        bfp.set_type_alignment_enabled(false);
        assert!(!bfp.is_type_alignment_enabled());
        bfp.set_use_ms_convention(true);
        // same as PCC_BITFIELD_TYPE_MATTERS: MS convention forces this true regardless.
        assert!(bfp.is_type_alignment_enabled());
    }

    #[test]
    fn zero_length_boundary_forced_to_zero_under_ms_convention() {
        let mut bfp = BitFieldPackingImpl::new();
        bfp.set_zero_length_boundary(8);
        assert_eq!(bfp.get_zero_length_boundary(), 8);
        bfp.set_use_ms_convention(true);
        assert_eq!(bfp.get_zero_length_boundary(), 0);
    }

    #[test]
    fn setters_round_trip() {
        let mut bfp = BitFieldPackingImpl::new();
        bfp.set_use_ms_convention(true);
        bfp.set_type_alignment_enabled(false);
        bfp.set_zero_length_boundary(4);
        assert!(bfp.use_ms_convention());
        assert_eq!(bfp.zero_length_boundary, 4);
    }

    #[test]
    fn equality_and_hash_are_field_based() {
        let a = BitFieldPackingImpl::new();
        let b = BitFieldPackingImpl::new();
        assert_eq!(a, b);

        let mut c = BitFieldPackingImpl::new();
        c.set_use_ms_convention(true);
        assert_ne!(a, c);
    }

    #[test]
    fn encode_all_defaults_writes_nothing() {
        let bfp = BitFieldPackingImpl::new();
        let mut encoder = MockEncoder::default();
        bfp.encode(&mut encoder).unwrap();
        assert!(encoder.writes.is_empty());
    }

    #[test]
    fn encode_writes_only_non_default_settings() {
        let mut bfp = BitFieldPackingImpl::new();
        bfp.set_zero_length_boundary(8);
        let mut encoder = MockEncoder::default();
        bfp.encode(&mut encoder).unwrap();

        assert_eq!(encoder.writes[0], "open:bitfield_packing");
        assert!(encoder.writes.contains(&"open:zero_length_boundary".to_string()));
        assert!(encoder.writes.contains(&"int:value=8".to_string()));
        assert!(!encoder.writes.iter().any(|w| w.contains("use_MS_convention")));
        assert!(!encoder.writes.iter().any(|w| w.contains("type_alignment_enabled")));
    }

    #[test]
    fn encode_writes_all_three_when_all_non_default() {
        let mut bfp = BitFieldPackingImpl::new();
        bfp.set_use_ms_convention(true);
        bfp.set_type_alignment_enabled(false);
        bfp.set_zero_length_boundary(2);
        let mut encoder = MockEncoder::default();
        bfp.encode(&mut encoder).unwrap();

        assert!(encoder.writes.contains(&"bool:value=true".to_string()));
        assert!(encoder.writes.contains(&"bool:value=false".to_string()));
        assert!(encoder.writes.contains(&"int:value=2".to_string()));
    }

    #[test]
    fn restore_xml_round_trips_all_settings() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("bitfield_packing", 0, &[]),
            MockElement::start("use_MS_convention", 1, &[("value", "true")]),
            MockElement::end("use_MS_convention", 1),
            MockElement::start("type_alignment_enabled", 1, &[("value", "false")]),
            MockElement::end("type_alignment_enabled", 1),
            MockElement::start("zero_length_boundary", 1, &[("value", "8")]),
            MockElement::end("zero_length_boundary", 1),
            MockElement::end("bitfield_packing", 0),
        ]);

        let mut bfp = BitFieldPackingImpl::new();
        bfp.restore_xml(&mut parser).unwrap();

        assert!(bfp.use_ms_convention());
        // MS convention forces this true regardless of the parsed false value.
        assert!(bfp.is_type_alignment_enabled());
        assert_eq!(bfp.zero_length_boundary, 8);
    }

    #[test]
    fn restore_xml_ignores_unknown_child_elements() {
        let mut parser = QueueParser::new(vec![
            MockElement::start("bitfield_packing", 0, &[]),
            MockElement::start("some_future_setting", 1, &[("value", "true")]),
            MockElement::end("some_future_setting", 1),
            MockElement::end("bitfield_packing", 0),
        ]);

        let mut bfp = BitFieldPackingImpl::new();
        bfp.restore_xml(&mut parser).unwrap();

        assert_eq!(bfp, BitFieldPackingImpl::new());
    }

    #[test]
    fn encode_then_restore_xml_round_trips() {
        let mut original = BitFieldPackingImpl::new();
        original.set_zero_length_boundary(16);

        // Manually build the same elements `encode` would have produced.
        let parsed = vec![
            MockElement::start("bitfield_packing", 0, &[]),
            MockElement::start("zero_length_boundary", 1, &[("value", "16")]),
            MockElement::end("zero_length_boundary", 1),
            MockElement::end("bitfield_packing", 0),
        ];
        let mut parser = QueueParser::new(parsed);

        let mut restored = BitFieldPackingImpl::new();
        restored.restore_xml(&mut parser).unwrap();

        assert_eq!(original, restored);
    }
}
