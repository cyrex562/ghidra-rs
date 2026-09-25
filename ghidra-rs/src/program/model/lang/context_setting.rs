//! Port of `ghidra.program.model.lang.ContextSetting`.
//!
//! A value type describing a single processor-context (or tracked) register setting applied over
//! an address range, as configured in a compiler spec's `<context_data>` block.

use std::io;

use crate::program::model::address::Address;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::pcode::address_xml::{self, AddressXml};
use crate::program::model::pcode::ids::{
    ATTRIB_NAME, ATTRIB_VAL, ELEM_CONTEXT_DATA, ELEM_CONTEXT_SET, ELEM_SET, ELEM_TRACKED_SET,
};
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Adapt an [`XmlException`] from the low-level [`XmlPullParser`] navigation helpers
/// (`start`/`end`/`end_matching`) to the [`XmlParseException`] this module's parse functions
/// report, mirroring the identical helper in `inject_payload_sleigh.rs`.
fn xml_err(e: XmlException) -> XmlParseException {
    XmlParseException::with_cause(e.to_string(), e)
}

/// Error produced while parsing a single `<set>` tag into a [`ContextSetting`]: either the
/// register name is unknown / has the wrong processor-context-ness (a `SleighException` in
/// Java, an unchecked `RuntimeException` there), or the register is a genuine `SleighException`.
///
/// Java's private `ContextSetting(XmlElement, CompilerSpec, boolean, Address, Address)`
/// constructor throws unchecked `SleighException`; this crate models it as an ordinary `Result`
/// error.
pub type ContextSettingParseError = crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;

/// Class for context configuration information as part of the compiler configuration
/// (`CompilerSpec`).
///
/// Port of `ghidra.program.model.lang.ContextSetting`.
#[derive(Debug, Clone)]
pub struct ContextSetting {
    /// Register being set in default context.
    register: RegisterRef,
    /// Value being set in default context. Stands in for `BigInteger`, mirroring how
    /// `RegisterValue`/`BasicCompilerSpec::add_context_setting` already represent an arbitrary
    /// register-sized value as `u128` in this crate.
    value: u128,
    /// Beginning address of context.
    start_addr: Address,
    /// Ending address of context.
    end_addr: Address,
}

impl ContextSetting {
    /// Constructs a `ContextSetting` directly.
    ///
    /// Port of `ContextSetting(Register, BigInteger, Address, Address)`.
    pub fn new(register: RegisterRef, value: u128, start_addr: Address, end_addr: Address) -> Self {
        Self { register, value, start_addr, end_addr }
    }

    /// Construct from an XML `<set>` tag. The tag is a child of either `<context_set>` or
    /// `<tracked_set>`, which provides details of the memory range affected.
    ///
    /// Port of the private `ContextSetting(XmlElement, CompilerSpec, boolean, Address, Address)`.
    ///
    /// # Errors
    /// Returns [`ContextSettingParseError`] if the register named in `el`'s `"name"` attribute is
    /// unknown, or if its processor-context-ness doesn't match `is_context_reg`.
    fn from_xml_element<E: XmlElement>(
        el: &E,
        cspec: &dyn CompilerSpec,
        is_context_reg: bool,
        first: Address,
        last: Address,
    ) -> Result<Self, ContextSettingParseError> {
        let name = el.get_attribute("name").unwrap_or_default();
        let value = get_big_integer(el.get_attribute("val").as_deref().unwrap_or(""), 0);
        let language = cspec.get_language();
        let register = language.get_register_by_name(&name).ok_or_else(|| {
            ContextSettingParseError::with_message(format!("Unknown register: {name}"))
        })?;
        let is_processor_context = register.is_processor_context();
        if is_context_reg {
            if !is_processor_context {
                return Err(ContextSettingParseError::with_message(format!(
                    "Register {name} is not a context register"
                )));
            }
        } else if is_processor_context {
            return Err(ContextSettingParseError::with_message(format!(
                "Unexpected context register {name}"
            )));
        }
        Ok(Self { start_addr: first, end_addr: last, value, register })
    }

    /// The register being set in default context.
    pub fn get_register(&self) -> &RegisterRef {
        &self.register
    }

    /// The value being set in default context.
    pub fn get_value(&self) -> u128 {
        self.value
    }

    /// The beginning address of the range this context setting applies to.
    pub fn get_start_address(&self) -> &Address {
        &self.start_addr
    }

    /// The ending address of the range this context setting applies to.
    pub fn get_end_address(&self) -> &Address {
        &self.end_addr
    }

    /// Encodes this single `<set>` element (just the register name and value; the enclosing
    /// range is encoded by the caller, see [`encode_context_data`]).
    ///
    /// Port of `ContextSetting.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SET)?;
        encoder.write_string(ATTRIB_NAME, &self.register.name().to_string())?;
        encoder.write_string(ATTRIB_VAL, &self.value.to_string())?;
        encoder.close_element(ELEM_SET)
    }

    /// Determine if this `ContextSetting` is equivalent to another specified instance.
    ///
    /// Port of `ContextSetting.isEquivalent(ContextSetting)`.
    pub fn is_equivalent(&self, other: &ContextSetting) -> bool {
        self.start_addr == other.start_addr
            && self.end_addr == other.end_addr
            && *self.register == *other.register
            && self.value == other.value
    }

    /// Parse a single `<context_set>` or `<tracked_set>` tag (and its child `<set>` tags) from
    /// `parser`, appending the resulting `ContextSetting`s to `res_list`.
    ///
    /// Port of `ContextSetting.parseContextSet(List, XmlPullParser, CompilerSpec)`.
    ///
    /// # Errors
    /// Returns [`XmlParseException`] if the tag name is not `"context_set"`/`"tracked_set"`, if
    /// the memory range attributes can't be parsed, or (wrapped) if a child `<set>` tag names an
    /// unknown or wrongly-context'd register.
    pub fn parse_context_set<P: XmlPullParser>(
        res_list: &mut Vec<ContextSetting>,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException> {
        let el = parser.start(&[]).map_err(xml_err)?;
        let is_context_reg = match el.get_name() {
            "context_set" => true,
            "tracked_set" => false,
            other => return Err(XmlParseException::new(format!("Unknown context setting tag: {other}"))),
        };
        let range = address_xml::restore_range_xml(&el, cspec)?;
        let first_addr = range.get_first_address();
        let last_addr = range.get_last_address();
        while parser.peek().is_start() {
            let subel = parser.start(&[]).map_err(xml_err)?;
            let ctx_setting =
                ContextSetting::from_xml_element(&subel, cspec, is_context_reg, first_addr.clone(), last_addr.clone())
                    .map_err(|e| XmlParseException::with_cause(e.to_string(), e))?;
            parser.end_matching(&subel).map_err(xml_err)?;
            res_list.push(ctx_setting);
        }
        parser.end_matching(&el).map_err(xml_err)?;
        Ok(())
    }

    /// Parse a `<context_data>` element (a sequence of `<context_set>`/`<tracked_set>` children)
    /// from `parser`, appending the resulting `ContextSetting`s to `res_list`.
    ///
    /// Port of `ContextSetting.parseContextData(List, XmlPullParser, CompilerSpec)`.
    ///
    /// # Errors
    /// Returns [`XmlParseException`] for any of the reasons [`ContextSetting::parse_context_set`]
    /// can fail.
    pub fn parse_context_data<P: XmlPullParser>(
        res_list: &mut Vec<ContextSetting>,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException> {
        parser.start(&[]).map_err(xml_err)?;
        while parser.peek().is_start() {
            ContextSetting::parse_context_set(res_list, parser, cspec)?;
        }
        parser.end().map_err(xml_err)?;
        Ok(())
    }

    /// Encode a full list of `ContextSetting`s to a `<context_data>` element, grouping
    /// consecutive settings that share the same context/tracked-ness and address range under a
    /// single `<context_set>`/`<tracked_set>` child.
    ///
    /// Port of `ContextSetting.encodeContextData(Encoder, List)`.
    ///
    /// # Real Java quirk faithfully reproduced
    /// If `ctx_list` has **exactly one** element, Java's grouping loop (`while
    /// (iter.hasNext())`, entered only *after* consuming the first element via `iter.next()`)
    /// never executes its body: the lone setting is silently dropped, and the emitted
    /// `<context_data>` element ends up with **no** children at all. See the regression test
    /// below (`single_element_list_is_silently_dropped`), which pins this exact behavior rather
    /// than "fixing" it.
    ///
    /// More generally, whichever setting is the last one consumed from the iterator gets
    /// silently dropped whenever consuming it is *also* what triggers a new group (a
    /// context/tracked-ness or address-range change): the inner loop reassigns `start_context`
    /// to it, detects the boundary, and `break`s *before* encoding it, and there is no further
    /// element left to make the outer `while (iter.hasNext())` run again and flush it. See
    /// `trailing_group_boundary_element_is_silently_dropped` (a lost *second* element) versus
    /// `address_range_change_starts_a_new_context_set_when_a_later_element_flushes_it` (a
    /// *third* element that arrives in time to flush the second) below.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode_context_data(encoder: &mut dyn Encoder, ctx_list: &[ContextSetting]) -> io::Result<()> {
        if ctx_list.is_empty() {
            return Ok(());
        }
        encoder.open_element(ELEM_CONTEXT_DATA)?;
        let mut iter = ctx_list.iter().peekable();
        // `start_context` mirrors Java's reassigned-in-place `startContext` local: it always
        // refers to the "current" setting under consideration, whether or not it has been
        // written yet.
        let mut start_context = iter.next().expect("checked non-empty above");
        let mut is_context_reg = start_context.register.is_processor_context();
        let mut first_addr = start_context.start_addr.clone();
        let mut last_addr = start_context.end_addr.clone();
        // NOTE: mirroring Java exactly -- this outer loop's condition is checked *after* the
        // first element was already consumed by `iter.next()` above, so a single-element list
        // never enters this loop at all (see the doc comment above).
        while iter.peek().is_some() {
            let elem = if is_context_reg { ELEM_CONTEXT_SET } else { ELEM_TRACKED_SET };
            encoder.open_element(elem)?;
            address_xml::encode_attributes_range(encoder, &first_addr, &last_addr)?;
            start_context.encode(encoder)?;
            while let Some(next) = iter.next() {
                start_context = next;
                let next_is_context = start_context.register.is_processor_context();
                let mut should_break = false;
                if is_context_reg != next_is_context {
                    is_context_reg = next_is_context;
                    should_break = true;
                }
                if first_addr != start_context.start_addr {
                    first_addr = start_context.start_addr.clone();
                    should_break = true;
                }
                if last_addr != start_context.end_addr {
                    last_addr = start_context.end_addr.clone();
                    should_break = true;
                }
                if should_break {
                    break;
                }
                start_context.encode(encoder)?;
            }
            let elem = if is_context_reg { ELEM_CONTEXT_SET } else { ELEM_TRACKED_SET };
            encoder.close_element(elem)?;
        }
        encoder.close_element(ELEM_CONTEXT_DATA)
    }
}

/// Port of the private `ContextSetting.getBigInteger(String, long)`: parses a decimal or
/// `0x`/`0X`-prefixed hex string, falling back to `default_value` on any parse failure.
fn get_big_integer(val_str: &str, default_value: u64) -> u128 {
    let (digits, radix) =
        if let Some(rest) = val_str.strip_prefix("0x").or_else(|| val_str.strip_prefix("0X")) {
            (rest, 16)
        } else {
            (val_str, 10)
        };
    u128::from_str_radix(digits, radix).unwrap_or(default_value as u128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::register::Register;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Records structural encode calls for assertions, mirroring the `RecordingEncoder` pattern
    /// used throughout this crate's other XML/encode test modules (e.g. `pcode_inject_library.rs`).
    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<crate::program::model::pcode::ids::ElementId>,
        closed: Vec<crate::program::model::pcode::ids::ElementId>,
        strings: Vec<(crate::program::model::pcode::ids::AttributeId, String)>,
    }
    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.opened.push(elem_id);
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.closed.push(elem_id);
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: u64) -> io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            index: i32,
            val: &str,
        ) -> io::Result<()> {
            self.strings.push((attrib_id, format!("[{index}]{val}")));
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _spc: &AddressSpace) -> io::Result<()> {
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
        fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn context_register() -> RegisterRef {
        Register::new("contextreg", "context", ram_space().address(0), 4, false, Register::TYPE_CONTEXT)
    }

    fn data_register(offset: i64) -> RegisterRef {
        Register::new("r0", "general", ram_space().address(offset), 4, false, Register::TYPE_NONE)
    }

    #[test]
    fn get_big_integer_parses_decimal() {
        assert_eq!(get_big_integer("42", 0), 42);
    }

    #[test]
    fn get_big_integer_parses_hex_with_0x_prefix() {
        assert_eq!(get_big_integer("0x2a", 0), 42);
        assert_eq!(get_big_integer("0X2A", 0), 42);
    }

    #[test]
    fn get_big_integer_falls_back_to_default_on_garbage() {
        assert_eq!(get_big_integer("not a number", 7), 7);
        assert_eq!(get_big_integer("", 3), 3);
    }

    #[test]
    fn new_and_accessors_roundtrip() {
        let reg = context_register();
        let setting = ContextSetting::new(reg.clone(), 0xABCD, ram_space().address(0x1000), ram_space().address(0x1fff));
        assert_eq!(setting.get_value(), 0xABCD);
        assert_eq!(setting.get_start_address(), &ram_space().address(0x1000));
        assert_eq!(setting.get_end_address(), &ram_space().address(0x1fff));
        assert!(crate::program::model::lang::Register::same(setting.get_register(), &reg));
    }

    #[test]
    fn is_equivalent_compares_all_fields() {
        let reg = context_register();
        let a = ContextSetting::new(reg.clone(), 1, ram_space().address(0), ram_space().address(0xf));
        let b = ContextSetting::new(reg.clone(), 1, ram_space().address(0), ram_space().address(0xf));
        let c = ContextSetting::new(reg, 2, ram_space().address(0), ram_space().address(0xf));
        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
    }

    #[test]
    fn encode_writes_name_and_value() {
        let mut encoder = RecordingEncoder::default();
        let reg = context_register();
        let setting = ContextSetting::new(reg, 255, ram_space().address(0), ram_space().address(0xf));
        setting.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec![ELEM_SET]);
        assert_eq!(encoder.closed, vec![ELEM_SET]);
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "contextreg".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_VAL, "255".to_string())));
    }

    // --- encode_context_data: grouping + the single-element-list quirk ---

    #[test]
    fn encode_context_data_empty_list_writes_nothing() {
        let mut encoder = RecordingEncoder::default();
        ContextSetting::encode_context_data(&mut encoder, &[]).unwrap();
        assert!(encoder.opened.is_empty());
    }

    #[test]
    fn single_element_list_is_silently_dropped() {
        // Real Java quirk (see the doc comment on `encode_context_data`): a single-element list
        // produces a `<context_data>` element with no children at all -- the lone setting is
        // never actually encoded.
        let mut encoder = RecordingEncoder::default();
        let reg = context_register();
        let list = vec![ContextSetting::new(reg, 1, ram_space().address(0), ram_space().address(0xf))];
        ContextSetting::encode_context_data(&mut encoder, &list).unwrap();

        assert_eq!(encoder.opened, vec![ELEM_CONTEXT_DATA]);
        assert_eq!(encoder.closed, vec![ELEM_CONTEXT_DATA]);
        assert!(!encoder.opened.contains(&ELEM_CONTEXT_SET));
        assert!(!encoder.opened.contains(&ELEM_SET));
    }

    #[test]
    fn two_elements_same_group_are_both_encoded_under_one_context_set() {
        let mut encoder = RecordingEncoder::default();
        let reg = context_register();
        let list = vec![
            ContextSetting::new(reg.clone(), 1, ram_space().address(0), ram_space().address(0xf)),
            ContextSetting::new(reg, 2, ram_space().address(0), ram_space().address(0xf)),
        ];
        ContextSetting::encode_context_data(&mut encoder, &list).unwrap();

        assert_eq!(encoder.opened, vec![ELEM_CONTEXT_DATA, ELEM_CONTEXT_SET, ELEM_SET, ELEM_SET]);
        assert_eq!(encoder.closed, vec![ELEM_SET, ELEM_SET, ELEM_CONTEXT_SET, ELEM_CONTEXT_DATA]);
        let val_count = encoder.strings.iter().filter(|(id, _)| *id == ATTRIB_VAL).count();
        assert_eq!(val_count, 2, "both settings in the group should be encoded");
    }

    #[test]
    fn trailing_group_boundary_element_is_silently_dropped() {
        // Generalizes the single-element quirk above: a *two*-element list where the second
        // element starts a new group (different address range) also drops that second element.
        // Tracing the real Java loop: `start_context` is reassigned to the second element inside
        // the inner `while`, the address-range change breaks out of the inner loop *before*
        // encoding it, and the outer `while (iter.hasNext())` is now false (no more elements),
        // so the pending second element's group is never opened/written at all.
        let mut encoder = RecordingEncoder::default();
        let reg = context_register();
        let list = vec![
            ContextSetting::new(reg.clone(), 1, ram_space().address(0), ram_space().address(0xf)),
            ContextSetting::new(reg, 2, ram_space().address(0x10), ram_space().address(0x1f)),
        ];
        ContextSetting::encode_context_data(&mut encoder, &list).unwrap();

        let context_set_opens = encoder.opened.iter().filter(|id| **id == ELEM_CONTEXT_SET).count();
        assert_eq!(context_set_opens, 1, "only the first group is ever opened");
        let val_count = encoder.strings.iter().filter(|(id, _)| *id == ATTRIB_VAL).count();
        assert_eq!(val_count, 1, "the second setting is silently dropped");
    }

    #[test]
    fn address_range_change_starts_a_new_context_set_when_a_later_element_flushes_it() {
        // With a *third* element sharing the second element's group, that third element's
        // presence is what finally triggers the outer loop to run again and flush the pending
        // second element -- so here nothing is dropped, unlike the two-element case above.
        let mut encoder = RecordingEncoder::default();
        let reg = context_register();
        let list = vec![
            ContextSetting::new(reg.clone(), 1, ram_space().address(0), ram_space().address(0xf)),
            ContextSetting::new(reg.clone(), 2, ram_space().address(0x10), ram_space().address(0x1f)),
            ContextSetting::new(reg, 3, ram_space().address(0x10), ram_space().address(0x1f)),
        ];
        ContextSetting::encode_context_data(&mut encoder, &list).unwrap();

        let context_set_opens = encoder.opened.iter().filter(|id| **id == ELEM_CONTEXT_SET).count();
        assert_eq!(context_set_opens, 2, "the address range change should start a new context_set");
        let val_count = encoder.strings.iter().filter(|(id, _)| *id == ATTRIB_VAL).count();
        assert_eq!(val_count, 3, "all three settings end up encoded once a later element flushes the pending one");
    }

    // --- XML parsing ---

    struct MockXmlElement {
        name: String,
        attrs: HashMap<String, String>,
    }
    impl MockXmlElement {
        fn new(name: &str, attrs: &[(&str, &str)]) -> Self {
            Self { name: name.to_string(), attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
        }
    }
    impl XmlElement for MockXmlElement {
        fn get_level(&self) -> i32 {
            0
        }
        fn is_start(&self) -> bool {
            true
        }
        fn is_end(&self) -> bool {
            false
        }
        fn is_content(&self) -> bool {
            false
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_attributes(&self) -> HashMap<String, String> {
            self.attrs.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attrs.iter().map(|(k, v)| (k.clone(), v.clone())))
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
            self.is_start() && self.name == name
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

    struct MockCompilerSpec {
        language: Arc<MockLanguage>,
    }
    struct MockLanguage {
        registers: HashMap<String, RegisterRef>,
        address_factory: Arc<dyn crate::program::model::address::AddressFactory>,
    }

    impl crate::program::model::lang::language::Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.values().cloned().collect()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.keys().cloned().collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.get(name).cloned()
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
            Err(crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException::new(
                &self.get_language_id(),
                compiler_spec_id,
            ))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct SharedLanguage(Arc<MockLanguage>);
    impl crate::program::model::lang::language::Language for SharedLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            self.0.get_language_id()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            struct ArcFactory(Arc<dyn crate::program::model::address::AddressFactory>);
            impl crate::program::model::address::AddressFactory for ArcFactory {
                fn get_address(&self, addr_string: &str) -> Option<Address> {
                    self.0.get_address(addr_string)
                }
                fn get_all_addresses_case(&self, addr_string: &str, case_sensitive: bool) -> Vec<Address> {
                    self.0.get_all_addresses_case(addr_string, case_sensitive)
                }
                fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
                    self.0.get_default_address_space()
                }
                fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
                    self.0.get_address_spaces()
                }
                fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
                    self.0.get_address_space_by_name(name)
                }
                fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
                    self.0.get_address_space_by_id(id)
                }
                fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
                    self.0.get_all_address_spaces()
                }
                fn get_num_address_spaces(&self) -> usize {
                    self.0.get_num_address_spaces()
                }
                fn is_valid_address(&self, address: &Address) -> bool {
                    self.0.is_valid_address(address)
                }
                fn get_index(&self, address: &Address) -> i64 {
                    self.0.get_index(address)
                }
                fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
                    self.0.get_physical_space(space)
                }
                fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
                    self.0.get_physical_spaces()
                }
                fn address(&self, space_id: i32, offset: i64) -> Option<Address> {
                    self.0.address(space_id, offset)
                }
                fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
                    self.0.get_stack_space()
                }
                fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
                    self.0.get_constant_space()
                }
                fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
                    self.0.get_unique_space()
                }
                fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
                    self.0.get_register_space()
                }
                fn get_constant_address(&self, offset: i64) -> Option<Address> {
                    self.0.get_constant_address(offset)
                }
                fn get_address_set_range(&self, min: &Address, max: &Address) -> crate::program::model::address::AddressSet {
                    self.0.get_address_set_range(min, max)
                }
                fn get_address_set(&self) -> crate::program::model::address::AddressSet {
                    self.0.get_address_set()
                }
                fn old_get_address_from_long(&self, value: i64) -> Option<Address> {
                    self.0.old_get_address_from_long(value)
                }
                fn has_multiple_memory_spaces(&self) -> bool {
                    self.0.has_multiple_memory_spaces()
                }
            }
            Box::new(ArcFactory(self.0.address_factory.clone()))
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
            self.0.get_registers_at(address)
        }
        fn get_register_in_space(&self, addrspc: &Arc<AddressSpace>, offset: i64, size: i32) -> Option<RegisterRef> {
            self.0.get_register_in_space(addrspc, offset, size)
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.0.get_registers()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.0.get_register_names()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.0.get_register_by_name(name)
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
            self.0.get_register_at(addr, size)
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
            self.0.get_compiler_spec_by_id(compiler_spec_id)
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language + Send + Sync> {
            Box::new(SharedLanguage(self.language.clone()))
        }
        fn get_compiler_spec_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_compiler_spec_id(&self) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
            crate::program::model::lang::compiler_spec_id::CompilerSpecID::new(Some("default"))
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, space_name: &str) -> Option<Arc<AddressSpace>> {
            self.language.address_factory.get_address_space_by_name(space_name)
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            self.get_stack_space()
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Arc<crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }
        fn get_decompiler_output_language(&self) -> crate::program::model::lang::decompiler_language::DecompilerLanguage {
            crate::program::model::lang::decompiler_language::DecompilerLanguage::CLanguage
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: crate::program::model::lang::compiler_spec::EvaluationModelType,
        ) -> Arc<crate::program::model::lang::prototype_model::PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            true
        }
        fn get_data_organization(&self) -> Arc<crate::program::model::data::data_organization_impl::DataOrganizationImpl> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn crate::program::seam_stubs::PcodeInjectLibrary> {
            unimplemented!("not exercised by this smoke test")
        }
        fn match_convention(&self, _convention_name: &str) -> Arc<crate::program::model::lang::prototype_model::PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn crate::program::model::listing::parameter::Parameter],
        ) -> Arc<crate::program::model::lang::prototype_model::PrototypeModel> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
            true
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            false
        }
    }

    fn mock_compiler_spec() -> MockCompilerSpec {
        let ram = ram_space();
        let mut registers = HashMap::new();
        registers.insert("contextreg".to_string(), context_register());
        registers.insert("r0".to_string(), data_register(0x100));
        let factory: Arc<dyn crate::program::model::address::AddressFactory> =
            Arc::new(DefaultAddressFactory::new(vec![ram]));
        MockCompilerSpec { language: Arc::new(MockLanguage { registers, address_factory: factory }) }
    }

    #[test]
    fn parse_context_set_reads_context_register_setting() {
        let cspec = mock_compiler_spec();
        let elements = vec![
            MockElement::start("context_set", 0, &[("space", "ram"), ("first", "0x0"), ("last", "0xff")]),
            MockElement::start("set", 1, &[("name", "contextreg"), ("val", "0x5")]),
            MockElement::end("set", 1),
            MockElement::end("context_set", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut res = Vec::new();
        ContextSetting::parse_context_set(&mut res, &mut parser, &cspec).unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].get_value(), 5);
        assert_eq!(res[0].get_start_address(), &ram_space().address(0));
        assert_eq!(res[0].get_end_address(), &ram_space().address(0xff));
    }

    #[test]
    fn parse_context_set_rejects_non_context_register_under_context_set() {
        let cspec = mock_compiler_spec();
        let elements = vec![
            MockElement::start("context_set", 0, &[("space", "ram"), ("first", "0x0"), ("last", "0xff")]),
            MockElement::start("set", 1, &[("name", "r0"), ("val", "0x5")]),
            MockElement::end("set", 1),
            MockElement::end("context_set", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut res = Vec::new();
        let err = ContextSetting::parse_context_set(&mut res, &mut parser, &cspec).unwrap_err();
        assert!(err.message().contains("is not a context register"));
    }

    #[test]
    fn parse_context_set_rejects_context_register_under_tracked_set() {
        let cspec = mock_compiler_spec();
        let elements = vec![
            MockElement::start("tracked_set", 0, &[("space", "ram"), ("first", "0x0"), ("last", "0xff")]),
            MockElement::start("set", 1, &[("name", "contextreg"), ("val", "0x5")]),
            MockElement::end("set", 1),
            MockElement::end("tracked_set", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut res = Vec::new();
        let err = ContextSetting::parse_context_set(&mut res, &mut parser, &cspec).unwrap_err();
        assert!(err.message().contains("Unexpected context register"));
    }

    #[test]
    fn parse_context_set_rejects_unknown_tag_name() {
        let cspec = mock_compiler_spec();
        let elements = vec![MockElement::start("bogus_set", 0, &[]), MockElement::end("bogus_set", 0)];
        let mut parser = QueueParser::new(elements);
        let mut res = Vec::new();
        let err = ContextSetting::parse_context_set(&mut res, &mut parser, &cspec).unwrap_err();
        assert!(err.message().contains("Unknown context setting tag"));
    }

    #[test]
    fn parse_context_set_rejects_unknown_register() {
        let cspec = mock_compiler_spec();
        let elements = vec![
            MockElement::start("context_set", 0, &[("space", "ram"), ("first", "0x0"), ("last", "0xff")]),
            MockElement::start("set", 1, &[("name", "nope"), ("val", "0x5")]),
            MockElement::end("set", 1),
            MockElement::end("context_set", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut res = Vec::new();
        let err = ContextSetting::parse_context_set(&mut res, &mut parser, &cspec).unwrap_err();
        assert!(err.message().contains("Unknown register"));
    }

    #[test]
    fn parse_context_data_reads_multiple_sets() {
        let cspec = mock_compiler_spec();
        let elements = vec![
            MockElement::start("context_data", 0, &[]),
            MockElement::start("context_set", 1, &[("space", "ram"), ("first", "0x0"), ("last", "0xff")]),
            MockElement::start("set", 2, &[("name", "contextreg"), ("val", "1")]),
            MockElement::end("set", 2),
            MockElement::end("context_set", 1),
            MockElement::start("tracked_set", 1, &[("space", "ram"), ("first", "0x100"), ("last", "0x1ff")]),
            MockElement::start("set", 2, &[("name", "r0"), ("val", "2")]),
            MockElement::end("set", 2),
            MockElement::end("tracked_set", 1),
            MockElement::end("context_data", 0),
        ];
        let mut parser = QueueParser::new(elements);
        let mut res = Vec::new();
        ContextSetting::parse_context_data(&mut res, &mut parser, &cspec).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].get_value(), 1);
        assert_eq!(res[1].get_value(), 2);
    }
}
