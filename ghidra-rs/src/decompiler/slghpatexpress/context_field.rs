//! Models `ghidra.pcodeCPort.slghpatexpress.ContextField`.

use crate::decompiler::seam_stubs::Pattern;
use crate::decompiler::slghpatexpress::TokenPattern;
use crate::decompiler::utils::utils::zzz_zero_extend;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_ENDBIT, ATTRIB_ENDBYTE, ATTRIB_SHIFT, ATTRIB_SIGNBIT, ATTRIB_STARTBIT, ATTRIB_STARTBYTE,
    ELEM_CONTEXTFIELD,
};
use crate::sleigh::grammar::Location;
use std::io;

/// A minimal [`TokenPattern`] implementation for context fields.
/// Carries the requested value and bit bounds but does not implement bit-level matching, since
/// [`Pattern`] is still stubbed pending its own port.
struct ContextFieldTokenPattern {
    location: Location,
    left_ellipsis: bool,
    right_ellipsis: bool,
}

impl ContextFieldTokenPattern {
    fn new(location: Location) -> Self {
        Self {
            location,
            left_ellipsis: false,
            right_ellipsis: false,
        }
    }
}

struct EmptyPattern;
impl Pattern for EmptyPattern {}

impl TokenPattern for ContextFieldTokenPattern {
    fn location(&self) -> &Location {
        &self.location
    }

    fn get_pattern(&self) -> &dyn Pattern {
        &EmptyPattern
    }

    fn always_true(&self) -> bool {
        false
    }

    fn always_false(&self) -> bool {
        false
    }

    fn always_instruction_true(&self) -> bool {
        false
    }

    fn get_left_ellipsis(&self) -> bool {
        self.left_ellipsis
    }

    fn get_right_ellipsis(&self) -> bool {
        self.right_ellipsis
    }

    fn set_left_ellipsis(&mut self, val: bool) {
        self.left_ellipsis = val;
    }

    fn set_right_ellipsis(&mut self, val: bool) {
        self.right_ellipsis = val;
    }

    fn get_minimum_length(&self) -> i32 {
        0
    }

    fn simplify_pattern(&mut self) {}

    fn copy_into(&mut self, tokpat: &dyn TokenPattern) {
        self.left_ellipsis = tokpat.get_left_ellipsis();
        self.right_ellipsis = tokpat.get_right_ellipsis();
    }

    fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(ContextFieldTokenPattern::new(self.location.clone()))
    }

    fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(ContextFieldTokenPattern::new(self.location.clone()))
    }

    fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(ContextFieldTokenPattern::new(self.location.clone()))
    }

    fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(ContextFieldTokenPattern::new(self.location.clone()))
    }
}

/// A context register field in a sleigh pattern expression.
///
/// A pattern value backed by a bit range `[startbit, endbit]` of the disassembly context
/// register. Its byte offsets and shift amount are derived from the bit range at construction
/// time, mirroring the Java constructor's precomputation.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.ContextField`.
#[derive(Clone)]
pub struct ContextField {
    location: Location,
    startbit: i32,
    endbit: i32,
    startbyte: i32,
    endbyte: i32,
    shift: i32,
    signbit: bool,
}

impl ContextField {
    /// Creates a new, empty context field with the given location.
    pub fn new(location: Location) -> Self {
        Self {
            location,
            startbit: 0,
            endbit: 0,
            startbyte: 0,
            endbyte: 0,
            shift: 0,
            signbit: false,
        }
    }

    /// Creates a new context field spanning `[sbit, ebit]`, deriving byte offsets and shift.
    pub fn with_bits(location: Location, s: bool, sbit: i32, ebit: i32) -> Self {
        Self {
            location,
            signbit: s,
            startbit: sbit,
            endbit: ebit,
            startbyte: sbit / 8,
            endbyte: ebit / 8,
            shift: 7 - (ebit % 8),
        }
    }

    /// The first bit, inclusive, of this field's range in the context register.
    pub fn get_start_bit(&self) -> i32 {
        self.startbit
    }

    /// The last bit, inclusive, of this field's range in the context register.
    pub fn get_end_bit(&self) -> i32 {
        self.endbit
    }

    /// Whether this field's value should be treated as signed.
    pub fn get_sign_bit(&self) -> bool {
        self.signbit
    }

    /// Generates the minimal (unconstrained) token pattern for this context field.
    pub fn gen_min_pattern(&self) -> Box<dyn TokenPattern> {
        Box::new(ContextFieldTokenPattern::new(self.location.clone()))
    }

    /// Encodes this context field to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_CONTEXTFIELD)?;
        encoder.write_bool(ATTRIB_SIGNBIT, self.signbit)?;
        encoder.write_signed_integer(ATTRIB_STARTBIT, self.startbit as i64)?;
        encoder.write_signed_integer(ATTRIB_ENDBIT, self.endbit as i64)?;
        encoder.write_signed_integer(ATTRIB_STARTBYTE, self.startbyte as i64)?;
        encoder.write_signed_integer(ATTRIB_ENDBYTE, self.endbyte as i64)?;
        encoder.write_signed_integer(ATTRIB_SHIFT, self.shift as i64)?;
        encoder.close_element(ELEM_CONTEXTFIELD)?;
        Ok(())
    }
}

impl std::fmt::Display for ContextField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cf:{{{},{},{},{},{},{}}}",
            self.startbit, self.endbit, self.startbyte, self.endbyte, self.shift, self.signbit
        )
    }
}

impl crate::decompiler::seam_stubs::PatternExpression for ContextField {}

impl crate::decompiler::slghpatexpress::PatternValue for ContextField {
    fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
        Box::new(ContextFieldTokenPattern::new(self.location.clone()))
    }

    fn min_value(&self) -> i64 {
        0
    }

    fn max_value(&self) -> i64 {
        let res: i64 = -1;
        zzz_zero_extend(res, self.endbit - self.startbit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::PatternValue;

    #[test]
    fn new_creates_with_location() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::new(location.clone());
        assert_eq!(field.location, location);
        assert_eq!(field.startbit, 0);
        assert_eq!(field.endbit, 0);
        assert!(!field.signbit);
    }

    #[test]
    fn with_bits_derives_bytes_and_shift() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location, true, 10, 21);
        assert_eq!(field.get_start_bit(), 10);
        assert_eq!(field.get_end_bit(), 21);
        assert!(field.get_sign_bit());
        assert_eq!(field.startbyte, 1);
        assert_eq!(field.endbyte, 2);
        assert_eq!(field.shift, 7 - (21 % 8));
    }

    #[test]
    fn min_value_is_always_zero() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location, true, 4, 12);
        assert_eq!(field.min_value(), 0);
    }

    #[test]
    fn max_value_is_field_width_mask() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location, false, 0, 3);
        assert_eq!(field.max_value(), 0xf);
    }

    #[test]
    fn max_value_for_single_bit_field() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location, false, 5, 5);
        assert_eq!(field.max_value(), 1); // bits [5,5] = 1-bit field, max = 2^1-1 = 1
    }

    #[test]
    fn display_matches_java_tostring_format() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location, true, 10, 21);
        assert_eq!(field.to_string(), "cf:{10,21,1,2,2,true}");
    }

    #[test]
    fn gen_pattern_returns_token_pattern() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location.clone(), false, 0, 7);
        let pattern = field.gen_pattern(5);
        assert_eq!(pattern.location(), &location);
    }

    #[test]
    fn gen_min_pattern_returns_token_pattern() {
        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location.clone(), false, 0, 7);
        let pattern = field.gen_min_pattern();
        assert_eq!(pattern.location(), &location);
    }

    #[test]
    fn encode_writes_element_and_attributes() {
        #[derive(Default)]
        struct TestEncoder {
            opened: usize,
            closed: usize,
            bools: Vec<bool>,
            ints: Vec<i64>,
        }

        impl Encoder for TestEncoder {
            fn open_element(
                &mut self,
                _elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.opened += 1;
                Ok(())
            }

            fn close_element(
                &mut self,
                _elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.closed += 1;
                Ok(())
            }

            fn write_bool(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                val: bool,
            ) -> io::Result<()> {
                self.bools.push(val);
                Ok(())
            }

            fn write_signed_integer(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                val: i64,
            ) -> io::Result<()> {
                self.ints.push(val);
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

        let location = Location::new("test.sleigh", 1);
        let field = ContextField::with_bits(location, true, 10, 21);
        let mut encoder = TestEncoder::default();

        field.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, 1);
        assert_eq!(encoder.closed, 1);
        assert_eq!(encoder.bools, vec![true]);
        assert_eq!(encoder.ints, vec![10, 21, 1, 2, 2]);
    }
}
