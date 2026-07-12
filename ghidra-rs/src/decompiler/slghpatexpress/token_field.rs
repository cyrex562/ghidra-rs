//! Models `ghidra.pcodeCPort.slghpatexpress.TokenField`.

use crate::decompiler::context::token::Token;
use crate::decompiler::seam_stubs::Pattern;
use crate::decompiler::slghpatexpress::TokenPattern;
use crate::decompiler::utils::utils::zzz_zero_extend;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_BIGENDIAN, ATTRIB_ENDBIT, ATTRIB_ENDBYTE, ATTRIB_SHIFT, ATTRIB_SIGNBIT,
    ATTRIB_STARTBIT, ATTRIB_STARTBYTE, ELEM_TOKENFIELD,
};
use crate::sleigh::grammar::Location;
use std::io;

/// A minimal [`TokenPattern`] implementation for token fields.
/// Carries only ellipsis state, since [`Pattern`] is still stubbed pending its own port.
struct TokenFieldTokenPattern {
    location: Location,
    left_ellipsis: bool,
    right_ellipsis: bool,
}

impl TokenFieldTokenPattern {
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

impl TokenPattern for TokenFieldTokenPattern {
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
        Box::new(TokenFieldTokenPattern::new(self.location.clone()))
    }

    fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(TokenFieldTokenPattern::new(self.location.clone()))
    }

    fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(TokenFieldTokenPattern::new(self.location.clone()))
    }

    fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(TokenFieldTokenPattern::new(self.location.clone()))
    }
}

/// A token field in a sleigh pattern expression.
///
/// A pattern value backed by a bit range `[bitstart, bitend]` of an instruction token. Its byte
/// offsets and shift amount are derived from the bit range and the token's endianness at
/// construction time, mirroring the Java constructor's precomputation.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.TokenField`.
#[derive(Clone)]
pub struct TokenField {
    location: Location,
    tok: Option<Token>,
    bigendian: bool,
    signbit: bool,
    bitstart: i32,
    bitend: i32,
    bytestart: i32,
    byteend: i32,
    shift: i32,
}

impl TokenField {
    /// Creates a new, empty token field with the given location.
    ///
    /// The underlying token is initially unset; a fully-populated field is created with
    /// [`TokenField::with_bits`].
    pub fn new(location: Location) -> Self {
        Self {
            location,
            tok: None,
            bigendian: false,
            signbit: false,
            bitstart: 0,
            bitend: 0,
            bytestart: 0,
            byteend: 0,
            shift: 0,
        }
    }

    /// Creates a new token field spanning `[bstart, bend]` of `tk`, deriving byte offsets and
    /// shift from the token's size, endianness, and the bit range.
    pub fn with_bits(location: Location, tk: Token, s: bool, bstart: i32, bend: i32) -> Self {
        let bigendian = tk.is_big_endian();
        let (bytestart, byteend) = if tk.is_big_endian() {
            (
                (tk.size() * 8 - bend - 1) / 8,
                (tk.size() * 8 - bstart - 1) / 8,
            )
        } else {
            (bstart / 8, bend / 8)
        };
        Self {
            location,
            tok: Some(tk),
            bigendian,
            signbit: s,
            bitstart: bstart,
            bitend: bend,
            bytestart,
            byteend,
            shift: bstart % 8,
        }
    }

    /// The underlying token this field reads from, if set.
    pub fn get_token(&self) -> Option<&Token> {
        self.tok.as_ref()
    }

    /// Whether this field's value should be treated as signed.
    pub fn get_sign_bit(&self) -> bool {
        self.signbit
    }

    /// Generates the minimal (unconstrained) token pattern for this token field.
    pub fn gen_min_pattern(&self) -> Box<dyn TokenPattern> {
        Box::new(TokenFieldTokenPattern::new(self.location.clone()))
    }

    /// Encodes this token field to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_TOKENFIELD)?;
        encoder.write_bool(ATTRIB_BIGENDIAN, self.bigendian)?;
        encoder.write_bool(ATTRIB_SIGNBIT, self.signbit)?;
        encoder.write_signed_integer(ATTRIB_STARTBIT, self.bitstart as i64)?;
        encoder.write_signed_integer(ATTRIB_ENDBIT, self.bitend as i64)?;
        encoder.write_signed_integer(ATTRIB_STARTBYTE, self.bytestart as i64)?;
        encoder.write_signed_integer(ATTRIB_ENDBYTE, self.byteend as i64)?;
        encoder.write_signed_integer(ATTRIB_SHIFT, self.shift as i64)?;
        encoder.close_element(ELEM_TOKENFIELD)?;
        Ok(())
    }
}

impl crate::decompiler::seam_stubs::PatternExpression for TokenField {}

impl crate::decompiler::slghpatexpress::PatternValue for TokenField {
    fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
        Box::new(TokenFieldTokenPattern::new(self.location.clone()))
    }

    fn min_value(&self) -> i64 {
        0
    }

    fn max_value(&self) -> i64 {
        let res: i64 = -1;
        zzz_zero_extend(res, self.bitend - self.bitstart)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_with_location_and_no_token() {
        let location = Location::new("test.sleigh", 1);
        let field = TokenField::new(location.clone());
        assert_eq!(field.location, location);
        assert!(field.get_token().is_none());
        assert_eq!(field.bitstart, 0);
        assert_eq!(field.bitend, 0);
        assert!(!field.signbit);
    }

    #[test]
    fn with_bits_derives_bytes_and_shift_little_endian() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, false, 0);
        let field = TokenField::with_bits(location, tok, true, 10, 21);
        assert_eq!(field.bitstart, 10);
        assert_eq!(field.bitend, 21);
        assert!(field.get_sign_bit());
        assert_eq!(field.bytestart, 1);
        assert_eq!(field.byteend, 2);
        assert_eq!(field.shift, 10 % 8);
        assert!(!field.bigendian);
    }

    #[test]
    fn with_bits_derives_bytes_big_endian() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, true, 0);
        let field = TokenField::with_bits(location, tok, false, 10, 21);
        assert!(field.bigendian);
        assert_eq!(field.byteend, (4 * 8 - 10 - 1) / 8);
        assert_eq!(field.bytestart, (4 * 8 - 21 - 1) / 8);
    }

    #[test]
    fn min_value_is_always_zero() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, false, 0);
        let field = TokenField::with_bits(location, tok, true, 4, 12);
        assert_eq!(field.min_value(), 0);
    }

    #[test]
    fn max_value_is_field_width_mask() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, false, 0);
        let field = TokenField::with_bits(location, tok, false, 0, 3);
        assert_eq!(field.max_value(), 0xf);
    }

    #[test]
    fn max_value_for_single_bit_field() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, false, 0);
        let field = TokenField::with_bits(location, tok, false, 5, 5);
        assert_eq!(field.max_value(), 0);
    }

    #[test]
    fn gen_pattern_returns_token_pattern() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, false, 0);
        let field = TokenField::with_bits(location.clone(), tok, false, 0, 7);
        let pattern = field.gen_pattern(5);
        assert_eq!(pattern.location(), &location);
    }

    #[test]
    fn gen_min_pattern_returns_token_pattern() {
        let location = Location::new("test.sleigh", 1);
        let tok = Token::new("tok", 4, false, 0);
        let field = TokenField::with_bits(location.clone(), tok, false, 0, 7);
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
        let tok = Token::new("tok", 4, true, 0);
        let field = TokenField::with_bits(location, tok, true, 10, 21);
        let mut encoder = TestEncoder::default();

        field.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, 1);
        assert_eq!(encoder.closed, 1);
        assert_eq!(encoder.bools, vec![true, true]);
        assert_eq!(encoder.ints, vec![10, 21, 1, 2, 2]);
    }
}
