//! Models `ghidra.pcodeCPort.slghpatexpress.StartInstructionValue`.

use crate::decompiler::seam_stubs::Pattern;
use crate::decompiler::slghpatexpress::TokenPattern;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ELEM_START_EXP;
use crate::sleigh::grammar::Location;
use std::io;

/// A minimal [`TokenPattern`] implementation for start instruction values.
/// Returns trivial patterns that just hold a location.
struct StartInstructionTokenPattern {
    location: Location,
    left_ellipsis: bool,
    right_ellipsis: bool,
}

impl StartInstructionTokenPattern {
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

impl TokenPattern for StartInstructionTokenPattern {
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

    fn do_and(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(StartInstructionTokenPattern::new(self.location.clone()))
    }

    fn do_or(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(StartInstructionTokenPattern::new(self.location.clone()))
    }

    fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(StartInstructionTokenPattern::new(self.location.clone()))
    }

    fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(StartInstructionTokenPattern::new(self.location.clone()))
    }
}

/// Represents the start instruction address in a sleigh pattern expression.
///
/// A pattern value that has fixed min/max bounds of 0, and generates trivial token patterns.
/// Its encode method writes the ELEM_START_EXP element.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.StartInstructionValue`.
#[derive(Clone)]
pub struct StartInstructionValue {
    location: Location,
}

impl StartInstructionValue {
    /// Creates a new start instruction value with the given location.
    pub fn new(location: Location) -> Self {
        Self { location }
    }

    /// Encodes this start instruction value to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_START_EXP)?;
        encoder.close_element(ELEM_START_EXP)?;
        Ok(())
    }
}

impl crate::decompiler::seam_stubs::PatternExpression for StartInstructionValue {}

impl crate::decompiler::slghpatexpress::PatternValue for StartInstructionValue {
    fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
        Box::new(StartInstructionTokenPattern::new(self.location.clone()))
    }

    fn min_value(&self) -> i64 {
        0
    }

    fn max_value(&self) -> i64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_with_location() {
        let location = Location::new("test.sleigh", 1);
        let value = StartInstructionValue::new(location.clone());
        assert_eq!(value.location, location);
    }

    #[test]
    fn min_value_returns_zero() {
        let location = Location::new("test.sleigh", 1);
        let value = StartInstructionValue::new(location);
        assert_eq!(value.min_value(), 0);
    }

    #[test]
    fn max_value_returns_zero() {
        let location = Location::new("test.sleigh", 1);
        let value = StartInstructionValue::new(location);
        assert_eq!(value.max_value(), 0);
    }

    #[test]
    fn gen_pattern_returns_token_pattern() {
        let location = Location::new("test.sleigh", 1);
        let value = StartInstructionValue::new(location);
        let pattern = value.gen_pattern(42);
        assert_eq!(pattern.location(), &Location::new("test.sleigh", 1));
    }

    #[test]
    fn gen_pattern_ignores_value() {
        let location = Location::new("test.sleigh", 1);
        let value = StartInstructionValue::new(location.clone());
        let pattern1 = value.gen_pattern(0);
        let pattern2 = value.gen_pattern(100);
        assert_eq!(pattern1.location(), pattern2.location());
    }

    #[test]
    fn encode_writes_element() {
        #[derive(Default)]
        struct TestEncoder {
            opened: usize,
            closed: usize,
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
                _val: bool,
            ) -> io::Result<()> {
                Ok(())
            }

            fn write_signed_integer(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                _val: i64,
            ) -> io::Result<()> {
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
        let value = StartInstructionValue::new(location);
        let mut encoder = TestEncoder::default();

        value.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, 1);
        assert_eq!(encoder.closed, 1);
    }
}
