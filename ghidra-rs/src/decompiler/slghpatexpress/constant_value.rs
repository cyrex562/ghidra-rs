//! Models `ghidra.pcodeCPort.slghpatexpress.ConstantValue`.

use crate::decompiler::slghpattern::Pattern;
use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_VAL, ELEM_INTB};
use crate::sleigh::grammar::Location;
use std::io;

/// A minimal [`TokenPattern`] implementation representing a boolean match result.
/// Used by [`ConstantValue::gen_pattern`] to represent "always true" or "always false" patterns.
struct BooleanTokenPattern {
    location: Location,
    is_true: bool,
    left_ellipsis: bool,
    right_ellipsis: bool,
}

impl BooleanTokenPattern {
    fn new(location: Location, is_true: bool) -> Self {
        Self {
            location,
            is_true,
            left_ellipsis: false,
            right_ellipsis: false,
        }
    }
}

struct EmptyPattern;
impl Pattern for EmptyPattern {
        fn simplify_clone(&self) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn shift_instruction(&mut self, _sa: i32) {}
        fn do_or(&self, _b: &dyn crate::decompiler::slghpattern::Pattern, _sa: i32) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn do_and(&self, _b: &dyn crate::decompiler::slghpattern::Pattern, _sa: i32) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn common_sub_pattern(&self, _b: &dyn crate::decompiler::slghpattern::Pattern, _sa: i32) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
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
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
            Ok(())
        }
    }

impl TokenPattern for BooleanTokenPattern {
    fn location(&self) -> &Location {
        &self.location
    }

    fn get_pattern(&self) -> &dyn Pattern {
        &EmptyPattern
    }

    fn always_true(&self) -> bool {
        self.is_true
    }

    fn always_false(&self) -> bool {
        !self.is_true
    }

    fn always_instruction_true(&self) -> bool {
        self.is_true
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
        let combined = self.is_true && !tokpat.always_false();
        Box::new(BooleanTokenPattern::new(self.location.clone(), combined))
    }

    fn do_or(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        let combined = self.is_true || !tokpat.always_false();
        Box::new(BooleanTokenPattern::new(self.location.clone(), combined))
    }

    fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        Box::new(BooleanTokenPattern::new(self.location.clone(), self.is_true))
    }

    fn common_sub_pattern(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
        let combined = self.is_true && tokpat.always_true();
        Box::new(BooleanTokenPattern::new(self.location.clone(), combined))
    }
}

/// A constant value in a sleigh pattern expression.
///
/// This pattern value represents a fixed integer constant that can appear in pattern
/// expressions. Its min and max values are both equal to the constant itself.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.ConstantValue`.
#[derive(Clone)]
pub struct ConstantValue {
    location: Location,
    val: i64,
}

impl ConstantValue {
    /// Creates a new constant value with the given location.
    pub fn new(location: Location) -> Self {
        Self { location, val: 0 }
    }

    /// Creates a new constant value with the given location and initial value.
    pub fn with_value(location: Location, val: i64) -> Self {
        Self { location, val }
    }

    /// Encodes this constant value to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_INTB)?;
        encoder.write_signed_integer(ATTRIB_VAL, self.val)?;
        encoder.close_element(ELEM_INTB)?;
        Ok(())
    }
}

impl crate::decompiler::slghpatexpress::PatternExpression for ConstantValue {
    fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn crate::decompiler::slghpatexpress::PatternValue>) {
        list.push(self);
    }

    fn get_min_max(
        &self,
        minlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>,
        maxlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>,
    ) {
        minlist.push_back(self.min_value());
        maxlist.push_back(self.max_value());
    }

    fn get_sub_value(
        &self,
        replace: &crate::generic::stl::vector_stl::VectorStl<i64>,
        listpos: &mut crate::decompiler::utils::MutableInt,
    ) -> i64 {
        let res = *replace.get(listpos.get() as usize);
        listpos.increment();
        res
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.encode(encoder)
    }
}

impl crate::decompiler::slghpatexpress::PatternValue for ConstantValue {
    fn gen_pattern(&self, val: i64) -> Box<dyn TokenPattern> {
        Box::new(BooleanTokenPattern::new(
            self.location.clone(),
            self.val == val,
        ))
    }

    fn min_value(&self) -> i64 {
        self.val
    }

    fn max_value(&self) -> i64 {
        self.val
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::PatternValue;

    #[test]
    fn constant_value_new_initializes_to_zero() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::new(location.clone());
        assert_eq!(val.val, 0);
        assert_eq!(val.location, location);
    }

    #[test]
    fn constant_value_with_value_stores_value() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location.clone(), 42);
        assert_eq!(val.val, 42);
        assert_eq!(val.location, location);
    }

    #[test]
    fn min_value_returns_val() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location, 15);
        assert_eq!(val.min_value(), 15);
    }

    #[test]
    fn max_value_returns_val() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location, 15);
        assert_eq!(val.max_value(), 15);
    }

    #[test]
    fn gen_pattern_true_when_values_match() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location, 10);
        let pattern = val.gen_pattern(10);
        assert!(pattern.always_true());
        assert!(!pattern.always_false());
    }

    #[test]
    fn gen_pattern_false_when_values_differ() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location, 10);
        let pattern = val.gen_pattern(20);
        assert!(!pattern.always_true());
        assert!(pattern.always_false());
    }

    #[test]
    fn gen_pattern_handles_zero() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location, 0);
        let pattern = val.gen_pattern(0);
        assert!(pattern.always_true());
    }

    #[test]
    fn gen_pattern_handles_negative_values() {
        let location = Location::new("test.sleigh", 1);
        let val = ConstantValue::with_value(location, -100);
        let pattern_match = val.gen_pattern(-100);
        let pattern_no_match = val.gen_pattern(100);
        assert!(pattern_match.always_true());
        assert!(pattern_no_match.always_false());
    }

    #[test]
    fn encode_writes_element_and_value() {
        use crate::program::model::pcode::encoder::Encoder;

        #[derive(Default)]
        struct TestEncoder {
            opened: usize,
            closed: usize,
            last_int_val: Option<i64>,
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
                val: i64,
            ) -> io::Result<()> {
                self.last_int_val = Some(val);
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
        let val = ConstantValue::with_value(location, 99);
        let mut encoder = TestEncoder::default();

        val.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, 1);
        assert_eq!(encoder.closed, 1);
        assert_eq!(encoder.last_int_val, Some(99));
    }
}
