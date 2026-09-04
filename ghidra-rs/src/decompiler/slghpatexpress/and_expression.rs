//! Models `ghidra.pcodeCPort.slghpatexpress.AndExpression`.

use crate::decompiler::slghpatexpress::BinaryExpression;
use crate::decompiler::slghpatexpress::{PatternExpression, PatternValue};
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ELEM_AND_EXP;
use crate::sleigh::grammar::Location;
use std::io;

/// A bitwise AND operator for pattern expressions.
///
/// AndExpression represents the bitwise AND of two pattern expressions.
/// When encoded, it wraps the operands' encoding in an AND_EXP element tag.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.AndExpression`.
pub struct AndExpression {
    binary: BinaryExpression,
}

impl AndExpression {
    /// Creates a new and expression with the given location.
    ///
    /// The operands are initially `None` and can be set via direct construction with
    /// `with_operands`.
    pub fn new(location: Location) -> Self {
        Self {
            binary: BinaryExpression::new(location),
        }
    }

    /// Creates a new and expression with left and right sub-expression operands.
    ///
    /// In Java, this calls `lay_claim()` on each operand; in Rust, we simply take ownership.
    pub fn with_operands(
        location: Location,
        left: Box<dyn PatternExpression>,
        right: Box<dyn PatternExpression>,
    ) -> Self {
        Self {
            binary: BinaryExpression::with_operands(location, left, right),
        }
    }

    /// Returns the left sub-expression of this and operation.
    pub fn get_left(&self) -> Option<&dyn PatternExpression> {
        self.binary.get_left()
    }

    /// Returns the right sub-expression of this and operation.
    pub fn get_right(&self) -> Option<&dyn PatternExpression> {
        self.binary.get_right()
    }

    /// Encodes this and expression to the given encoder.
    ///
    /// Wraps the operands' encoding in ELEM_AND_EXP tags.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_AND_EXP)?;
        self.binary.encode(encoder)?;
        encoder.close_element(ELEM_AND_EXP)?;
        Ok(())
    }
}

impl PatternExpression for AndExpression {
    fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn PatternValue>) {
        self.binary.list_values(list);
    }

    fn get_min_max(&self, minlist: &mut VectorStl<i64>, maxlist: &mut VectorStl<i64>) {
        self.binary.get_min_max(minlist, maxlist);
    }

    /// Models `AndExpression.getSubValue`: evaluates the left operand first (Java relies on this
    /// evaluation order to advance `listpos` correctly), then the right, then combines them
    /// with `&`.
    fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut MutableInt) -> i64 {
        let left = self.binary.get_left().expect("AndExpression requires a left operand");
        let leftval = left.get_sub_value(replace, listpos); // Must be left first
        let right = self.binary.get_right().expect("AndExpression requires a right operand");
        let rightval = right.get_sub_value(replace, listpos);
        leftval & rightval
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.encode(encoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_with_location() {
        let location = Location::new("test.sleigh", 1);
        let _expr = AndExpression::new(location);
    }

    #[test]
    fn with_operands_stores_both_operands() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {
            fn list_values<'a>(&'a self, _list: &mut Vec<&'a dyn crate::decompiler::slghpatexpress::PatternValue>) {
                unimplemented!("not exercised by this test")
            }
            fn get_min_max(&self, _minlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>, _maxlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>) {
                unimplemented!("not exercised by this test")
            }
            fn get_sub_value(&self, _replace: &crate::generic::stl::vector_stl::VectorStl<i64>, _listpos: &mut crate::decompiler::utils::MutableInt) -> i64 {
                unimplemented!("not exercised by this test")
            }
            fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
                Ok(())
            }
        }

        let left = Box::new(DummyOperand);
        let right = Box::new(DummyOperand);
        let expr = AndExpression::with_operands(location, left, right);
        assert!(expr.get_left().is_some());
        assert!(expr.get_right().is_some());
    }

    #[test]
    fn get_left_returns_stored_left_operand() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {
            fn list_values<'a>(&'a self, _list: &mut Vec<&'a dyn crate::decompiler::slghpatexpress::PatternValue>) {
                unimplemented!("not exercised by this test")
            }
            fn get_min_max(&self, _minlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>, _maxlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>) {
                unimplemented!("not exercised by this test")
            }
            fn get_sub_value(&self, _replace: &crate::generic::stl::vector_stl::VectorStl<i64>, _listpos: &mut crate::decompiler::utils::MutableInt) -> i64 {
                unimplemented!("not exercised by this test")
            }
            fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
                Ok(())
            }
        }

        let left = Box::new(DummyOperand);
        let right = Box::new(DummyOperand);
        let expr = AndExpression::with_operands(location, left, right);
        assert!(expr.get_left().is_some());
    }

    #[test]
    fn get_right_returns_stored_right_operand() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {
            fn list_values<'a>(&'a self, _list: &mut Vec<&'a dyn crate::decompiler::slghpatexpress::PatternValue>) {
                unimplemented!("not exercised by this test")
            }
            fn get_min_max(&self, _minlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>, _maxlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>) {
                unimplemented!("not exercised by this test")
            }
            fn get_sub_value(&self, _replace: &crate::generic::stl::vector_stl::VectorStl<i64>, _listpos: &mut crate::decompiler::utils::MutableInt) -> i64 {
                unimplemented!("not exercised by this test")
            }
            fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
                Ok(())
            }
        }

        let left = Box::new(DummyOperand);
        let right = Box::new(DummyOperand);
        let expr = AndExpression::with_operands(location, left, right);
        assert!(expr.get_right().is_some());
    }

    #[test]
    fn get_left_and_right_return_none_when_empty() {
        let location = Location::new("test.sleigh", 1);
        let expr = AndExpression::new(location);
        assert!(expr.get_left().is_none());
        assert!(expr.get_right().is_none());
    }

    #[test]
    fn encode_wraps_with_element_tags() {
        use crate::program::model::pcode::encoder::Encoder;

        #[derive(Default)]
        struct TestEncoder {
            opened: Vec<String>,
            closed: Vec<String>,
        }

        impl Encoder for TestEncoder {
            fn open_element(
                &mut self,
                elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.opened.push(format!("{:?}", elem_id));
                Ok(())
            }

            fn close_element(
                &mut self,
                elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.closed.push(format!("{:?}", elem_id));
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
        let expr = AndExpression::new(location);
        let mut encoder = TestEncoder::default();

        expr.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.len(), 1);
        assert_eq!(encoder.closed.len(), 1);
    }

    #[test]
    fn encode_calls_operands_encode() {
        use crate::program::model::pcode::encoder::Encoder;

        #[derive(Default)]
        struct TestEncoder {
            calls: Vec<String>,
        }

        impl Encoder for TestEncoder {
            fn open_element(
                &mut self,
                _elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.calls.push("open".to_string());
                Ok(())
            }

            fn close_element(
                &mut self,
                _elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.calls.push("close".to_string());
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

        struct CountingOperand {
            encoded: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        impl PatternExpression for CountingOperand {
            fn list_values<'a>(&'a self, _list: &mut Vec<&'a dyn crate::decompiler::slghpatexpress::PatternValue>) {
                unimplemented!("not exercised by this test")
            }
            fn get_min_max(&self, _minlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>, _maxlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>) {
                unimplemented!("not exercised by this test")
            }
            fn get_sub_value(&self, _replace: &crate::generic::stl::vector_stl::VectorStl<i64>, _listpos: &mut crate::decompiler::utils::MutableInt) -> i64 {
                unimplemented!("not exercised by this test")
            }
            fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
                self.encoded
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let location = Location::new("test.sleigh", 1);
        let left_encoded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let left = Box::new(CountingOperand {
            encoded: left_encoded.clone(),
        });
        let right_encoded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let right = Box::new(CountingOperand {
            encoded: right_encoded.clone(),
        });

        let expr = AndExpression::with_operands(location, left, right);
        let mut encoder = TestEncoder::default();

        expr.encode(&mut encoder).unwrap();

        assert!(left_encoded.load(std::sync::atomic::Ordering::SeqCst));
        assert!(right_encoded.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Regression test for a real bug found while porting `PatternExpression`: nested pattern
    /// expressions (`(a & b) & c`) are stored as `Box<dyn PatternExpression>` operands, so
    /// `AndExpression::encode`'s inner `self.binary.encode()` call reaches the inner operand only
    /// through the trait's `encode` method, not `AndExpression`'s own inherent one. Before
    /// `PatternExpression::encode` had a real (required) implementation, every composite type's
    /// blank `impl PatternExpression for X {}` silently fell back to the seam's `Ok(())` no-op
    /// default, so a nested `AndExpression` operand would open no tag at all instead of its own
    /// `ELEM_AND_EXP` wrapper -- this would have passed unnoticed since every prior test only
    /// exercised a *single*, non-nested `AndExpression`.
    #[test]
    fn encode_reaches_nested_composite_operand_through_trait_object() {
        use crate::program::model::pcode::encoder::Encoder;

        #[derive(Default)]
        struct RecordingEncoder {
            opened: Vec<crate::program::model::pcode::ids::ElementId>,
            closed: Vec<crate::program::model::pcode::ids::ElementId>,
        }

        impl Encoder for RecordingEncoder {
            fn open_element(
                &mut self,
                elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.opened.push(elem_id);
                Ok(())
            }

            fn close_element(
                &mut self,
                elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> io::Result<()> {
                self.closed.push(elem_id);
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

        use crate::decompiler::slghpatexpress::ConstantValue;

        let loc = Location::new("test.sleigh", 1);
        let inner = AndExpression::with_operands(
            loc.clone(),
            Box::new(ConstantValue::with_value(loc.clone(), 1)),
            Box::new(ConstantValue::with_value(loc.clone(), 2)),
        );
        let outer = AndExpression::with_operands(
            loc.clone(),
            Box::new(inner),
            Box::new(ConstantValue::with_value(loc, 3)),
        );

        let mut encoder = RecordingEncoder::default();
        outer.encode(&mut encoder).unwrap();

        // Two ELEM_AND_EXP wrappers (outer + inner) plus three ELEM_INTB leaves.
        let and_opens = encoder
            .opened
            .iter()
            .filter(|e| e.name == "and_exp")
            .count();
        let intb_opens = encoder
            .opened
            .iter()
            .filter(|e| e.name == "intb")
            .count();
        assert_eq!(and_opens, 2, "expected both the outer and inner AndExpression to open their own tag");
        assert_eq!(intb_opens, 3, "expected all three ConstantValue leaves to encode");
        assert_eq!(encoder.opened.len(), encoder.closed.len());
    }

    /// Regression test for the same class of bug as
    /// [`encode_reaches_nested_composite_operand_through_trait_object`], but for
    /// `get_sub_value`: verifies `AndExpression`'s combination logic (`leftval & rightval`,
    /// left evaluated before right) against real `ConstantValue` leaves reached polymorphically
    /// through `&dyn PatternExpression`, not just a synthetic test double. A `PatternValue`
    /// leaf's `getSubValue` reads (and advances past) the next entry of `replace` rather than
    /// returning its own fixed value directly (Java's `PatternValue.getSubValue`), so `replace`
    /// is pre-populated with one entry per leaf, in evaluation order.
    #[test]
    fn get_sub_value_combines_real_leaf_operands_with_bitwise_and() {
        use crate::decompiler::slghpatexpress::ConstantValue;
        use crate::generic::stl::vector_stl::VectorStl;

        let loc = Location::new("test.sleigh", 1);
        let expr = AndExpression::with_operands(
            loc.clone(),
            Box::new(ConstantValue::with_value(loc.clone(), 0)),
            Box::new(ConstantValue::with_value(loc, 0)),
        );

        let dyn_expr: &dyn PatternExpression = &expr;
        let mut replace = VectorStl::new();
        replace.push_back(0b1100);
        replace.push_back(0b1010);
        let mut listpos = crate::decompiler::utils::MutableInt::new(0);
        let result = dyn_expr.get_sub_value(&replace, &mut listpos);

        assert_eq!(result, 0b1000);
        assert_eq!(listpos.get(), 2, "left and right operands should each consume one entry");
    }
}
