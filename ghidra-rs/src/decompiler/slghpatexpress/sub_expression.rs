//! Models `ghidra.pcodeCPort.slghpatexpress.SubExpression`.

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::BinaryExpression;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ELEM_SUB_EXP;
use crate::sleigh::grammar::Location;
use std::io;

/// A subtraction operator for pattern expressions.
///
/// SubExpression represents the difference of two pattern expressions.
/// When encoded, it wraps the operands' encoding in a SUB_EXP element tag.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.SubExpression`.
pub struct SubExpression {
    binary: BinaryExpression,
}

impl SubExpression {
    /// Creates a new sub expression with the given location.
    ///
    /// The operands are initially `None` and can be set via direct construction with
    /// `with_operands`.
    pub fn new(location: Location) -> Self {
        Self {
            binary: BinaryExpression::new(location),
        }
    }

    /// Creates a new sub expression with left and right sub-expression operands.
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

    /// Returns the left sub-expression of this sub operation.
    pub fn get_left(&self) -> Option<&dyn PatternExpression> {
        self.binary.get_left()
    }

    /// Returns the right sub-expression of this sub operation.
    pub fn get_right(&self) -> Option<&dyn PatternExpression> {
        self.binary.get_right()
    }

    /// Encodes this sub expression to the given encoder.
    ///
    /// Wraps the operands' encoding in ELEM_SUB_EXP tags.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SUB_EXP)?;
        self.binary.encode(encoder)?;
        encoder.close_element(ELEM_SUB_EXP)?;
        Ok(())
    }
}

impl crate::decompiler::seam_stubs::PatternExpression for SubExpression {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_with_location() {
        let location = Location::new("test.sleigh", 1);
        let _expr = SubExpression::new(location);
    }

    #[test]
    fn with_operands_stores_both_operands() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {}

        let left = Box::new(DummyOperand);
        let right = Box::new(DummyOperand);
        let expr = SubExpression::with_operands(location, left, right);
        assert!(expr.get_left().is_some());
        assert!(expr.get_right().is_some());
    }

    #[test]
    fn get_left_returns_stored_left_operand() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {}

        let left = Box::new(DummyOperand);
        let right = Box::new(DummyOperand);
        let expr = SubExpression::with_operands(location, left, right);
        assert!(expr.get_left().is_some());
    }

    #[test]
    fn get_right_returns_stored_right_operand() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {}

        let left = Box::new(DummyOperand);
        let right = Box::new(DummyOperand);
        let expr = SubExpression::with_operands(location, left, right);
        assert!(expr.get_right().is_some());
    }

    #[test]
    fn get_left_and_right_return_none_when_empty() {
        let location = Location::new("test.sleigh", 1);
        let expr = SubExpression::new(location);
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
        let expr = SubExpression::new(location);
        let mut encoder = TestEncoder::default();

        expr.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.len(), 1);
        assert_eq!(encoder.closed.len(), 1);
    }

    #[test]
    fn encode_calls_operand_encode() {
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
            fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
                self.encoded.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let location = Location::new("test.sleigh", 1);
        let encoded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let operand = Box::new(CountingOperand {
            encoded: encoded.clone(),
        });

        let expr = SubExpression::with_operands(location, operand, Box::new(CountingOperand {
            encoded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }));
        let mut encoder = TestEncoder::default();

        expr.encode(&mut encoder).unwrap();

        assert!(encoded.load(std::sync::atomic::Ordering::SeqCst));
    }
}
