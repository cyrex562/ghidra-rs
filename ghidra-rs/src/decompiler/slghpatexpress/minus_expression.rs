//! Models `ghidra.pcodeCPort.slghpatexpress.MinusExpression`.

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::UnaryExpression;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::ELEM_MINUS_EXP;
use crate::sleigh::grammar::Location;
use std::io;

/// A unary negation operator for pattern expressions.
///
/// MinusExpression represents the arithmetic negation (unary minus) of a pattern expression.
/// When evaluated, it negates the value of its operand. When encoded, it wraps the operand's
/// encoding in a MINUS_EXP element tag.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.MinusExpression`.
pub struct MinusExpression {
    unary: UnaryExpression,
}

impl MinusExpression {
    /// Creates a new minus expression with the given location.
    ///
    /// The operand is initially `None` and can be set via direct construction with
    /// `with_operand`.
    pub fn new(location: Location) -> Self {
        Self {
            unary: UnaryExpression::new(location),
        }
    }

    /// Creates a new minus expression with a sub-expression operand.
    ///
    /// In Java, this calls `lay_claim()` on the operand; in Rust, we simply take ownership.
    pub fn with_operand(location: Location, operand: Box<dyn PatternExpression>) -> Self {
        Self {
            unary: UnaryExpression::with_operand(location, operand),
        }
    }

    /// Returns the sub-expression of this minus operation.
    pub fn get_unary(&self) -> Option<&dyn PatternExpression> {
        self.unary.get_unary()
    }

    /// Encodes this minus expression to the given encoder.
    ///
    /// Wraps the operand's encoding in ELEM_MINUS_EXP tags.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_MINUS_EXP)?;
        if let Some(operand) = self.get_unary() {
            operand.encode(encoder)?;
        }
        encoder.close_element(ELEM_MINUS_EXP)?;
        Ok(())
    }
}

impl crate::decompiler::seam_stubs::PatternExpression for MinusExpression {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_with_location() {
        let location = Location::new("test.sleigh", 1);
        let _expr = MinusExpression::new(location);
    }

    #[test]
    fn with_operand_stores_operand() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {}

        let operand = Box::new(DummyOperand);
        let expr = MinusExpression::with_operand(location, operand);
        assert!(expr.get_unary().is_some());
    }

    #[test]
    fn get_unary_returns_stored_operand() {
        let location = Location::new("test.sleigh", 1);

        struct DummyOperand;
        impl PatternExpression for DummyOperand {}

        let operand = Box::new(DummyOperand);
        let expr = MinusExpression::with_operand(location, operand);
        assert!(expr.get_unary().is_some());
    }

    #[test]
    fn get_unary_returns_none_when_empty() {
        let location = Location::new("test.sleigh", 1);
        let expr = MinusExpression::new(location);
        assert!(expr.get_unary().is_none());
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
        let expr = MinusExpression::new(location);
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
                self.encoded
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let location = Location::new("test.sleigh", 1);
        let encoded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let operand = Box::new(CountingOperand {
            encoded: std::sync::Arc::clone(&encoded),
        });

        let expr = MinusExpression::with_operand(location, operand);
        let mut encoder = TestEncoder::default();

        expr.encode(&mut encoder).unwrap();

        assert!(encoded.load(std::sync::atomic::Ordering::SeqCst));
    }
}
