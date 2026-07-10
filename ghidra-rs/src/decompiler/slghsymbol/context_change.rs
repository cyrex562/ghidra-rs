use crate::program::model::pcode::Encoder;
use std::io;

/// Models `ghidra.pcodeCPort.slghsymbol.ContextChange`.
pub trait ContextChange {
    /// Validate this context change.
    fn validate(&self);

    /// Encode this context change to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;

    /// Clean up any resources associated with this context change.
    fn dispose(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::address::AddressSpace;

    struct MockContextChange;

    impl ContextChange for MockContextChange {
        fn validate(&self) {}

        fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
            encoder.open_element(ElementId::new("test", 1))?;
            encoder.close_element(ElementId::new("test", 1))?;
            Ok(())
        }

        fn dispose(&self) {}
    }

    #[test]
    fn test_mock_context_change_validate() {
        let ctx = MockContextChange;
        ctx.validate();
    }

    #[test]
    fn test_mock_context_change_encode() {
        let ctx = MockContextChange;
        struct TrackingEncoder {
            opened: usize,
            closed: usize,
        }

        impl Encoder for TrackingEncoder {
            fn open_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
                self.opened += 1;
                Ok(())
            }

            fn close_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
                self.closed += 1;
                Ok(())
            }

            fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
                Ok(())
            }

            fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
                Ok(())
            }

            fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> io::Result<()> {
                Ok(())
            }

            fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
                Ok(())
            }

            fn write_string_indexed(
                &mut self,
                _attrib_id: AttributeId,
                _index: i32,
                _val: &str,
            ) -> io::Result<()> {
                Ok(())
            }

            fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
                Ok(())
            }

            fn write_space_indexed(
                &mut self,
                _attrib_id: AttributeId,
                _index: i32,
                _name: &str,
            ) -> io::Result<()> {
                Ok(())
            }

            fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
                Ok(())
            }

            fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
                Ok(())
            }
        }

        let mut encoder = TrackingEncoder {
            opened: 0,
            closed: 0,
        };

        assert!(ctx.encode(&mut encoder).is_ok());
        assert_eq!(encoder.opened, 1);
        assert_eq!(encoder.closed, 1);
    }

    #[test]
    fn test_mock_context_change_dispose() {
        let ctx = MockContextChange;
        ctx.dispose();
    }

    #[test]
    fn test_trait_object_dispatch() {
        let ctx: Box<dyn ContextChange> = Box::new(MockContextChange);
        ctx.validate();
        ctx.dispose();
    }
}
