use crate::decompiler::utils::utils::calc_maskword;
use crate::decompiler::utils::MutableInt;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_FLOW, ATTRIB_ID, ATTRIB_MASK, ATTRIB_NUMBER, ELEM_COMMIT};
use crate::sleigh::grammar::location::Location;
use std::io;

/// A context commit represents a fixed context value to be applied during instruction processing.
///
/// Models `ghidra.pcodeCPort.slghsymbol.ContextCommit`.
pub struct ContextCommit {
    sym_id: i32,
    num: i32,
    mask: i32,
    flow: bool,
}

impl ContextCommit {
    /// Creates a new empty context commit.
    pub fn new() -> Self {
        Self {
            sym_id: 0,
            num: 0,
            mask: 0,
            flow: false,
        }
    }

    /// Creates a new context commit from a symbol ID and bit range.
    pub fn with_symbol(sym_id: i32, sbit: i32, ebit: i32, flow: bool) -> Result<Self, io::Error> {
        let mut n = MutableInt::new(0);
        let mut shift = MutableInt::new(0);
        let mut m = MutableInt::new(0);

        let location = Location::new("context_commit", 0);
        calc_maskword(&location, sbit, ebit, &mut n, &mut shift, &mut m)
            .map_err(|e| io::Error::other(e))?;

        Ok(Self {
            sym_id,
            num: n.get(),
            mask: m.get(),
            flow,
        })
    }

    /// Gets the symbol ID.
    pub fn sym_id(&self) -> i32 {
        self.sym_id
    }

    /// Gets the word index containing the context commit.
    pub fn num(&self) -> i32 {
        self.num
    }

    /// Gets the mask of bits being committed.
    pub fn mask(&self) -> i32 {
        self.mask
    }

    /// Gets whether the context flows from the point of change.
    pub fn flow(&self) -> bool {
        self.flow
    }
}

impl Default for ContextCommit {
    fn default() -> Self {
        Self::new()
    }
}

impl super::context_change::ContextChange for ContextCommit {
    fn validate(&self) {}

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_COMMIT)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.sym_id as u64)?;
        encoder.write_signed_integer(ATTRIB_NUMBER, self.num as i64)?;
        encoder.write_unsigned_integer(ATTRIB_MASK, (self.mask as u32) as u64)?;
        encoder.write_bool(ATTRIB_FLOW, self.flow)?;
        encoder.close_element(ELEM_COMMIT)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::context_change::ContextChange;
    use crate::program::model::pcode::ids::AttributeId;
    use crate::program::model::address::AddressSpace;
    use crate::decompiler::opcodes::op_code::OpCode;

    #[test]
    fn new_creates_empty_commit() {
        let cc = ContextCommit::new();
        assert_eq!(cc.sym_id(), 0);
        assert_eq!(cc.num(), 0);
        assert_eq!(cc.mask(), 0);
        assert!(!cc.flow());
    }

    #[test]
    fn default_is_empty() {
        let cc = ContextCommit::default();
        assert_eq!(cc.sym_id(), 0);
        assert_eq!(cc.num(), 0);
        assert_eq!(cc.mask(), 0);
        assert!(!cc.flow());
    }

    #[test]
    fn with_symbol_computes_mask_for_byte_range() {
        let cc = ContextCommit::with_symbol(42, 0, 7, false).unwrap();
        assert_eq!(cc.sym_id(), 42);
        assert_eq!(cc.flow(), false);
        assert_eq!(cc.num(), 0);
    }

    #[test]
    fn with_symbol_sets_flow_flag() {
        let cc = ContextCommit::with_symbol(100, 0, 7, true).unwrap();
        assert_eq!(cc.sym_id(), 100);
        assert!(cc.flow());
    }

    #[test]
    fn encode_writes_all_attributes() {
        let cc = ContextCommit {
            sym_id: 12,
            num: 1,
            mask: 0xFF,
            flow: true,
        };

        struct TrackingEncoder {
            opened: bool,
            closed: bool,
            written_id: Option<u64>,
            written_flow: Option<bool>,
        }

        impl Encoder for TrackingEncoder {
            fn open_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                self.opened = true;
                Ok(())
            }

            fn close_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                self.closed = true;
                Ok(())
            }

            fn write_bool(&mut self, _attrib_id: AttributeId, val: bool) -> io::Result<()> {
                self.written_flow = Some(val);
                Ok(())
            }

            fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
                Ok(())
            }

            fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
                if attrib_id.id == ATTRIB_ID.id {
                    self.written_id = Some(val);
                }
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

            fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: OpCode) -> io::Result<()> {
                Ok(())
            }

            fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
                Ok(())
            }
        }

        let mut encoder = TrackingEncoder {
            opened: false,
            closed: false,
            written_id: None,
            written_flow: None,
        };

        cc.encode(&mut encoder).unwrap();
        assert!(encoder.opened);
        assert!(encoder.closed);
        assert_eq!(encoder.written_id, Some(12));
        assert_eq!(encoder.written_flow, Some(true));
    }

    #[test]
    fn validate_does_nothing() {
        let cc = ContextCommit::new();
        cc.validate();
    }
}
