//! Models `ghidra.pcodeCPort.slghsymbol.ContextSymbol`.

use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use super::varnode_symbol::VarnodeSymbol;
use crate::decompiler::seam_stubs::ValueSymbol;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_FLOW, ATTRIB_HIGH, ATTRIB_ID, ATTRIB_LOW, ATTRIB_VARNODE, ELEM_CONTEXT_SYM,
    ELEM_CONTEXT_SYM_HEAD,
};
use std::io;

/// A named piece of the disassembly context register.
///
/// Combines a [`ValueSymbol`]'s pattern value with a bit range `[low, high]` of a backing
/// [`VarnodeSymbol`], plus whether the value flows forward into subsequent instructions.
///
/// Models `ghidra.pcodeCPort.slghsymbol.ContextSymbol`, which extends `ValueSymbol` (stubbed
/// pending its own port, which would in turn require porting `FamilySymbol`). `SleighSymbol` is
/// exposed via [`ContextSymbol::symbol`] rather than through inheritance, mirroring how other
/// symbol kinds in this crate embed it as a header field.
pub trait ContextSymbol: ValueSymbol {
    /// Gets a reference to the base SleighSymbol (name/id/scope shared by every symbol kind).
    fn symbol(&self) -> &SleighSymbol;

    /// The varnode this context field is backed by (`vn` in Java).
    fn get_varnode(&self) -> &VarnodeSymbol;

    /// The first bit, inclusive, of this field's range within the varnode.
    fn get_low(&self) -> i32;

    /// The last bit, inclusive, of this field's range within the varnode.
    fn get_high(&self) -> i32;

    /// Whether this context value should propagate to subsequently disassembled instructions.
    fn is_flow(&self) -> bool;

    /// Returns the symbol type for this context symbol.
    fn symbol_type(&self) -> SymbolType {
        SymbolType::ContextSymbol
    }

    /// Encodes this context symbol to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_CONTEXT_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol().id() as u64)?;
        encoder.write_unsigned_integer(ATTRIB_VARNODE, self.get_varnode().symbol().id() as u64)?;
        encoder.write_signed_integer(ATTRIB_LOW, self.get_low() as i64)?;
        encoder.write_signed_integer(ATTRIB_HIGH, self.get_high() as i64)?;
        encoder.write_bool(ATTRIB_FLOW, self.is_flow())?;
        self.get_pattern_value().encode(encoder)?;
        encoder.close_element(ELEM_CONTEXT_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this context symbol.
    fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_CONTEXT_SYM_HEAD)?;
        self.symbol().encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_CONTEXT_SYM_HEAD)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::PatternExpression;
    use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
    use crate::sleigh::grammar::location::Location;

    struct MockPatternValue;
    impl PatternExpression for MockPatternValue {}
    impl PatternValue for MockPatternValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
            unimplemented!("not exercised by this smoke test")
        }
        fn min_value(&self) -> i64 {
            0
        }
        fn max_value(&self) -> i64 {
            0xff
        }
    }

    struct MockContextSymbol {
        symbol: SleighSymbol,
        varnode: VarnodeSymbol,
        low: i32,
        high: i32,
        flow: bool,
        patval: MockPatternValue,
    }

    impl ValueSymbol for MockContextSymbol {
        fn get_pattern_value(&self) -> &dyn PatternValue {
            &self.patval
        }
    }

    impl ContextSymbol for MockContextSymbol {
        fn symbol(&self) -> &SleighSymbol {
            &self.symbol
        }

        fn get_varnode(&self) -> &VarnodeSymbol {
            &self.varnode
        }

        fn get_low(&self) -> i32 {
            self.low
        }

        fn get_high(&self) -> i32 {
            self.high
        }

        fn is_flow(&self) -> bool {
            self.flow
        }
    }

    fn mock() -> MockContextSymbol {
        let loc = Location::new("test.sla", 1);
        MockContextSymbol {
            symbol: SleighSymbol::with_name(loc.clone(), "ctx"),
            varnode: VarnodeSymbol::with_name(loc, "contextreg"),
            low: 3,
            high: 7,
            flow: true,
            patval: MockPatternValue,
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let sym = mock();
        let dyn_sym: &dyn ContextSymbol = &sym;
        assert_eq!(dyn_sym.get_low(), 3);
        assert_eq!(dyn_sym.get_high(), 7);
        assert!(dyn_sym.is_flow());
        assert_eq!(dyn_sym.get_varnode().name(), "contextreg");
    }

    #[test]
    fn symbol_type_defaults_to_context_symbol() {
        let sym = mock();
        assert_eq!(sym.symbol_type(), SymbolType::ContextSymbol);
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        uints: Vec<u64>,
        ints: Vec<i64>,
        bools: Vec<bool>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }

        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.closed.push(elem_id.name);
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
            val: u64,
        ) -> io::Result<()> {
            self.uints.push(val);
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

    #[test]
    fn encode_writes_element_and_attributes() {
        let sym = mock();
        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["context_sym"]);
        assert_eq!(encoder.closed, vec!["context_sym"]);
        assert_eq!(encoder.ints, vec![3, 7]);
        assert_eq!(encoder.bools, vec![true]);
    }

    #[test]
    fn encode_header_writes_header_element() {
        let sym = mock();
        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["context_sym_head"]);
        assert_eq!(encoder.closed, vec!["context_sym_head"]);
    }
}
