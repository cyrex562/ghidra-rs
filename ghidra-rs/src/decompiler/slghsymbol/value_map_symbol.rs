//! Models `ghidra.pcodeCPort.slghsymbol.ValueMapSymbol`.

use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::decompiler::seam_stubs::ValueSymbol;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_ID, ATTRIB_VAL, ELEM_VALUEMAP_SYM, ELEM_VALUEMAP_SYM_HEAD, ELEM_VALUETAB,
};
use std::io;

/// A symbol whose pattern value indexes into a fixed table of numeric values.
///
/// Combines a [`ValueSymbol`]'s pattern value with a lookup table of values, one per possible
/// pattern value; entries in the table are filled with application-specific payloads, and unfilled
/// entries are marked with a sentinel value (0xBADBEEF).
///
/// Models `ghidra.pcodeCPort.slghsymbol.ValueMapSymbol`, which extends `ValueSymbol` (stubbed
/// pending its own port, which would in turn require porting `FamilySymbol`). `SleighSymbol` is
/// exposed via [`ValueMapSymbol::symbol`] rather than through inheritance, mirroring
/// [`super::NameSymbol`].
pub trait ValueMapSymbol: ValueSymbol {
    /// Gets a reference to the base SleighSymbol (name/id/scope shared by every symbol kind).
    fn symbol(&self) -> &SleighSymbol;

    /// The table of numeric values, indexed by pattern value (`valuetable` in Java).
    fn valuetable(&self) -> &[i64];

    /// Whether every value in `[patval.min_value(), patval.max_value()]` has a table entry.
    ///
    /// Mirrors the Java `checkTableFill`, which caches this in a `tableisfilled` field computed
    /// once at construction. This trait has no constructor to cache the result in, so it is
    /// recomputed on demand instead; since `valuetable`/the pattern value don't change after
    /// construction, the result is the same.
    ///
    /// An entry is considered filled if it is not the sentinel value 0xBADBEEF.
    fn is_table_filled(&self) -> bool {
        const SENTINEL: i64 = 0xBADBEEF;
        let min = self.get_pattern_value().min_value();
        let max = self.get_pattern_value().max_value();
        let table = self.valuetable();
        min >= 0
            && max < table.len() as i64
            && table.iter().all(|&v| v != SENTINEL)
    }

    /// Returns the symbol type for this value map symbol.
    fn symbol_type(&self) -> SymbolType {
        SymbolType::ValuemapSymbol
    }

    /// Encodes this value map symbol to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VALUEMAP_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol().id() as u64)?;
        self.get_pattern_value().encode(encoder)?;
        for val in self.valuetable() {
            encoder.open_element(ELEM_VALUETAB)?;
            encoder.write_signed_integer(ATTRIB_VAL, *val)?;
            encoder.close_element(ELEM_VALUETAB)?;
        }
        encoder.close_element(ELEM_VALUEMAP_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this value map symbol.
    fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VALUEMAP_SYM_HEAD)?;
        self.symbol().encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_VALUEMAP_SYM_HEAD)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::PatternExpression;
    use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
    use crate::sleigh::grammar::location::Location;

    struct MockPatternValue {
        min: i64,
        max: i64,
    }

    impl PatternExpression for MockPatternValue {}
    impl PatternValue for MockPatternValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
            unimplemented!("not exercised by this smoke test")
        }
        fn min_value(&self) -> i64 {
            self.min
        }
        fn max_value(&self) -> i64 {
            self.max
        }
    }

    struct MockValueMapSymbol {
        symbol: SleighSymbol,
        valuetable: Vec<i64>,
        patval: MockPatternValue,
    }

    impl ValueSymbol for MockValueMapSymbol {
        fn get_pattern_value(&self) -> &dyn PatternValue {
            &self.patval
        }
    }

    impl ValueMapSymbol for MockValueMapSymbol {
        fn symbol(&self) -> &SleighSymbol {
            &self.symbol
        }

        fn valuetable(&self) -> &[i64] {
            &self.valuetable
        }
    }

    fn mock(min: i64, max: i64, valuetable: Vec<i64>) -> MockValueMapSymbol {
        let loc = Location::new("test.sla", 1);
        MockValueMapSymbol {
            symbol: SleighSymbol::with_name(loc, "mapping"),
            valuetable,
            patval: MockPatternValue { min, max },
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let sym = mock(0, 1, vec![10, 20]);
        let dyn_sym: &dyn ValueMapSymbol = &sym;
        assert_eq!(dyn_sym.valuetable().len(), 2);
    }

    #[test]
    fn symbol_type_defaults_to_valuemap_symbol() {
        let sym = mock(0, 1, vec![10, 20]);
        assert_eq!(sym.symbol_type(), SymbolType::ValuemapSymbol);
    }

    #[test]
    fn table_filled_when_every_value_has_an_entry() {
        let sym = mock(0, 1, vec![10, 20]);
        assert!(sym.is_table_filled());
    }

    #[test]
    fn table_not_filled_when_min_is_negative() {
        let sym = mock(-1, 1, vec![10, 20]);
        assert!(!sym.is_table_filled());
    }

    #[test]
    fn table_not_filled_when_max_reaches_beyond_table() {
        let sym = mock(0, 2, vec![10, 20]);
        assert!(!sym.is_table_filled());
    }

    #[test]
    fn table_not_filled_when_an_entry_is_sentinel() {
        let sym = mock(0, 1, vec![10, 0xBADBEEF]);
        assert!(!sym.is_table_filled());
    }

    #[test]
    fn table_filled_even_with_negative_values() {
        let sym = mock(0, 1, vec![-100, -200]);
        assert!(sym.is_table_filled());
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        signed_ints: Vec<i64>,
        uints: Vec<u64>,
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
            _val: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.signed_ints.push(val);
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
    fn encode_writes_elements_and_valuetab_entries() {
        let sym = mock(0, 1, vec![10, 20]);
        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();
        assert_eq!(
            encoder.opened,
            vec!["valuemap_sym", "valuetab", "valuetab"]
        );
        assert_eq!(
            encoder.closed,
            vec!["valuetab", "valuetab", "valuemap_sym"]
        );
        assert_eq!(encoder.signed_ints, vec![10, 20]);
    }

    #[test]
    fn encode_header_writes_header_element() {
        let sym = mock(0, 1, vec![10, 20]);
        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["valuemap_sym_head"]);
        assert_eq!(encoder.closed, vec!["valuemap_sym_head"]);
    }

    #[test]
    fn encode_with_empty_table() {
        let sym = mock(0, 0, vec![]);
        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["valuemap_sym"]);
        assert_eq!(encoder.closed, vec!["valuemap_sym"]);
        assert_eq!(encoder.signed_ints, vec![]);
    }
}
