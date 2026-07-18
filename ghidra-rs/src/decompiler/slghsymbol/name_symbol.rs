//! Models `ghidra.pcodeCPort.slghsymbol.NameSymbol`.

use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::decompiler::seam_stubs::ValueSymbol;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_ID, ATTRIB_NAME, ELEM_NAMETAB, ELEM_NAME_SYM, ELEM_NAME_SYM_HEAD,
};
use std::io;

/// A symbol whose pattern value indexes into a fixed table of display names.
///
/// Combines a [`ValueSymbol`]'s pattern value with a lookup table of names, one per possible
/// pattern value; a missing table entry is represented as `None` (the Java `nametable` stores
/// `null` for these).
///
/// Models `ghidra.pcodeCPort.slghsymbol.NameSymbol`, which extends `ValueSymbol` (stubbed
/// pending its own port, which would in turn require porting `FamilySymbol`). `SleighSymbol` is
/// exposed via [`NameSymbol::symbol`] rather than through inheritance, mirroring
/// [`super::ContextSymbol`].
pub trait NameSymbol: ValueSymbol {
    /// Gets a reference to the base SleighSymbol (name/id/scope shared by every symbol kind).
    fn symbol(&self) -> &SleighSymbol;

    /// The table of display names, indexed by pattern value (`nametable` in Java).
    fn nametable(&self) -> &[Option<String>];

    /// Whether every value in `[patval.min_value(), patval.max_value()]` has a table entry.
    ///
    /// Mirrors the Java `checkTableFill`, which caches this in a `tableisfilled` field computed
    /// once at construction. This trait has no constructor to cache the result in, so it is
    /// recomputed on demand instead; since `nametable`/the pattern value don't change after
    /// construction, the result is the same.
    fn is_table_filled(&self) -> bool {
        let min = self.get_pattern_value().min_value();
        let max = self.get_pattern_value().max_value();
        let table = self.nametable();
        min >= 0 && max < table.len() as i64 && table.iter().all(Option::is_some)
    }

    /// Returns the symbol type for this name symbol.
    fn symbol_type(&self) -> SymbolType {
        SymbolType::NameSymbol
    }

    /// Encodes this name symbol to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_NAME_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol().id() as u64)?;
        self.get_pattern_value().encode(encoder)?;
        for name in self.nametable() {
            encoder.open_element(ELEM_NAMETAB)?;
            if let Some(name) = name {
                encoder.write_string(ATTRIB_NAME, name)?;
            }
            encoder.close_element(ELEM_NAMETAB)?;
        }
        encoder.close_element(ELEM_NAME_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this name symbol.
    fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_NAME_SYM_HEAD)?;
        self.symbol().encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_NAME_SYM_HEAD)?;
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

    struct MockNameSymbol {
        symbol: SleighSymbol,
        nametable: Vec<Option<String>>,
        patval: MockPatternValue,
    }

    impl ValueSymbol for MockNameSymbol {
        fn get_pattern_value(&self) -> &dyn PatternValue {
            &self.patval
        }
    }

    impl NameSymbol for MockNameSymbol {
        fn symbol(&self) -> &SleighSymbol {
            &self.symbol
        }

        fn nametable(&self) -> &[Option<String>] {
            &self.nametable
        }
    }

    fn mock(min: i64, max: i64, nametable: Vec<Option<String>>) -> MockNameSymbol {
        let loc = Location::new("test.sla", 1);
        MockNameSymbol {
            symbol: SleighSymbol::with_name(loc, "mnemonic"),
            nametable,
            patval: MockPatternValue { min, max },
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let sym = mock(0, 1, vec![Some("a".into()), Some("b".into())]);
        let dyn_sym: &dyn NameSymbol = &sym;
        assert_eq!(dyn_sym.nametable().len(), 2);
    }

    #[test]
    fn symbol_type_defaults_to_name_symbol() {
        let sym = mock(0, 1, vec![Some("a".into()), Some("b".into())]);
        assert_eq!(sym.symbol_type(), SymbolType::NameSymbol);
    }

    #[test]
    fn table_filled_when_every_value_has_an_entry() {
        let sym = mock(0, 1, vec![Some("a".into()), Some("b".into())]);
        assert!(sym.is_table_filled());
    }

    #[test]
    fn table_not_filled_when_min_is_negative() {
        let sym = mock(-1, 1, vec![Some("a".into()), Some("b".into())]);
        assert!(!sym.is_table_filled());
    }

    #[test]
    fn table_not_filled_when_max_reaches_beyond_table() {
        let sym = mock(0, 2, vec![Some("a".into()), Some("b".into())]);
        assert!(!sym.is_table_filled());
    }

    #[test]
    fn table_not_filled_when_an_entry_is_missing() {
        let sym = mock(0, 1, vec![Some("a".into()), None]);
        assert!(!sym.is_table_filled());
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        uints: Vec<u64>,
        strings: Vec<String>,
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
            _val: i64,
        ) -> io::Result<()> {
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
            val: &str,
        ) -> io::Result<()> {
            self.strings.push(val.to_string());
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
    fn encode_writes_element_and_nametab_entries() {
        let sym = mock(0, 1, vec![Some("a".into()), None]);
        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["name_sym", "nametab", "nametab"]);
        assert_eq!(encoder.closed, vec!["nametab", "nametab", "name_sym"]);
        assert_eq!(encoder.strings, vec!["a"]);
    }

    #[test]
    fn encode_header_writes_header_element() {
        let sym = mock(0, 1, vec![Some("a".into()), Some("b".into())]);
        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["name_sym_head"]);
        assert_eq!(encoder.closed, vec!["name_sym_head"]);
    }
}
