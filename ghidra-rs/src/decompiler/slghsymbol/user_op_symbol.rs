use super::symbol_type::SymbolType;
use super::sleigh_symbol::SleighSymbol;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_ID, ATTRIB_INDEX, ELEM_USEROP, ELEM_USEROP_HEAD};
use crate::sleigh::grammar::location::Location;
use std::io;

/// A user-defined p-code operation symbol in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.UserOpSymbol`.
pub struct UserOpSymbol {
    symbol: SleighSymbol,
    index: i32,
}

impl UserOpSymbol {
    /// Creates an unnamed user-op symbol at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
            index: 0,
        }
    }

    /// Creates a named user-op symbol at the given location.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            index: 0,
        }
    }

    /// Sets the index of this user-op symbol.
    pub fn set_index(&mut self, index: i32) {
        self.index = index;
    }

    /// Gets the index of this user-op symbol.
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Returns the symbol type for this user-op.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::UseropSymbol
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    /// Encodes this user-op symbol.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_USEROP)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol.id as u64)?;
        encoder.write_signed_integer(ATTRIB_INDEX, self.index as i64)?;
        encoder.close_element(ELEM_USEROP)?;
        Ok(())
    }

    /// Encodes the header for this user-op symbol.
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_USEROP_HEAD)?;
        self.symbol.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_USEROP_HEAD)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::decompiler::opcodes::op_code::OpCode;

    fn loc() -> Location {
        Location::new("test.sla", 7)
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opens: Vec<String>,
        closes: Vec<String>,
        writes: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opens.push(elem_id.name.to_string());
            Ok(())
        }

        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.closes.push(elem_id.name.to_string());
            Ok(())
        }

        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.writes.push(format!("sint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.writes.push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.writes.push(format!("str:{}={}", attrib_id.name, val));
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

        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &crate::program::model::address::AddressSpace) -> io::Result<()> {
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

    #[test]
    fn new_unnamed_has_zero_index() {
        let sym = UserOpSymbol::new(loc());
        assert_eq!(sym.index(), 0);
        assert_eq!(sym.symbol().name(), "");
    }

    #[test]
    fn with_name_sets_name_and_zero_index() {
        let sym = UserOpSymbol::with_name(loc(), "my_op");
        assert_eq!(sym.symbol().name(), "my_op");
        assert_eq!(sym.index(), 0);
    }

    #[test]
    fn set_index_updates_value() {
        let mut sym = UserOpSymbol::with_name(loc(), "op");
        assert_eq!(sym.index(), 0);
        sym.set_index(42);
        assert_eq!(sym.index(), 42);
        sym.set_index(-1);
        assert_eq!(sym.index(), -1);
    }

    #[test]
    fn symbol_type_is_userop() {
        let sym = UserOpSymbol::new(loc());
        assert_eq!(sym.symbol_type(), SymbolType::UseropSymbol);
    }

    #[test]
    fn encode_writes_element_and_attributes() {
        let mut sym = UserOpSymbol::with_name(loc(), "custom_op");
        sym.symbol_mut().id = 7;
        sym.set_index(99);

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opens, vec!["userop"]);
        assert_eq!(encoder.closes, vec!["userop"]);
        assert_eq!(encoder.writes.len(), 2);
        assert!(encoder.writes[0].contains("id=7"));
        assert!(encoder.writes[1].contains("index=99"));
    }

    #[test]
    fn encode_header_writes_element_with_symbol_header() {
        let mut sym = UserOpSymbol::with_name(loc(), "test_op");
        sym.symbol_mut().id = 5;
        sym.symbol_mut().scope_id = 2;

        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();

        assert_eq!(encoder.opens, vec!["userop_head"]);
        assert_eq!(encoder.closes, vec!["userop_head"]);
        assert!(encoder.writes.len() >= 2);
        assert!(encoder.writes.iter().any(|w| w.contains("id=5")));
        assert!(encoder.writes.iter().any(|w| w.contains("scope=2")));
        assert!(encoder.writes.iter().any(|w| w.contains("name=test_op")));
    }

    #[test]
    fn symbol_access() {
        let sym = UserOpSymbol::with_name(loc(), "op_name");
        assert_eq!(sym.symbol().name(), "op_name");
    }

    #[test]
    fn symbol_mut_access() {
        let mut sym = UserOpSymbol::new(loc());
        sym.symbol_mut().id = 10;
        assert_eq!(sym.symbol().id(), 10);
    }

    #[test]
    fn multiple_indices() {
        let mut sym1 = UserOpSymbol::with_name(loc(), "op1");
        let mut sym2 = UserOpSymbol::with_name(loc(), "op2");

        sym1.set_index(1);
        sym2.set_index(2);

        assert_eq!(sym1.index(), 1);
        assert_eq!(sym2.index(), 2);
    }
}
