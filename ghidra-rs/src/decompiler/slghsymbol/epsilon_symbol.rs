//! Models `ghidra.pcodeCPort.slghsymbol.EpsilonSymbol`.

use super::patternless_symbol::PatternlessSymbol;
use super::specific_symbol::SpecificSymbol;
use super::symbol_type::SymbolType;
use super::triple_symbol::TripleSymbol;
use crate::decompiler::seam_stubs::VarnodeTpl as VarnodeTplTrait;
use crate::program::model::lang::sleigh::template::{ConstTpl, VarnodeTpl};
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_ID, ELEM_EPSILON_SYM, ELEM_EPSILON_SYM_HEAD};
use crate::sleigh::grammar::location::Location;
use std::io;

/// A symbol representing an epsilon (zero pattern/value).
///
/// Models `ghidra.pcodeCPort.slghsymbol.EpsilonSymbol`. An epsilon symbol represents
/// a constant zero pattern/value in SLEIGH semantics.
pub struct EpsilonSymbol {
    patternless: PatternlessSymbol,
}

impl EpsilonSymbol {
    /// Creates a new epsilon symbol at the given location.
    ///
    /// Mirrors the Java `EpsilonSymbol(Location)` constructor.
    pub fn new(location: Location) -> Self {
        Self {
            patternless: PatternlessSymbol::new(location),
        }
    }

    /// Creates a new epsilon symbol with a name at the given location.
    ///
    /// Mirrors the Java `EpsilonSymbol(Location, String)` constructor part of
    /// `EpsilonSymbol(Location, String, AddrSpace)`. The address space is not stored
    /// since it requires cross-layer access between decompiler and program model layers.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            patternless: PatternlessSymbol::with_name(location, name),
        }
    }

    /// Returns the symbol type for this epsilon.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::EpsilonSymbol
    }

    /// Encodes this epsilon symbol to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_EPSILON_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.patternless.symbol().id() as u64)?;
        encoder.close_element(ELEM_EPSILON_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this epsilon symbol.
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_EPSILON_SYM_HEAD)?;
        self.patternless.symbol().encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_EPSILON_SYM_HEAD)?;
        Ok(())
    }
}

impl TripleSymbol for EpsilonSymbol {
    fn get_pattern_expression(&self) -> Box<dyn crate::decompiler::seam_stubs::PatternExpression> {
        self.patternless.get_pattern_expression()
    }
}

impl SpecificSymbol for EpsilonSymbol {
    fn get_varnode(&self) -> Box<dyn VarnodeTplTrait> {
        let space_const = ConstTpl::new();
        let offset_const = ConstTpl::new();
        let size_const = ConstTpl::new();

        Box::new(VarnodeTpl {
            space: space_const,
            offset: offset_const,
            size: size_const,
        })
    }
}

impl Clone for EpsilonSymbol {
    fn clone(&self) -> Self {
        Self {
            patternless: self.patternless.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    #[test]
    fn new_creates_epsilon() {
        let eps = EpsilonSymbol::new(loc());
        assert_eq!(eps.symbol_type(), SymbolType::EpsilonSymbol);
    }

    #[test]
    fn with_name_sets_name() {
        let eps = EpsilonSymbol::with_name(loc(), "eps");
        assert_eq!(eps.patternless.name(), "eps");
        assert_eq!(eps.symbol_type(), SymbolType::EpsilonSymbol);
    }

    #[test]
    fn symbol_type_is_epsilon() {
        let eps = EpsilonSymbol::new(loc());
        assert_eq!(eps.symbol_type(), SymbolType::EpsilonSymbol);
    }

    #[test]
    fn get_varnode_returns_varnode_tpl() {
        let eps = EpsilonSymbol::new(loc());
        let _varnode = eps.get_varnode();
    }

    #[test]
    fn clone_creates_independent_instance() {
        let eps1 = EpsilonSymbol::new(loc());
        let eps2 = eps1.clone();
        assert_eq!(eps1.symbol_type(), eps2.symbol_type());
    }

    #[test]
    fn triple_symbol_trait_provides_pattern_expression() {
        let eps = EpsilonSymbol::new(loc());
        let dyn_symbol: &dyn TripleSymbol = &eps;
        let _pattern = dyn_symbol.get_pattern_expression();
    }

    #[test]
    fn encode_works() {
        use crate::program::model::pcode::encoder::Encoder;
        use crate::program::model::pcode::ids::AttributeId;
        use std::io;

        struct RecordingEncoder {
            writes: Vec<String>,
        }

        impl Encoder for RecordingEncoder {
            fn open_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                Ok(())
            }

            fn close_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                Ok(())
            }

            fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
                Ok(())
            }

            fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
                Ok(())
            }

            fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
                self.writes.push(format!("uint:{}={}", attrib_id.name, val));
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

            fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::OpCode) -> io::Result<()> {
                Ok(())
            }

            fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
                Ok(())
            }
        }

        let mut eps = EpsilonSymbol::new(loc());
        eps.patternless.symbol_mut().id = 5;
        let mut encoder = RecordingEncoder {
            writes: Vec::new(),
        };
        eps.encode(&mut encoder).unwrap();
        assert!(encoder.writes.iter().any(|w| w.contains("id=5")));
    }

    #[test]
    fn encode_header_works() {
        use crate::program::model::pcode::encoder::Encoder;
        use crate::program::model::pcode::ids::AttributeId;
        use std::io;

        struct RecordingEncoder {
            writes: Vec<String>,
        }

        impl Encoder for RecordingEncoder {
            fn open_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                Ok(())
            }

            fn close_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                Ok(())
            }

            fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
                Ok(())
            }

            fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
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

            fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::OpCode) -> io::Result<()> {
                Ok(())
            }

            fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
                Ok(())
            }
        }

        let mut eps = EpsilonSymbol::new(loc());
        eps.patternless.symbol_mut().id = 3;
        let mut encoder = RecordingEncoder {
            writes: Vec::new(),
        };
        eps.encode_header(&mut encoder).unwrap();
        assert!(encoder.writes.iter().any(|w| w.contains("id=3")));
    }
}
