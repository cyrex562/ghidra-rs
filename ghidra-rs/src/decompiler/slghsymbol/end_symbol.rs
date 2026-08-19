//! Models `ghidra.pcodeCPort.slghsymbol.EndSymbol`.

use super::sleigh_symbol::SleighSymbol;
use super::specific_symbol::SpecificSymbol;
use super::symbol_type::SymbolType;
use super::triple_symbol::TripleSymbol;
use crate::decompiler::seam_stubs::VarnodeTpl as VarnodeTplTrait;
use crate::decompiler::slghpatexpress::EndInstructionValue;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType, VarnodeTpl};
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_ID, ELEM_END_SYM, ELEM_END_SYM_HEAD};
use crate::sleigh::grammar::location::Location;
use std::io;
use std::sync::Arc;

/// A symbol representing the next instruction offset (the `inst_next` pseudo-symbol).
///
/// Models `ghidra.pcodeCPort.slghsymbol.EndSymbol`. The bare [`EndSymbol::new`] constructor
/// mirrors the Java no-name constructor, which leaves the pattern expression and constant
/// space unset; only [`EndSymbol::with_name`] produces a symbol usable in pattern expressions
/// or varnode templates.
pub struct EndSymbol {
    symbol: SleighSymbol,
    const_space: Option<Arc<AddressSpace>>,
    patexp: Option<EndInstructionValue>,
}

impl EndSymbol {
    /// Creates a new, unnamed end symbol at the given location with no pattern expression.
    ///
    /// Mirrors the Java `EndSymbol(Location)` constructor.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
            const_space: None,
            patexp: None,
        }
    }

    /// Creates a new named end symbol at the given location, bound to the constant address
    /// space.
    ///
    /// Mirrors the Java `EndSymbol(Location, String, AddrSpace)` constructor.
    pub fn with_name(
        location: Location,
        name: impl Into<String>,
        const_space: Arc<AddressSpace>,
    ) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location.clone(), name),
            const_space: Some(const_space),
            patexp: Some(EndInstructionValue::new(location)),
        }
    }

    /// Returns the symbol type for this end symbol.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::EndSymbol
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    /// Encodes this end symbol to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_END_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol.id() as u64)?;
        encoder.close_element(ELEM_END_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this end symbol.
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_END_SYM_HEAD)?;
        self.symbol.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_END_SYM_HEAD)?;
        Ok(())
    }
}

impl TripleSymbol for EndSymbol {
    fn get_pattern_expression(&self) -> Box<dyn crate::decompiler::seam_stubs::PatternExpression> {
        Box::new(
            self.patexp
                .clone()
                .expect("EndSymbol must be constructed via EndSymbol::with_name to have a pattern expression"),
        )
    }
}

impl SpecificSymbol for EndSymbol {
    fn get_varnode(&self) -> Box<dyn VarnodeTplTrait> {
        let const_space = self
            .const_space
            .as_ref()
            .expect("EndSymbol must be constructed via EndSymbol::with_name to have a varnode");

        let space_const = ConstTpl {
            tp: ConstTplType::SpaceId,
            value_real: 0,
            value_spaceid: Some(const_space.clone()),
            handle_index: 0,
            select: None,
        };

        let offset_const = ConstTpl {
            tp: ConstTplType::JNext,
            value_real: 0,
            value_spaceid: None,
            handle_index: 0,
            select: None,
        };

        let size_const = ConstTpl::new();

        Box::new(VarnodeTpl {
            space: space_const,
            offset: offset_const,
            size: size_const,
        })
    }
}

impl Clone for EndSymbol {
    fn clone(&self) -> Self {
        Self {
            symbol: self.symbol.clone(),
            const_space: self.const_space.clone(),
            patexp: self.patexp.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new(
            "const",
            8,
            1,
            crate::program::model::address::AddressSpaceType::Constant,
            0,
        )
    }

    #[test]
    fn new_creates_unnamed_symbol() {
        let end = EndSymbol::new(loc());
        assert_eq!(end.symbol_type(), SymbolType::EndSymbol);
        assert_eq!(end.symbol().name(), "");
    }

    #[test]
    fn with_name_sets_name() {
        let space = mock_space();
        let end = EndSymbol::with_name(loc(), "inst_next", space);
        assert_eq!(end.symbol_type(), SymbolType::EndSymbol);
        assert_eq!(end.symbol().name(), "inst_next");
    }

    #[test]
    fn get_varnode_returns_varnode_tpl() {
        let space = mock_space();
        let end = EndSymbol::with_name(loc(), "inst_next", space);
        let _varnode = end.get_varnode();
    }

    #[test]
    #[should_panic(expected = "EndSymbol::with_name")]
    fn get_varnode_panics_without_const_space() {
        let end = EndSymbol::new(loc());
        let _varnode = end.get_varnode();
    }

    #[test]
    fn get_pattern_expression_returns_pattern() {
        let space = mock_space();
        let end = EndSymbol::with_name(loc(), "inst_next", space);
        let _pattern = end.get_pattern_expression();
    }

    #[test]
    #[should_panic(expected = "EndSymbol::with_name")]
    fn get_pattern_expression_panics_without_patexp() {
        let end = EndSymbol::new(loc());
        let _pattern = end.get_pattern_expression();
    }

    #[test]
    fn clone_creates_independent_instance() {
        let space = mock_space();
        let end1 = EndSymbol::with_name(loc(), "inst_next", space);
        let end2 = end1.clone();
        assert_eq!(end1.symbol_type(), end2.symbol_type());
        assert_eq!(end1.symbol().name(), end2.symbol().name());
    }

    #[test]
    fn triple_symbol_trait_provides_pattern_expression() {
        let space = mock_space();
        let end = EndSymbol::with_name(loc(), "inst_next", space);
        let dyn_symbol: &dyn TripleSymbol = &end;
        let _pattern = dyn_symbol.get_pattern_expression();
    }

    #[test]
    fn const_space_is_preserved() {
        let space = mock_space();
        let end = EndSymbol::with_name(loc(), "inst_next", space);
        let varnode = end.get_varnode();
        let varnode_tpl = &*varnode as *const dyn VarnodeTplTrait as *const VarnodeTpl;
        let vt = unsafe { &*varnode_tpl };
        assert!(vt.space.value_spaceid.is_some());
        assert_eq!(vt.offset.tp, ConstTplType::JNext);
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

        let mut end = EndSymbol::new(loc());
        end.symbol_mut().id = 7;
        let mut encoder = RecordingEncoder { writes: Vec::new() };
        end.encode(&mut encoder).unwrap();
        assert!(encoder.writes.iter().any(|w| w.contains("id=7")));
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

        let mut end = EndSymbol::with_name(loc(), "inst_next", mock_space());
        end.symbol_mut().id = 4;
        let mut encoder = RecordingEncoder { writes: Vec::new() };
        end.encode_header(&mut encoder).unwrap();
        assert!(encoder.writes.iter().any(|w| w.contains("name=inst_next")));
        assert!(encoder.writes.iter().any(|w| w.contains("id=4")));
    }
}
