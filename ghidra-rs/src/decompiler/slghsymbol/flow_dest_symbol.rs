//! Models `ghidra.pcodeCPort.slghsymbol.FlowDestSymbol`.

use super::patternless_symbol::PatternlessSymbol;
use super::specific_symbol::SpecificSymbol;
use super::symbol_type::SymbolType;
use super::triple_symbol::TripleSymbol;
use crate::decompiler::seam_stubs::VarnodeTpl as VarnodeTplTrait;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType, VarnodeTpl};
use crate::sleigh::grammar::location::Location;
use std::sync::Arc;

/// A symbol representing the original primary call destination address.
///
/// Models `ghidra.pcodeCPort.slghsymbol.FlowDestSymbol`. This symbol resolves to the
/// original call destination address and can only be used in pcode snippets, not in
/// pattern expressions.
pub struct FlowDestSymbol {
    patternless: PatternlessSymbol,
    const_space: Arc<AddressSpace>,
}

impl FlowDestSymbol {
    /// Creates a new flow destination symbol at the given location.
    ///
    /// Mirrors the Java `FlowDestSymbol(Location, String, AddrSpace)` constructor.
    pub fn new(location: Location, name: impl Into<String>, const_space: Arc<AddressSpace>) -> Self {
        Self {
            patternless: PatternlessSymbol::with_name(location, name),
            const_space,
        }
    }

    /// Returns the symbol type for this flow destination.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::FlowdestSymbol
    }

    /// Gets a reference to the base PatternlessSymbol.
    pub fn patternless(&self) -> &PatternlessSymbol {
        &self.patternless
    }

    /// Gets a mutable reference to the base PatternlessSymbol.
    pub fn patternless_mut(&mut self) -> &mut PatternlessSymbol {
        &mut self.patternless
    }
}

impl TripleSymbol for FlowDestSymbol {
    fn get_pattern_expression(&self) -> Box<dyn crate::decompiler::seam_stubs::PatternExpression> {
        self.patternless.get_pattern_expression()
    }
}

impl SpecificSymbol for FlowDestSymbol {
    fn get_varnode(&self) -> Box<dyn VarnodeTplTrait> {
        let space_const = ConstTpl {
            tp: ConstTplType::SpaceId,
            value_real: 0,
            value_spaceid: Some(self.const_space.clone()),
            handle_index: 0,
            select: None,
        };

        let offset_const = ConstTpl {
            tp: ConstTplType::JFlowDest,
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

impl Clone for FlowDestSymbol {
    fn clone(&self) -> Self {
        Self {
            patternless: self.patternless.clone(),
            const_space: self.const_space.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::ids::*;
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
    fn new_creates_symbol() {
        let space = mock_space();
        let fds = FlowDestSymbol::new(loc(), "inst_dest", space);
        assert_eq!(fds.symbol_type(), SymbolType::FlowdestSymbol);
        assert_eq!(fds.patternless().name(), "inst_dest");
    }

    #[test]
    fn symbol_type_is_flowdest() {
        let space = mock_space();
        let fds = FlowDestSymbol::new(loc(), "test", space);
        assert_eq!(fds.symbol_type(), SymbolType::FlowdestSymbol);
    }

    #[test]
    fn get_varnode_returns_varnode_tpl() {
        let space = mock_space();
        let fds = FlowDestSymbol::new(loc(), "test", space);
        let _varnode = fds.get_varnode();
    }

    #[test]
    fn get_pattern_expression_returns_pattern() {
        let space = mock_space();
        let fds = FlowDestSymbol::new(loc(), "test", space);
        let _pattern = fds.get_pattern_expression();
    }

    #[test]
    fn clone_creates_independent_instance() {
        let space = mock_space();
        let fds1 = FlowDestSymbol::new(loc(), "test", space);
        let fds2 = fds1.clone();
        assert_eq!(fds1.symbol_type(), fds2.symbol_type());
        assert_eq!(fds1.patternless().name(), fds2.patternless().name());
    }

    #[test]
    fn triple_symbol_trait_provides_pattern_expression() {
        let space = mock_space();
        let fds = FlowDestSymbol::new(loc(), "test", space);
        let dyn_symbol: &dyn TripleSymbol = &fds;
        let _pattern = dyn_symbol.get_pattern_expression();
    }

    #[test]
    fn const_space_is_preserved() {
        let space = mock_space();
        let fds = FlowDestSymbol::new(loc(), "test", space.clone());
        let varnode = fds.get_varnode();
        let varnode_tpl = &*varnode as *const dyn VarnodeTplTrait as *const VarnodeTpl;
        let vt = unsafe { &*varnode_tpl };
        assert!(vt.space.value_spaceid.is_some());
    }
}
