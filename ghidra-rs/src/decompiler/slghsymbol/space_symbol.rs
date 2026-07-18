//! Models `ghidra.pcodeCPort.slghsymbol.SpaceSymbol`.

use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::decompiler::space::AddrSpace;
use crate::sleigh::grammar::location::Location;
use std::sync::Arc;

/// A symbol representing an address space in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.SpaceSymbol`.
pub struct SpaceSymbol {
    symbol: SleighSymbol,
    space: Arc<dyn AddrSpace>,
}

impl SpaceSymbol {
    /// Creates a new space symbol at the given location with the given address space.
    ///
    /// Mirrors the Java `SpaceSymbol(Location, AddrSpace)` constructor.
    pub fn new(location: Location, space: Arc<dyn AddrSpace>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, space.name()),
            space,
        }
    }

    /// Gets the address space associated with this symbol.
    pub fn space(&self) -> &dyn AddrSpace {
        &*self.space
    }

    /// Returns the symbol type for this space.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::SpaceSymbol
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }
}

impl Clone for SpaceSymbol {
    fn clone(&self) -> Self {
        Self {
            symbol: self.symbol.clone(),
            space: self.space.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::space::SpaceType;
    use crate::decompiler::translate::Translate;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    struct StubTranslate;
    impl Translate for StubTranslate {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn alignment(&self) -> i32 {
            1
        }

        fn get_unique_base(&self) -> i64 {
            0
        }

        fn get_iop_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_fspec_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_stack_space(&self) -> Option<&dyn AddrSpace> {
            None
        }
    }

    struct MockAddrSpace;
    impl AddrSpace for MockAddrSpace {
        fn name(&self) -> &str {
            "ram"
        }

        fn get_trans(&self) -> &dyn Translate {
            &StubTranslate
        }

        fn get_type(&self) -> SpaceType {
            SpaceType::Processor
        }

        fn get_delay(&self) -> i32 {
            0
        }

        fn get_index(&self) -> i32 {
            0
        }

        fn get_word_size(&self) -> i32 {
            1
        }

        fn get_scale(&self) -> i32 {
            0
        }

        fn get_addr_size(&self) -> i32 {
            4
        }

        fn get_mask(&self) -> i64 {
            0xffffffff
        }

        fn get_short_cut(&self) -> char {
            'r'
        }

        fn flags(&self) -> i32 {
            0
        }
    }

    #[test]
    fn new_creates_symbol_with_space_name() {
        let space = Arc::new(MockAddrSpace);
        let sym = SpaceSymbol::new(loc(), space);
        assert_eq!(sym.symbol().name(), "ram");
        assert_eq!(sym.symbol_type(), SymbolType::SpaceSymbol);
    }

    #[test]
    fn symbol_type_is_space() {
        let space = Arc::new(MockAddrSpace);
        let sym = SpaceSymbol::new(loc(), space);
        assert_eq!(sym.symbol_type(), SymbolType::SpaceSymbol);
    }

    #[test]
    fn space_getter_returns_reference() {
        let space = Arc::new(MockAddrSpace);
        let sym = SpaceSymbol::new(loc(), space);
        assert_eq!(sym.space().name(), "ram");
    }

    #[test]
    fn can_access_base_symbol() {
        let space = Arc::new(MockAddrSpace);
        let sym = SpaceSymbol::new(loc(), space);
        let base = sym.symbol();
        assert_eq!(base.name(), "ram");
    }

    #[test]
    fn can_mutate_via_symbol_mut() {
        let space = Arc::new(MockAddrSpace);
        let mut sym = SpaceSymbol::new(loc(), space);
        sym.symbol_mut().set_was_sought(true);
        assert!(sym.symbol().was_sought());
    }

    #[test]
    fn clone_creates_independent_instance() {
        let space = Arc::new(MockAddrSpace);
        let sym1 = SpaceSymbol::new(loc(), space);
        let sym2 = sym1.clone();
        assert_eq!(sym1.symbol_type(), sym2.symbol_type());
        assert_eq!(sym1.symbol().name(), sym2.symbol().name());
    }
}
