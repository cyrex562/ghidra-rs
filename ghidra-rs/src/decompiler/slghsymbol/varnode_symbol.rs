use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::sleigh::grammar::location::Location;

/// A symbol representing a global varnode in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.VarnodeSymbol`.
///
/// INCOMPLETE (found phantom-DONE 2026-09, reverted to TODO in PORT_MANIFEST.tsv, while sizing
/// `VarnodeListSymbol.java`, which extends this class): only covers the base `SleighSymbol`
/// identity (name/id/scope) and `symbol_type()`. Missing the real class's `fix: VarnodeData`
/// field (space/offset/size, with the real constructor's overflow-checking `SleighError` on a
/// varnode that would extend beyond the end of its address space), `get_fixed_varnode`,
/// `get_size`/`collect_local_values`/`get_varnode` (`SpecificSymbol`/`TripleSymbol` overrides --
/// `get_varnode` needs `VarnodeTpl`'s `(Location, ConstTpl, ConstTpl, ConstTpl)` constructor,
/// which also isn't ported yet -- see `VarnodeTpl`'s own doc comment), and `encode`/
/// `encode_header`. Needed by `VarnodeListSymbol`/`SymbolTable` (`ghidra.pcodeCPort.slghsymbol.
/// {VarnodeListSymbol,SymbolTable}`, still `TODO`), which is how this gap was found.
pub struct VarnodeSymbol {
    symbol: SleighSymbol,
}

impl VarnodeSymbol {
    /// Creates a new varnode symbol at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
        }
    }

    /// Creates a new varnode symbol with a name at the given location.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
        }
    }

    /// Returns the symbol type for this varnode.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::VarnodeSymbol
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    /// Gets the name of this symbol.
    pub fn name(&self) -> &str {
        self.symbol.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    #[test]
    fn new_creates_unnamed_symbol() {
        let vs = VarnodeSymbol::new(loc());
        assert_eq!(vs.name(), "");
        assert_eq!(vs.symbol_type(), SymbolType::VarnodeSymbol);
    }

    #[test]
    fn with_name_sets_name() {
        let vs = VarnodeSymbol::with_name(loc(), "my_varnode");
        assert_eq!(vs.name(), "my_varnode");
    }

    #[test]
    fn symbol_type_is_varnode() {
        let vs = VarnodeSymbol::with_name(loc(), "test");
        assert_eq!(vs.symbol_type(), SymbolType::VarnodeSymbol);
    }

    #[test]
    fn can_access_base_symbol() {
        let vs = VarnodeSymbol::with_name(loc(), "varnode1");
        let sym = vs.symbol();
        assert_eq!(sym.name(), "varnode1");
    }

    #[test]
    fn can_mutate_via_symbol_mut() {
        let mut vs = VarnodeSymbol::with_name(loc(), "initial");
        vs.symbol_mut().set_was_sought(true);
        assert!(vs.symbol().was_sought());
    }
}
