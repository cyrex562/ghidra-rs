use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::sleigh::grammar::location::Location;

/// A symbol representing a global varnode in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.VarnodeSymbol`.
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
