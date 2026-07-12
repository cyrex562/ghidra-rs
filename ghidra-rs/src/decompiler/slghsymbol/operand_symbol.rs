use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::sleigh::grammar::location::Location;

/// An operand symbol in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.OperandSymbol`.
pub struct OperandSymbol {
    symbol: SleighSymbol,
}

impl OperandSymbol {
    /// Creates a new operand symbol at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
        }
    }

    /// Creates a new operand symbol with a name.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
        }
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    /// Returns the symbol type for this operand.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::OperandSymbol
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    #[test]
    fn new_creates_operand() {
        let operand = OperandSymbol::new(loc());
        assert_eq!(operand.symbol_type(), SymbolType::OperandSymbol);
    }

    #[test]
    fn with_name_stores_name() {
        let operand = OperandSymbol::with_name(loc(), "op1");
        assert_eq!(operand.symbol().name(), "op1");
    }

    #[test]
    fn symbol_type_is_operand() {
        let operand = OperandSymbol::new(loc());
        assert_eq!(operand.symbol_type(), SymbolType::OperandSymbol);
    }
}
