use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::sleigh::grammar::location::Location;

const MARKED_FLAG: u32 = 8;

/// An operand symbol in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.OperandSymbol`.
pub struct OperandSymbol {
    symbol: SleighSymbol,
    pub flags: u32,
    pub reloffset: i32,
    pub offsetbase: i32,
}

impl OperandSymbol {
    /// Creates a new operand symbol at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
            flags: 0,
            reloffset: 0,
            offsetbase: 0,
        }
    }

    /// Creates a new operand symbol with a name.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            flags: 0,
            reloffset: 0,
            offsetbase: 0,
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

    /// Marks this operand symbol.
    pub fn set_mark(&mut self) {
        self.flags |= MARKED_FLAG;
    }

    /// Clears the mark on this operand symbol.
    pub fn clear_mark(&mut self) {
        self.flags &= !MARKED_FLAG;
    }

    /// Returns whether this operand symbol is marked.
    pub fn is_marked(&self) -> bool {
        (self.flags & MARKED_FLAG) != 0
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

    #[test]
    fn mark_sets_and_checks_marked_flag() {
        let mut operand = OperandSymbol::new(loc());
        assert!(!operand.is_marked());
        operand.set_mark();
        assert!(operand.is_marked());
    }

    #[test]
    fn clear_mark_removes_marked_flag() {
        let mut operand = OperandSymbol::new(loc());
        operand.set_mark();
        assert!(operand.is_marked());
        operand.clear_mark();
        assert!(!operand.is_marked());
    }

    #[test]
    fn offsets_are_mutable() {
        let mut operand = OperandSymbol::new(loc());
        operand.reloffset = 5;
        operand.offsetbase = 10;
        assert_eq!(operand.reloffset, 5);
        assert_eq!(operand.offsetbase, 10);
    }
}
