use super::operand_symbol::OperandSymbol;
use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::sleigh::grammar::location::Location;

/// A macro symbol in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.MacroSymbol`.
pub struct MacroSymbol {
    symbol: SleighSymbol,
    index: i32,
    construct: Option<ConstructTpl>,
    operands: Vec<OperandSymbol>,
}

impl MacroSymbol {
    /// Creates a new macro symbol at the given location with the given index.
    pub fn new(location: Location, name: impl Into<String>, index: i32) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            index,
            construct: None,
            operands: Vec::new(),
        }
    }

    /// Gets the index of this macro.
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Sets the construct template for this macro.
    pub fn set_construct(&mut self, construct: ConstructTpl) {
        self.construct = Some(construct);
    }

    /// Gets the construct template for this macro.
    pub fn construct(&self) -> Option<&ConstructTpl> {
        self.construct.as_ref()
    }

    /// Adds an operand to this macro.
    pub fn add_operand(&mut self, operand: OperandSymbol) {
        self.operands.push(operand);
    }

    /// Gets the number of operands.
    pub fn num_operands(&self) -> usize {
        self.operands.len()
    }

    /// Gets a reference to the operand at the given index.
    pub fn operand(&self, index: usize) -> Option<&OperandSymbol> {
        self.operands.get(index)
    }

    /// Gets a mutable reference to the operand at the given index.
    pub fn operand_mut(&mut self, index: usize) -> Option<&mut OperandSymbol> {
        self.operands.get_mut(index)
    }

    /// Returns the symbol type for this macro.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::MacroSymbol
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

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    #[test]
    fn new_initializes_fields() {
        let macro_sym = MacroSymbol::new(loc(), "test_macro", 42);
        assert_eq!(macro_sym.symbol().name(), "test_macro");
        assert_eq!(macro_sym.index(), 42);
        assert!(macro_sym.construct().is_none());
        assert_eq!(macro_sym.num_operands(), 0);
    }

    #[test]
    fn add_operand() {
        let mut macro_sym = MacroSymbol::new(loc(), "macro", 1);
        assert_eq!(macro_sym.num_operands(), 0);

        let op = OperandSymbol::with_name(loc(), "op1");
        macro_sym.add_operand(op);
        assert_eq!(macro_sym.num_operands(), 1);

        let op2 = OperandSymbol::with_name(loc(), "op2");
        macro_sym.add_operand(op2);
        assert_eq!(macro_sym.num_operands(), 2);
    }

    #[test]
    fn get_operand() {
        let mut macro_sym = MacroSymbol::new(loc(), "macro", 1);
        let op = OperandSymbol::with_name(loc(), "op1");
        macro_sym.add_operand(op);

        assert!(macro_sym.operand(0).is_some());
        assert_eq!(macro_sym.operand(0).unwrap().symbol().name(), "op1");
        assert!(macro_sym.operand(1).is_none());
    }

    #[test]
    fn symbol_type() {
        let macro_sym = MacroSymbol::new(loc(), "macro", 1);
        assert_eq!(macro_sym.symbol_type(), SymbolType::MacroSymbol);
    }

    #[test]
    fn construct_operations() {
        let mut macro_sym = MacroSymbol::new(loc(), "macro", 1);
        assert!(macro_sym.construct().is_none());

        let construct = ConstructTpl::new();
        macro_sym.set_construct(construct);
        assert!(macro_sym.construct().is_some());
    }

    #[test]
    fn operand_mut() {
        let mut macro_sym = MacroSymbol::new(loc(), "macro", 1);
        let op = OperandSymbol::with_name(loc(), "op1");
        macro_sym.add_operand(op);

        if let Some(operand) = macro_sym.operand_mut(0) {
            // Verify we got a mutable reference
            let _ = operand.symbol_mut();
        }
        assert!(macro_sym.operand_mut(0).is_some());
        assert!(macro_sym.operand_mut(1).is_none());
    }

    #[test]
    fn multiple_macros_with_different_indices() {
        let macro1 = MacroSymbol::new(loc(), "macro1", 10);
        let macro2 = MacroSymbol::new(loc(), "macro2", 20);

        assert_eq!(macro1.index(), 10);
        assert_eq!(macro2.index(), 20);
    }
}
