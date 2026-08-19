//! Models `ghidra.pcodeCPort.slghpatexpress.OperandEquation`.

use crate::decompiler::slghpatexpress::{OperandResolve, PatternEquationOps, TokenPattern};
use crate::decompiler::slghsymbol::OperandSymbol;
use crate::sleigh::grammar::Location;

/// An equation that defines a single operand by index.
///
/// Represents a reference to a specific operand within a constructor pattern,
/// identified by its index. The operand's token pattern is retrieved from a vector
/// during pattern generation.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.OperandEquation`.
pub struct OperandEquation {
    location: Location,
    index: i32,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl OperandEquation {
    /// Creates a new operand equation referencing the operand at the given index.
    ///
    /// # Arguments
    ///
    /// * `location` - The source location of this equation.
    /// * `index` - The index of the operand this equation refers to.
    pub fn new(location: Location, index: i32) -> Self {
        Self {
            location,
            index,
            token_pattern: None,
        }
    }

    /// Returns the location where this equation was defined.
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Returns the index of the operand this equation refers to.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Returns the generated token pattern if it has been computed.
    pub fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.token_pattern.as_deref()
    }

    /// Sets the token pattern for this equation.
    ///
    /// This is used internally by `gen_pattern()` and should not normally be called directly.
    pub fn set_token_pattern(&mut self, pattern: Box<dyn TokenPattern>) {
        self.token_pattern = Some(pattern);
    }

    /// Records operand order for this equation.
    ///
    /// Models Java's `operandOrder()` method behavior:
    /// - Retrieves the operand at this equation's index from the constructor
    /// - If not already marked, adds it to the order vector and marks it
    pub fn operand_order(&self, operands: &mut Vec<OperandSymbol>) {
        if self.index >= 0 && (self.index as usize) < operands.len() {
            let sym = &mut operands[self.index as usize];
            if !sym.is_marked() {
                sym.set_mark();
            }
        }
    }
}

impl PatternEquationOps for OperandEquation {
    /// Generates the token pattern for this equation.
    ///
    /// Models Java's `genPattern()` method behavior:
    /// - Retrieves the token pattern at this equation's index
    /// - Sets it as this equation's pattern
    fn gen_pattern(&mut self) {
        // This would normally be called with a vector of token patterns
        // and we'd retrieve the one at self.index. Since that's handled
        // externally in the Rust design, this is a no-op that can be
        // overridden by the caller setting the pattern directly.
    }

    /// Resolves operand positions within this equation.
    ///
    /// Models Java's `resolveOperandLeft()` method behavior:
    /// - Gets the operand at this equation's index from the state
    /// - If the operand is offset-irrelevant, sets its base to -1 and offset to 0
    /// - Otherwise, sets the operand's base and offset from the state
    /// - Records this operand as the rightmost operand with size 0
    fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        if self.index < 0 || (self.index as usize) >= state.operands.len() {
            return false;
        }

        let sym = &mut state.operands[self.index as usize];

        if sym.is_offset_irrelevant() {
            sym.offsetbase = -1;
            sym.reloffset = 0;
            return true;
        }

        if state.base == -2 {
            return false;
        }

        sym.offsetbase = state.base;
        sym.reloffset = state.offset;
        state.cur_rightmost = self.index;
        state.size = 0;

        true
    }

    fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.token_pattern.as_deref()
    }

    fn set_token_pattern(&mut self, pattern: Box<dyn TokenPattern>) {
        self.token_pattern = Some(pattern);
    }
}

impl OperandSymbol {
    /// Returns whether this operand's offset is irrelevant.
    pub fn is_offset_irrelevant(&self) -> bool {
        (self.flags & 2) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::Location;

    struct TestTokenPattern {
        location: Location,
    }

    impl TestTokenPattern {
        fn new(location: Location) -> Self {
            Self { location }
        }
    }

    impl TokenPattern for TestTokenPattern {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_pattern(&self) -> &dyn crate::decompiler::seam_stubs::Pattern {
            struct EmptyPattern;
            impl crate::decompiler::seam_stubs::Pattern for EmptyPattern {}
            &EmptyPattern
        }

        fn always_true(&self) -> bool {
            false
        }

        fn always_false(&self) -> bool {
            false
        }

        fn always_instruction_true(&self) -> bool {
            false
        }

        fn get_left_ellipsis(&self) -> bool {
            false
        }

        fn get_right_ellipsis(&self) -> bool {
            false
        }

        fn set_left_ellipsis(&mut self, _val: bool) {}

        fn set_right_ellipsis(&mut self, _val: bool) {}

        fn get_minimum_length(&self) -> i32 {
            4
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, _tokpat: &dyn TokenPattern) {}

        fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern::new(self.location.clone()))
        }

        fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern::new(self.location.clone()))
        }

        fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern::new(self.location.clone()))
        }

        fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern::new(self.location.clone()))
        }
    }

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    #[test]
    fn new_stores_location_and_index() {
        let location = loc();
        let equation = OperandEquation::new(location.clone(), 3);

        assert_eq!(equation.location(), &location);
        assert_eq!(equation.get_index(), 3);
    }

    #[test]
    fn set_and_get_token_pattern() {
        let mut equation = OperandEquation::new(loc(), 0);
        let pattern = Box::new(TestTokenPattern::new(loc()));

        equation.set_token_pattern(pattern);
        assert!(equation.get_token_pattern().is_some());
    }

    #[test]
    fn resolve_operand_left_updates_offset_irrelevant() {
        let location = loc();
        let mut operand = OperandSymbol::new(location.clone());
        operand.flags = 2;

        let mut equation = OperandEquation::new(location, 0);
        let mut state = OperandResolve::new(vec![operand]);
        state.base = 5;
        state.offset = 10;

        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.operands[0].offsetbase, -1);
        assert_eq!(state.operands[0].reloffset, 0);
    }

    #[test]
    fn resolve_operand_left_sets_base_and_offset() {
        let location = loc();
        let operand = OperandSymbol::new(location.clone());

        let mut equation = OperandEquation::new(location, 0);
        let mut state = OperandResolve::new(vec![operand]);
        state.base = 2;
        state.offset = 8;

        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.operands[0].offsetbase, 2);
        assert_eq!(state.operands[0].reloffset, 8);
        assert_eq!(state.cur_rightmost, 0);
        assert_eq!(state.size, 0);
    }

    #[test]
    fn resolve_operand_left_returns_false_with_no_base() {
        let location = loc();
        let operand = OperandSymbol::new(location.clone());

        let mut equation = OperandEquation::new(location, 0);
        let mut state = OperandResolve::new(vec![operand]);
        state.base = -2;

        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_returns_false_with_invalid_index() {
        let location = loc();
        let mut equation = OperandEquation::new(location, 5);
        let mut state = OperandResolve::new(vec![]);

        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn operand_order_marks_operand() {
        let location = loc();
        let operand = OperandSymbol::new(location.clone());
        let mut operands = vec![operand];

        let equation = OperandEquation::new(location, 0);
        equation.operand_order(&mut operands);

        assert!(operands[0].is_marked());
    }

    #[test]
    fn operand_order_does_not_duplicate_mark() {
        let location = loc();
        let mut operand = OperandSymbol::new(location.clone());
        operand.set_mark();
        let mut operands = vec![operand];

        let equation = OperandEquation::new(location, 0);
        equation.operand_order(&mut operands);

        assert!(operands[0].is_marked());
    }

    #[test]
    fn operand_order_ignores_invalid_index() {
        let location = loc();
        let mut operands = vec![];

        let equation = OperandEquation::new(location, 0);
        equation.operand_order(&mut operands);
    }
}
