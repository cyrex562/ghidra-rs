//! Models `ghidra.pcodeCPort.slghpatexpress.ValExpressEquation`.

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::{OperandResolve, PatternValue, TokenPattern};
use crate::sleigh::grammar::Location;

/// An abstract equation for pattern matching against a pattern value and expression.
///
/// ValExpressEquation represents an equation that constrains a pattern value (lhs) to satisfy
/// some relationship with a pattern expression (rhs). It serves as the base class for concrete
/// comparison equations like EqualEquation, LessEquation, etc.
///
/// In Java, the abstract methods `genPattern()` and `resolveOperandLeft()` are inherited from
/// `PatternEquation`. In Rust, these would be implemented by concrete subclasses that wrap
/// this struct.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.ValExpressEquation`.
pub struct ValExpressEquation {
    location: Location,
    lhs: Box<dyn PatternValue>,
    rhs: Box<dyn PatternExpression>,
}

impl ValExpressEquation {
    /// Creates a new value-expression equation with the given operands.
    ///
    /// # Arguments
    ///
    /// * `location` - The source location of this equation.
    /// * `lhs` - The pattern value (left-hand side).
    /// * `rhs` - The pattern expression (right-hand side).
    pub fn new(location: Location, lhs: Box<dyn PatternValue>, rhs: Box<dyn PatternExpression>) -> Self {
        Self { location, lhs, rhs }
    }

    /// Returns a reference to the left-hand side pattern value.
    pub fn get_lhs(&self) -> &dyn PatternValue {
        self.lhs.as_ref()
    }

    /// Returns a reference to the right-hand side pattern expression.
    pub fn get_rhs(&self) -> &dyn PatternExpression {
        self.rhs.as_ref()
    }

    /// Returns the source location of this equation.
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Resolves operand positions and sizes within this equation.
    ///
    /// Sets the initial state for operand resolution:
    /// - `cur_rightmost` is set to -1 (no operand selected yet)
    /// - `size` is set based on ellipsis: -1 if ellipsis present, minimum length otherwise
    ///
    /// This method models the Java behavior of the `resolveOperandLeft()` method.
    /// Subclasses may override this in their own implementations.
    pub fn resolve_operand_left(
        &self,
        token_pattern: &dyn TokenPattern,
        state: &mut OperandResolve,
    ) -> bool {
        state.cur_rightmost = -1;
        if token_pattern.get_left_ellipsis() || token_pattern.get_right_ellipsis() {
            state.size = -1;
        } else {
            state.size = token_pattern.get_minimum_length();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::Pattern;
    use crate::sleigh::grammar::Location;

    struct MockPattern;
    impl Pattern for MockPattern {}

    struct MockTokenPattern {
        location: Location,
        left_ellipsis: bool,
        right_ellipsis: bool,
        min_length: i32,
    }

    impl MockTokenPattern {
        fn new(location: Location) -> Self {
            Self {
                location,
                left_ellipsis: false,
                right_ellipsis: false,
                min_length: 4,
            }
        }
    }

    impl TokenPattern for MockTokenPattern {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_pattern(&self) -> &dyn Pattern {
            &MockPattern
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
            self.left_ellipsis
        }

        fn get_right_ellipsis(&self) -> bool {
            self.right_ellipsis
        }

        fn set_left_ellipsis(&mut self, val: bool) {
            self.left_ellipsis = val;
        }

        fn set_right_ellipsis(&mut self, val: bool) {
            self.right_ellipsis = val;
        }

        fn get_minimum_length(&self) -> i32 {
            self.min_length
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, _tokpat: &dyn TokenPattern) {}

        fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }

        fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }

        fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }

        fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }
    }

    struct MockPatternExpression;
    impl PatternExpression for MockPatternExpression {}

    struct MockPatternValue;
    impl PatternExpression for MockPatternValue {}
    impl PatternValue for MockPatternValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(Location::new("test.sleigh", 1)))
        }

        fn min_value(&self) -> i64 {
            0
        }

        fn max_value(&self) -> i64 {
            100
        }
    }

    #[test]
    fn new_stores_operands() {
        let location = Location::new("test.sleigh", 1);
        let lhs: Box<dyn PatternValue> = Box::new(MockPatternValue);
        let rhs: Box<dyn PatternExpression> = Box::new(MockPatternExpression);

        let equation = ValExpressEquation::new(location.clone(), lhs, rhs);
        assert_eq!(equation.location(), &location);
    }

    #[test]
    fn get_lhs_returns_operand() {
        let location = Location::new("test.sleigh", 1);
        let lhs: Box<dyn PatternValue> = Box::new(MockPatternValue);
        let rhs: Box<dyn PatternExpression> = Box::new(MockPatternExpression);

        let equation = ValExpressEquation::new(location, lhs, rhs);
        let _retrieved_lhs = equation.get_lhs();
    }

    #[test]
    fn get_rhs_returns_operand() {
        let location = Location::new("test.sleigh", 1);
        let lhs: Box<dyn PatternValue> = Box::new(MockPatternValue);
        let rhs: Box<dyn PatternExpression> = Box::new(MockPatternExpression);

        let equation = ValExpressEquation::new(location, lhs, rhs);
        let _retrieved_rhs = equation.get_rhs();
    }

    #[test]
    fn resolve_operand_left_sets_initial_state() {
        let location = Location::new("test.sleigh", 1);
        let lhs: Box<dyn PatternValue> = Box::new(MockPatternValue);
        let rhs: Box<dyn PatternExpression> = Box::new(MockPatternExpression);
        let equation = ValExpressEquation::new(location.clone(), lhs, rhs);

        let mut state = OperandResolve::new(vec![]);
        let token_pattern = MockTokenPattern::new(location);

        let result = equation.resolve_operand_left(&token_pattern, &mut state);
        assert!(result);
        assert_eq!(state.cur_rightmost, -1);
        assert_eq!(state.size, 4); // min_length without ellipsis
    }

    #[test]
    fn resolve_operand_left_with_left_ellipsis_sets_size_negative() {
        let location = Location::new("test.sleigh", 1);
        let lhs: Box<dyn PatternValue> = Box::new(MockPatternValue);
        let rhs: Box<dyn PatternExpression> = Box::new(MockPatternExpression);
        let equation = ValExpressEquation::new(location.clone(), lhs, rhs);

        let mut token_pattern = MockTokenPattern::new(location);
        token_pattern.set_left_ellipsis(true);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&token_pattern, &mut state);

        assert!(result);
        assert_eq!(state.cur_rightmost, -1);
        assert_eq!(state.size, -1);
    }

    #[test]
    fn resolve_operand_left_with_right_ellipsis_sets_size_negative() {
        let location = Location::new("test.sleigh", 1);
        let lhs: Box<dyn PatternValue> = Box::new(MockPatternValue);
        let rhs: Box<dyn PatternExpression> = Box::new(MockPatternExpression);
        let equation = ValExpressEquation::new(location.clone(), lhs, rhs);

        let mut token_pattern = MockTokenPattern::new(location);
        token_pattern.set_right_ellipsis(true);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&token_pattern, &mut state);

        assert!(result);
        assert_eq!(state.cur_rightmost, -1);
        assert_eq!(state.size, -1);
    }
}
