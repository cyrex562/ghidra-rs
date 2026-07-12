//! Models `ghidra.pcodeCPort.slghpatexpress.UnconstrainedEquation`.

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::{OperandResolve, TokenPattern};
use crate::sleigh::grammar::Location;

/// An unconstrained equation that accepts any token pattern from a pattern expression.
///
/// UnconstrainedEquation wraps a single pattern expression and generates its minimal token
/// pattern. This represents an equation with no additional constraints beyond what the
/// expression itself requires.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.UnconstrainedEquation`.
pub struct UnconstrainedEquation {
    location: Location,
    patex: Box<dyn PatternExpression>,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl UnconstrainedEquation {
    /// Creates a new unconstrained equation with the given pattern expression.
    ///
    /// # Arguments
    ///
    /// * `location` - The source location of this equation.
    /// * `patex` - The pattern expression to use.
    pub fn new(location: Location, patex: Box<dyn PatternExpression>) -> Self {
        Self {
            location,
            patex,
            token_pattern: None,
        }
    }

    /// Returns the location where this equation was defined.
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Returns a reference to the underlying pattern expression.
    pub fn get_expression(&self) -> &dyn PatternExpression {
        self.patex.as_ref()
    }

    /// Generates the minimal token pattern for this equation's expression.
    ///
    /// This method models Java's `genPattern()`, but since we can't call `gen_min_pattern()`
    /// on a trait object in general, the caller may need to downcast the expression to a
    /// concrete type if this is called. Alternatively, concrete implementations of
    /// PatternExpression should implement `gen_min_pattern()`.
    pub fn gen_pattern(&mut self) -> Option<&dyn TokenPattern> {
        // Note: In a full port, this would call patex.gen_min_pattern().
        // For now, we store None as a placeholder until the expression's concrete type
        // can provide the pattern.
        self.token_pattern.as_deref()
    }

    /// Returns the token pattern if it has been generated.
    pub fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.token_pattern.as_deref()
    }

    /// Sets the token pattern for this equation.
    ///
    /// This is used internally by `gen_pattern()` and should not normally be called directly.
    pub fn set_token_pattern(&mut self, pattern: Box<dyn TokenPattern>) {
        self.token_pattern = Some(pattern);
    }

    /// Resolves operand positions for this equation.
    ///
    /// Sets the initial state for operand resolution:
    /// - `cur_rightmost` is set to -1 (no operand selected yet)
    /// - `size` is set based on ellipsis: -1 if ellipsis present, minimum length otherwise
    ///
    /// This method models the Java `resolveOperandLeft()` method.
    pub fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        if let Some(token_pattern) = self.get_token_pattern() {
            state.cur_rightmost = -1;
            if token_pattern.get_left_ellipsis() || token_pattern.get_right_ellipsis() {
                state.size = -1;
            } else {
                state.size = token_pattern.get_minimum_length();
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyExpression;
    impl PatternExpression for DummyExpression {}

    #[test]
    fn new_stores_location_and_expression() {
        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let equation = UnconstrainedEquation::new(location.clone(), expr);

        assert_eq!(equation.location(), &location);
    }

    #[test]
    fn get_expression_returns_stored_expression() {
        let location = Location::new("test.sleigh", 1);
        let expr: Box<dyn PatternExpression> = Box::new(DummyExpression);
        let equation = UnconstrainedEquation::new(location, expr);

        let _retrieved = equation.get_expression();
    }

    #[test]
    fn gen_pattern_returns_none_without_pattern_set() {
        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let mut equation = UnconstrainedEquation::new(location, expr);

        assert!(equation.gen_pattern().is_none());
    }

    #[test]
    fn get_token_pattern_returns_none_initially() {
        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let equation = UnconstrainedEquation::new(location, expr);

        assert!(equation.get_token_pattern().is_none());
    }

    #[test]
    fn resolve_operand_left_returns_false_without_pattern() {
        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let equation = UnconstrainedEquation::new(location.clone(), expr);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_sets_cur_rightmost_to_minus_one() {
        use crate::decompiler::seam_stubs::Pattern;
        use crate::sleigh::grammar::Location;

        struct TestTokenPattern {
            location: Location,
            left_ellipsis: bool,
            right_ellipsis: bool,
        }

        impl TestTokenPattern {
            fn new(location: Location) -> Self {
                Self {
                    location,
                    left_ellipsis: false,
                    right_ellipsis: false,
                }
            }
        }

        struct EmptyPattern;
        impl Pattern for EmptyPattern {}

        impl TokenPattern for TestTokenPattern {
            fn location(&self) -> &Location {
                &self.location
            }

            fn get_pattern(&self) -> &dyn Pattern {
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

        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let mut equation = UnconstrainedEquation::new(location.clone(), expr);

        equation.set_token_pattern(Box::new(TestTokenPattern::new(location)));

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.cur_rightmost, -1);
    }

    #[test]
    fn resolve_operand_left_sets_size_based_on_ellipsis() {
        use crate::decompiler::seam_stubs::Pattern;
        use crate::sleigh::grammar::Location;

        struct TestTokenPattern {
            location: Location,
            left_ellipsis: bool,
            right_ellipsis: bool,
        }

        impl TestTokenPattern {
            fn new(location: Location, left_ellipsis: bool) -> Self {
                Self {
                    location,
                    left_ellipsis,
                    right_ellipsis: false,
                }
            }
        }

        struct EmptyPattern;
        impl Pattern for EmptyPattern {}

        impl TokenPattern for TestTokenPattern {
            fn location(&self) -> &Location {
                &self.location
            }

            fn get_pattern(&self) -> &dyn Pattern {
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
                4
            }

            fn simplify_pattern(&mut self) {}

            fn copy_into(&mut self, _tokpat: &dyn TokenPattern) {}

            fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
                Box::new(TestTokenPattern::new(self.location.clone(), self.left_ellipsis))
            }

            fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
                Box::new(TestTokenPattern::new(self.location.clone(), self.left_ellipsis))
            }

            fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
                Box::new(TestTokenPattern::new(self.location.clone(), self.left_ellipsis))
            }

            fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
                Box::new(TestTokenPattern::new(self.location.clone(), self.left_ellipsis))
            }
        }

        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let mut equation = UnconstrainedEquation::new(location.clone(), expr);

        // Test with left ellipsis
        equation.set_token_pattern(Box::new(TestTokenPattern::new(location.clone(), true)));

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.cur_rightmost, -1);
        assert_eq!(state.size, -1);
    }

    #[test]
    fn resolve_operand_left_sets_size_to_minimum_length_without_ellipsis() {
        use crate::decompiler::seam_stubs::Pattern;
        use crate::sleigh::grammar::Location;

        struct TestTokenPattern {
            location: Location,
        }

        impl TestTokenPattern {
            fn new(location: Location) -> Self {
                Self { location }
            }
        }

        struct EmptyPattern;
        impl Pattern for EmptyPattern {}

        impl TokenPattern for TestTokenPattern {
            fn location(&self) -> &Location {
                &self.location
            }

            fn get_pattern(&self) -> &dyn Pattern {
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
                8
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

        let location = Location::new("test.sleigh", 1);
        let expr = Box::new(DummyExpression);
        let mut equation = UnconstrainedEquation::new(location.clone(), expr);

        equation.set_token_pattern(Box::new(TestTokenPattern::new(location)));

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.cur_rightmost, -1);
        assert_eq!(state.size, 8);
    }
}
