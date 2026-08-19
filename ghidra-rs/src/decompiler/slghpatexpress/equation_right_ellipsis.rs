//! Models `ghidra.pcodeCPort.slghpatexpress.EquationRightEllipsis`.

use crate::decompiler::slghpatexpress::{OperandResolve, PatternEquationOps, TokenPattern};
use crate::sleigh::grammar::Location;

/// Represents a pattern equation followed by ellipses.
///
/// A wrapper equation that generates a token pattern with the right ellipsis flag set.
/// This allows tokens to match past the right end of the pattern.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.EquationRightEllipsis`.
pub struct EquationRightEllipsis {
    location: Location,
    eq: Box<dyn PatternEquationOps>,
}

impl EquationRightEllipsis {
    /// Creates a new equation followed by right ellipsis.
    ///
    /// # Arguments
    ///
    /// * `location` - The source location of this equation.
    /// * `eq` - The wrapped pattern equation.
    pub fn new(location: Location, eq: Box<dyn PatternEquationOps>) -> Self {
        Self { location, eq }
    }

    /// Returns the location where this equation was defined.
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Returns a reference to the wrapped equation.
    pub fn get_equation(&self) -> &dyn PatternEquationOps {
        self.eq.as_ref()
    }

    /// Returns the generated token pattern from the wrapped equation.
    ///
    /// The pattern is guaranteed to have right_ellipsis set to true after gen_pattern is called.
    pub fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.eq.get_token_pattern()
    }

    /// Generates the token pattern for this equation with right ellipsis set.
    ///
    /// Models Java's `genPattern()` method behavior:
    /// - Calls genPattern on the wrapped equation
    /// - Sets the right ellipsis flag on the resulting pattern
    pub fn gen_pattern(&mut self) {
        self.eq.gen_pattern();

        if let Some(eq_pattern) = self.eq.get_token_pattern() {
            let pattern_ptr = eq_pattern as *const dyn TokenPattern as *mut dyn TokenPattern;
            unsafe {
                (*pattern_ptr).set_right_ellipsis(true);
            }
        }
    }

    /// Resolves operand positions for this equation.
    ///
    /// This method models Java's `resolveOperandLeft()` behavior:
    /// - Resolves operands in the wrapped equation
    /// - Sets size to -1 (indicating size cannot be predicted)
    pub fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        let res = self.eq.resolve_operand_left(state);
        if !res {
            return false;
        }
        state.size = -1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEquation {
        token_pattern: Option<Box<dyn TokenPattern>>,
    }

    impl MockEquation {
        fn new() -> Self {
            Self {
                token_pattern: None,
            }
        }
    }

    impl PatternEquationOps for MockEquation {
        fn gen_pattern(&mut self) {}

        fn resolve_operand_left(&self, _state: &mut OperandResolve) -> bool {
            true
        }

        fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
            self.token_pattern.as_deref()
        }

        fn set_token_pattern(&mut self, pattern: Box<dyn TokenPattern>) {
            self.token_pattern = Some(pattern);
        }
    }

    struct TestTokenPattern {
        location: Location,
        right_ellipsis: bool,
    }

    impl TestTokenPattern {
        fn new(location: Location) -> Self {
            Self {
                location,
                right_ellipsis: false,
            }
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
            self.right_ellipsis
        }

        fn set_left_ellipsis(&mut self, _val: bool) {}

        fn set_right_ellipsis(&mut self, val: bool) {
            self.right_ellipsis = val;
        }

        fn get_minimum_length(&self) -> i32 {
            4
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, tokpat: &dyn TokenPattern) {
            self.right_ellipsis = tokpat.get_right_ellipsis();
        }

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

    #[test]
    fn new_stores_location_and_equation() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let equation = EquationRightEllipsis::new(location.clone(), eq);

        assert_eq!(equation.location(), &location);
    }

    #[test]
    fn gen_pattern_sets_right_ellipsis_on_wrapped_pattern() {
        let location = Location::new("test.sleigh", 1);
        let mut eq = MockEquation::new();
        let test_pattern = TestTokenPattern::new(location.clone());
        assert!(!test_pattern.get_right_ellipsis());
        eq.set_token_pattern(Box::new(test_pattern));

        let mut equation = EquationRightEllipsis::new(location, Box::new(eq));
        equation.gen_pattern();

        assert!(equation.get_token_pattern().is_some());
        let pattern = equation.get_token_pattern().unwrap();
        assert!(pattern.get_right_ellipsis());
    }

    #[test]
    fn gen_pattern_delegates_to_wrapped_equation() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let mut equation = EquationRightEllipsis::new(location, eq);

        equation.gen_pattern();
    }

    #[test]
    fn resolve_operand_left_delegates_to_wrapped_equation() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let equation = EquationRightEllipsis::new(location, eq);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
    }

    #[test]
    fn resolve_operand_left_sets_size_to_negative_one() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let equation = EquationRightEllipsis::new(location, eq);

        let mut state = OperandResolve::new(vec![]);
        state.size = 42;
        equation.resolve_operand_left(&mut state);

        assert_eq!(state.size, -1);
    }

    #[test]
    fn resolve_operand_left_returns_false_on_wrapped_failure() {
        let location = Location::new("test.sleigh", 1);

        struct FailingEquation;
        impl PatternEquationOps for FailingEquation {
            fn gen_pattern(&mut self) {}
            fn resolve_operand_left(&self, _state: &mut OperandResolve) -> bool {
                false
            }
            fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
                None
            }
            fn set_token_pattern(&mut self, _pattern: Box<dyn TokenPattern>) {}
        }

        let equation = EquationRightEllipsis::new(location, Box::new(FailingEquation));

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_does_not_modify_size_on_failure() {
        let location = Location::new("test.sleigh", 1);

        struct FailingEquation;
        impl PatternEquationOps for FailingEquation {
            fn gen_pattern(&mut self) {}
            fn resolve_operand_left(&self, _state: &mut OperandResolve) -> bool {
                false
            }
            fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
                None
            }
            fn set_token_pattern(&mut self, _pattern: Box<dyn TokenPattern>) {}
        }

        let equation = EquationRightEllipsis::new(location, Box::new(FailingEquation));

        let mut state = OperandResolve::new(vec![]);
        state.size = 42;
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
        assert_eq!(state.size, 42);
    }
}
