//! Models `ghidra.pcodeCPort.slghpatexpress.EquationLeftEllipsis`.

use crate::decompiler::slghpatexpress::{OperandResolve, PatternEquationOps, TokenPattern};
use crate::sleigh::grammar::Location;

/// Represents a pattern equation preceded by ellipses.
///
/// A wrapper equation that generates a token pattern with the left ellipsis flag set.
/// This allows tokens to match past the left end of the pattern.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.EquationLeftEllipsis`.
pub struct EquationLeftEllipsis {
    location: Location,
    eq: Box<dyn PatternEquationOps>,
}

impl EquationLeftEllipsis {
    /// Creates a new equation preceded by left ellipsis.
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
    /// The pattern is guaranteed to have left_ellipsis set to true after gen_pattern is called.
    pub fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.eq.get_token_pattern()
    }

    /// Generates the token pattern for this equation with left ellipsis set.
    ///
    /// Models Java's `genPattern()` method behavior:
    /// - Calls genPattern on the wrapped equation
    /// - Sets the left ellipsis flag on the resulting pattern
    pub fn gen_pattern(&mut self) {
        self.eq.gen_pattern();

        if let Some(eq_pattern) = self.eq.get_token_pattern() {
            let pattern_ptr = eq_pattern as *const dyn TokenPattern as *mut dyn TokenPattern;
            unsafe {
                (*pattern_ptr).set_left_ellipsis(true);
            }
        }
    }

    /// Resolves operand positions for this equation.
    ///
    /// This method models Java's `resolveOperandLeft()` behavior:
    /// - Saves the current base
    /// - Temporarily sets base to -2 (indicating no anchor)
    /// - Resolves operands in the wrapped equation
    /// - Restores the original base
    pub fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        let cur_base = state.base;
        state.base = -2;
        let res = self.eq.resolve_operand_left(state);
        if !res {
            return false;
        }
        state.base = cur_base;
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
        left_ellipsis: bool,
    }

    impl TestTokenPattern {
        fn new(location: Location) -> Self {
            Self {
                location,
                left_ellipsis: false,
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
            self.left_ellipsis
        }

        fn get_right_ellipsis(&self) -> bool {
            false
        }

        fn set_left_ellipsis(&mut self, val: bool) {
            self.left_ellipsis = val;
        }

        fn set_right_ellipsis(&mut self, _val: bool) {}

        fn get_minimum_length(&self) -> i32 {
            4
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, tokpat: &dyn TokenPattern) {
            self.left_ellipsis = tokpat.get_left_ellipsis();
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
        let equation = EquationLeftEllipsis::new(location.clone(), eq);

        assert_eq!(equation.location(), &location);
    }

    #[test]
    fn gen_pattern_sets_left_ellipsis_on_wrapped_pattern() {
        let location = Location::new("test.sleigh", 1);
        let mut eq = MockEquation::new();
        let mut test_pattern = TestTokenPattern::new(location.clone());
        assert!(!test_pattern.get_left_ellipsis());
        eq.set_token_pattern(Box::new(test_pattern));

        let mut equation = EquationLeftEllipsis::new(location, Box::new(eq));
        equation.gen_pattern();

        assert!(equation.get_token_pattern().is_some());
        let pattern = equation.get_token_pattern().unwrap();
        assert!(pattern.get_left_ellipsis());
    }

    #[test]
    fn gen_pattern_delegates_to_wrapped_equation() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let mut equation = EquationLeftEllipsis::new(location, eq);

        equation.gen_pattern();
    }

    #[test]
    fn resolve_operand_left_delegates_to_wrapped_equation() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let equation = EquationLeftEllipsis::new(location, eq);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
    }

    #[test]
    fn resolve_operand_left_sets_base_to_negative_two() {
        let location = Location::new("test.sleigh", 1);

        struct TrackingEquation {
            observed_base: std::sync::atomic::AtomicI32,
            token_pattern: Option<Box<dyn TokenPattern>>,
        }

        impl PatternEquationOps for TrackingEquation {
            fn gen_pattern(&mut self) {}

            fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
                self.observed_base
                    .store(state.base, std::sync::atomic::Ordering::SeqCst);
                true
            }

            fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
                self.token_pattern.as_deref()
            }

            fn set_token_pattern(&mut self, _pattern: Box<dyn TokenPattern>) {}
        }

        let tracking_eq = TrackingEquation {
            observed_base: std::sync::atomic::AtomicI32::new(0),
            token_pattern: None,
        };

        let equation = EquationLeftEllipsis::new(location, Box::new(tracking_eq));

        let mut state = OperandResolve::new(vec![]);
        state.base = 5;
        equation.resolve_operand_left(&mut state);

        assert_eq!(state.base, 5);
    }

    #[test]
    fn resolve_operand_left_restores_base_on_success() {
        let location = Location::new("test.sleigh", 1);
        let eq = Box::new(MockEquation::new());
        let equation = EquationLeftEllipsis::new(location, eq);

        let mut state = OperandResolve::new(vec![]);
        state.base = 7;
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.base, 7);
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

        let equation = EquationLeftEllipsis::new(location, Box::new(FailingEquation));

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_does_not_restore_base_on_failure() {
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

        let equation = EquationLeftEllipsis::new(location, Box::new(FailingEquation));

        let mut state = OperandResolve::new(vec![]);
        state.base = 5;
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
        assert_eq!(state.base, -2);
    }
}
