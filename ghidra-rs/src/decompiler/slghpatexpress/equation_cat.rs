//! Models `ghidra.pcodeCPort.slghpatexpress.EquationCat`.

use crate::decompiler::slghpatexpress::{OperandResolve, PatternEquationOps, TokenPattern};
use crate::sleigh::grammar::Location;

/// Concatenates two pattern equations.
///
/// An equation that represents the concatenation of two pattern equations, where the
/// left equation's pattern occupies the leading bytes and the right equation's pattern
/// follows immediately after.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.EquationCat`.
pub struct EquationCat {
    location: Location,
    left: Box<dyn PatternEquationOps>,
    right: Box<dyn PatternEquationOps>,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl EquationCat {
    /// Creates a new equation that concatenates two pattern equations.
    ///
    /// # Arguments
    ///
    /// * `location` - The source location of this equation.
    /// * `left` - The left pattern equation operand.
    /// * `right` - The right pattern equation operand.
    pub fn new(
        location: Location,
        left: Box<dyn PatternEquationOps>,
        right: Box<dyn PatternEquationOps>,
    ) -> Self {
        Self {
            location,
            left,
            right,
            token_pattern: None,
        }
    }

    /// Returns the location where this equation was defined.
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Returns a reference to the left operand.
    pub fn get_left(&self) -> &dyn PatternEquationOps {
        self.left.as_ref()
    }

    /// Returns a reference to the right operand.
    pub fn get_right(&self) -> &dyn PatternEquationOps {
        self.right.as_ref()
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

    /// Generates the token pattern for this equation by concatenating the patterns of both
    /// operands.
    ///
    /// Models Java's `genPattern()` method behavior:
    /// - Calls genPattern on both left and right operands
    /// - Combines their patterns using doCat()
    pub fn gen_pattern(&mut self) {
        self.left.gen_pattern();
        self.right.gen_pattern();

        if let (Some(left_pattern), Some(right_pattern)) =
            (self.left.get_token_pattern(), self.right.get_token_pattern())
        {
            let combined = left_pattern.do_cat(right_pattern);
            self.set_token_pattern(combined);
        }
    }

    /// Resolves operand positions for this equation.
    ///
    /// This method models Java's `resolveOperandLeft()` behavior:
    /// - First resolves the left operand
    /// - Advances the offset past the left operand's pattern (or re-anchors on the
    ///   rightmost operand seen so far if the left pattern has an ellipsis)
    /// - Then resolves the right operand
    /// - Restores the base and offset, and combines rightmost/size state from both operands
    pub fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        if !self.left.resolve_operand_left(state) {
            return false;
        }
        let cur_base = state.base;
        let cur_offset = state.offset;

        if let Some(left_pattern) = self.left.get_token_pattern() {
            if !left_pattern.get_left_ellipsis() && !left_pattern.get_right_ellipsis() {
                // Keep the same base, but add to its size.
                state.offset += left_pattern.get_minimum_length();
            } else if state.cur_rightmost != -1 {
                state.base = state.cur_rightmost;
                state.offset = state.size;
            } else if state.size != -1 {
                state.offset += state.size;
            } else {
                state.base = -2; // We have no anchor
            }
        }

        let cur_rightmost = state.cur_rightmost;
        let cur_size = state.size;

        if !self.right.resolve_operand_left(state) {
            return false;
        }
        state.base = cur_base; // Restore base and offset
        state.offset = cur_offset;
        if state.cur_rightmost == -1
            && state.size != -1
            && cur_rightmost != -1
            && cur_size != -1
        {
            state.cur_rightmost = cur_rightmost;
            state.size += cur_size;
        }

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
        right_ellipsis: bool,
        minimum_length: i32,
    }

    impl TestTokenPattern {
        fn new(location: Location) -> Self {
            Self {
                location,
                left_ellipsis: false,
                right_ellipsis: false,
                minimum_length: 4,
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
            self.right_ellipsis
        }

        fn set_left_ellipsis(&mut self, val: bool) {
            self.left_ellipsis = val;
        }

        fn set_right_ellipsis(&mut self, val: bool) {
            self.right_ellipsis = val;
        }

        fn get_minimum_length(&self) -> i32 {
            self.minimum_length
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

    #[test]
    fn new_stores_location_and_operands() {
        let location = Location::new("test.sleigh", 1);
        let left = Box::new(MockEquation::new());
        let right = Box::new(MockEquation::new());
        let equation = EquationCat::new(location.clone(), left, right);

        assert_eq!(equation.location(), &location);
    }

    #[test]
    fn gen_pattern_combines_operand_patterns() {
        let location = Location::new("test.sleigh", 1);
        let mut left = MockEquation::new();
        let mut right = MockEquation::new();

        let test_pattern = Box::new(TestTokenPattern::new(location.clone()));
        left.set_token_pattern(test_pattern);
        let test_pattern = Box::new(TestTokenPattern::new(location.clone()));
        right.set_token_pattern(test_pattern);

        let mut equation = EquationCat::new(location.clone(), Box::new(left), Box::new(right));

        equation.gen_pattern();

        assert!(equation.get_token_pattern().is_some());
    }

    #[test]
    fn resolve_operand_left_delegates_to_operands() {
        let location = Location::new("test.sleigh", 1);
        let left = Box::new(MockEquation::new());
        let right = Box::new(MockEquation::new());
        let equation = EquationCat::new(location, left, right);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
    }

    #[test]
    fn resolve_operand_left_returns_false_on_left_failure() {
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

        let left = Box::new(FailingEquation);
        let right = Box::new(MockEquation::new());
        let equation = EquationCat::new(location, left, right);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_returns_false_on_right_failure() {
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

        let left = Box::new(MockEquation::new());
        let right = Box::new(FailingEquation);
        let equation = EquationCat::new(location, left, right);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_advances_offset_by_left_minimum_length() {
        let location = Location::new("test.sleigh", 1);
        let mut left = MockEquation::new();
        left.set_token_pattern(Box::new(TestTokenPattern::new(location.clone())));
        let right = MockEquation::new();

        let equation = EquationCat::new(location, Box::new(left), Box::new(right));

        let mut state = OperandResolve::new(vec![]);
        state.offset = 2;
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        // Offset is restored to its pre-call value after the call completes.
        assert_eq!(state.offset, 2);
    }

    #[test]
    fn resolve_operand_left_sets_no_anchor_when_left_has_ellipsis_and_no_state() {
        let location = Location::new("test.sleigh", 1);
        let mut left_pattern = TestTokenPattern::new(location.clone());
        left_pattern.left_ellipsis = true;
        let mut left = MockEquation::new();
        left.set_token_pattern(Box::new(left_pattern));
        let right = MockEquation::new();

        let equation = EquationCat::new(location, Box::new(left), Box::new(right));

        let mut state = OperandResolve::new(vec![]);
        state.cur_rightmost = -1;
        state.size = -1;
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        // base is restored to its pre-call value (-1) after the call completes.
        assert_eq!(state.base, -1);
    }

    #[test]
    fn resolve_operand_left_combines_rightmost_and_size_from_both_operands() {
        let location = Location::new("test.sleigh", 1);

        struct RightmostEquation {
            rightmost: i32,
            size: i32,
        }
        impl PatternEquationOps for RightmostEquation {
            fn gen_pattern(&mut self) {}
            fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
                state.cur_rightmost = self.rightmost;
                state.size = self.size;
                true
            }
            fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
                None
            }
            fn set_token_pattern(&mut self, _pattern: Box<dyn TokenPattern>) {}
        }

        let left = Box::new(RightmostEquation {
            rightmost: 3,
            size: 4,
        });
        let right = Box::new(RightmostEquation {
            rightmost: -1,
            size: 5,
        });
        let equation = EquationCat::new(location, left, right);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(result);
        assert_eq!(state.cur_rightmost, 3);
        assert_eq!(state.size, 9);
    }
}
