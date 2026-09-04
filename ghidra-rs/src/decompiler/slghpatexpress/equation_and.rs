//! Models `ghidra.pcodeCPort.slghpatexpress.EquationAnd`.

use crate::decompiler::slghpatexpress::{OperandResolve, TokenPattern};
use crate::sleigh::grammar::Location;

/// Trait for pattern equations that can be combined.
///
/// This trait captures the essential interface of `ghidra.pcodeCPort.slghpatexpress.PatternEquation`
/// for use in composite equations like `EquationAnd`.
pub trait PatternEquationOps: Send + Sync {
    /// Generates the token pattern for this equation.
    fn gen_pattern(&mut self);

    /// Resolves operand positions within this equation.
    fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool;

    /// Returns the generated token pattern.
    fn get_token_pattern(&self) -> Option<&dyn TokenPattern>;

    /// Returns a mutable reference to the generated token pattern, if any.
    ///
    /// Needed by wrapper equations (`EquationLeftEllipsis`/`EquationRightEllipsis`) that must
    /// flip a flag (`set_left_ellipsis`/`set_right_ellipsis`) on the *same* pattern object their
    /// wrapped equation already produced, matching Java's `genPattern()`, which mutates the
    /// shared `TokenPattern` reference directly (Java has no immutable/mutable reference
    /// distinction). Defaults to `None`; composite equations that own a `token_pattern` field
    /// override it to expose that field directly.
    fn get_token_pattern_mut(&mut self) -> Option<&mut dyn TokenPattern> {
        None
    }

    /// Sets the token pattern for this equation.
    fn set_token_pattern(&mut self, pattern: Box<dyn TokenPattern>);
}

/// Combines two pattern equations with an AND operation.
///
/// An equation that represents the logical AND of two pattern equations.
/// Both sub-equations must be satisfied for this equation to match.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.EquationAnd`.
pub struct EquationAnd {
    location: Location,
    left: Box<dyn PatternEquationOps>,
    right: Box<dyn PatternEquationOps>,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl EquationAnd {
    /// Creates a new equation that ANDs two pattern equations together.
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

    /// Generates the token pattern for this equation by ANDing the patterns of both operands.
    ///
    /// Models Java's `genPattern()` method behavior:
    /// - Calls genPattern on both left and right operands
    /// - Combines their patterns using doAnd()
    pub fn gen_pattern(&mut self) {
        self.left.gen_pattern();
        self.right.gen_pattern();

        if let (Some(left_pattern), Some(right_pattern)) =
            (self.left.get_token_pattern(), self.right.get_token_pattern())
        {
            let combined = left_pattern.do_and(right_pattern);
            self.set_token_pattern(combined);
        }
    }

    /// Resolves operand positions for this equation.
    ///
    /// This method models Java's `resolveOperandLeft()` behavior:
    /// - First resolves the right operand
    /// - Saves state information from right
    /// - Then resolves the left operand
    /// - Combines state from both operands
    pub fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        let mut cur_rightmost = -1;
        let mut cur_size = -1;

        if !self.right.resolve_operand_left(state) {
            return false;
        }
        if state.cur_rightmost != -1 && state.size != -1 {
            cur_rightmost = state.cur_rightmost;
            cur_size = state.size;
        }

        if !self.left.resolve_operand_left(state) {
            return false;
        }
        if state.cur_rightmost == -1 || state.size == -1 {
            state.cur_rightmost = cur_rightmost;
            state.size = cur_size;
        }

        true
    }
}

impl PatternEquationOps for EquationAnd {
    fn gen_pattern(&mut self) {
        self.gen_pattern()
    }

    fn resolve_operand_left(&self, state: &mut OperandResolve) -> bool {
        self.resolve_operand_left(state)
    }

    fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.get_token_pattern()
    }

    fn get_token_pattern_mut(&mut self) -> Option<&mut dyn TokenPattern> {
        match &mut self.token_pattern { Some(p) => Some(&mut **p), None => None }
    }

    fn set_token_pattern(&mut self, pattern: Box<dyn TokenPattern>) {
        self.set_token_pattern(pattern)
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

        fn get_pattern(&self) -> &dyn crate::decompiler::slghpattern::Pattern {
            struct EmptyPattern;
            impl crate::decompiler::slghpattern::Pattern for EmptyPattern {
        fn simplify_clone(&self) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn shift_instruction(&mut self, _sa: i32) {}
        fn do_or(&self, _b: &dyn crate::decompiler::slghpattern::Pattern, _sa: i32) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn do_and(&self, _b: &dyn crate::decompiler::slghpattern::Pattern, _sa: i32) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn common_sub_pattern(&self, _b: &dyn crate::decompiler::slghpattern::Pattern, _sa: i32) -> Box<dyn crate::decompiler::slghpattern::Pattern> {
            unimplemented!("not exercised by these tests")
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
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
            Ok(())
        }
    }
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

    #[test]
    fn new_stores_location_and_operands() {
        let location = Location::new("test.sleigh", 1);
        let left = Box::new(MockEquation::new());
        let right = Box::new(MockEquation::new());
        let equation = EquationAnd::new(location.clone(), left, right);

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

        let mut equation = EquationAnd::new(
            location.clone(),
            Box::new(left),
            Box::new(right),
        );

        equation.gen_pattern();

        assert!(equation.get_token_pattern().is_some());
    }

    #[test]
    fn resolve_operand_left_delegates_to_operands() {
        let location = Location::new("test.sleigh", 1);
        let left = Box::new(MockEquation::new());
        let right = Box::new(MockEquation::new());
        let equation = EquationAnd::new(location, left, right);

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
        let equation = EquationAnd::new(location, left, right);

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
        let equation = EquationAnd::new(location, left, right);

        let mut state = OperandResolve::new(vec![]);
        let result = equation.resolve_operand_left(&mut state);

        assert!(!result);
    }

    #[test]
    fn resolve_operand_left_preserves_rightmost_from_right() {
        let location = Location::new("test.sleigh", 1);
        let left = Box::new(MockEquation::new());
        let right = Box::new(MockEquation::new());
        let equation = EquationAnd::new(location, left, right);

        let mut state = OperandResolve::new(vec![]);
        state.cur_rightmost = 5;
        state.size = 10;

        equation.resolve_operand_left(&mut state);

        assert_eq!(state.cur_rightmost, 5);
        assert_eq!(state.size, 10);
    }

    /// Regression test for a real bug found while porting `Constructor`: none of the composite
    /// equation types (`EquationAnd`/`Or`/`Cat`/`LeftEllipsis`/`RightEllipsis`) actually
    /// implemented `PatternEquationOps` -- they only had matching inherent methods -- so a
    /// composite equation could never be nested inside another one (`(a & b) & c` couldn't be
    /// constructed at all, since `EquationAnd::new` requires `Box<dyn PatternEquationOps>` for
    /// its operands). This proves an `EquationAnd` now satisfies that bound and that a doubly
    /// nested AND correctly combines all three leaves' patterns.
    #[test]
    fn equation_and_can_be_nested_inside_another_equation_and() {
        let location = Location::new("test.sleigh", 1);

        let mut inner_left = MockEquation::new();
        inner_left.set_token_pattern(Box::new(TestTokenPattern::new(location.clone())));
        let mut inner_right = MockEquation::new();
        inner_right.set_token_pattern(Box::new(TestTokenPattern::new(location.clone())));

        let inner: Box<dyn PatternEquationOps> = Box::new(EquationAnd::new(
            location.clone(),
            Box::new(inner_left),
            Box::new(inner_right),
        ));

        let mut outer_right = MockEquation::new();
        outer_right.set_token_pattern(Box::new(TestTokenPattern::new(location.clone())));

        let mut outer = EquationAnd::new(location, inner, Box::new(outer_right));
        outer.gen_pattern();

        // Only reachable if the inner EquationAnd genuinely satisfies Box<dyn
        // PatternEquationOps> (the bug: it didn't) *and* its own gen_pattern actually ran and
        // combined its two leaves, since the outer AND only combines patterns when both sides
        // report Some.
        assert!(outer.get_token_pattern().is_some());
    }
}
