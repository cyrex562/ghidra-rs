//! Models `ghidra.pcodeCPort.slghpatexpress.GreaterEqualEquation`.

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::comparison_equation::gen_comparison_pattern;
use crate::decompiler::slghpatexpress::val_express_equation::ValExpressEquation;
use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::sleigh::grammar::Location;

/// An equation that constrains a pattern value to be greater than or equal to one of the
/// values its right-hand pattern expression can take on.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.GreaterEqualEquation`, which extends
/// `ValExpressEquation` and overrides only `genPattern()`. Exposed as a trait for the same
/// reason as [`EqualEquation`](super::equal_equation::EqualEquation): callers can depend on
/// "something that behaves like a greater-or-equal-constraint equation" without pulling in a
/// specific implementation.
pub trait GreaterEqualEquation: Send + Sync {
    /// Generates (and stores) the token pattern constraining this equation's left-hand pattern
    /// value to be `>=` at least one value the right-hand expression can take on.
    ///
    /// # Panics
    /// Panics with a [`crate::decompiler::context::SleighError`] if no `lhsval` in range ever
    /// satisfies the constraint against any combination of the right-hand expression's values.
    fn gen_pattern(&mut self);

    /// Returns the token pattern computed by the most recent
    /// [`GreaterEqualEquation::gen_pattern`] call, if any.
    fn get_token_pattern(&self) -> Option<&dyn TokenPattern>;
}

/// The concrete `ghidra.pcodeCPort.slghpatexpress.GreaterEqualEquation`.
pub struct GreaterEqualEquationImpl {
    equation: ValExpressEquation,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl GreaterEqualEquationImpl {
    /// Creates a new greater-or-equal-constraint equation from its left- and right-hand
    /// operands.
    pub fn new(location: Location, lhs: Box<dyn PatternValue>, rhs: Box<dyn PatternExpression>) -> Self {
        Self {
            equation: ValExpressEquation::new(location, lhs, rhs),
            token_pattern: None,
        }
    }

    /// The source location this equation was defined at.
    pub fn location(&self) -> &Location {
        self.equation.location()
    }

    /// The pattern value being constrained (the Java `lhs` field).
    pub fn get_lhs(&self) -> &dyn PatternValue {
        self.equation.get_lhs()
    }

    /// The pattern expression `lhs` must be `>=` at least one value of (the Java `rhs` field).
    pub fn get_rhs(&self) -> &dyn PatternExpression {
        self.equation.get_rhs()
    }
}

impl GreaterEqualEquation for GreaterEqualEquationImpl {
    fn gen_pattern(&mut self) {
        let pattern = gen_comparison_pattern(
            self.equation.get_lhs(),
            self.equation.get_rhs(),
            self.equation.location(),
            |lhsval, val| lhsval >= val,
            "Greater than or equal constraint is impossible to match",
        );
        self.token_pattern = Some(pattern);
    }

    fn get_token_pattern(&self) -> Option<&dyn TokenPattern> {
        self.token_pattern.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::tests_support::{loc, FixedValuesExpression, LeafValue};

    #[test]
    fn gen_pattern_matches_when_some_lhsval_is_ge_a_value() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 0, 10, 5));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![5]));
        let mut equation = GreaterEqualEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();

        assert!(equation.get_token_pattern().is_some());
    }

    #[test]
    #[should_panic(expected = "Greater than or equal constraint is impossible to match")]
    fn gen_pattern_panics_when_every_lhsval_is_below_every_value() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 0, 4, 0));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![50]));
        let mut equation = GreaterEqualEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();
    }

    #[test]
    fn get_lhs_and_rhs_expose_operands() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 0, 1, 0));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![0]));
        let equation = GreaterEqualEquationImpl::new(loc(), lhs, rhs);

        assert_eq!(equation.get_lhs().min_value(), 0);
        assert_eq!(equation.location(), &loc());
        let _rhs = equation.get_rhs();
    }
}
