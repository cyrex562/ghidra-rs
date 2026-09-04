//! Models `ghidra.pcodeCPort.slghpatexpress.GreaterEquation`.

use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::comparison_equation::gen_comparison_pattern;
use crate::decompiler::slghpatexpress::val_express_equation::ValExpressEquation;
use crate::decompiler::slghpatexpress::{PatternValue, TokenPattern};
use crate::sleigh::grammar::Location;

/// An equation that constrains a pattern value to be strictly greater than one of the values
/// its right-hand pattern expression can take on.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.GreaterEquation`; see
/// [`GreaterEqualEquation`](super::greater_equal_equation::GreaterEqualEquation) for why this
/// is exposed as a trait.
pub trait GreaterEquation: Send + Sync {
    /// Generates (and stores) the token pattern constraining this equation's left-hand pattern
    /// value to be `>` at least one value the right-hand expression can take on.
    ///
    /// # Panics
    /// Panics with a [`crate::decompiler::context::SleighError`] if no `lhsval` in range ever
    /// satisfies the constraint against any combination of the right-hand expression's values.
    fn gen_pattern(&mut self);

    /// Returns the token pattern computed by the most recent [`GreaterEquation::gen_pattern`]
    /// call, if any.
    fn get_token_pattern(&self) -> Option<&dyn TokenPattern>;
}

/// The concrete `ghidra.pcodeCPort.slghpatexpress.GreaterEquation`.
pub struct GreaterEquationImpl {
    equation: ValExpressEquation,
    token_pattern: Option<Box<dyn TokenPattern>>,
}

impl GreaterEquationImpl {
    /// Creates a new greater-than-constraint equation from its left- and right-hand operands.
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

    /// The pattern expression `lhs` must be `>` at least one value of (the Java `rhs` field).
    pub fn get_rhs(&self) -> &dyn PatternExpression {
        self.equation.get_rhs()
    }
}

impl GreaterEquation for GreaterEquationImpl {
    fn gen_pattern(&mut self) {
        let pattern = gen_comparison_pattern(
            self.equation.get_lhs(),
            self.equation.get_rhs(),
            self.equation.location(),
            |lhsval, val| lhsval > val,
            "Greater than constraint is impossible to match",
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
    fn gen_pattern_matches_when_some_lhsval_is_gt_a_value() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 0, 10, 5));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![5]));
        let mut equation = GreaterEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();

        assert!(equation.get_token_pattern().is_some());
    }

    #[test]
    #[should_panic(expected = "Greater than constraint is impossible to match")]
    fn gen_pattern_panics_when_no_lhsval_exceeds_any_value() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 0, 4, 0));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![50]));
        let mut equation = GreaterEquationImpl::new(loc(), lhs, rhs);

        equation.gen_pattern();
    }

    #[test]
    fn equal_lhsval_and_val_do_not_satisfy_strict_greater_than() {
        // lhsmin=lhsmax=5, rhs value 5: strict > excludes equality, so this must panic.
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 5, 5, 5));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![5]));
        let mut equation = GreaterEquationImpl::new(loc(), lhs, rhs);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| equation.gen_pattern()));
        assert!(result.is_err());
    }

    #[test]
    fn get_lhs_and_rhs_expose_operands() {
        let lhs: Box<dyn PatternValue> = Box::new(LeafValue::new(loc(), 0, 1, 0));
        let rhs: Box<dyn PatternExpression> = Box::new(FixedValuesExpression::new(vec![0]));
        let equation = GreaterEquationImpl::new(loc(), lhs, rhs);

        assert_eq!(equation.get_lhs().min_value(), 0);
        assert_eq!(equation.location(), &loc());
        let _rhs = equation.get_rhs();
    }
}
