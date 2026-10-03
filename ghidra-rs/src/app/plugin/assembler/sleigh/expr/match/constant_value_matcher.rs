//! Port of `ghidra.app.plugin.assembler.sleigh.expr.match.ConstantValueMatcher`.

use super::{AbstractExpressionMatcherBase, ExpressionMatcher, MatchResult};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// A matcher for a given constant value.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.match.ConstantValueMatcher`. Java's
/// `ConstantValueMatcher extends AbstractExpressionMatcher<ConstantValue>`; this crate's
/// [`PatternExpression`] flattened `ConstantValue` into the `Constant(i64)` variant (see
/// [`super::AbstractExpressionMatcherBase`]'s own docs), so this matcher's `ops` predicate
/// recognizes that variant rather than a distinct `ConstantValue` class.
#[derive(Debug)]
pub struct ConstantValueMatcher {
    base: AbstractExpressionMatcherBase,
    value: i64,
}

impl ConstantValueMatcher {
    /// Port of `public ConstantValueMatcher(long value)`.
    pub fn new(value: i64) -> Self {
        ConstantValueMatcher {
            base: AbstractExpressionMatcherBase::single(|e| matches!(e, PatternExpression::Constant(_))),
            value,
        }
    }

    /// Port of `matchDetails(ConstantValue, Map)`: `expression.getValue() == value`.
    fn match_details(&self, expression: &PatternExpression, _result: &mut MatchResult) -> bool {
        matches!(expression, PatternExpression::Constant(v) if *v == self.value)
    }
}

impl ExpressionMatcher for ConstantValueMatcher {
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        self.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_exact_constant_value() {
        let m = ConstantValueMatcher::new(5);
        assert!(m.try_match(&PatternExpression::Constant(5)).is_some());
    }

    #[test]
    fn rejects_a_different_constant_value() {
        let m = ConstantValueMatcher::new(5);
        assert!(m.try_match(&PatternExpression::Constant(6)).is_none());
    }

    #[test]
    fn rejects_a_non_constant_expression() {
        let m = ConstantValueMatcher::new(5);
        assert!(m.try_match(&PatternExpression::StartInstruction).is_none());
    }

    #[test]
    fn captures_the_matched_expression() {
        let m = ConstantValueMatcher::new(9);
        let result = m.try_match(&PatternExpression::Constant(9)).expect("matches");
        assert!(matches!(m.get(&result), Some(PatternExpression::Constant(9))));
    }

    #[test]
    fn negative_values_are_matched_correctly() {
        let m = ConstantValueMatcher::new(-1);
        assert!(m.try_match(&PatternExpression::Constant(-1)).is_some());
        assert!(m.try_match(&PatternExpression::Constant(1)).is_none());
    }
}
