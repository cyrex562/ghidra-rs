//! Port of `ghidra.app.plugin.assembler.sleigh.expr.match.UnaryExpressionMatcher`.

use super::{AbstractExpressionMatcherBase, ExpressionMatcher, MatchResult};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// A matcher for a unary expression.
///
/// If the required type matches, the matching descends to the child operand.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.match.UnaryExpressionMatcher`. Java's
/// `UnaryExpressionMatcher<T extends UnaryExpression>` collapses to a plain predicate over this
/// crate's flattened [`PatternExpression`] enum, per [`super::AbstractExpressionMatcherBase`]'s
/// own docs; [`PatternExpression::unary_operand`] stands in for the generic
/// `UnaryExpression.getUnary()` accessor.
#[derive(Debug)]
pub struct UnaryExpressionMatcher {
    base: AbstractExpressionMatcherBase,
    unary_matcher: Box<dyn ExpressionMatcher>,
}

impl UnaryExpressionMatcher {
    /// Port of `public UnaryExpressionMatcher(Set<Class<? extends T>> ops, ExpressionMatcher<?>
    /// unaryMatcher)`.
    pub fn new(
        ops: Vec<fn(&PatternExpression) -> bool>,
        unary_matcher: Box<dyn ExpressionMatcher>,
    ) -> Self {
        UnaryExpressionMatcher { base: AbstractExpressionMatcherBase::new(ops), unary_matcher }
    }

    /// Port of `public UnaryExpressionMatcher(Class<T> cls, ExpressionMatcher<?> unaryMatcher)`.
    pub fn single(
        op: fn(&PatternExpression) -> bool,
        unary_matcher: Box<dyn ExpressionMatcher>,
    ) -> Self {
        UnaryExpressionMatcher { base: AbstractExpressionMatcherBase::single(op), unary_matcher }
    }

    /// Port of `matchDetails(T, Map)`: `unaryMatcher.match(expression.getUnary(), result)`.
    fn match_details(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        match expression.unary_operand() {
            Some(operand) => self.unary_matcher.match_into(operand, result),
            None => false,
        }
    }
}

impl ExpressionMatcher for UnaryExpressionMatcher {
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        self.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minus(operand: PatternExpression) -> PatternExpression {
        PatternExpression::Minus(Box::new(operand))
    }

    fn not(operand: PatternExpression) -> PatternExpression {
        PatternExpression::Not(Box::new(operand))
    }

    #[derive(Debug)]
    struct IsFive;
    impl ExpressionMatcher for IsFive {
        fn match_into(&self, expression: &PatternExpression, _result: &mut MatchResult) -> bool {
            matches!(expression, PatternExpression::Constant(5))
        }
    }

    #[test]
    fn matches_a_unary_form_whose_operand_matches() {
        let m = UnaryExpressionMatcher::single(
            |e| matches!(e, PatternExpression::Minus(_)),
            Box::new(IsFive),
        );
        assert!(m.try_match(&minus(PatternExpression::Constant(5))).is_some());
    }

    #[test]
    fn rejects_a_unary_form_whose_operand_does_not_match() {
        let m = UnaryExpressionMatcher::single(
            |e| matches!(e, PatternExpression::Minus(_)),
            Box::new(IsFive),
        );
        assert!(m.try_match(&minus(PatternExpression::Constant(6))).is_none());
    }

    #[test]
    fn rejects_a_non_matching_op_kind() {
        // Restricted to Minus only -- a Not shouldn't match even with a valid operand.
        let m = UnaryExpressionMatcher::single(
            |e| matches!(e, PatternExpression::Minus(_)),
            Box::new(IsFive),
        );
        assert!(m.try_match(&not(PatternExpression::Constant(5))).is_none());
    }

    #[test]
    fn new_with_multiple_ops_accepts_either_unary_kind() {
        let m = UnaryExpressionMatcher::new(
            vec![
                |e| matches!(e, PatternExpression::Minus(_)),
                |e| matches!(e, PatternExpression::Not(_)),
            ],
            Box::new(IsFive),
        );
        assert!(m.try_match(&minus(PatternExpression::Constant(5))).is_some());
        assert!(m.try_match(&not(PatternExpression::Constant(5))).is_some());
    }

    #[test]
    fn rejects_a_non_unary_expression() {
        let m = UnaryExpressionMatcher::single(
            |e| matches!(e, PatternExpression::Minus(_)),
            Box::new(IsFive),
        );
        assert!(m.try_match(&PatternExpression::Constant(5)).is_none());
    }

    #[test]
    fn captures_both_the_unary_expression_and_its_operand() {
        let inner = crate::app::plugin::assembler::sleigh::expr::r#match::AnyMatcher::any();
        let m = UnaryExpressionMatcher::single(|e| matches!(e, PatternExpression::Minus(_)), Box::new(inner));
        let expr = minus(PatternExpression::Constant(3));
        let result = m.try_match(&expr).expect("matches");
        assert!(matches!(m.get(&result), Some(PatternExpression::Minus(_))));
    }
}
