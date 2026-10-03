//! Port of `ghidra.app.plugin.assembler.sleigh.expr.match.AnyMatcher`.

use super::{AbstractExpressionMatcherBase, ExpressionMatcher, MatchResult};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// A matcher which accepts any expression of the required type.
///
/// This requires no further consideration of the expression's operands. If the type matches, the
/// expression matches.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.match.AnyMatcher`. Java's
/// `AnyMatcher<T extends PatternExpression>` composes [`AbstractExpressionMatcherBase`] (see that
/// module's own docs on why the `T`/`Class<T>` generic collapses to a plain predicate over this
/// crate's flattened [`PatternExpression`] enum).
#[derive(Debug)]
pub struct AnyMatcher {
    base: AbstractExpressionMatcherBase,
}

impl AnyMatcher {
    /// A matcher accepting any [`PatternExpression`] whatsoever.
    ///
    /// Port of `public static AnyMatcher<PatternExpression> any()`, which constructs
    /// `new AnyMatcher<>(PatternExpression.class)` -- since `PatternExpression` is the root type,
    /// every instance matches its own class; mirrored here with an always-true predicate.
    pub fn any() -> Self {
        Self::single(|_| true)
    }

    /// Port of `public AnyMatcher(Set<Class<? extends T>> ops)`.
    pub fn new(ops: Vec<fn(&PatternExpression) -> bool>) -> Self {
        AnyMatcher { base: AbstractExpressionMatcherBase::new(ops) }
    }

    /// Port of `public AnyMatcher(Class<T> cls)`.
    pub fn single(op: fn(&PatternExpression) -> bool) -> Self {
        AnyMatcher { base: AbstractExpressionMatcherBase::single(op) }
    }

    /// Port of `matchDetails(T, Map)`, which unconditionally accepts.
    fn match_details(&self, _expression: &PatternExpression, _result: &mut MatchResult) -> bool {
        true
    }
}

impl ExpressionMatcher for AnyMatcher {
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        self.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_matches_every_kind_of_expression() {
        let m = AnyMatcher::any();
        for expr in [
            PatternExpression::Constant(5),
            PatternExpression::StartInstruction,
            PatternExpression::Plus(
                Box::new(PatternExpression::Constant(1)),
                Box::new(PatternExpression::Constant(2)),
            ),
        ] {
            assert!(m.try_match(&expr).is_some(), "{expr:?} should match `any()`");
        }
    }

    #[test]
    fn any_captures_the_matched_expression() {
        let m = AnyMatcher::any();
        let expr = PatternExpression::Constant(42);
        let result = m.try_match(&expr).expect("any() always matches");
        assert!(matches!(m.get(&result), Some(PatternExpression::Constant(42))));
    }

    #[test]
    fn single_restricts_to_the_given_predicate() {
        let m = AnyMatcher::single(|e| matches!(e, PatternExpression::Constant(_)));
        assert!(m.try_match(&PatternExpression::Constant(1)).is_some());
        assert!(m.try_match(&PatternExpression::StartInstruction).is_none());
    }

    #[test]
    fn new_with_multiple_ops_matches_any_of_them() {
        let m = AnyMatcher::new(vec![
            |e| matches!(e, PatternExpression::Constant(_)),
            |e| matches!(e, PatternExpression::StartInstruction),
        ]);
        assert!(m.try_match(&PatternExpression::Constant(1)).is_some());
        assert!(m.try_match(&PatternExpression::StartInstruction).is_some());
        assert!(m.try_match(&PatternExpression::EndInstruction).is_none());
    }

    #[test]
    fn reusing_an_any_matcher_with_an_identical_expression_still_succeeds() {
        // Since matchDetails always accepts, re-matching only turns on recordResult's
        // expressionsIdenticallyDefined check.
        let m = AnyMatcher::any();
        let mut result = MatchResult::new();
        let a = PatternExpression::Constant(7);
        let b = PatternExpression::Constant(7);
        let c = PatternExpression::Constant(8);
        assert!(m.match_into(&a, &mut result));
        assert!(m.match_into(&b, &mut result));
        assert!(!m.match_into(&c, &mut result));
    }
}
