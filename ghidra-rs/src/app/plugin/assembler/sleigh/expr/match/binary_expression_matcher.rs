//! Port of `ghidra.app.plugin.assembler.sleigh.expr.match.BinaryExpressionMatcher`.

use std::collections::HashSet;

use super::{AbstractExpressionMatcherBase, ExpressionMatcher, MatchResult};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// A matcher for a binary expression.
///
/// If the required type matches, the matching descends to the left then right operands.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.match.BinaryExpressionMatcher`. Java's
/// `BinaryExpressionMatcher<T extends BinaryExpression>` collapses to a plain predicate over this
/// crate's flattened [`PatternExpression`] enum, per [`super::AbstractExpressionMatcherBase`]'s
/// own docs; [`PatternExpression::binary_operands`] stands in for the generic
/// `BinaryExpression.getLeft()`/`getRight()` accessors.
#[derive(Debug)]
pub struct BinaryExpressionMatcher {
    base: AbstractExpressionMatcherBase,
    left_matcher: Box<dyn ExpressionMatcher>,
    right_matcher: Box<dyn ExpressionMatcher>,
}

impl BinaryExpressionMatcher {
    /// Port of `public BinaryExpressionMatcher(Set<Class<? extends T>> ops, ExpressionMatcher<?>
    /// leftMatcher, ExpressionMatcher<?> rightMatcher)`.
    pub fn new(
        ops: Vec<fn(&PatternExpression) -> bool>,
        left_matcher: Box<dyn ExpressionMatcher>,
        right_matcher: Box<dyn ExpressionMatcher>,
    ) -> Self {
        BinaryExpressionMatcher { base: AbstractExpressionMatcherBase::new(ops), left_matcher, right_matcher }
    }

    /// Port of `public BinaryExpressionMatcher(Class<T> cls, ExpressionMatcher<?> leftMatcher,
    /// ExpressionMatcher<?> rightMatcher)`.
    pub fn single(
        op: fn(&PatternExpression) -> bool,
        left_matcher: Box<dyn ExpressionMatcher>,
        right_matcher: Box<dyn ExpressionMatcher>,
    ) -> Self {
        BinaryExpressionMatcher { base: AbstractExpressionMatcherBase::single(op), left_matcher, right_matcher }
    }

    /// Port of `matchDetails(T, Map)`:
    /// `leftMatcher.match(expression.getLeft(), result) && rightMatcher.match(expression.getRight(), result)`.
    fn match_details(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        let Some((l, r)) = expression.binary_operands() else { return false };
        self.left_matcher.match_into(l, result) && self.right_matcher.match_into(r, result)
    }
}

impl ExpressionMatcher for BinaryExpressionMatcher {
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        self.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
    }
}

/// A matcher for binary expressions allowing commutativity.
///
/// This behaves the same as [`BinaryExpressionMatcher`], but if the first attempt fails, the
/// operand match is re-attempted with the operands swapped.
///
/// Port of the nested `BinaryExpressionMatcher.Commutative<T>`, which Java declares as
/// `extends BinaryExpressionMatcher<T>`. Per this crate's composition-over-inheritance
/// convention, this embeds a [`BinaryExpressionMatcher`] (mirroring the Java superclass fields)
/// rather than re-deriving from it, and supplies its own `matchDetails` override.
#[derive(Debug)]
pub struct Commutative {
    inner: BinaryExpressionMatcher,
}

impl Commutative {
    /// Port of `public Commutative(Set<Class<? extends T>> ops, ExpressionMatcher<?>
    /// leftMatcher, ExpressionMatcher<?> rightMatcher)`.
    pub fn new(
        ops: Vec<fn(&PatternExpression) -> bool>,
        left_matcher: Box<dyn ExpressionMatcher>,
        right_matcher: Box<dyn ExpressionMatcher>,
    ) -> Self {
        Commutative { inner: BinaryExpressionMatcher::new(ops, left_matcher, right_matcher) }
    }

    /// Port of `public Commutative(Class<T> cls, ExpressionMatcher<?> leftMatcher,
    /// ExpressionMatcher<?> rightMatcher)`.
    pub fn single(
        op: fn(&PatternExpression) -> bool,
        left_matcher: Box<dyn ExpressionMatcher>,
        right_matcher: Box<dyn ExpressionMatcher>,
    ) -> Self {
        Commutative { inner: BinaryExpressionMatcher::single(op, left_matcher, right_matcher) }
    }

    /// Port of the overridden `matchDetails(T, Map)`: try left-then-right; on failure, restore the
    /// result map to its state before the attempt and try right-then-left.
    fn match_details(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        let Some((l, r)) = expression.binary_operands() else { return false };

        let reset: HashSet<usize> = result.keys().copied().collect();
        if self.inner.left_matcher.match_into(l, result) && self.inner.right_matcher.match_into(r, result) {
            return true;
        }
        result.retain(|k, _| reset.contains(k));
        self.inner.right_matcher.match_into(l, result) && self.inner.left_matcher.match_into(r, result)
    }
}

impl ExpressionMatcher for Commutative {
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        self.inner.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plus(l: PatternExpression, r: PatternExpression) -> PatternExpression {
        PatternExpression::Plus(Box::new(l), Box::new(r))
    }

    fn sub(l: PatternExpression, r: PatternExpression) -> PatternExpression {
        PatternExpression::Sub(Box::new(l), Box::new(r))
    }

    #[derive(Debug)]
    struct IsConst(i64);
    impl ExpressionMatcher for IsConst {
        fn match_into(&self, expression: &PatternExpression, _result: &mut MatchResult) -> bool {
            matches!(expression, PatternExpression::Constant(v) if *v == self.0)
        }
    }

    fn is_plus(e: &PatternExpression) -> bool {
        matches!(e, PatternExpression::Plus(_, _))
    }

    // ---- BinaryExpressionMatcher ----

    #[test]
    fn matches_when_both_operands_match_in_order() {
        let m = BinaryExpressionMatcher::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        assert!(m.try_match(&plus(PatternExpression::Constant(1), PatternExpression::Constant(2))).is_some());
    }

    #[test]
    fn rejects_when_operands_are_swapped() {
        let m = BinaryExpressionMatcher::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        // Non-commutative: left/right must match in exactly the given order.
        assert!(m.try_match(&plus(PatternExpression::Constant(2), PatternExpression::Constant(1))).is_none());
    }

    #[test]
    fn rejects_a_non_matching_op_kind() {
        let m = BinaryExpressionMatcher::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        assert!(m.try_match(&sub(PatternExpression::Constant(1), PatternExpression::Constant(2))).is_none());
    }

    #[test]
    fn rejects_a_non_binary_expression() {
        let m = BinaryExpressionMatcher::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        assert!(m.try_match(&PatternExpression::Constant(1)).is_none());
    }

    #[test]
    fn new_with_multiple_ops_accepts_any_of_them() {
        let m = BinaryExpressionMatcher::new(
            vec![is_plus, |e| matches!(e, PatternExpression::Sub(_, _))],
            Box::new(IsConst(1)),
            Box::new(IsConst(2)),
        );
        assert!(m.try_match(&plus(PatternExpression::Constant(1), PatternExpression::Constant(2))).is_some());
        assert!(m.try_match(&sub(PatternExpression::Constant(1), PatternExpression::Constant(2))).is_some());
    }

    // ---- Commutative ----

    #[test]
    fn commutative_matches_in_order_first() {
        let m = Commutative::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        assert!(m.try_match(&plus(PatternExpression::Constant(1), PatternExpression::Constant(2))).is_some());
    }

    #[test]
    fn commutative_matches_when_swapped() {
        let m = Commutative::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        assert!(m.try_match(&plus(PatternExpression::Constant(2), PatternExpression::Constant(1))).is_some());
    }

    #[test]
    fn commutative_rejects_when_neither_order_matches() {
        let m = Commutative::single(is_plus, Box::new(IsConst(1)), Box::new(IsConst(2)));
        assert!(m.try_match(&plus(PatternExpression::Constant(3), PatternExpression::Constant(4))).is_none());
    }

    #[test]
    fn commutative_restores_partial_captures_from_the_failed_first_attempt() {
        // left = AnyMatcher-equivalent (captures whatever it sees), right = IsConst(2).
        // Direct order fails (right operand is 1, not 2); swapped order should succeed, and the
        // partial capture from the failed first attempt must not leak into the final result.
        #[derive(Debug)]
        struct CaptureAny;
        impl ExpressionMatcher for CaptureAny {
            fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
                result.insert(self.key(), expression.clone());
                true
            }
        }
        // `key()` is address-based identity (see `ExpressionMatcher::key`'s docs), so it must be
        // read from the *boxed* (heap) value -- taking it before `Box::new` would capture the
        // moved-from stack slot's address instead, which the box's allocation does not share.
        let left: Box<dyn ExpressionMatcher> = Box::new(CaptureAny);
        let left_key = left.key();
        let m = Commutative::single(is_plus, left, Box::new(IsConst(2)));

        let expr = plus(PatternExpression::Constant(2), PatternExpression::Constant(1));
        let result = m.try_match(&expr).expect("commutative match should succeed swapped");
        // The left matcher (CaptureAny) ends up bound to the *right* operand (1) of the original
        // expression, since matching succeeded on the swapped attempt: leftMatcher.match(right).
        assert!(matches!(result.get(&left_key), Some(PatternExpression::Constant(1))));
    }
}
