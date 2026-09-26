//! Port of `ghidra.app.plugin.assembler.sleigh.expr.match.AbstractExpressionMatcher`.
//!
//! # Port strategy: composition, not inheritance
//!
//! Java's `AbstractExpressionMatcher<T extends PatternExpression>` is an abstract class
//! implementing the sibling [`ExpressionMatcher`] interface, supplying a concrete `match(...)`
//! body built atop one abstract method (`matchDetails`) that concrete subclasses fill in.
//! Following this crate's "composition over inheritance" convention, this becomes
//! [`AbstractExpressionMatcherBase`]: a plain struct a concrete matcher holds as a `base` field,
//! whose [`AbstractExpressionMatcherBase::match_into`] drives the same algorithm Java's `match`
//! does -- taking the concrete matcher's own `match_details` logic as a closure parameter (Rust
//! has no `super` call to invoke from an override, so the composing type passes its callback in
//! rather than the base "calling back up" implicitly).
//!
//! # Deviation: `ops: Set<Class<? extends T>>` becomes a predicate list
//!
//! Java's `ops` set holds `Class` objects used only for `Class::isInstance`/`Class::cast`
//! (`opMatches`) -- "is this expression one of the accepted concrete subtypes, and if so, treat
//! it as a `T`". The sibling [`ExpressionMatcher`]'s own docs already establish the precedent for
//! this situation: since this crate's [`PatternExpression`] collapsed the whole
//! `PatternExpression` subtype hierarchy into one enum, there is no narrower runtime `Class<T>`
//! left to check membership against, and (per [`Context::var_of`]'s docs) "a predicate over the
//! enum plays the same role" as `Class<T>`. [`AbstractExpressionMatcherBase::op_matches`] follows
//! that same precedent.

use std::collections::HashMap;

use super::{ExpressionMatcher, MatchResult};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// Shared state and algorithm for expression matchers whose acceptance is determined by "is the
/// expression one of a fixed set of forms".
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.match.AbstractExpressionMatcher`. See the
/// module docs for the composition strategy and the `ops` deviation.
#[derive(Debug)]
pub struct AbstractExpressionMatcherBase {
    /// Predicates identifying the accepted expression forms. Java: `Set<Class<? extends T>>
    /// ops`. Kept as a `Vec` rather than a true set (see the module docs): a duplicate predicate
    /// is harmless here since [`AbstractExpressionMatcherBase::op_matches`] only needs "does any
    /// predicate match", not a deduplicated enumeration.
    ops: Vec<fn(&PatternExpression) -> bool>,
}

impl AbstractExpressionMatcherBase {
    /// Java: `AbstractExpressionMatcher(Set<Class<? extends T>> ops)`.
    pub fn new(ops: Vec<fn(&PatternExpression) -> bool>) -> Self {
        AbstractExpressionMatcherBase { ops }
    }

    /// Java: `AbstractExpressionMatcher(Class<? extends T> cls)`.
    pub fn single(op: fn(&PatternExpression) -> bool) -> Self {
        AbstractExpressionMatcherBase { ops: vec![op] }
    }

    /// Java: `protected T opMatches(PatternExpression expression)`.
    ///
    /// Returns the expression itself (i.e. "yes, and here it is, narrowed") if any accepted
    /// predicate matches, `None` otherwise. Since this crate's [`PatternExpression`] is already
    /// the flattened type, "narrowing" is just handing back the same reference -- mirroring
    /// Java's `op.cast(expression)`, which is a reference reinterpretation, not a copy.
    pub fn op_matches<'a>(&self, expression: &'a PatternExpression) -> Option<&'a PatternExpression> {
        if self.ops.iter().any(|op| op(expression)) {
            Some(expression)
        } else {
            None
        }
    }

    /// Drives the shared match algorithm. Mirrors `AbstractExpressionMatcher.match(...)`.
    ///
    /// * `self_key` should be the composing type's own [`ExpressionMatcher::key`] -- identity,
    ///   not this base struct's own address, is the correct map key, since Java's `this` in
    ///   `recordResult(this, expression, result)` refers to the concrete subclass instance, not
    ///   some inner helper object.
    /// * `match_details` mirrors the abstract `matchDetails` method concrete subclasses (here,
    ///   the composing Rust type) must supply.
    pub fn match_into(
        &self,
        self_key: usize,
        expression: &PatternExpression,
        result: &mut MatchResult,
        match_details: impl FnOnce(&PatternExpression, &mut MatchResult) -> bool,
    ) -> bool {
        let Some(t) = self.op_matches(expression) else {
            return false;
        };
        if !match_details(t, result) {
            return false;
        }
        Self::record_result(self_key, t, result)
    }

    /// Java: `protected boolean recordResult(PatternExpression expression, Map<...> result)`.
    fn record_result(self_key: usize, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        match result.insert(self_key, expression.clone()) {
            None => true,
            Some(already) => Self::expressions_identically_defined(&already, expression),
        }
    }

    /// Java: `protected static boolean expressionsIdenticallyDefined(PatternExpression a,
    /// PatternExpression b)`.
    ///
    /// Java's version starts with `if (a.getClass() != b.getClass()) return false;`, then
    /// dispatches on `a`'s specific subtype. Since this port's [`PatternExpression`] is a single
    /// enum, matching `(a, b)` as a tuple naturally requires the same variant to reach any
    /// non-`false` arm, subsuming that initial class check; the trailing `throw new
    /// AssertionError()` for an unhandled subtype has no reachable equivalent here, since every
    /// variant is covered by a match arm (a genuine improvement Rust's exhaustiveness checking
    /// gives for free, not a behavior change for any real input).
    pub fn expressions_identically_defined(a: &PatternExpression, b: &PatternExpression) -> bool {
        use PatternExpression::*;
        match (a, b) {
            (EndInstruction, EndInstruction) => true,
            (Next2Instruction, Next2Instruction) => true,
            (StartInstruction, StartInstruction) => true,
            (Constant(va), Constant(vb)) => va == vb,
            (Minus(ua), Minus(ub)) | (Not(ua), Not(ub)) => {
                Self::expressions_identically_defined(ua, ub)
            }
            (Plus(la, ra), Plus(lb, rb))
            | (Sub(la, ra), Sub(lb, rb))
            | (Mult(la, ra), Mult(lb, rb))
            | (LeftShift(la, ra), LeftShift(lb, rb))
            | (RightShift(la, ra), RightShift(lb, rb))
            | (And(la, ra), And(lb, rb))
            | (Or(la, ra), Or(lb, rb))
            | (Xor(la, ra), Xor(lb, rb))
            | (Div(la, ra), Div(lb, rb)) => {
                Self::expressions_identically_defined(la, lb)
                    && Self::expressions_identically_defined(ra, rb)
            }
            (TokenField(ta), TokenField(tb)) => {
                ta.bitstart == tb.bitstart && ta.bitend == tb.bitend && ta.signbit == tb.signbit
            }
            (ContextField(ca), ContextField(cb)) => {
                ca.bitstart == cb.bitstart && ca.bitend == cb.bitend && ca.signbit == cb.signbit
            }
            (Operand(oa), Operand(ob)) => {
                oa.constructor_id == ob.constructor_id && oa.index == ob.index
            }
            // Different variants (Java: different `getClass()`, so `false`), or two same-variant
            // expressions not covered by a specific arm above -- unreachable, since every
            // `PatternExpression` variant is covered.
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::expression::{ContextField, OperandValue, TokenField};

    /// A concrete matcher composing [`AbstractExpressionMatcherBase`], demonstrating the
    /// composition pattern this module documents. Mirrors a simple, single-form
    /// `BinaryExpressionMatcher`-style subclass: matches `Plus(_, Constant(n))` for a specific
    /// `n`.
    #[derive(Debug)]
    struct PlusConstMatcher {
        base: AbstractExpressionMatcherBase,
        expected_rhs: i64,
    }

    impl PlusConstMatcher {
        fn new(expected_rhs: i64) -> Self {
            PlusConstMatcher {
                base: AbstractExpressionMatcherBase::single(|e| matches!(e, PatternExpression::Plus(_, _))),
                expected_rhs,
            }
        }

        /// Java: `protected abstract boolean matchDetails(T expression, Map<...> result)`.
        fn match_details(&self, expression: &PatternExpression, _result: &mut MatchResult) -> bool {
            matches!(
                expression,
                PatternExpression::Plus(_, r) if matches!(r.as_ref(), PatternExpression::Constant(v) if *v == self.expected_rhs)
            )
        }
    }

    impl ExpressionMatcher for PlusConstMatcher {
        fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
            self.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
        }
    }

    fn plus(l: PatternExpression, r: PatternExpression) -> PatternExpression {
        PatternExpression::Plus(Box::new(l), Box::new(r))
    }

    // ---- op_matches ----

    #[test]
    fn op_matches_accepts_matching_form() {
        // `PatternExpression` has no `PartialEq` (see the sibling `expression_matcher.rs` tests,
        // which use `matches!` for the same reason), so identity (`std::ptr::eq`) stands in:
        // `op_matches` mirrors Java's `Class::cast`, a reference reinterpretation of the very
        // same expression, not a copy.
        let base = AbstractExpressionMatcherBase::single(|e| matches!(e, PatternExpression::Constant(_)));
        let expr = PatternExpression::Constant(5);
        let result = base.op_matches(&expr);
        assert!(result.is_some());
        assert!(std::ptr::eq(result.unwrap(), &expr));
    }

    #[test]
    fn op_matches_rejects_nonmatching_form() {
        let base = AbstractExpressionMatcherBase::single(|e| matches!(e, PatternExpression::Constant(_)));
        let expr = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        assert!(base.op_matches(&expr).is_none());
    }

    #[test]
    fn op_matches_with_multiple_predicates_matches_any() {
        let base = AbstractExpressionMatcherBase::new(vec![
            |e| matches!(e, PatternExpression::Constant(_)),
            |e| matches!(e, PatternExpression::Plus(_, _)),
        ]);
        assert!(base.op_matches(&PatternExpression::Constant(1)).is_some());
        assert!(base
            .op_matches(&plus(PatternExpression::Constant(1), PatternExpression::Constant(2)))
            .is_some());
        assert!(base.op_matches(&PatternExpression::StartInstruction).is_none());
    }

    // ---- match_into (via a composing matcher) ----

    #[test]
    fn match_into_succeeds_and_records_result() {
        let matcher = PlusConstMatcher::new(2);
        let expr = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let mut result = MatchResult::new();
        assert!(matcher.match_into(&expr, &mut result));
        assert!(matches!(result.get(&matcher.key()), Some(PatternExpression::Plus(_, _))));
    }

    #[test]
    fn match_into_fails_when_op_does_not_match() {
        let matcher = PlusConstMatcher::new(2);
        let expr = PatternExpression::Constant(5);
        let mut result = MatchResult::new();
        assert!(!matcher.match_into(&expr, &mut result));
        assert!(result.is_empty());
    }

    #[test]
    fn match_into_fails_when_match_details_rejects() {
        let matcher = PlusConstMatcher::new(99);
        let expr = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let mut result = MatchResult::new();
        assert!(!matcher.match_into(&expr, &mut result));
    }

    #[test]
    fn match_into_reusing_a_matcher_with_an_identical_expression_still_succeeds() {
        // recordResult: re-matching the same matcher against an identically-defined expression
        // succeeds (expressionsIdenticallyDefined), rather than failing outright.
        let matcher = PlusConstMatcher::new(2);
        let mut result = MatchResult::new();
        let e1 = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let e2 = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        assert!(matcher.match_into(&e1, &mut result));
        assert!(matcher.match_into(&e2, &mut result));
    }

    #[test]
    fn match_into_reusing_a_matcher_with_a_different_expression_fails() {
        let matcher = PlusConstMatcher::new(2);
        let mut result = MatchResult::new();
        let e1 = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let e2 = plus(PatternExpression::Constant(999), PatternExpression::Constant(2));
        assert!(matcher.match_into(&e1, &mut result));
        assert!(!matcher.match_into(&e2, &mut result));
    }

    // ---- expressions_identically_defined ----

    #[test]
    fn leaf_singleton_forms_are_identically_defined() {
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(
            &PatternExpression::EndInstruction,
            &PatternExpression::EndInstruction,
        ));
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(
            &PatternExpression::Next2Instruction,
            &PatternExpression::Next2Instruction,
        ));
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(
            &PatternExpression::StartInstruction,
            &PatternExpression::StartInstruction,
        ));
    }

    #[test]
    fn constants_compare_by_value() {
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(
            &PatternExpression::Constant(5),
            &PatternExpression::Constant(5),
        ));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(
            &PatternExpression::Constant(5),
            &PatternExpression::Constant(6),
        ));
    }

    #[test]
    fn unary_expressions_recurse_into_the_operand() {
        let a = PatternExpression::Minus(Box::new(PatternExpression::Constant(1)));
        let b = PatternExpression::Minus(Box::new(PatternExpression::Constant(1)));
        let c = PatternExpression::Minus(Box::new(PatternExpression::Constant(2)));
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(&a, &b));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(&a, &c));
    }

    #[test]
    fn binary_expressions_recurse_into_both_operands() {
        let a = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let b = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let c = plus(PatternExpression::Constant(1), PatternExpression::Constant(3));
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(&a, &b));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(&a, &c));
    }

    #[test]
    fn different_binary_operators_are_not_identically_defined() {
        let a = plus(PatternExpression::Constant(1), PatternExpression::Constant(2));
        let b = PatternExpression::Sub(
            Box::new(PatternExpression::Constant(1)),
            Box::new(PatternExpression::Constant(2)),
        );
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(&a, &b));
    }

    #[test]
    fn token_fields_compare_by_bit_position_and_signedness() {
        let mk = |bitstart, bitend, signbit| {
            PatternExpression::TokenField(TokenField {
                bigendian: false,
                signbit,
                bitstart,
                bitend,
                bytestart: 0,
                byteend: 0,
                shift: 0,
            })
        };
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(
            &mk(0, 7, false),
            &mk(0, 7, false),
        ));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(
            &mk(0, 7, false),
            &mk(0, 8, false),
        ));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(
            &mk(0, 7, false),
            &mk(0, 7, true),
        ));
    }

    #[test]
    fn context_fields_compare_by_bit_position_and_signedness() {
        let mk = |bitstart, bitend, signbit| {
            PatternExpression::ContextField(ContextField {
                signbit,
                bitstart,
                bitend,
                bytestart: 0,
                byteend: 0,
                shift: 0,
            })
        };
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(
            &mk(2, 9, true),
            &mk(2, 9, true),
        ));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(
            &mk(2, 9, true),
            &mk(3, 9, true),
        ));
    }

    #[test]
    fn operand_values_compare_by_constructor_and_index() {
        let a = PatternExpression::Operand(OperandValue { index: 0, constructor_id: 1, table_id: 0 });
        let b = PatternExpression::Operand(OperandValue { index: 0, constructor_id: 1, table_id: 0 });
        let c = PatternExpression::Operand(OperandValue { index: 1, constructor_id: 1, table_id: 0 });
        assert!(AbstractExpressionMatcherBase::expressions_identically_defined(&a, &b));
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(&a, &c));
    }

    #[test]
    fn mismatched_variants_are_never_identically_defined() {
        assert!(!AbstractExpressionMatcherBase::expressions_identically_defined(
            &PatternExpression::Constant(1),
            &PatternExpression::StartInstruction,
        ));
    }
}
