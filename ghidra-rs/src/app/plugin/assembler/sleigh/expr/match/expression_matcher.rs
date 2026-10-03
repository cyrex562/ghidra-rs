use std::collections::HashMap;

use crate::program::model::lang::sleigh::expression::PatternExpression;

/// The substitutions accumulated while attempting a match: maps a sub-matcher's
/// [`ExpressionMatcher::key`] to the expression it captured.
///
/// Mirrors the Java `Map<ExpressionMatcher<?>, PatternExpression>`. Java keys that map by each
/// matcher's default (identity-based) `equals`/`hashCode`; Rust trait objects have no built-in
/// identity, so [`ExpressionMatcher::key`] stands in for it (see that method's docs).
pub type MatchResult = HashMap<usize, PatternExpression>;

/// A matcher for a form of pattern expression.
///
/// Some solvers may need to apply sophisticated heuristics to recognize certain forms that
/// commonly occur in pattern expressions. These can certainly be programmed manually, but for
/// many cases, the form recognition can be accomplished by describing the form as an expression
/// matcher. For a shorter syntax to construct such matchers, see [`Context`].
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher`, cut to a trait to
/// break a dependency cycle at this node in the port graph. The Java interface is generic over
/// `T extends PatternExpression`: the specific expression subtype (e.g. `AndExpression`,
/// `ConstantValue`) a given matcher recognizes, used only so [`ExpressionMatcher::get`] can return
/// a narrower type than the root `PatternExpression`. The Rust port of `PatternExpression` (at
/// [`crate::program::model::lang::sleigh::expression::PatternExpression`]) collapsed that whole
/// subtype hierarchy into a single enum, so there is no per-matcher type left to parametrize
/// over -- every matcher captures the same `PatternExpression` enum value.
pub trait ExpressionMatcher: std::fmt::Debug {
    /// Attempt to match the given expression, recording substitutions in the given result map.
    ///
    /// Even if the match was unsuccessful, the result map may contain attempted substitutions.
    /// Thus, the map should be discarded if unsuccessful.
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool;

    /// Attempt to match the given expression, recording the substitutions if successful.
    fn try_match(&self, expression: &PatternExpression) -> Option<MatchResult> {
        let mut result = MatchResult::new();
        if self.match_into(expression, &mut result) {
            Some(result)
        } else {
            None
        }
    }

    /// A stable identity for this matcher instance, used as its key within a [`MatchResult`].
    ///
    /// Java keys the result map by each matcher's default (identity-based) `equals`/`hashCode`,
    /// i.e. by object identity. This returns the matcher's own address as a stand-in for that
    /// identity: two calls on the same live instance return the same key, and distinct live
    /// instances return distinct keys.
    fn key(&self) -> usize {
        self as *const Self as *const () as usize
    }

    /// Retrieve the expression substituted for this matcher from a previous successful match.
    ///
    /// Calling this on the root matcher is relatively useless, as it would simply return the
    /// expression passed to [`ExpressionMatcher::try_match`]. Instead, sub-matchers should be
    /// saved in a variable, allowing their values to be retrieved. See [`Context`], for an
    /// example.
    fn get(&self, results: &MatchResult) -> Option<PatternExpression> {
        results.get(&self.key()).cloned()
    }
}

/// A context for defining expression matchers succinctly.
///
/// Implementations of this trait have easy access to factory methods for each kind of
/// [`PatternExpression`]. Additionally, the implementing type itself provides a convenient
/// container for saving important sub-matchers, so that important sub-expressions can be readily
/// retrieved. For example:
///
/// ```ignore
/// struct MyMatchers {
///     shamt: Box<dyn ExpressionMatcher>,
///     exp: Box<dyn ExpressionMatcher>,
/// }
///
/// impl Context for MyMatchers {}
///
/// impl MyMatchers {
///     fn new(ctx: &impl Context) -> Self {
///         let shamt = ctx.var();
///         let exp = ctx.shl(ctx.var(), ctx.var());
///         Self { shamt, exp }
///     }
/// }
/// ```
///
/// Mirrors the nested `ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher.Context`
/// interface. Each factory method here mirrors a `new XxxMatcher<>(...)` call in Java, backed by
/// one of the sibling matcher classes in the same Java package
/// (`BinaryExpressionMatcher`/`ConstantValueMatcher`/`AnyMatcher`/`OperandValueMatcher`/
/// `FieldSizeMatcher`/`UnaryExpressionMatcher`). None of those classes are ported yet (each is its
/// own row in `PORT_MANIFEST.tsv`), so every factory method below hands back a placeholder
/// [`crate::app::seam_stubs::UnimplementedExpressionMatcher`] that never matches, until the real
/// sibling gets ported.
pub trait Context {
    /// Match the form `L & R` or `R & L`.
    fn and(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L / R`.
    fn div(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L << R`.
    fn shl(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L * R` or `R * L`.
    fn mul(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L | R` or `R | L`.
    fn or(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L + R` or `R + L`.
    fn plus(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L >> R`.
    fn shr(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L - R`.
    fn sub(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `L $xor R` or `R $xor L`.
    fn xor(
        &self,
        _left: Box<dyn ExpressionMatcher>,
        _right: Box<dyn ExpressionMatcher>,
    ) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match a given constant value.
    ///
    /// **NOTE:** To match an unspecified constant value, use [`Context::var`].
    fn cv(&self, _value: i64) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match any expression.
    ///
    /// This matches any expression without consideration of its operands, except insofar when it
    /// appears in multiple places, it will check that subsequent matches are identical to the
    /// first.
    fn var(&self) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match any expression accepted by the given predicate.
    ///
    /// Mirrors the Java `var(Class<T> cls)` overload, which matches any expression whose runtime
    /// type is `cls`. Since the Rust port of `PatternExpression` collapsed its Java subtype
    /// hierarchy into a single enum, there is no `Class<T>` to pass; a predicate over the enum
    /// plays the same role.
    fn var_of(&self, _predicate: fn(&PatternExpression) -> bool) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match an operand value.
    ///
    /// Typically, this must wrap any use of a field, since that field is considered an operand
    /// from the constructor's perspective.
    fn opnd(&self, _def: Box<dyn ExpressionMatcher>) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match a field by its size.
    ///
    /// This matches either a token field or a context field. If matched, it then passes the
    /// field's size (in bits) into the given size matcher.
    fn fld_sz(&self, _size: Box<dyn ExpressionMatcher>) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `-U`.
    fn neg(&self, _unary: Box<dyn ExpressionMatcher>) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }

    /// Match the form `~U`.
    fn not(&self, _unary: Box<dyn ExpressionMatcher>) -> Box<dyn ExpressionMatcher> {
        unimplemented_matcher()
    }
}

fn unimplemented_matcher() -> Box<dyn ExpressionMatcher> {
    Box::new(crate::app::seam_stubs::UnimplementedExpressionMatcher)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matches an unspecified expression, capturing whatever it sees (mirrors `AnyMatcher`).
    #[derive(Debug)]
    struct MockAnyMatcher;

    impl ExpressionMatcher for MockAnyMatcher {
        fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
            result.insert(self.key(), expression.clone());
            true
        }
    }

    /// Matches a specific constant value (mirrors `ConstantValueMatcher`).
    #[derive(Debug)]
    struct MockConstMatcher {
        expected: i64,
    }

    impl ExpressionMatcher for MockConstMatcher {
        fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
            if let PatternExpression::Constant(v) = expression {
                if *v == self.expected {
                    result.insert(self.key(), expression.clone());
                    return true;
                }
            }
            false
        }
    }

    /// Matches `left + right`, recursing into sub-matchers (mirrors `BinaryExpressionMatcher`).
    #[derive(Debug)]
    struct MockPlusMatcher {
        left: MockAnyMatcher,
        right: MockConstMatcher,
    }

    impl ExpressionMatcher for MockPlusMatcher {
        fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
            if let PatternExpression::Plus(l, r) = expression {
                if self.left.match_into(l, result) && self.right.match_into(r, result) {
                    result.insert(self.key(), expression.clone());
                    return true;
                }
            }
            false
        }
    }

    #[test]
    fn matches_and_captures_sub_expression() {
        let matcher = MockPlusMatcher {
            left: MockAnyMatcher,
            right: MockConstMatcher { expected: 2 },
        };
        let expr = PatternExpression::Plus(
            Box::new(PatternExpression::Constant(1)),
            Box::new(PatternExpression::Constant(2)),
        );

        let result = matcher.try_match(&expr).expect("should match L + 2");

        // The root matcher's own key is present.
        assert!(matches!(
            matcher.get(&result),
            Some(PatternExpression::Plus(_, _))
        ));
        // The sub-matcher for the left operand captured the actual left operand (1), proving
        // identity-keyed lookup retrieves the *right* sub-matcher's value, not just any value.
        match matcher.left.get(&result) {
            Some(PatternExpression::Constant(1)) => {}
            other => panic!("expected captured left operand Constant(1), got {other:?}"),
        }
    }

    #[test]
    fn mismatched_constant_fails_to_match() {
        let matcher = MockPlusMatcher {
            left: MockAnyMatcher,
            right: MockConstMatcher { expected: 99 },
        };
        let expr = PatternExpression::Plus(
            Box::new(PatternExpression::Constant(1)),
            Box::new(PatternExpression::Constant(2)),
        );

        assert!(matcher.try_match(&expr).is_none());
    }

    #[test]
    fn distinct_instances_have_distinct_keys() {
        let a = MockAnyMatcher;
        let b = MockAnyMatcher;
        assert_ne!(a.key(), b.key());
    }

    #[test]
    fn object_safety_via_boxed_trait_object() {
        let matchers: Vec<Box<dyn ExpressionMatcher>> = vec![
            Box::new(MockAnyMatcher),
            Box::new(MockConstMatcher { expected: 5 }),
        ];
        let expr = PatternExpression::Constant(5);

        assert!(matchers[0].try_match(&expr).is_some());
        assert!(matchers[1].try_match(&expr).is_some());

        let non_match = PatternExpression::Constant(6);
        assert!(matchers[1].try_match(&non_match).is_none());
    }

    #[test]
    fn context_placeholder_factories_never_match() {
        struct MyContext;
        impl Context for MyContext {}

        let ctx = MyContext;
        let placeholder = ctx.cv(42);
        assert!(placeholder
            .try_match(&PatternExpression::Constant(42))
            .is_none());
    }
}
