//! Port of `ghidra.app.plugin.assembler.sleigh.expr.match.FieldSizeMatcher`.

use super::{AbstractExpressionMatcherBase, ExpressionMatcher, MatchResult};
use crate::program::model::lang::sleigh::expression::PatternExpression;

/// A matcher for a token or context field, constrained by its size in bits.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.expr.match.FieldSizeMatcher`.
#[derive(Debug)]
pub struct FieldSizeMatcher {
    base: AbstractExpressionMatcherBase,
    size_matcher: Box<dyn ExpressionMatcher>,
}

impl FieldSizeMatcher {
    /// Port of `public FieldSizeMatcher(ExpressionMatcher<?> sizeMatcher)`, whose `ops` is fixed
    /// to `Set.of(ContextField.class, TokenField.class)`.
    pub fn new(size_matcher: Box<dyn ExpressionMatcher>) -> Self {
        FieldSizeMatcher {
            base: AbstractExpressionMatcherBase::new(vec![
                |e| matches!(e, PatternExpression::ContextField(_)),
                |e| matches!(e, PatternExpression::TokenField(_)),
            ]),
            size_matcher,
        }
    }

    /// Port of `matchDetails(PatternValue, Map)`: computes the field's bit-width as
    /// `endBit - startBit + 1` and matches it, wrapped as a `ConstantValue`, against the size
    /// matcher.
    fn match_details(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        match expression {
            PatternExpression::ContextField(cf) => {
                let size = (cf.bitend - cf.bitstart + 1) as i64;
                self.size_matcher.match_into(&PatternExpression::Constant(size), result)
            }
            PatternExpression::TokenField(tf) => {
                let size = (tf.bitend - tf.bitstart + 1) as i64;
                self.size_matcher.match_into(&PatternExpression::Constant(size), result)
            }
            _ => false,
        }
    }
}

impl ExpressionMatcher for FieldSizeMatcher {
    fn match_into(&self, expression: &PatternExpression, result: &mut MatchResult) -> bool {
        self.base.match_into(self.key(), expression, result, |e, r| self.match_details(e, r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::expression::{ContextField, TokenField};

    fn token_field(bitstart: i32, bitend: i32) -> PatternExpression {
        PatternExpression::TokenField(TokenField {
            bigendian: false,
            signbit: false,
            bitstart,
            bitend,
            bytestart: 0,
            byteend: 0,
            shift: 0,
        })
    }

    fn context_field(bitstart: i32, bitend: i32) -> PatternExpression {
        PatternExpression::ContextField(ContextField {
            signbit: false,
            bitstart,
            bitend,
            bytestart: 0,
            byteend: 0,
            shift: 0,
        })
    }

    #[derive(Debug)]
    struct SizeIs(i64);
    impl ExpressionMatcher for SizeIs {
        fn match_into(&self, expression: &PatternExpression, _result: &mut MatchResult) -> bool {
            matches!(expression, PatternExpression::Constant(v) if *v == self.0)
        }
    }

    #[test]
    fn matches_a_token_field_of_the_expected_size() {
        // bits [0, 7] -> 8 bits wide.
        let m = FieldSizeMatcher::new(Box::new(SizeIs(8)));
        assert!(m.try_match(&token_field(0, 7)).is_some());
    }

    #[test]
    fn matches_a_context_field_of_the_expected_size() {
        let m = FieldSizeMatcher::new(Box::new(SizeIs(4)));
        assert!(m.try_match(&context_field(2, 5)).is_some());
    }

    #[test]
    fn rejects_a_field_of_the_wrong_size() {
        let m = FieldSizeMatcher::new(Box::new(SizeIs(8)));
        assert!(m.try_match(&token_field(0, 3)).is_none());
    }

    #[test]
    fn rejects_expressions_that_are_neither_context_nor_token_fields() {
        let m = FieldSizeMatcher::new(Box::new(SizeIs(8)));
        assert!(m.try_match(&PatternExpression::Constant(8)).is_none());
        assert!(m.try_match(&PatternExpression::StartInstruction).is_none());
    }

    #[test]
    fn size_matcher_observes_the_computed_bit_width() {
        // The size matcher is handed a synthesized `Constant(size)`, not the field itself --
        // verify the exact value it sees, via a matcher that records into a shared, owned cell
        // (`Rc` rather than a borrow, since `Box<dyn ExpressionMatcher>` requires `'static`).
        use std::cell::RefCell;
        use std::rc::Rc;

        #[derive(Debug)]
        struct CaptureRc(Rc<RefCell<Option<i64>>>);
        impl ExpressionMatcher for CaptureRc {
            fn match_into(&self, expression: &PatternExpression, _result: &mut MatchResult) -> bool {
                if let PatternExpression::Constant(v) = expression {
                    *self.0.borrow_mut() = Some(*v);
                    true
                } else {
                    false
                }
            }
        }

        let seen = Rc::new(RefCell::new(None));
        let m = FieldSizeMatcher::new(Box::new(CaptureRc(Rc::clone(&seen))));
        assert!(m.try_match(&token_field(0, 15)).is_some());
        assert_eq!(*seen.borrow(), Some(16));
    }
}
