/// Base marker trait for [`crate::generic::expressions::expression_operator::ExpressionOperator`],
/// `ExpressionValue`, and `ExpressionGrouper`.
///
/// Port of the `generic.expressions.ExpressionElement` marker interface. The Java original
/// declares no methods; it exists only so the expression-parsing algorithm (see
/// [`crate::generic::expressions::expression_evaluator::ExpressionEvaluator`]) can hold a single
/// common type for the tokens it produces. This trait mirrors that: no required methods, and
/// object-safe by construction, so any concrete element type can be stored as
/// `Box<dyn ExpressionElement>` / `&dyn ExpressionElement` without this crate depending on the
/// concrete element set up front.
///
/// Selected as a dependency-cycle cut-point.
pub trait ExpressionElement {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for a token like `ExpressionOperator`.
    struct MockOperatorToken {
        symbol: &'static str,
    }
    impl ExpressionElement for MockOperatorToken {}

    /// Stands in for a token like `ExpressionValue`, distinct from `MockOperatorToken` -- the
    /// point of the marker trait is that both can be treated uniformly despite being unrelated
    /// concrete types.
    struct MockValueToken {
        value: i64,
    }
    impl ExpressionElement for MockValueToken {}

    /// Builds a heterogeneous token stream the way a real parser would for `"1 + 2"`, then hands
    /// it to a function that only knows about `dyn ExpressionElement`, proving the marker trait
    /// lets unrelated concrete types be grouped and moved through common APIs.
    fn build_token_stream() -> Vec<Box<dyn ExpressionElement>> {
        vec![
            Box::new(MockValueToken { value: 1 }),
            Box::new(MockOperatorToken { symbol: "+" }),
            Box::new(MockValueToken { value: 2 }),
        ]
    }

    fn count_tokens(tokens: &[Box<dyn ExpressionElement>]) -> usize {
        tokens.len()
    }

    #[test]
    fn heterogeneous_tokens_share_the_marker_trait() {
        let tokens = build_token_stream();
        assert_eq!(count_tokens(&tokens), 3);

        // Draining moves each boxed element through a `dyn ExpressionElement`-only API without
        // any knowledge of the concrete `MockValueToken`/`MockOperatorToken` types behind it --
        // the behavior the marker trait exists to enable.
        let mut drained: Vec<Box<dyn ExpressionElement>> = Vec::new();
        for token in tokens {
            drained.push(token);
        }
        assert_eq!(count_tokens(&drained), 3);
    }
}
