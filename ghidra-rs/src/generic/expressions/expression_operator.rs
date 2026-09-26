/// Trait for a supported operator of the [`crate::generic::expressions::expression_evaluator::ExpressionEvaluator`].
///
/// Port of the `generic.expressions.ExpressionOperator` enum. The Java type is a closed enum of
/// 18 fixed operators (`~`, `!`, unary `+`/`-`, `*`, `/`, binary `+`/`-`, `<<`, `>>`, `<`, `>`,
/// `<=`, `>=`, `==`, `!=`, `&`, `^`, `|`, `&&`, `||`), each carrying a symbol, a unary/binary
/// arity, and a precedence used to group binary operators for the evaluator's shunting-yard-style
/// parse. Selected as a dependency-cycle cut-point, so it is ported here as an object-safe trait
/// rather than a concrete enum: any future concrete operator set (the real 18 Ghidra operators, or
/// a test/DSL-specific subset) can implement this trait without this crate needing to depend on
/// that concrete set up front.
///
/// The two Java static methods (`getBinaryOperatorsByPrecedence`, `getOperator`) operate over
/// `values()` -- the full enum universe -- which has no equivalent for a trait. They are ported as
/// free functions ([`get_binary_operators_by_precedence`], [`get_operator`]) that take the operator
/// universe as an explicit slice of trait objects instead.
pub trait ExpressionOperator {
    /// Returns the operator's textual symbol, e.g. `"+"` or `"<<"`. Mirrors `toString()`.
    fn symbol(&self) -> &str;

    /// Returns whether this is a unary operator. Mirrors `isUnary()`.
    fn is_unary(&self) -> bool;

    /// Returns whether this is a binary operator. Mirrors `isBinary()`.
    fn is_binary(&self) -> bool;

    /// Returns the relative precedence used to group binary operators, lower binding tighter.
    /// The Java field backing this is private, but grouping by precedence
    /// ([`get_binary_operators_by_precedence`]) requires comparing it across the whole operator
    /// universe, so it is exposed here rather than hidden inside a single enum's private state.
    fn precedence(&self) -> i32;

    /// Returns the number of chars in the operator's symbol. Mirrors `size()`.
    fn size(&self) -> usize {
        self.symbol().len()
    }
}

/// Returns all the binary operators in `operators` in precedence order, grouped into buckets
/// where each bucket holds all operators of the same precedence.
///
/// Mirrors the static `ExpressionOperator.getBinaryOperatorsByPrecedence()`. The Java original
/// lazily caches the result on first call and reuses `values()` as the operator universe; since
/// this is a trait rather than a closed enum, the caller supplies that universe explicitly and no
/// caching is performed.
pub fn get_binary_operators_by_precedence<'a>(
    operators: &[&'a dyn ExpressionOperator],
) -> Vec<Vec<&'a dyn ExpressionOperator>> {
    let mut precedences: Vec<i32> = operators
        .iter()
        .filter(|op| op.is_binary())
        .map(|op| op.precedence())
        .collect();
    precedences.sort_unstable();
    precedences.dedup();

    precedences
        .into_iter()
        .map(|precedence| {
            operators
                .iter()
                .filter(|op| op.is_binary() && op.precedence() == precedence)
                .copied()
                .collect()
        })
        .collect()
}

/// Returns the operator from `operators` matching `token` (optionally merged with `lookahead1` to
/// try a double-char operator first) that has the expected unary/binary arity.
///
/// Mirrors the static `ExpressionOperator.getOperator(String, String, boolean)`.
pub fn get_operator<'a>(
    operators: &[&'a dyn ExpressionOperator],
    token: &str,
    lookahead1: Option<&str>,
    prefer_binary: bool,
) -> Option<&'a dyn ExpressionOperator> {
    if let Some(lookahead1) = lookahead1 {
        let double_token = format!("{token}{lookahead1}");
        if let Some(operator) = find_operator(operators, &double_token, prefer_binary) {
            return Some(operator);
        }
    }
    find_operator(operators, token, prefer_binary)
}

fn find_operator<'a>(
    operators: &[&'a dyn ExpressionOperator],
    tokens: &str,
    expect_binary: bool,
) -> Option<&'a dyn ExpressionOperator> {
    operators
        .iter()
        .find(|op| op.symbol() == tokens && op.is_binary() == expect_binary)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOp {
        symbol: &'static str,
        unary: bool,
        precedence: i32,
    }

    impl ExpressionOperator for MockOp {
        fn symbol(&self) -> &str {
            self.symbol
        }

        fn is_unary(&self) -> bool {
            self.unary
        }

        fn is_binary(&self) -> bool {
            !self.unary
        }

        fn precedence(&self) -> i32 {
            self.precedence
        }
    }

    const UNARY_MINUS: MockOp = MockOp { symbol: "-", unary: true, precedence: 1 };
    const MULTIPLY: MockOp = MockOp { symbol: "*", unary: false, precedence: 2 };
    const SUBTRACT: MockOp = MockOp { symbol: "-", unary: false, precedence: 3 };
    const SHIFT_LEFT: MockOp = MockOp { symbol: "<<", unary: false, precedence: 4 };
    const LESS_THAN: MockOp = MockOp { symbol: "<", unary: false, precedence: 5 };
    const LOGICAL_AND: MockOp = MockOp { symbol: "&&", unary: false, precedence: 6 };
    const BITWISE_AND: MockOp = MockOp { symbol: "&", unary: false, precedence: 7 };

    fn universe() -> Vec<&'static dyn ExpressionOperator> {
        vec![
            &UNARY_MINUS,
            &MULTIPLY,
            &SUBTRACT,
            &SHIFT_LEFT,
            &LESS_THAN,
            &LOGICAL_AND,
            &BITWISE_AND,
        ]
    }

    #[test]
    fn size_defaults_to_symbol_length() {
        assert_eq!(SHIFT_LEFT.size(), 2);
        assert_eq!(BITWISE_AND.size(), 1);
    }

    #[test]
    fn get_operator_prefers_double_char_token_when_present() {
        let ops = universe();
        // "&" followed by lookahead "&" should merge into the binary "&&" operator, not the
        // single-char "&" operator, mirroring the double-token-first lookup in Java.
        let found = get_operator(&ops, "&", Some("&"), true).unwrap();
        assert_eq!(found.symbol(), "&&");
    }

    #[test]
    fn get_operator_falls_back_to_single_token_when_double_does_not_match() {
        let ops = universe();
        let found = get_operator(&ops, "<", Some("x"), true).unwrap();
        assert_eq!(found.symbol(), "<");
    }

    #[test]
    fn get_operator_distinguishes_unary_and_binary_minus_by_context() {
        let ops = universe();
        let unary = get_operator(&ops, "-", None, false).unwrap();
        assert!(unary.is_unary());

        let binary = get_operator(&ops, "-", None, true).unwrap();
        assert!(binary.is_binary());
    }

    #[test]
    fn get_operator_returns_none_for_unknown_token() {
        let ops = universe();
        assert!(get_operator(&ops, "?", None, true).is_none());
    }

    #[test]
    fn binary_operators_group_by_precedence_in_ascending_order() {
        let ops = universe();
        let grouped = get_binary_operators_by_precedence(&ops);

        // Unary minus is excluded; the remaining 6 binary operators all have distinct
        // precedences here, so each group has exactly one operator, ordered ascending.
        let symbols: Vec<&str> = grouped.iter().map(|group| group[0].symbol()).collect();
        assert_eq!(symbols, vec!["*", "-", "<<", "<", "&&", "&"]);
        assert!(grouped.iter().all(|group| group.len() == 1));
    }

    #[test]
    fn same_precedence_operators_share_a_group() {
        let same_precedence_ops: Vec<&dyn ExpressionOperator> =
            vec![&SUBTRACT, &MULTIPLY_SAME_PRECEDENCE];
        let grouped = get_binary_operators_by_precedence(&same_precedence_ops);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].len(), 2);
    }

    const MULTIPLY_SAME_PRECEDENCE: MockOp = MockOp { symbol: "*", unary: false, precedence: 3 };
}
