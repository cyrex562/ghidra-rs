use crate::generic::expressions::expression_element::ExpressionElement;

/// Grouping [`ExpressionElement`]s.
///
/// Port of the `generic.expressions.ExpressionGrouper` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionGrouper {
    LeftParen,
    RightParen,
}

impl ExpressionElement for ExpressionGrouper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(ExpressionGrouper::LeftParen, ExpressionGrouper::RightParen);
    }

    #[test]
    fn variants_are_copy_and_clone() {
        let a = ExpressionGrouper::LeftParen;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn implements_expression_element_marker_trait() {
        fn accepts<E: ExpressionElement>(_e: &E) {}
        accepts(&ExpressionGrouper::LeftParen);
        accepts(&ExpressionGrouper::RightParen);
    }

    #[test]
    fn usable_as_boxed_expression_element() {
        let tokens: Vec<Box<dyn ExpressionElement>> = vec![
            Box::new(ExpressionGrouper::LeftParen),
            Box::new(ExpressionGrouper::RightParen),
        ];
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn hashable() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ExpressionGrouper::LeftParen);
        set.insert(ExpressionGrouper::RightParen);
        set.insert(ExpressionGrouper::LeftParen);
        assert_eq!(set.len(), 2);
    }
}
