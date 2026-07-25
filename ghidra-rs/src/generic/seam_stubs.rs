//! Minimal placeholder traits/types for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use thiserror::Error;

/// Placeholder for `generic.expressions.ExpressionValue`, needed by
/// [`crate::generic::expressions::expression_evaluator::ExpressionEvaluator`].
///
/// The real interface also declares `applyUnaryOperator`/`applyBinaryOperator` (which take
/// `generic.expressions.ExpressionOperator`, itself unported), but `ExpressionEvaluator`'s own
/// trait surface never calls those directly -- that dispatch lives inside each concrete
/// evaluator's parsing algorithm. Only the accessor `ExpressionEvaluator.parseAsLong` needs
/// (recovering the `LongExpressionValue` special case) is declared here.
pub trait ExpressionValueLike {
    /// Returns the long value carried by this expression value, mirroring the
    /// `instanceof LongExpressionValue` check in `ExpressionEvaluator.parseAsLong`, or `None` if
    /// this value is not a long-valued result.
    fn as_long(&self) -> Option<i64>;
}

/// Placeholder for `generic.expressions.ExpressionException`, needed by
/// [`crate::generic::expressions::expression_evaluator::ExpressionEvaluator`].
///
/// The Java original is a trivial single-field checked exception, so this placeholder already
/// carries its full behavior.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct ExpressionException(pub String);

impl ExpressionException {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Placeholder for `generic.util.datastruct.SortedList`, needed by
/// [`crate::generic::util::datastruct::value_sorted_map::ValueSortedMap::values`].
///
/// `SortedList` is itself an unported interface (`SortedList<E> extends
/// ValueSortedMap.LesserList<E>`, adding `lowerIndex`/`floorIndex`/`ceilingIndex`/
/// `higherIndex`). `ValueSortedMap`'s own interface only returns the type from `values()` and
/// never calls those extra navigation methods itself, so this placeholder adds nothing beyond
/// the already-ported `LesserList<V>` supertrait it needs to be a usable collection view.
pub trait SortedListPlaceholder<V>:
    crate::generic::util::datastruct::value_sorted_map::LesserList<V>
{
}
