/// Abstract row key for BSim database tables.
///
/// Mirrors `ghidra.features.bsim.query.description.RowKey`. Implementations must
/// provide a total ordering (Java's `Comparable<RowKey>` contract) so they can be
/// used as keys in sorted collections.
pub trait RowKey: Ord {
    /// Returns the (least significant) 64-bits of the row key.
    fn get_long(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct TestKey(i64);

    impl RowKey for TestKey {
        fn get_long(&self) -> i64 {
            self.0
        }
    }

    #[test]
    fn test_get_long_positive() {
        assert_eq!(TestKey(42).get_long(), 42);
    }

    #[test]
    fn test_get_long_negative() {
        assert_eq!(TestKey(-1).get_long(), -1);
    }

    #[test]
    fn test_get_long_zero() {
        assert_eq!(TestKey(0).get_long(), 0);
    }

    #[test]
    fn test_get_long_min_max() {
        assert_eq!(TestKey(i64::MIN).get_long(), i64::MIN);
        assert_eq!(TestKey(i64::MAX).get_long(), i64::MAX);
    }

    #[test]
    fn test_ordering_less() {
        assert_eq!(TestKey(1).cmp(&TestKey(2)), Ordering::Less);
    }

    #[test]
    fn test_ordering_greater() {
        assert_eq!(TestKey(2).cmp(&TestKey(1)), Ordering::Greater);
    }

    #[test]
    fn test_ordering_equal() {
        assert_eq!(TestKey(5).cmp(&TestKey(5)), Ordering::Equal);
    }

    #[test]
    fn test_ordering_min_lt_max() {
        assert!(TestKey(i64::MIN) < TestKey(i64::MAX));
    }
}
