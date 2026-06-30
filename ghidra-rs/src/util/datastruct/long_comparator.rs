use std::cmp::Ordering;

/// Interface for comparing two `i64` values.
///
/// Port of `ghidra.util.datastruct.LongComparator`.
pub trait LongComparator {
    /// Compares `a` and `b`.
    ///
    /// Returns [`Ordering::Equal`] if `a == b`, [`Ordering::Greater`] if `a > b`,
    /// and [`Ordering::Less`] if `a < b`.
    fn compare(&self, a: i64, b: i64) -> Ordering;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AscendingLongComparator;

    impl LongComparator for AscendingLongComparator {
        fn compare(&self, a: i64, b: i64) -> Ordering {
            a.cmp(&b)
        }
    }

    #[test]
    fn less_when_a_less_than_b() {
        assert_eq!(AscendingLongComparator.compare(1, 2), Ordering::Less);
    }

    #[test]
    fn equal_when_a_equals_b() {
        assert_eq!(AscendingLongComparator.compare(5, 5), Ordering::Equal);
    }

    #[test]
    fn greater_when_a_greater_than_b() {
        assert_eq!(AscendingLongComparator.compare(3, 2), Ordering::Greater);
    }

    #[test]
    fn handles_zero() {
        assert_eq!(AscendingLongComparator.compare(0, 0), Ordering::Equal);
        assert_eq!(AscendingLongComparator.compare(-1, 0), Ordering::Less);
        assert_eq!(AscendingLongComparator.compare(0, -1), Ordering::Greater);
    }

    #[test]
    fn handles_min_max_values() {
        assert_eq!(AscendingLongComparator.compare(i64::MIN, i64::MAX), Ordering::Less);
        assert_eq!(AscendingLongComparator.compare(i64::MAX, i64::MIN), Ordering::Greater);
        assert_eq!(AscendingLongComparator.compare(i64::MIN, i64::MIN), Ordering::Equal);
    }
}
