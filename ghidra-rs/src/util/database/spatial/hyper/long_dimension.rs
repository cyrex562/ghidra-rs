use std::cmp::Ordering;

/// A signed-64-bit-valued dimension in a hyper-dimensional spatial index.
///
/// Corresponds to `ghidra.util.database.spatial.hyper.LongDimension`.
pub trait LongDimension {
    /// Signed comparison of two coordinate values.
    fn compare(a: i64, b: i64) -> Ordering {
        a.cmp(&b)
    }

    /// Approximate distance between two coordinate values.
    ///
    /// Mirrors Java's `upper - lower`, using wrapping arithmetic so the result
    /// stays defined even when the subtraction would otherwise overflow `i64`.
    fn distance(upper: i64, lower: i64) -> f64 {
        upper.wrapping_sub(lower) as f64
    }

    /// Midpoint between `a` and `b`.
    ///
    /// Mirrors Java's `a + (b - a) / 2`, using wrapping arithmetic so the
    /// result stays defined across the full `i64` range.
    fn mid(a: i64, b: i64) -> i64 {
        a.wrapping_add(b.wrapping_sub(a) / 2)
    }

    /// The absolute minimum coordinate: [`i64::MIN`].
    fn absolute_min() -> i64 {
        i64::MIN
    }

    /// The absolute maximum coordinate: [`i64::MAX`].
    fn absolute_max() -> i64 {
        i64::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dim;
    impl LongDimension for Dim {}

    // --- compare ---

    #[test]
    fn compare_equal() {
        assert_eq!(Dim::compare(42, 42), Ordering::Equal);
    }

    #[test]
    fn compare_less() {
        assert_eq!(Dim::compare(1, 2), Ordering::Less);
    }

    #[test]
    fn compare_greater() {
        assert_eq!(Dim::compare(10, 5), Ordering::Greater);
    }

    #[test]
    fn compare_negative_values() {
        assert_eq!(Dim::compare(-5, 5), Ordering::Less);
        assert_eq!(Dim::compare(i64::MIN, i64::MAX), Ordering::Less);
    }

    // --- distance ---

    #[test]
    fn distance_zero() {
        assert_eq!(Dim::distance(5, 5), 0.0);
    }

    #[test]
    fn distance_positive() {
        assert_eq!(Dim::distance(10, 3), 7.0);
    }

    #[test]
    fn distance_negative() {
        assert_eq!(Dim::distance(3, 10), -7.0);
    }

    // --- mid ---

    #[test]
    fn mid_basic() {
        assert_eq!(Dim::mid(0, 10), 5);
    }

    #[test]
    fn mid_odd_range() {
        // (0 + 11) / 2 = 5 (floor).
        assert_eq!(Dim::mid(0, 11), 5);
    }

    #[test]
    fn mid_same_value() {
        assert_eq!(Dim::mid(7, 7), 7);
    }

    #[test]
    fn mid_negative_range() {
        assert_eq!(Dim::mid(-10, 10), 0);
    }

    #[test]
    fn mid_result_between_inputs() {
        let a = -100i64;
        let b = 200i64;
        let m = Dim::mid(a, b);
        assert!(
            Dim::compare(a, m) != Ordering::Greater,
            "mid should be >= a"
        );
        assert!(
            Dim::compare(m, b) != Ordering::Greater,
            "mid should be <= b"
        );
    }

    // --- absolute_min / absolute_max ---

    #[test]
    fn absolute_min_is_i64_min() {
        assert_eq!(Dim::absolute_min(), i64::MIN);
    }

    #[test]
    fn absolute_max_is_i64_max() {
        assert_eq!(Dim::absolute_max(), i64::MAX);
    }

    #[test]
    fn absolute_min_less_than_absolute_max() {
        assert_eq!(
            Dim::compare(Dim::absolute_min(), Dim::absolute_max()),
            Ordering::Less
        );
    }
}
