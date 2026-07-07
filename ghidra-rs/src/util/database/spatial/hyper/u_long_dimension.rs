use std::cmp::Ordering;

/// An unsigned-64-bit-valued dimension in a hyper-dimensional spatial index.
///
/// Corresponds to `ghidra.util.database.spatial.hyper.ULongDimension`.
///
/// Java stores these as signed `long` but treats them as unsigned via
/// `Long.compareUnsigned` and `Long.divideUnsigned`. The Rust equivalent
/// uses `u64` directly, so comparisons and arithmetic are always unsigned.
pub trait ULongDimension {
    /// Unsigned comparison of two coordinate values.
    fn compare(a: u64, b: u64) -> Ordering {
        a.cmp(&b)
    }

    /// Approximate distance between two coordinate values.
    ///
    /// Returns the unsigned difference `upper.wrapping_sub(lower)` cast to `f64`,
    /// mirroring Java's `upper - lower` (both treated as unsigned via their bit patterns).
    fn distance(upper: u64, lower: u64) -> f64 {
        upper.wrapping_sub(lower) as f64
    }

    /// Midpoint between `a` and `b` in unsigned 64-bit space.
    ///
    /// Mirrors Java's `a + Long.divideUnsigned(b - a, 2)`, using wrapping arithmetic
    /// so the result is always correct even when values span the signed/unsigned boundary.
    fn mid(a: u64, b: u64) -> u64 {
        a.wrapping_add(b.wrapping_sub(a) / 2)
    }

    /// The absolute minimum coordinate: `0`.
    fn absolute_min() -> u64 {
        0
    }

    /// The absolute maximum coordinate: [`u64::MAX`].
    ///
    /// Mirrors Java's `-1L`, which has the same bit pattern as `u64::MAX`.
    fn absolute_max() -> u64 {
        u64::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dim;
    impl ULongDimension for Dim {}

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
    fn compare_unsigned_high_values() {
        // u64::MAX should be greater than any smaller value.
        assert_eq!(Dim::compare(u64::MAX, 0), Ordering::Greater);
        assert_eq!(Dim::compare(0, u64::MAX), Ordering::Less);
    }

    #[test]
    fn compare_unsigned_wraps_signed_boundary() {
        // Values above i64::MAX are still correctly ordered when treated as u64.
        let large: u64 = u64::MAX / 2 + 1; // i64::MIN as u64
        assert_eq!(Dim::compare(large, large - 1), Ordering::Greater);
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
    fn distance_full_range() {
        // u64::MAX - 0 = u64::MAX.
        let d = Dim::distance(u64::MAX, 0);
        assert!(d > 0.0, "full-range distance should be positive, got {d}");
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
    fn mid_full_range() {
        // mid(0, u64::MAX) = u64::MAX / 2.
        assert_eq!(Dim::mid(0, u64::MAX), u64::MAX / 2);
    }

    #[test]
    fn mid_large_values() {
        // mid(u64::MAX - 2, u64::MAX) = u64::MAX - 1.
        assert_eq!(Dim::mid(u64::MAX - 2, u64::MAX), u64::MAX - 1);
    }

    #[test]
    fn mid_result_between_inputs() {
        let a = 100u64;
        let b = 200u64;
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
    fn absolute_min_is_zero() {
        assert_eq!(Dim::absolute_min(), 0u64);
    }

    #[test]
    fn absolute_max_is_u64_max() {
        assert_eq!(Dim::absolute_max(), u64::MAX);
    }

    #[test]
    fn absolute_min_less_than_absolute_max() {
        assert_eq!(
            Dim::compare(Dim::absolute_min(), Dim::absolute_max()),
            Ordering::Less
        );
    }
}
