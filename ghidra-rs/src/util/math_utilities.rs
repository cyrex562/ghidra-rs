use std::cmp::Ordering;

/// Static utility methods for mathematical operations, including unsigned arithmetic
/// on signed integer types.
pub struct MathUtilities;

impl MathUtilities {
    /// Perform unsigned division. Provides proper handling of all 64-bit unsigned values.
    ///
    /// # Panics
    /// Panics if `denominator` is negative.
    pub fn unsigned_divide(numerator: i64, denominator: i64) -> i64 {
        if denominator < 0 {
            panic!("denominator too big");
        }
        (numerator as u64 / denominator as u64) as i64
    }

    /// Perform unsigned modulo. Provides proper handling of all 64-bit unsigned values.
    ///
    /// # Panics
    /// Panics if `denominator` is negative.
    pub fn unsigned_modulo(numerator: i64, denominator: i64) -> i64 {
        if denominator < 0 {
            panic!("denominator too big");
        }
        (numerator as u64 % denominator as u64) as i64
    }

    /// Ensures that the given value is within the range `[min, max]`.
    pub fn clamp(value: i32, min: i32, max: i32) -> i32 {
        value.clamp(min, max)
    }

    /// Compute the minimum of two `i64` values treated as unsigned.
    pub fn unsigned_min_i64(a: i64, b: i64) -> i64 {
        if (a as u64) < (b as u64) { a } else { b }
    }

    /// Compute the minimum of two `i32` values treated as unsigned.
    pub fn unsigned_min_i32(a: i32, b: i32) -> i32 {
        if (a as u32) < (b as u32) { a } else { b }
    }

    /// Compute the minimum of an `i32` and an `i64` treated as unsigned.
    ///
    /// The `i32` is zero-extended before comparison. Returns `i32` since the `i64`
    /// would never be selected if it overflows an `i32`.
    pub fn unsigned_min_i32_i64(a: i32, b: i64) -> i32 {
        if (a as u32 as u64) < (b as u64) { a } else { b as i32 }
    }

    /// Compute the minimum of an `i64` and an `i32` treated as unsigned.
    ///
    /// The `i32` is zero-extended before comparison. Returns `i32` since the `i64`
    /// would never be selected if it overflows an `i32`.
    pub fn unsigned_min_i64_i32(a: i64, b: i32) -> i32 {
        if (a as u64) < (b as u32 as u64) { a as i32 } else { b }
    }

    /// Compute the maximum of two `i64` values treated as unsigned.
    pub fn unsigned_max_i64(a: i64, b: i64) -> i64 {
        if (a as u64) > (b as u64) { a } else { b }
    }

    /// Compute the maximum of two `i32` values treated as unsigned.
    pub fn unsigned_max_i32(a: i32, b: i32) -> i32 {
        if (a as u32) > (b as u32) { a } else { b }
    }

    /// Compute the maximum of an `i32` and an `i64` treated as unsigned.
    ///
    /// The `i32` is zero-extended before comparison.
    pub fn unsigned_max_i32_i64(a: i32, b: i64) -> i64 {
        if (a as u32 as u64) > (b as u64) { a as i64 } else { b }
    }

    /// Compute the maximum of an `i64` and an `i32` treated as unsigned.
    ///
    /// The `i32` is zero-extended before comparison.
    pub fn unsigned_max_i64_i32(a: i64, b: i32) -> i64 {
        if (a as u64) > (b as u32 as u64) { a } else { b as i64 }
    }

    /// Return the smaller of `a` and `b` according to `comp`. Returns `a` on ties.
    pub fn cmin_by<C, F>(a: C, b: C, comp: F) -> C
    where
        F: Fn(&C, &C) -> Ordering,
    {
        if comp(&a, &b) != Ordering::Greater { a } else { b }
    }

    /// Return the smaller of two [`Ord`] values using natural ordering. Returns `a` on ties.
    pub fn cmin<C: Ord>(a: C, b: C) -> C {
        Self::cmin_by(a, b, |x, y| x.cmp(y))
    }

    /// Return the larger of `a` and `b` according to `comp`. Returns `a` on ties.
    pub fn cmax_by<C, F>(a: C, b: C, comp: F) -> C
    where
        F: Fn(&C, &C) -> Ordering,
    {
        if comp(&a, &b) != Ordering::Less { a } else { b }
    }

    /// Return the larger of two [`Ord`] values using natural ordering. Returns `a` on ties.
    pub fn cmax<C: Ord>(a: C, b: C) -> C {
        Self::cmax_by(a, b, |x, y| x.cmp(y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;

    // --- unsigned_divide ---

    #[test]
    fn unsigned_divide_positive_numerator() {
        assert_eq!(MathUtilities::unsigned_divide(27, 4), 6);
        assert_eq!(MathUtilities::unsigned_divide(0, 4), 0);
        assert_eq!(MathUtilities::unsigned_divide(4, 4), 1);
    }

    #[test]
    fn unsigned_divide_negative_numerator() {
        // -1 as u64 = u64::MAX; u64::MAX / 4 = 4611686018427387903
        assert_eq!(MathUtilities::unsigned_divide(-1, 4), 4611686018427387903_i64);
        // -4 as u64 = u64::MAX - 3; / 4
        assert_eq!(MathUtilities::unsigned_divide(-4, 4), 4611686018427387903_i64);
    }

    #[test]
    #[should_panic]
    fn unsigned_divide_negative_denominator_panics() {
        MathUtilities::unsigned_divide(1, -1);
    }

    // --- unsigned_modulo ---

    #[test]
    fn unsigned_modulo_positive_numerator() {
        assert_eq!(MathUtilities::unsigned_modulo(27, 4), 3);
        assert_eq!(MathUtilities::unsigned_modulo(28, 4), 0);
    }

    #[test]
    fn unsigned_modulo_negative_numerator() {
        // u64::MAX % 4 == 3 (u64::MAX = 4 * 4611686018427387903 + 3)
        assert_eq!(MathUtilities::unsigned_modulo(-1, 4), 3);
        // u64::MAX - 3 = 4 * 4611686018427387903; remainder = 0
        assert_eq!(MathUtilities::unsigned_modulo(-4, 4), 0);
    }

    #[test]
    #[should_panic]
    fn unsigned_modulo_negative_denominator_panics() {
        MathUtilities::unsigned_modulo(1, -1);
    }

    #[test]
    fn unsigned_divide_modulo_reconstruct() {
        // (q * d) + r == n for unsigned interpretation
        let d: i64 = 4;
        for n in [27_i64, 1, 0, -1, -4, -27, i64::MIN, i64::MAX] {
            let q = MathUtilities::unsigned_divide(n, d);
            let r = MathUtilities::unsigned_modulo(n, d);
            let reconstructed = (q as u64).wrapping_mul(d as u64).wrapping_add(r as u64);
            assert_eq!(reconstructed, n as u64, "failed for n={:#x}", n);
        }
    }

    // --- clamp ---

    #[test]
    fn clamp_within_range() {
        assert_eq!(MathUtilities::clamp(5, 0, 10), 5);
    }

    #[test]
    fn clamp_below_min() {
        assert_eq!(MathUtilities::clamp(-5, 0, 10), 0);
    }

    #[test]
    fn clamp_above_max() {
        assert_eq!(MathUtilities::clamp(15, 0, 10), 10);
    }

    #[test]
    fn clamp_at_boundaries() {
        assert_eq!(MathUtilities::clamp(0, 0, 10), 0);
        assert_eq!(MathUtilities::clamp(10, 0, 10), 10);
    }

    // --- unsigned_min / unsigned_max (i64 x i64) ---

    #[test]
    fn unsigned_min_i64_positive() {
        assert_eq!(MathUtilities::unsigned_min_i64(3, 5), 3);
        assert_eq!(MathUtilities::unsigned_min_i64(5, 3), 3);
    }

    #[test]
    fn unsigned_min_i64_negative_is_large_unsigned() {
        // -1 as u64 > 5 as u64, so min is 5
        assert_eq!(MathUtilities::unsigned_min_i64(-1, 5), 5);
        assert_eq!(MathUtilities::unsigned_min_i64(5, -1), 5);
        // both negative: -1 > -2 unsigned (u64::MAX > u64::MAX-1), so min is -2
        assert_eq!(MathUtilities::unsigned_min_i64(-1, -2), -2);
    }

    #[test]
    fn unsigned_max_i64_negative_is_large_unsigned() {
        // -1 as u64 > 5 as u64, so max is -1
        assert_eq!(MathUtilities::unsigned_max_i64(-1, 5), -1);
        assert_eq!(MathUtilities::unsigned_max_i64(5, -1), -1);
        // both negative: -1 > -2 unsigned, so max is -1
        assert_eq!(MathUtilities::unsigned_max_i64(-1, -2), -1);
    }

    // --- unsigned_min / unsigned_max (i32 x i32) ---

    #[test]
    fn unsigned_min_max_i32() {
        assert_eq!(MathUtilities::unsigned_min_i32(3, 5), 3);
        assert_eq!(MathUtilities::unsigned_max_i32(3, 5), 5);
        // -1i32 as u32 = u32::MAX, larger than any positive i32
        assert_eq!(MathUtilities::unsigned_min_i32(-1, 5), 5);
        assert_eq!(MathUtilities::unsigned_max_i32(-1, 5), -1);
    }

    // --- unsigned_min / unsigned_max (mixed i32/i64) ---

    #[test]
    fn unsigned_min_i32_i64_zero_extends() {
        // -1i32 zero-extended to u64 = 0xFFFFFFFF = 4294967295
        // 4294967295 < i64::MAX (unsigned), so -1i32 < i64::MAX → min is -1i32
        assert_eq!(MathUtilities::unsigned_min_i32_i64(-1i32, i64::MAX), -1i32);
        // 4294967295 > 1 unsigned, so min is 1
        assert_eq!(MathUtilities::unsigned_min_i32_i64(-1i32, 1_i64), 1_i32);
    }

    #[test]
    fn unsigned_min_i64_i32_zero_extends() {
        // -1i32 zero-extended = 4294967295; 4294967294 < 4294967295 → min is 4294967294 as i32
        let a: i64 = 4294967294; // 0xFFFFFFFE, fits as u32 = 4294967294 > any positive i32
        assert_eq!(MathUtilities::unsigned_min_i64_i32(a, -1i32), a as i32);
        // 1 < 4294967295 unsigned → min is 1 as i32 (truncated from i64)
        assert_eq!(MathUtilities::unsigned_min_i64_i32(1_i64, -1i32), 1_i32);
    }

    #[test]
    fn unsigned_max_i32_i64_zero_extends() {
        // -1i32 zero-extended = 4294967295; 4294967295 > 1 → max is -1i32 as i64 = -1
        assert_eq!(MathUtilities::unsigned_max_i32_i64(-1i32, 1_i64), -1_i64);
        // 1 < i64::MAX unsigned → max is i64::MAX
        assert_eq!(MathUtilities::unsigned_max_i32_i64(1_i32, i64::MAX), i64::MAX);
    }

    #[test]
    fn unsigned_max_i64_i32_zero_extends() {
        // -1i32 zero-extended = 4294967295; i64::MAX (as u64) > 4294967295 → max is i64::MAX
        assert_eq!(MathUtilities::unsigned_max_i64_i32(i64::MAX, -1i32), i64::MAX);
        // 1 < 4294967295 unsigned → max is -1i32 as i64 = -1
        assert_eq!(MathUtilities::unsigned_max_i64_i32(1_i64, -1i32), -1_i64);
    }

    // --- cmin / cmax ---

    #[test]
    fn cmin_natural_order() {
        assert_eq!(MathUtilities::cmin(3, 5), 3);
        assert_eq!(MathUtilities::cmin(5, 3), 3);
        assert_eq!(MathUtilities::cmin(4, 4), 4); // ties return a
    }

    #[test]
    fn cmax_natural_order() {
        assert_eq!(MathUtilities::cmax(3, 5), 5);
        assert_eq!(MathUtilities::cmax(5, 3), 5);
        assert_eq!(MathUtilities::cmax(4, 4), 4); // ties return a
    }

    #[test]
    fn cmin_by_reverse_order() {
        // Reverse comparator: largest value is "smallest"
        assert_eq!(MathUtilities::cmin_by(3, 5, |a, b| Reverse(a).cmp(&Reverse(b))), 5);
        assert_eq!(MathUtilities::cmin_by(5, 3, |a, b| Reverse(a).cmp(&Reverse(b))), 5);
    }

    #[test]
    fn cmax_by_reverse_order() {
        assert_eq!(MathUtilities::cmax_by(3, 5, |a, b| Reverse(a).cmp(&Reverse(b))), 3);
        assert_eq!(MathUtilities::cmax_by(5, 3, |a, b| Reverse(a).cmp(&Reverse(b))), 3);
    }

    #[test]
    fn cmin_cmax_strings() {
        assert_eq!(MathUtilities::cmin("apple", "banana"), "apple");
        assert_eq!(MathUtilities::cmax("apple", "banana"), "banana");
    }
}
