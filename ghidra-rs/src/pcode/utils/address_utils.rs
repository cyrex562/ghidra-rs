/// Utilities for unsigned 64-bit arithmetic on signed `i64` values.
///
/// Corresponds to `ghidra.pcode.utils.AddressUtils`.

/// Compares `v1` and `v2` as unsigned 64-bit integers.
///
/// Returns `0` if equal, `-1` if `v1 < v2` unsigned, `1` if `v1 > v2` unsigned.
pub fn unsigned_compare(v1: i64, v2: i64) -> i32 {
    (v1 as u64).cmp(&(v2 as u64)) as i32
}

/// Subtracts `b` from `a` with wrapping (unsigned) semantics.
pub fn unsigned_subtract(a: i64, b: i64) -> i64 {
    a.wrapping_sub(b)
}

/// Adds `a` and `b` with wrapping (unsigned) semantics.
pub fn unsigned_add(a: i64, b: i64) -> i64 {
    a.wrapping_add(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_equal_values() {
        assert_eq!(unsigned_compare(0, 0), 0);
        assert_eq!(unsigned_compare(42, 42), 0);
        assert_eq!(unsigned_compare(-1, -1), 0);
    }

    #[test]
    fn compare_both_non_negative() {
        assert_eq!(unsigned_compare(1, 2), -1);
        assert_eq!(unsigned_compare(2, 1), 1);
    }

    #[test]
    fn compare_both_negative_as_signed() {
        // Both have high bit set; compare normally as signed (same order as unsigned here)
        assert_eq!(unsigned_compare(-2, -1), -1);
        assert_eq!(unsigned_compare(-1, -2), 1);
    }

    #[test]
    fn compare_negative_greater_than_positive_unsigned() {
        // Negative signed = high bit set = large unsigned value
        assert_eq!(unsigned_compare(-1, 0), 1);
        assert_eq!(unsigned_compare(0, -1), -1);
        assert_eq!(unsigned_compare(i64::MAX, -1), -1);
        assert_eq!(unsigned_compare(-1, i64::MAX), 1);
    }

    #[test]
    fn subtract_basic() {
        assert_eq!(unsigned_subtract(10, 3), 7);
        assert_eq!(unsigned_subtract(0, 0), 0);
    }

    #[test]
    fn subtract_wraps_on_underflow() {
        assert_eq!(unsigned_subtract(0, 1), -1i64); // 0u64 - 1 = u64::MAX = -1i64
        assert_eq!(unsigned_subtract(i64::MIN, 1), i64::MAX);
    }

    #[test]
    fn add_basic() {
        assert_eq!(unsigned_add(3, 4), 7);
        assert_eq!(unsigned_add(0, 0), 0);
    }

    #[test]
    fn add_wraps_on_overflow() {
        assert_eq!(unsigned_add(i64::MAX, 1), i64::MIN);
        assert_eq!(unsigned_add(-1i64, 1), 0);
    }
}
