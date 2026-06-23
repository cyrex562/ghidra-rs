use std::cmp::Ordering;

// --- private helpers ---

/// Clamped character code at position `i` in string `s`.
///
/// Mirrors Java `StringDimension.charAt`:
/// - `None` (null): position 0 → 128, others → 0.
/// - Real string: chars beyond the end → 0; in-range chars clamped to 127.
fn char_at(s: Option<&str>, i: usize) -> u32 {
    match s {
        None => {
            if i == 0 {
                128
            } else {
                0
            }
        }
        Some(s) => match s.chars().nth(i) {
            Some(c) => (c as u32).min(127),
            None => 0,
        },
    }
}

/// Length used for string arithmetic: max of the two char counts, treating `None` as zero length.
///
/// Mirrors Java `StringDimension.lenStrings`.
fn len_strings(a: Option<&str>, b: Option<&str>) -> usize {
    let char_len = |s: Option<&str>| s.map_or(0, |s| s.chars().count());
    match (a, b) {
        (None, Some(b)) => b.chars().count(),
        (Some(a), None) => a.chars().count(),
        _ => char_len(a).max(char_len(b)),
    }
}

/// Compute `b − a` as a normalized big-endian base-128 digit vector.
///
/// `compare(b, a) >= Equal` must hold. Each returned digit is in `[0, 127]`.
/// Mirrors Java `StringDimension.subtractExact`, but works directly on digits to avoid
/// arbitrary-precision integers.
fn subtract_base128(b: Option<&str>, a: Option<&str>, len: usize) -> Vec<u8> {
    if len == 0 {
        return vec![];
    }
    let mut diffs: Vec<i32> = (0..len)
        .map(|i| char_at(b, i) as i32 - char_at(a, i) as i32)
        .collect();
    // Propagate borrows from LSB (index len-1) to MSB (index 0).
    for i in (1..len).rev() {
        if diffs[i] < 0 {
            diffs[i] += 128;
            diffs[i - 1] -= 1;
        }
    }
    diffs.iter().map(|&d| d as u8).collect()
}

/// Divide a normalized base-128 big-endian digit vector by 2.
///
/// Returns `(quotient_digits, was_odd)`.
fn halve_base128(digits: &[u8]) -> (Vec<u8>, bool) {
    let mut out = vec![0u8; digits.len()];
    let mut carry: u32 = 0;
    for (i, &d) in digits.iter().enumerate() {
        let v = carry * 128 + d as u32;
        out[i] = (v / 2) as u8;
        carry = v & 1;
    }
    (out, carry != 0)
}

/// Add base-128 `digits` to string `a`, producing a `len`-character string.
///
/// Produces the `len` low-order digits of `(a + digits)`; any final carry is discarded.
/// Mirrors Java `StringDimension.add`.
fn add_base128(a: Option<&str>, digits: &[u8], len: usize) -> String {
    let mut out = vec![0u8; len];
    let mut carry: u32 = 0;
    for i in (0..len).rev() {
        let v = char_at(a, i) + digits[i] as u32 + carry;
        out[i] = (v % 128) as u8;
        carry = v / 128;
    }
    out.iter().map(|&c| c as char).collect()
}

// --- public trait ---

/// A string-valued dimension in a hyper-dimensional spatial index.
///
/// Corresponds to `ghidra.util.database.spatial.hyper.StringDimension`.
///
/// `None` represents the Java `null` sentinel returned by
/// [`absolute_max`][StringDimension::absolute_max], and is treated as the absolute maximum
/// in all comparisons.
pub trait StringDimension {
    /// Lexicographic comparison treating `None` (null) as the absolute maximum.
    fn compare(a: Option<&str>, b: Option<&str>) -> Ordering {
        match (a, b) {
            (None, None) => Ordering::Equal,
            (None, _) => Ordering::Greater,
            (_, None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }

    /// Approximate floating-point distance between two string coordinates.
    ///
    /// Sums per-character differences scaled by descending place values (base 128), stopping
    /// when the running total can no longer absorb additional precision.
    fn distance(upper: Option<&str>, lower: Option<&str>) -> f64 {
        if upper == lower {
            return 0.0;
        }
        let len = len_strings(upper, lower);
        let mut result = 0.0_f64;
        // Java Double.MAX_VALUE / 128 as the starting place value.
        let mut place_val = f64::MAX / 128.0;
        for i in 0..len {
            let cu = char_at(upper, i) as f64;
            let cl = char_at(lower, i) as f64;
            let old = result;
            result += place_val * (cu - cl);
            if old == result {
                // f64 can no longer capture additional precision.
                return result;
            }
            // f64::from_bits(1) is the smallest positive subnormal — Java Double.MIN_VALUE.
            if place_val == f64::from_bits(1) || place_val == 0.0 {
                return result;
            }
            place_val /= 128.0;
        }
        result
    }

    /// Midpoint string between `a` and `b` in the string dimension ordering.
    ///
    /// When the exact midpoint falls between two representable strings, a `'\x40'` character
    /// is appended to mark the half-step (mirrors the Java `(char) 64` suffix).
    fn mid(a: Option<&str>, b: Option<&str>) -> Option<String> {
        if a == b {
            return a.map(str::to_string);
        }
        if a.is_none() && b == Some("") {
            return Some(String::from('\x40'));
        }
        if b.is_none() && a == Some("") {
            return Some(String::from('\x40'));
        }
        // Ensure lo ≤ hi.
        let (lo, hi) = if Self::compare(a, b) == Ordering::Greater {
            (b, a)
        } else {
            (a, b)
        };
        let len = len_strings(lo, hi);
        let diff = subtract_base128(hi, lo, len);
        let (halved, was_odd) = halve_base128(&diff);
        let mut s = add_base128(lo, &halved, len);
        if was_odd {
            s.push('\x40');
        }
        Some(s)
    }

    /// The absolute minimum: the empty string.
    fn absolute_min() -> String {
        String::new()
    }

    /// The absolute maximum: `None` (null sentinel).
    fn absolute_max() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Concrete implementor to exercise the trait defaults.
    struct Dim;
    impl StringDimension for Dim {}

    // --- compare ---

    #[test]
    fn compare_equal_strings() {
        assert_eq!(Dim::compare(Some("abc"), Some("abc")), Ordering::Equal);
    }

    #[test]
    fn compare_null_null() {
        assert_eq!(Dim::compare(None, None), Ordering::Equal);
    }

    #[test]
    fn compare_null_is_greater_than_any_string() {
        assert_eq!(Dim::compare(None, Some("zzz")), Ordering::Greater);
        assert_eq!(Dim::compare(Some("zzz"), None), Ordering::Less);
    }

    #[test]
    fn compare_null_greater_than_empty() {
        assert_eq!(Dim::compare(None, Some("")), Ordering::Greater);
    }

    #[test]
    fn compare_lexicographic() {
        assert_eq!(Dim::compare(Some("a"), Some("b")), Ordering::Less);
        assert_eq!(Dim::compare(Some("b"), Some("a")), Ordering::Greater);
        assert_eq!(Dim::compare(Some("abc"), Some("abd")), Ordering::Less);
    }

    // --- distance ---

    #[test]
    fn distance_same_string_is_zero() {
        assert_eq!(Dim::distance(Some("hello"), Some("hello")), 0.0);
    }

    #[test]
    fn distance_same_none_is_zero() {
        assert_eq!(Dim::distance(None, None), 0.0);
    }

    #[test]
    fn distance_nonempty_positive() {
        let d = Dim::distance(Some("b"), Some("a"));
        assert!(d > 0.0, "distance(b, a) should be positive, got {d}");
    }

    #[test]
    fn distance_null_upper_large() {
        let d = Dim::distance(None, Some("a"));
        assert!(d > 0.0, "distance(null, a) should be positive, got {d}");
    }

    // --- absolute_min / absolute_max ---

    #[test]
    fn absolute_min_is_empty() {
        assert_eq!(Dim::absolute_min(), "");
    }

    #[test]
    fn absolute_max_is_none() {
        assert_eq!(Dim::absolute_max(), None);
    }

    // --- mid ---

    #[test]
    fn mid_equal_strings_returns_same() {
        assert_eq!(Dim::mid(Some("abc"), Some("abc")), Some("abc".to_string()));
    }

    #[test]
    fn mid_null_and_null_returns_null() {
        assert_eq!(Dim::mid(None, None), None);
    }

    #[test]
    fn mid_null_and_empty_returns_at_char() {
        assert_eq!(Dim::mid(None, Some("")), Some("\x40".to_string()));
        assert_eq!(Dim::mid(Some(""), None), Some("\x40".to_string()));
    }

    #[test]
    fn mid_aa_zz() {
        // Verified against the Java implementation.
        let m = Dim::mid(Some("aa"), Some("zz")).unwrap();
        assert!(m > "aa".to_string() && m < "zz".to_string(),
            "mid(aa, zz) = {m:?} should be between aa and zz");
    }

    #[test]
    fn mid_is_commutative() {
        let ab = Dim::mid(Some("apple"), Some("mango"));
        let ba = Dim::mid(Some("mango"), Some("apple"));
        assert_eq!(ab, ba);
    }

    #[test]
    fn mid_result_between_inputs() {
        let a = "cat";
        let b = "dog";
        let m = Dim::mid(Some(a), Some(b)).unwrap();
        assert!(
            Dim::compare(Some(a), Some(&m)) != Ordering::Greater,
            "mid should be >= lower"
        );
        assert!(
            Dim::compare(Some(&m), Some(b)) != Ordering::Greater,
            "mid should be <= upper"
        );
    }

    #[test]
    fn mid_adjacent_chars() {
        // mid("a", "b") should be between 'a' and 'b'.
        let m = Dim::mid(Some("a"), Some("b")).unwrap();
        assert!(m >= "a".to_string());
        assert!(m <= "b".to_string());
    }

    #[test]
    fn mid_with_null_upper() {
        // mid("x", null) should be some string > "x".
        let m = Dim::mid(Some("x"), None).unwrap();
        assert!(
            Dim::compare(Some("x"), Some(&m)) != Ordering::Greater,
            "mid with null upper should be >= x"
        );
    }

    // --- char_at (private helper, tested via mid/distance) ---

    #[test]
    fn char_at_null_position_zero_is_128() {
        assert_eq!(char_at(None, 0), 128);
    }

    #[test]
    fn char_at_null_other_position_is_zero() {
        assert_eq!(char_at(None, 5), 0);
    }

    #[test]
    fn char_at_past_end_is_zero() {
        assert_eq!(char_at(Some("ab"), 5), 0);
    }

    #[test]
    fn char_at_clamps_to_127() {
        // char 200 (non-ASCII) should be clamped to 127.
        let s = "\u{00c8}"; // 'È', code point 200
        assert_eq!(char_at(Some(s), 0), 127);
    }
}
