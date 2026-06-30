const PRIMES: &[i32] = &[
    17, 37, 67, 131, 257,
    521, 1031, 2053, 4099, 8209, 16411, 29251, 65537,
    131101, 262147, 524309, 1048583, 2097169, 4194319, 8388617, 16777259,
    33554467, 67108879, 134217757, 268435459, 536870923, 1073741827, 2147483647,
];

/// Returns the first prime in the table that is strictly greater than `n`,
/// or `0` if `n` is at or beyond the largest entry.
pub fn next_prime(n: i32) -> i32 {
    for &p in PRIMES {
        if p > n {
            return p;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_first_prime_above_zero() {
        assert_eq!(next_prime(0), 17);
    }

    #[test]
    fn skips_equal_value() {
        assert_eq!(next_prime(17), 37);
    }

    #[test]
    fn mid_table() {
        assert_eq!(next_prime(1000), 1031);
    }

    #[test]
    fn just_below_entry() {
        assert_eq!(next_prime(64), 67);
    }

    #[test]
    fn just_at_entry() {
        assert_eq!(next_prime(67), 131);
    }

    #[test]
    fn negative_input() {
        assert_eq!(next_prime(-1), 17);
    }

    #[test]
    fn largest_entry_returns_zero() {
        assert_eq!(next_prime(2147483647), 0);
    }

    #[test]
    fn second_largest_returns_max() {
        assert_eq!(next_prime(1073741827), 2147483647);
    }
}
