use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Extended-real number supporting ±∞ and NaN, used for interval arithmetic bounds.
///
/// Mirrors `it.unive.lisa.util.numeric.MathNumber` from the LiSA library, inlined here
/// as a dependency for [`LongInterval`].
#[derive(Clone, Copy, Debug)]
pub enum MathNumber {
    NaN,
    MinusInfinity,
    Finite(f64),
    PlusInfinity,
}

impl MathNumber {
    pub const MINUS_INFINITY: Self = Self::MinusInfinity;
    pub const PLUS_INFINITY: Self = Self::PlusInfinity;
    pub const NAN: Self = Self::NaN;
    pub const ZERO: Self = Self::Finite(0.0);
    pub const ONE: Self = Self::Finite(1.0);

    pub fn new_long(n: i64) -> Self {
        Self::Finite(n as f64)
    }

    pub fn is_nan(self) -> bool {
        matches!(self, Self::NaN)
    }

    pub fn is_minus_infinity(self) -> bool {
        matches!(self, Self::MinusInfinity)
    }

    pub fn is_plus_infinity(self) -> bool {
        matches!(self, Self::PlusInfinity)
    }

    pub fn is_finite(self) -> bool {
        matches!(self, Self::Finite(_))
    }

    pub fn is_zero(self) -> bool {
        matches!(self, Self::Finite(v) if v == 0.0)
    }

    pub fn is(self, n: i64) -> bool {
        match self {
            Self::Finite(v) => v == n as f64,
            _ => false,
        }
    }

    pub fn to_long(self) -> Result<i64, String> {
        match self {
            Self::Finite(v) => Ok(v as i64),
            _ => Err(format!("{:?} is not a finite value", self)),
        }
    }

    pub fn round_down(self) -> Self {
        match self {
            Self::Finite(v) => Self::Finite(v.floor()),
            other => other,
        }
    }

    pub fn round_up(self) -> Self {
        match self {
            Self::Finite(v) => Self::Finite(v.ceil()),
            other => other,
        }
    }

    pub fn add(self, other: Self) -> Self {
        match (self, other) {
            (Self::NaN, _) | (_, Self::NaN) => Self::NaN,
            (Self::MinusInfinity, Self::PlusInfinity)
            | (Self::PlusInfinity, Self::MinusInfinity) => Self::NaN,
            (Self::MinusInfinity, _) | (_, Self::MinusInfinity) => Self::MinusInfinity,
            (Self::PlusInfinity, _) | (_, Self::PlusInfinity) => Self::PlusInfinity,
            (Self::Finite(a), Self::Finite(b)) => Self::Finite(a + b),
        }
    }

    pub fn subtract(self, other: Self) -> Self {
        match (self, other) {
            (Self::NaN, _) | (_, Self::NaN) => Self::NaN,
            (Self::MinusInfinity, Self::MinusInfinity)
            | (Self::PlusInfinity, Self::PlusInfinity) => Self::NaN,
            (Self::MinusInfinity, _) | (_, Self::PlusInfinity) => Self::MinusInfinity,
            (Self::PlusInfinity, _) | (_, Self::MinusInfinity) => Self::PlusInfinity,
            (Self::Finite(a), Self::Finite(b)) => Self::Finite(a - b),
        }
    }

    pub fn multiply(self, other: Self) -> Self {
        match (self, other) {
            (Self::NaN, _) | (_, Self::NaN) => Self::NaN,
            // 0 * anything = 0 (interval arithmetic convention)
            (Self::Finite(v), _) if v == 0.0 => Self::Finite(0.0),
            (_, Self::Finite(v)) if v == 0.0 => Self::Finite(0.0),
            (Self::MinusInfinity, Self::MinusInfinity)
            | (Self::PlusInfinity, Self::PlusInfinity) => Self::PlusInfinity,
            (Self::MinusInfinity, Self::PlusInfinity)
            | (Self::PlusInfinity, Self::MinusInfinity) => Self::MinusInfinity,
            (Self::MinusInfinity, Self::Finite(v))
            | (Self::Finite(v), Self::MinusInfinity) => {
                if v > 0.0 {
                    Self::MinusInfinity
                } else {
                    Self::PlusInfinity
                }
            }
            (Self::PlusInfinity, Self::Finite(v))
            | (Self::Finite(v), Self::PlusInfinity) => {
                if v > 0.0 {
                    Self::PlusInfinity
                } else {
                    Self::MinusInfinity
                }
            }
            (Self::Finite(a), Self::Finite(b)) => Self::Finite(a * b),
        }
    }

    pub fn divide(self, other: Self) -> Self {
        match (self, other) {
            (Self::NaN, _) | (_, Self::NaN) => Self::NaN,
            (_, Self::Finite(d)) if d == 0.0 => Self::NaN,
            (Self::Finite(_), Self::MinusInfinity)
            | (Self::Finite(_), Self::PlusInfinity) => Self::Finite(0.0),
            (Self::MinusInfinity, Self::MinusInfinity)
            | (Self::PlusInfinity, Self::PlusInfinity) => Self::PlusInfinity,
            (Self::MinusInfinity, Self::PlusInfinity)
            | (Self::PlusInfinity, Self::MinusInfinity) => Self::MinusInfinity,
            (Self::MinusInfinity, Self::Finite(v)) => {
                if v > 0.0 {
                    Self::MinusInfinity
                } else {
                    Self::PlusInfinity
                }
            }
            (Self::PlusInfinity, Self::Finite(v)) => {
                if v > 0.0 {
                    Self::PlusInfinity
                } else {
                    Self::MinusInfinity
                }
            }
            (Self::Finite(a), Self::Finite(b)) => Self::Finite(a / b),
        }
    }

    pub fn min(self, other: Self) -> Self {
        if self.cmp(&other) != Ordering::Greater {
            self
        } else {
            other
        }
    }

    pub fn max(self, other: Self) -> Self {
        if self.cmp(&other) != Ordering::Less {
            self
        } else {
            other
        }
    }
}

impl PartialEq for MathNumber {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NaN, Self::NaN) => true,
            (Self::NaN, _) | (_, Self::NaN) => false,
            (Self::MinusInfinity, Self::MinusInfinity) => true,
            (Self::PlusInfinity, Self::PlusInfinity) => true,
            (Self::Finite(a), Self::Finite(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

impl Eq for MathNumber {}

impl Hash for MathNumber {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::NaN => 0u8.hash(state),
            Self::MinusInfinity => 1u8.hash(state),
            Self::Finite(v) => {
                2u8.hash(state);
                v.to_bits().hash(state);
            }
            Self::PlusInfinity => 3u8.hash(state),
        }
    }
}

impl PartialOrd for MathNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MathNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        fn rank(n: &MathNumber) -> i32 {
            match n {
                MathNumber::NaN => 0,
                MathNumber::MinusInfinity => 1,
                MathNumber::Finite(_) => 2,
                MathNumber::PlusInfinity => 3,
            }
        }
        let r1 = rank(self);
        let r2 = rank(other);
        if r1 != r2 {
            return r1.cmp(&r2);
        }
        match (self, other) {
            (Self::Finite(a), Self::Finite(b)) => {
                a.partial_cmp(b).unwrap_or(Ordering::Equal)
            }
            _ => Ordering::Equal,
        }
    }
}

impl fmt::Display for MathNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NaN => write!(f, "NaN"),
            Self::MinusInfinity => write!(f, "-Inf"),
            Self::Finite(v) => {
                if *v == v.floor() && v.abs() < i64::MAX as f64 {
                    write!(f, "{}", *v as i64)
                } else {
                    write!(f, "{}", v)
                }
            }
            Self::PlusInfinity => write!(f, "+Inf"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// An interval with `i64` bounds, supporting ±∞.
///
/// Corresponds to `ghidra.lisa.pcode.analyses.LongInterval` in the Java source.
///
/// The bounds are stored as [`MathNumber`] values so that infinite endpoints
/// can be represented.  All arithmetic produces rounded (integer-boundary)
/// results via internal `cache_and_round` calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LongInterval {
    low: MathNumber,
    high: MathNumber,
}

impl LongInterval {
    /// The interval `[-Inf, +Inf]`.
    pub const INFINITY: Self = Self {
        low: MathNumber::MinusInfinity,
        high: MathNumber::PlusInfinity,
    };

    /// The interval `[0, 0]`.
    pub const ZERO: Self = Self {
        low: MathNumber::Finite(0.0),
        high: MathNumber::Finite(0.0),
    };

    /// The interval `[1, 1]`.
    pub const ONE: Self = Self {
        low: MathNumber::Finite(1.0),
        high: MathNumber::Finite(1.0),
    };

    /// The interval `[-1, -1]`.
    pub const MINUS_ONE: Self = Self {
        low: MathNumber::Finite(-1.0),
        high: MathNumber::Finite(-1.0),
    };

    /// Creates a new interval from `i64` bounds.
    ///
    /// If `low > high` the bounds are swapped automatically.
    pub fn new(low: i64, high: i64) -> Self {
        Self::from_math(MathNumber::new_long(low), MathNumber::new_long(high))
    }

    /// Creates a new interval from optional `i32` bounds.
    ///
    /// `None` maps to the corresponding infinity.  Bounds are swapped if needed.
    pub fn from_opt(low: Option<i32>, high: Option<i32>) -> Self {
        let lo = low
            .map(|n| MathNumber::new_long(n as i64))
            .unwrap_or(MathNumber::MINUS_INFINITY);
        let hi = high
            .map(|n| MathNumber::new_long(n as i64))
            .unwrap_or(MathNumber::PLUS_INFINITY);
        Self::from_math(lo, hi)
    }

    /// Creates a new interval from [`MathNumber`] bounds.
    ///
    /// Bounds are swapped if needed; NaN in either bound propagates to both.
    pub fn from_math(low: MathNumber, high: MathNumber) -> Self {
        if low.is_nan() || high.is_nan() {
            return Self { low: MathNumber::NAN, high: MathNumber::NAN };
        }
        if low.cmp(&high) <= Ordering::Equal {
            Self { low, high }
        } else {
            Self { low: high, high: low }
        }
    }

    /// Returns the upper bound of this interval.
    pub fn get_high(self) -> MathNumber {
        self.high
    }

    /// Returns the lower bound of this interval.
    pub fn get_low(self) -> MathNumber {
        self.low
    }

    /// Returns `true` if the lower bound is −∞.
    pub fn low_is_minus_infinity(self) -> bool {
        self.low.is_minus_infinity()
    }

    /// Returns `true` if the upper bound is +∞.
    pub fn high_is_plus_infinity(self) -> bool {
        self.high.is_plus_infinity()
    }

    /// Returns `true` if at least one bound is infinite.
    pub fn is_infinite(self) -> bool {
        self.high_is_plus_infinity() || self.low_is_minus_infinity()
    }

    /// Returns `true` if both bounds are finite.
    pub fn is_finite(self) -> bool {
        !self.is_infinite()
    }

    /// Returns `true` if this is `[-Inf, +Inf]`.
    pub fn is_infinity(self) -> bool {
        self.low.is_minus_infinity() && self.high.is_plus_infinity()
    }

    /// Returns `true` if this is a singleton interval (`low == high`).
    pub fn is_singleton(self) -> bool {
        self.is_finite() && self.low == self.high
    }

    /// Returns `true` if this is the singleton interval `[n, n]`.
    pub fn is(self, n: i64) -> bool {
        self.is_singleton() && self.low.is(n)
    }

    fn cache_and_round(i: LongInterval) -> LongInterval {
        if i.is(0) {
            return Self::ZERO;
        }
        if i.is(1) {
            return Self::ONE;
        }
        if i.is(-1) {
            return Self::MINUS_ONE;
        }
        Self::from_math(i.low.round_down(), i.high.round_up())
    }

    /// Computes `self + other`.
    pub fn plus(self, other: LongInterval) -> LongInterval {
        if self.is_infinity() || other.is_infinity() {
            return Self::INFINITY;
        }
        Self::cache_and_round(Self::from_math(
            self.low.add(other.low),
            self.high.add(other.high),
        ))
    }

    /// Computes `self - other`.
    pub fn diff(self, other: LongInterval) -> LongInterval {
        if self.is_infinity() || other.is_infinity() {
            return Self::INFINITY;
        }
        Self::cache_and_round(Self::from_math(
            self.low.subtract(other.high),
            self.high.subtract(other.low),
        ))
    }

    /// Computes the interval complement.
    ///
    /// This is not a set-theoretic complement; it handles two cases:
    /// intervals unbounded at one end and boolean intervals (`[0,0]`/`[1,1]`).
    pub fn complement(self) -> LongInterval {
        if self == Self::ONE {
            return Self::ZERO;
        }
        if self == Self::ZERO {
            return Self::ONE;
        }
        if self.high == Self::INFINITY.high {
            return Self::cache_and_round(Self::from_math(
                Self::INFINITY.low,
                self.low.subtract(MathNumber::ONE),
            ));
        }
        if self.low == Self::INFINITY.low {
            return Self::cache_and_round(Self::from_math(
                self.high.add(MathNumber::ONE),
                Self::INFINITY.high,
            ));
        }
        Self::INFINITY
    }

    /// Flips the interval around infinity.
    ///
    /// `[x, +∞]` → `[-∞, x]`, `[-∞, y]` → `[y, +∞]`, finite → `[-∞, +∞]`.
    pub fn flip(self) -> LongInterval {
        if self.high == Self::INFINITY.high {
            return Self::cache_and_round(Self::from_math(Self::INFINITY.low, self.low));
        }
        if self.low == Self::INFINITY.low {
            return Self::cache_and_round(Self::from_math(self.high, Self::INFINITY.high));
        }
        Self::INFINITY
    }

    fn math_min(nums: &[MathNumber]) -> MathNumber {
        assert!(!nums.is_empty(), "No numbers provided");
        let mut m = nums[0];
        for &n in &nums[1..] {
            m = m.min(n);
        }
        m
    }

    fn math_max(nums: &[MathNumber]) -> MathNumber {
        assert!(!nums.is_empty(), "No numbers provided");
        let mut m = nums[0];
        for &n in &nums[1..] {
            m = m.max(n);
        }
        m
    }

    /// Computes `self * other`.
    pub fn mul(self, other: LongInterval) -> LongInterval {
        if self.is(0) || other.is(0) {
            return Self::ZERO;
        }
        if self.is_infinity() || other.is_infinity() {
            return Self::INFINITY;
        }

        if self.low.cmp(&MathNumber::ZERO) >= Ordering::Equal
            && other.low.cmp(&MathNumber::ZERO) >= Ordering::Equal
        {
            return Self::cache_and_round(Self::from_math(
                self.low.multiply(other.low),
                self.high.multiply(other.high),
            ));
        }

        let ll = self.low.multiply(other.low);
        let lh = self.low.multiply(other.high);
        let hl = self.high.multiply(other.low);
        let hh = self.high.multiply(other.high);
        Self::cache_and_round(Self::from_math(
            Self::math_min(&[ll, lh, hl, hh]),
            Self::math_max(&[ll, lh, hl, hh]),
        ))
    }

    /// Computes `self / other`.
    ///
    /// * `ignore_zero` — when `true` and `other` straddles 0, ignores the zero
    ///   and uses a smaller result interval.
    /// * `error_on_zero` — when `true` and `other` contains 0, panics with
    ///   `"IntInterval divide by zero"`.
    pub fn div(self, other: LongInterval, ignore_zero: bool, error_on_zero: bool) -> LongInterval {
        if error_on_zero && (other.is(0) || other.includes(Self::ZERO)) {
            panic!("IntInterval divide by zero");
        }

        if self.is(0) {
            return Self::ZERO;
        }

        if !other.includes(Self::ZERO) {
            return self.mul(Self::from_math(
                MathNumber::ONE.divide(other.high),
                MathNumber::ONE.divide(other.low),
            ));
        } else if other.high.is_zero() {
            return self.mul(Self::from_math(
                MathNumber::MINUS_INFINITY,
                MathNumber::ONE.divide(other.low),
            ));
        } else if other.low.is_zero() {
            return self.mul(Self::from_math(
                MathNumber::ONE.divide(other.high),
                MathNumber::PLUS_INFINITY,
            ));
        } else if ignore_zero {
            return self.mul(Self::from_math(
                MathNumber::ONE.divide(other.low),
                MathNumber::ONE.divide(other.high),
            ));
        } else {
            let lower = self.mul(Self::from_math(
                MathNumber::MINUS_INFINITY,
                MathNumber::ONE.divide(other.low),
            ));
            let higher = self.mul(Self::from_math(
                MathNumber::ONE.divide(other.high),
                MathNumber::PLUS_INFINITY,
            ));

            if lower.includes(higher) {
                return lower;
            } else if higher.includes(lower) {
                return higher;
            } else {
                let merged_low = if lower.low.cmp(&higher.low) > Ordering::Equal {
                    higher.low
                } else {
                    lower.low
                };
                let merged_high = if lower.high.cmp(&higher.high) < Ordering::Equal {
                    higher.high
                } else {
                    lower.high
                };
                return Self::cache_and_round(Self::from_math(merged_low, merged_high));
            }
        }
    }

    /// Returns `true` if this interval includes (contains) `other`.
    pub fn includes(self, other: LongInterval) -> bool {
        self.low.cmp(&other.low) <= Ordering::Equal
            && self.high.cmp(&other.high) >= Ordering::Equal
    }

    /// Returns `true` if this interval intersects with `other`.
    pub fn intersects(self, other: LongInterval) -> bool {
        self.includes(other)
            || other.includes(self)
            || (self.high.cmp(&other.low) >= Ordering::Equal
                && self.high.cmp(&other.high) <= Ordering::Equal)
            || (other.high.cmp(&self.low) >= Ordering::Equal
                && other.high.cmp(&self.high) <= Ordering::Equal)
    }

    /// Returns an iterator over the `i64` values in `[low, high]`.
    ///
    /// # Panics
    ///
    /// Panics if either bound is infinite or NaN.
    pub fn iter(self) -> LongIntervalIter {
        if !self.low.is_finite() || !self.high.is_finite() || self.low.is_nan() || self.high.is_nan()
        {
            panic!("{} is infinite or NaN", self.low);
        }
        let lo = self.low.to_long().expect("Cannot convert low to long");
        let hi = self.high.to_long().expect("Cannot convert high to long");
        LongIntervalIter { current: lo, end: hi }
    }
}

impl PartialOrd for LongInterval {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LongInterval {
    fn cmp(&self, other: &Self) -> Ordering {
        let c = self.low.cmp(&other.low);
        if c != Ordering::Equal {
            return c;
        }
        self.high.cmp(&other.high)
    }
}

impl fmt::Display for LongInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.low, self.high)
    }
}

impl IntoIterator for LongInterval {
    type Item = i64;
    type IntoIter = LongIntervalIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the `i64` values in a finite [`LongInterval`].
pub struct LongIntervalIter {
    current: i64,
    end: i64,
}

impl Iterator for LongIntervalIter {
    type Item = i64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current <= self.end {
            let val = self.current;
            self.current += 1;
            Some(val)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MathNumber ───────────────────────────────────────────────────────────

    #[test]
    fn math_number_predicates() {
        assert!(MathNumber::MINUS_INFINITY.is_minus_infinity());
        assert!(MathNumber::PLUS_INFINITY.is_plus_infinity());
        assert!(MathNumber::NAN.is_nan());
        assert!(MathNumber::ZERO.is_finite());
        assert!(MathNumber::ONE.is_finite());
        assert!(MathNumber::ZERO.is_zero());
        assert!(!MathNumber::ONE.is_zero());
    }

    #[test]
    fn math_number_is() {
        assert!(MathNumber::Finite(42.0).is(42));
        assert!(!MathNumber::Finite(42.0).is(43));
        assert!(!MathNumber::PLUS_INFINITY.is(0));
    }

    #[test]
    fn math_number_to_long() {
        assert_eq!(MathNumber::Finite(7.0).to_long(), Ok(7));
        assert!(MathNumber::PLUS_INFINITY.to_long().is_err());
    }

    #[test]
    fn math_number_round() {
        assert_eq!(MathNumber::Finite(1.7).round_down(), MathNumber::Finite(1.0));
        assert_eq!(MathNumber::Finite(1.1).round_up(), MathNumber::Finite(2.0));
        assert_eq!(MathNumber::MINUS_INFINITY.round_down(), MathNumber::MINUS_INFINITY);
        assert_eq!(MathNumber::PLUS_INFINITY.round_up(), MathNumber::PLUS_INFINITY);
    }

    #[test]
    fn math_number_add() {
        assert_eq!(
            MathNumber::Finite(3.0).add(MathNumber::Finite(4.0)),
            MathNumber::Finite(7.0)
        );
        assert_eq!(
            MathNumber::MINUS_INFINITY.add(MathNumber::Finite(100.0)),
            MathNumber::MINUS_INFINITY
        );
        assert_eq!(
            MathNumber::PLUS_INFINITY.add(MathNumber::PLUS_INFINITY),
            MathNumber::PLUS_INFINITY
        );
        assert!(MathNumber::MINUS_INFINITY.add(MathNumber::PLUS_INFINITY).is_nan());
    }

    #[test]
    fn math_number_subtract() {
        assert_eq!(
            MathNumber::Finite(10.0).subtract(MathNumber::Finite(3.0)),
            MathNumber::Finite(7.0)
        );
        assert_eq!(
            MathNumber::Finite(5.0).subtract(MathNumber::PLUS_INFINITY),
            MathNumber::MINUS_INFINITY
        );
        assert!(MathNumber::MINUS_INFINITY.subtract(MathNumber::MINUS_INFINITY).is_nan());
    }

    #[test]
    fn math_number_multiply() {
        assert_eq!(
            MathNumber::Finite(3.0).multiply(MathNumber::Finite(4.0)),
            MathNumber::Finite(12.0)
        );
        assert_eq!(
            MathNumber::Finite(0.0).multiply(MathNumber::PLUS_INFINITY),
            MathNumber::Finite(0.0)
        );
        assert_eq!(
            MathNumber::MINUS_INFINITY.multiply(MathNumber::MINUS_INFINITY),
            MathNumber::PLUS_INFINITY
        );
        assert_eq!(
            MathNumber::PLUS_INFINITY.multiply(MathNumber::Finite(-2.0)),
            MathNumber::MINUS_INFINITY
        );
    }

    #[test]
    fn math_number_divide() {
        assert_eq!(
            MathNumber::Finite(6.0).divide(MathNumber::Finite(2.0)),
            MathNumber::Finite(3.0)
        );
        assert_eq!(
            MathNumber::Finite(1.0).divide(MathNumber::PLUS_INFINITY),
            MathNumber::Finite(0.0)
        );
        assert!(MathNumber::Finite(1.0).divide(MathNumber::Finite(0.0)).is_nan());
    }

    #[test]
    fn math_number_ordering() {
        assert!(MathNumber::MINUS_INFINITY < MathNumber::ZERO);
        assert!(MathNumber::ZERO < MathNumber::PLUS_INFINITY);
        assert!(MathNumber::Finite(-1.0) < MathNumber::Finite(1.0));
        assert_eq!(
            MathNumber::Finite(5.0).min(MathNumber::Finite(3.0)),
            MathNumber::Finite(3.0)
        );
        assert_eq!(
            MathNumber::Finite(5.0).max(MathNumber::Finite(3.0)),
            MathNumber::Finite(5.0)
        );
    }

    #[test]
    fn math_number_eq_and_hash() {
        use std::collections::hash_map::DefaultHasher;
        let a = MathNumber::Finite(1.0);
        let b = MathNumber::Finite(1.0);
        assert_eq!(a, b);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        a.hash(&mut h1);
        b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());

        assert_ne!(MathNumber::NAN, MathNumber::Finite(1.0));
        // NaN == NaN (our convention for hashing/equality)
        assert_eq!(MathNumber::NAN, MathNumber::NAN);
    }

    // ── LongInterval constants ───────────────────────────────────────────────

    #[test]
    fn constants_are_correct() {
        assert!(LongInterval::INFINITY.is_infinity());
        assert!(LongInterval::ZERO.is(0));
        assert!(LongInterval::ONE.is(1));
        assert!(LongInterval::MINUS_ONE.is(-1));
    }

    // ── LongInterval construction ────────────────────────────────────────────

    #[test]
    fn new_normalizes_order() {
        let i = LongInterval::new(5, 2);
        assert_eq!(i.get_low(), MathNumber::Finite(2.0));
        assert_eq!(i.get_high(), MathNumber::Finite(5.0));
    }

    #[test]
    fn from_opt_none_gives_infinity() {
        let i = LongInterval::from_opt(None, None);
        assert!(i.is_infinity());
    }

    #[test]
    fn from_opt_low_none() {
        let i = LongInterval::from_opt(None, Some(10));
        assert!(i.low_is_minus_infinity());
        assert_eq!(i.get_high(), MathNumber::Finite(10.0));
    }

    // ── Predicates ───────────────────────────────────────────────────────────

    #[test]
    fn is_finite_and_infinite() {
        assert!(LongInterval::new(1, 5).is_finite());
        assert!(!LongInterval::new(1, 5).is_infinite());
        assert!(LongInterval::INFINITY.is_infinite());
        assert!(!LongInterval::INFINITY.is_finite());
    }

    #[test]
    fn is_singleton() {
        assert!(LongInterval::new(3, 3).is_singleton());
        assert!(!LongInterval::new(2, 3).is_singleton());
        assert!(!LongInterval::INFINITY.is_singleton());
    }

    // ── Arithmetic ───────────────────────────────────────────────────────────

    #[test]
    fn plus_basic() {
        let a = LongInterval::new(1, 3);
        let b = LongInterval::new(2, 4);
        assert_eq!(a.plus(b), LongInterval::new(3, 7));
    }

    #[test]
    fn plus_with_infinity_returns_infinity() {
        assert_eq!(LongInterval::new(1, 5).plus(LongInterval::INFINITY), LongInterval::INFINITY);
    }

    #[test]
    fn diff_basic() {
        let a = LongInterval::new(5, 10);
        let b = LongInterval::new(1, 3);
        assert_eq!(a.diff(b), LongInterval::new(2, 9));
    }

    #[test]
    fn mul_basic() {
        let a = LongInterval::new(2, 3);
        let b = LongInterval::new(4, 5);
        assert_eq!(a.mul(b), LongInterval::new(8, 15));
    }

    #[test]
    fn mul_zero_short_circuits() {
        assert_eq!(LongInterval::ZERO.mul(LongInterval::INFINITY), LongInterval::ZERO);
        assert_eq!(LongInterval::INFINITY.mul(LongInterval::ZERO), LongInterval::ZERO);
    }

    #[test]
    fn mul_mixed_signs() {
        // [-2, 3] * [-1, 4]: ll=2, lh=-8, hl=-3, hh=12 → [-8, 12]
        let a = LongInterval::new(-2, 3);
        let b = LongInterval::new(-1, 4);
        assert_eq!(a.mul(b), LongInterval::new(-8, 12));
    }

    #[test]
    fn div_no_zero() {
        // [6, 12] / [2, 3] = [6,12] * [1/3, 1/2] = [2, 6]
        let a = LongInterval::new(6, 12);
        let b = LongInterval::new(2, 3);
        assert_eq!(a.div(b, false, false), LongInterval::new(2, 6));
    }

    #[test]
    #[should_panic(expected = "IntInterval divide by zero")]
    fn div_error_on_zero_panics() {
        LongInterval::new(1, 5).div(LongInterval::ZERO, false, true);
    }

    #[test]
    fn div_self_zero_returns_zero() {
        assert_eq!(
            LongInterval::ZERO.div(LongInterval::new(1, 5), false, false),
            LongInterval::ZERO
        );
    }

    // ── Set operations ───────────────────────────────────────────────────────

    #[test]
    fn includes() {
        let outer = LongInterval::new(0, 10);
        let inner = LongInterval::new(2, 5);
        assert!(outer.includes(inner));
        assert!(!inner.includes(outer));
    }

    #[test]
    fn intersects() {
        assert!(LongInterval::new(0, 5).intersects(LongInterval::new(3, 8)));
        assert!(!LongInterval::new(0, 2).intersects(LongInterval::new(5, 8)));
    }

    // ── complement / flip ────────────────────────────────────────────────────

    #[test]
    fn complement_boolean() {
        assert_eq!(LongInterval::ONE.complement(), LongInterval::ZERO);
        assert_eq!(LongInterval::ZERO.complement(), LongInterval::ONE);
    }

    #[test]
    fn complement_unbounded_high() {
        // [5, +∞].complement() = [-∞, 4]
        let i = LongInterval::from_math(
            MathNumber::Finite(5.0),
            MathNumber::PLUS_INFINITY,
        );
        let c = i.complement();
        assert_eq!(c.get_low(), MathNumber::MINUS_INFINITY);
        assert_eq!(c.get_high(), MathNumber::Finite(4.0));
    }

    #[test]
    fn complement_unbounded_low() {
        // [-∞, 3].complement() = [4, +∞]
        let i = LongInterval::from_math(MathNumber::MINUS_INFINITY, MathNumber::Finite(3.0));
        let c = i.complement();
        assert_eq!(c.get_low(), MathNumber::Finite(4.0));
        assert_eq!(c.get_high(), MathNumber::PLUS_INFINITY);
    }

    #[test]
    fn complement_finite_returns_infinity() {
        assert_eq!(LongInterval::new(2, 5).complement(), LongInterval::INFINITY);
    }

    #[test]
    fn flip_unbounded_high() {
        // [3, +∞].flip() = [-∞, 3]
        let i = LongInterval::from_math(MathNumber::Finite(3.0), MathNumber::PLUS_INFINITY);
        let f = i.flip();
        assert_eq!(f.get_low(), MathNumber::MINUS_INFINITY);
        assert_eq!(f.get_high(), MathNumber::Finite(3.0));
    }

    #[test]
    fn flip_unbounded_low() {
        // [-∞, 5].flip() = [5, +∞]
        let i = LongInterval::from_math(MathNumber::MINUS_INFINITY, MathNumber::Finite(5.0));
        let f = i.flip();
        assert_eq!(f.get_low(), MathNumber::Finite(5.0));
        assert_eq!(f.get_high(), MathNumber::PLUS_INFINITY);
    }

    #[test]
    fn flip_finite_returns_infinity() {
        assert_eq!(LongInterval::new(1, 5).flip(), LongInterval::INFINITY);
    }

    // ── Iterator ─────────────────────────────────────────────────────────────

    #[test]
    fn iter_collects_range() {
        let collected: Vec<i64> = LongInterval::new(2, 5).iter().collect();
        assert_eq!(collected, vec![2, 3, 4, 5]);
    }

    #[test]
    fn into_iter_collects_range() {
        let collected: Vec<i64> = LongInterval::new(0, 2).into_iter().collect();
        assert_eq!(collected, vec![0, 1, 2]);
    }

    #[test]
    fn iter_singleton() {
        let collected: Vec<i64> = LongInterval::new(7, 7).iter().collect();
        assert_eq!(collected, vec![7]);
    }

    #[test]
    #[should_panic]
    fn iter_infinite_panics() {
        let _ = LongInterval::INFINITY.iter().next();
    }

    // ── Ordering ─────────────────────────────────────────────────────────────

    #[test]
    fn compare_by_low_then_high() {
        let a = LongInterval::new(1, 5);
        let b = LongInterval::new(1, 8);
        let c = LongInterval::new(3, 4);
        assert!(a < b);
        assert!(b < c);
    }

    // ── Display ──────────────────────────────────────────────────────────────

    #[test]
    fn display() {
        assert_eq!(LongInterval::new(1, 5).to_string(), "[1, 5]");
        assert_eq!(LongInterval::INFINITY.to_string(), "[-Inf, +Inf]");
    }

    // ── Eq / Hash ────────────────────────────────────────────────────────────

    #[test]
    fn eq_and_hash_consistent() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(LongInterval::new(1, 3), "a");
        assert_eq!(map[&LongInterval::new(1, 3)], "a");
    }
}
