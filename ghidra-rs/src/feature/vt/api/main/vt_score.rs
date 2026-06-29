use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// A numerical score for a version-tracking correlator.
///
/// Scores constructed from a floating-point value are rounded to three decimal
/// places (mirroring Java's `DecimalFormat("0.000")` round-trip). Scores
/// parsed from a string via [`FromStr`] retain full precision, matching the
/// Java `VTScore(String)` constructor.
#[derive(Clone, Debug)]
pub struct VtScore {
    score: f64,
}

impl VtScore {
    /// Creates a new score from a floating-point value, rounded to three decimal places.
    pub fn new(score: f64) -> Self {
        Self {
            score: Self::round(score),
        }
    }

    fn round(value: f64) -> f64 {
        format!("{:.3}", value)
            .parse()
            .unwrap_or(value)
    }

    /// Returns the raw score value.
    pub fn score(&self) -> f64 {
        self.score
    }

    /// Returns the base-10 logarithm of the score.
    pub fn log10_score(&self) -> f64 {
        self.score.log10()
    }

    /// Returns the score formatted to three decimal places.
    pub fn formatted_score(&self) -> String {
        format!("{:.3}", self.score)
    }

    /// Returns the base-10 logarithm formatted to three decimal places.
    ///
    /// Returns `"0.00"` for NaN and `"N/A"` for infinite values, matching
    /// the Java source.
    pub fn formatted_log10_score(&self) -> String {
        let log10 = self.log10_score();
        if log10.is_nan() {
            "0.00".to_string()
        } else if log10.is_infinite() {
            "N/A".to_string()
        } else {
            format!("{:.3}", log10)
        }
    }

    /// Returns a string suitable for persistent storage.
    ///
    /// Corresponds to Java's `Double.toString(score)`.
    pub fn to_storage_string(&self) -> String {
        self.score.to_string()
    }
}

impl PartialEq for VtScore {
    fn eq(&self, other: &Self) -> bool {
        self.score.to_bits() == other.score.to_bits()
    }
}

impl Eq for VtScore {}

impl Hash for VtScore {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.score.to_bits().hash(state);
    }
}

impl PartialOrd for VtScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VtScore {
    fn cmp(&self, other: &Self) -> Ordering {
        // Mirror Java's compareTo: neither < nor > holds for NaN, so treat as Equal.
        self.score
            .partial_cmp(&other.score)
            .unwrap_or(Ordering::Equal)
    }
}

impl fmt::Display for VtScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.formatted_score())
    }
}

impl FromStr for VtScore {
    type Err = std::num::ParseFloatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self { score: s.parse()? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rounds_to_three_decimal_places() {
        let s = VtScore::new(0.12345);
        assert_eq!(s.score(), 0.123);
    }

    #[test]
    fn new_rounds_up_correctly() {
        let s = VtScore::new(0.9999);
        assert_eq!(s.score(), 1.0);
    }

    #[test]
    fn from_str_does_not_round() {
        let s: VtScore = "0.12345".parse().unwrap();
        assert_eq!(s.score(), 0.12345);
    }

    #[test]
    fn from_str_invalid_returns_error() {
        assert!("not_a_number".parse::<VtScore>().is_err());
    }

    #[test]
    fn log10_score_positive() {
        let s = VtScore::new(1.0);
        assert_eq!(s.log10_score(), 0.0);
    }

    #[test]
    fn formatted_score_three_decimal_places() {
        let s = VtScore::new(0.5);
        assert_eq!(s.formatted_score(), "0.500");
    }

    #[test]
    fn formatted_log10_score_normal() {
        let s = VtScore::new(1.0);
        assert_eq!(s.formatted_log10_score(), "0.000");
    }

    #[test]
    fn formatted_log10_score_nan_returns_zero_string() {
        // log10 of a negative number is NaN
        let s: VtScore = "-1.0".parse().unwrap();
        assert_eq!(s.formatted_log10_score(), "0.00");
    }

    #[test]
    fn formatted_log10_score_infinite_returns_na() {
        // log10(0) is -infinity
        let s: VtScore = "0.0".parse().unwrap();
        assert_eq!(s.formatted_log10_score(), "N/A");
    }

    #[test]
    fn display_uses_formatted_score() {
        let s = VtScore::new(0.75);
        assert_eq!(s.to_string(), "0.750");
    }

    #[test]
    fn equality_by_bit_representation() {
        let a = VtScore::new(0.5);
        let b = VtScore::new(0.5);
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_scores() {
        let a = VtScore::new(0.5);
        let b = VtScore::new(0.6);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = VtScore::new(0.5);
        let b = VtScore::new(0.5);
        assert_eq!(a, b);

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        a.hash(&mut h1);
        b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn ordering_less_than() {
        let a = VtScore::new(0.3);
        let b = VtScore::new(0.7);
        assert!(a < b);
    }

    #[test]
    fn ordering_greater_than() {
        let a = VtScore::new(0.9);
        let b = VtScore::new(0.1);
        assert!(a > b);
    }

    #[test]
    fn ordering_equal() {
        let a = VtScore::new(0.5);
        let b = VtScore::new(0.5);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn clone_preserves_value() {
        let a = VtScore::new(0.42);
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn to_storage_string_is_parseable() {
        let a = VtScore::new(0.123);
        let s = a.to_storage_string();
        let b: VtScore = s.parse().unwrap();
        assert_eq!(a, b);
    }
}
