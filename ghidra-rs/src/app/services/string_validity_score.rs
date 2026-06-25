/// Represents the result of a string validation scoring operation.
///
/// This struct encapsulates the scores and thresholds for validating a string,
/// as determined by a StringValidatorService. It tracks both the original and
/// transformed versions of the string, along with the computed score and threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct StringValidityScore {
    /// The original string being scored
    original_string: String,
    /// The transformed string after tweaks
    transformed_string: String,
    /// The validity score; larger values are more valid
    score: f64,
    /// The threshold that the score must exceed to be considered valid
    threshold: f64,
}

impl StringValidityScore {
    /// Creates a new StringValidityScore.
    ///
    /// # Arguments
    ///
    /// * `original_string` - The original string being scored
    /// * `transformed_string` - The transformed string after tweaks
    /// * `score` - The validity score; larger values are more valid
    /// * `threshold` - The threshold that the score must exceed to be valid
    pub fn new(
        original_string: impl Into<String>,
        transformed_string: impl Into<String>,
        score: f64,
        threshold: f64,
    ) -> Self {
        StringValidityScore {
            original_string: original_string.into(),
            transformed_string: transformed_string.into(),
            score,
            threshold,
        }
    }

    /// Creates a dummy StringValidityScore for the given string.
    ///
    /// The dummy has the same string for both original and transformed,
    /// with a score of 0 and a threshold of 100.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to create a dummy for
    pub fn make_dummy_for(s: impl Into<String>) -> Self {
        let s_owned = s.into();
        StringValidityScore {
            original_string: s_owned.clone(),
            transformed_string: s_owned,
            score: 0.0,
            threshold: 100.0,
        }
    }

    /// Returns the original string.
    pub fn original_string(&self) -> &str {
        &self.original_string
    }

    /// Returns the transformed string.
    pub fn transformed_string(&self) -> &str {
        &self.transformed_string
    }

    /// Returns the validity score.
    pub fn score(&self) -> f64 {
        self.score
    }

    /// Returns the threshold value.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Checks if the score is above the threshold.
    ///
    /// # Returns
    ///
    /// `true` if `score > threshold`, otherwise `false`
    pub fn is_score_above_threshold(&self) -> bool {
        self.score > self.threshold
    }
}

impl std::fmt::Display for StringValidityScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StringValidityScore(original='{}', transformed='{}', score={}, threshold={})",
            self.original_string, self.transformed_string, self.score, self.threshold
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_all_params() {
        let svs = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        assert_eq!(svs.original_string(), "hello");
        assert_eq!(svs.transformed_string(), "HELLO");
        assert_eq!(svs.score(), 42.5);
        assert_eq!(svs.threshold(), 50.0);
    }

    #[test]
    fn test_make_dummy_for() {
        let svs = StringValidityScore::make_dummy_for("test");
        assert_eq!(svs.original_string(), "test");
        assert_eq!(svs.transformed_string(), "test");
        assert_eq!(svs.score(), 0.0);
        assert_eq!(svs.threshold(), 100.0);
    }

    #[test]
    fn test_make_dummy_for_empty_string() {
        let svs = StringValidityScore::make_dummy_for("");
        assert_eq!(svs.original_string(), "");
        assert_eq!(svs.transformed_string(), "");
        assert_eq!(svs.score(), 0.0);
        assert_eq!(svs.threshold(), 100.0);
    }

    #[test]
    fn test_make_dummy_for_with_special_chars() {
        let svs = StringValidityScore::make_dummy_for("@#$%^&*()");
        assert_eq!(svs.original_string(), "@#$%^&*()");
        assert_eq!(svs.transformed_string(), "@#$%^&*()");
    }

    #[test]
    fn test_is_score_above_threshold_true() {
        let svs = StringValidityScore::new("test", "test", 100.0, 50.0);
        assert!(svs.is_score_above_threshold());
    }

    #[test]
    fn test_is_score_above_threshold_false() {
        let svs = StringValidityScore::new("test", "test", 40.0, 50.0);
        assert!(!svs.is_score_above_threshold());
    }

    #[test]
    fn test_is_score_above_threshold_equal() {
        let svs = StringValidityScore::new("test", "test", 50.0, 50.0);
        assert!(!svs.is_score_above_threshold());
    }

    #[test]
    fn test_is_score_above_threshold_zero_and_threshold() {
        let svs = StringValidityScore::new("test", "test", 0.0, 0.0);
        assert!(!svs.is_score_above_threshold());
    }

    #[test]
    fn test_is_score_above_threshold_with_negative_values() {
        let svs = StringValidityScore::new("test", "test", -10.0, -20.0);
        assert!(svs.is_score_above_threshold());
    }

    #[test]
    fn test_is_score_above_threshold_negative_score() {
        let svs = StringValidityScore::new("test", "test", -5.0, 0.0);
        assert!(!svs.is_score_above_threshold());
    }

    #[test]
    fn test_clone() {
        let svs1 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let svs2 = svs1.clone();
        assert_eq!(svs1, svs2);
        assert_eq!(svs1.original_string(), svs2.original_string());
    }

    #[test]
    fn test_equality() {
        let svs1 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let svs2 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        assert_eq!(svs1, svs2);
    }

    #[test]
    fn test_inequality_different_original() {
        let svs1 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let svs2 = StringValidityScore::new("world", "HELLO", 42.5, 50.0);
        assert_ne!(svs1, svs2);
    }

    #[test]
    fn test_inequality_different_transformed() {
        let svs1 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let svs2 = StringValidityScore::new("hello", "hello", 42.5, 50.0);
        assert_ne!(svs1, svs2);
    }

    #[test]
    fn test_inequality_different_score() {
        let svs1 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let svs2 = StringValidityScore::new("hello", "HELLO", 40.0, 50.0);
        assert_ne!(svs1, svs2);
    }

    #[test]
    fn test_inequality_different_threshold() {
        let svs1 = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let svs2 = StringValidityScore::new("hello", "HELLO", 42.5, 60.0);
        assert_ne!(svs1, svs2);
    }

    #[test]
    fn test_display() {
        let svs = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let display = svs.to_string();
        assert!(display.contains("hello"));
        assert!(display.contains("HELLO"));
        assert!(display.contains("42.5"));
        assert!(display.contains("50"));
    }

    #[test]
    fn test_debug() {
        let svs = StringValidityScore::new("hello", "HELLO", 42.5, 50.0);
        let debug_str = format!("{:?}", svs);
        assert!(debug_str.contains("StringValidityScore"));
    }

    #[test]
    fn test_string_into_conversion() {
        let svs = StringValidityScore::new("hello".to_string(), "HELLO".to_string(), 42.5, 50.0);
        assert_eq!(svs.original_string(), "hello");
        assert_eq!(svs.transformed_string(), "HELLO");
    }

    #[test]
    fn test_floating_point_precision() {
        let svs = StringValidityScore::new("test", "test", 99.99999999999999, 100.0);
        assert!(!svs.is_score_above_threshold());
    }

    #[test]
    fn test_very_large_numbers() {
        let svs = StringValidityScore::new("test", "test", 1e100, 1e99);
        assert!(svs.is_score_above_threshold());
    }

    #[test]
    fn test_very_small_numbers() {
        let svs = StringValidityScore::new("test", "test", 1e-100, 1e-101);
        assert!(svs.is_score_above_threshold());
    }

    #[test]
    fn test_unicode_strings() {
        let svs = StringValidityScore::new("café", "CAFÉ", 50.0, 50.0);
        assert_eq!(svs.original_string(), "café");
        assert_eq!(svs.transformed_string(), "CAFÉ");
        assert!(!svs.is_score_above_threshold());
    }

    #[test]
    fn test_empty_original_and_transformed() {
        let svs = StringValidityScore::new("", "", 10.0, 5.0);
        assert_eq!(svs.original_string(), "");
        assert_eq!(svs.transformed_string(), "");
        assert!(svs.is_score_above_threshold());
    }

    #[test]
    fn test_multiline_strings() {
        let original = "line1\nline2";
        let transformed = "line1\nline2\nline3";
        let svs = StringValidityScore::new(original, transformed, 75.0, 70.0);
        assert_eq!(svs.original_string(), original);
        assert_eq!(svs.transformed_string(), transformed);
        assert!(svs.is_score_above_threshold());
    }
}
