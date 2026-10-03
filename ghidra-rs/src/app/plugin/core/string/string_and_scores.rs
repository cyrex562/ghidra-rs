use once_cell::sync::Lazy;
use regex::Regex;

use crate::util::msg::Msg;

static NON_ASCII_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[^\x00-\x7F]").unwrap());
static MULTI_SPACE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r" {2,}").unwrap());
static MULTI_TAB_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\t{2,}").unwrap());

/// Storage class for Strings identified by the String Searcher and their associated
/// ngram scores. The scores, combined with the score thresholds, determine if this
/// string passes or fails.
#[derive(Debug)]
pub struct StringAndScores {
    original_string: String,
    scored_string: String,
    ascii_codes_for_string: Vec<i32>,
    ngram_score: f64,
    score_threshold: f64,
}

impl StringAndScores {
    pub fn new(str: &str, is_lower_case_model: bool) -> Self {
        let original_string = str.to_string();
        let scored_string = if is_lower_case_model {
            original_string.to_lowercase()
        } else {
            original_string.clone()
        };

        let mut result = StringAndScores {
            original_string,
            scored_string,
            ascii_codes_for_string: Vec::new(),
            // If score threshold is not set by the code that instantiates the object,
            // the string will never pass the threshold test.
            ngram_score: -100.0,
            score_threshold: 10.0,
        };

        result.normalize_and_store_ascii_codes();

        result
    }

    fn normalize_and_store_ascii_codes(&mut self) {
        let intermediate_string = if NON_ASCII_RE.is_match(&self.scored_string) {
            self.replace_invalid_ascii(&self.scored_string.clone())
        } else {
            self.scored_string.clone()
        };

        self.scored_string = Self::normalize_spaces(&intermediate_string);
        self.translate_to_ascii_codes();
    }

    fn replace_invalid_ascii(&self, string: &str) -> String {
        let string_chars: Vec<char> = string.chars().collect();
        let mut ascii_string_chars: Vec<char> = Vec::with_capacity(string_chars.len());

        let mut bad = String::new();
        for &current_char in &string_chars {
            if (current_char as u32) <= 127 {
                ascii_string_chars.push(current_char);
            } else {
                let digit = current_char.to_digit(10).map(|d| d as i32).unwrap_or(-1);
                bad.push_str(&digit.to_string());
                bad.push(' ');
                ascii_string_chars.push(' ');
            }
        }

        Msg::debug(
            "StringAndScores",
            &format!(
                "Warning: found non-ASCII character(s) while analyzing '{}' \
                --replacing with space characters during analysis.  Char values: {}",
                self.scored_string, bad
            ),
        );

        ascii_string_chars.into_iter().collect()
    }

    fn translate_to_ascii_codes(&mut self) {
        self.ascii_codes_for_string = self
            .scored_string
            .chars()
            .map(|c| c as i32)
            .collect();
    }

    fn normalize_spaces(str: &str) -> String {
        // Remove leading and trailing spaces
        let new_str = str.trim();

        // Collapse consecutive spaces into 1 space
        let new_str = MULTI_SPACE_RE.replace_all(new_str, " ");

        // Collapse consecutive tabs into 1 tab
        let new_str = MULTI_TAB_RE.replace_all(&new_str, "\t");

        new_str.into_owned()
    }

    pub fn set_ngram_score(&mut self, ng_sc: f64) {
        self.ngram_score = ng_sc;
    }

    pub fn set_score_threshold(&mut self, thresh: f64) {
        self.score_threshold = thresh;
    }

    pub fn get_original_string(&self) -> &str {
        &self.original_string
    }

    pub fn get_scored_string(&self) -> &str {
        &self.scored_string
    }

    pub fn get_ngram_score(&self) -> f64 {
        self.ngram_score
    }

    pub fn get_score_threshold(&self) -> f64 {
        self.score_threshold
    }

    pub fn get_scored_string_length(&self) -> usize {
        self.ascii_codes_for_string.len()
    }

    pub fn get_ascii_codes(&self) -> &[i32] {
        &self.ascii_codes_for_string
    }

    pub fn is_score_above_threshold(&self) -> bool {
        self.ngram_score > self.score_threshold
    }

    pub fn summary_to_string(&self) -> String {
        format!("{}\t{}", self.ngram_score, self.original_string)
    }
}

impl PartialEq for StringAndScores {
    fn eq(&self, other: &Self) -> bool {
        self.original_string == other.original_string
    }
}

impl Eq for StringAndScores {}

impl std::hash::Hash for StringAndScores {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.original_string.hash(state);
    }
}

impl std::fmt::Display for StringAndScores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OrigString ={},ScoredString ={},ASCII =",
            self.original_string, self.scored_string
        )?;

        for code in &self.ascii_codes_for_string {
            write!(f, "{} ", code)?;
        }

        write!(
            f,
            ",ngScore ={}, threshold = {}",
            self.ngram_score, self.score_threshold
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_basic() {
        let sas = StringAndScores::new("Hello World", false);
        assert_eq!(sas.get_original_string(), "Hello World");
        assert_eq!(sas.get_scored_string(), "Hello World");
        assert_eq!(sas.get_ngram_score(), -100.0);
        assert_eq!(sas.get_score_threshold(), 10.0);
    }

    #[test]
    fn test_new_lowercase_model() {
        let sas = StringAndScores::new("Hello World", true);
        assert_eq!(sas.get_original_string(), "Hello World");
        assert_eq!(sas.get_scored_string(), "hello world");
    }

    #[test]
    fn test_ascii_codes() {
        let sas = StringAndScores::new("AB", false);
        assert_eq!(sas.get_ascii_codes(), &[65, 66]);
        assert_eq!(sas.get_scored_string_length(), 2);
    }

    #[test]
    fn test_normalize_spaces_trims_and_collapses() {
        let sas = StringAndScores::new("  a   b  ", false);
        assert_eq!(sas.get_scored_string(), "a b");
    }

    #[test]
    fn test_normalize_collapses_tabs() {
        let sas = StringAndScores::new("a\t\t\tb", false);
        assert_eq!(sas.get_scored_string(), "a\tb");
    }

    #[test]
    fn test_non_ascii_replaced_with_space() {
        let sas = StringAndScores::new("café", false);
        assert_eq!(sas.get_scored_string(), "caf");
        // The trailing non-ASCII char becomes a space, which is then
        // trimmed away by normalize_spaces, leaving "caf" (length 3).
        assert_eq!(sas.get_scored_string_length(), 3);
    }

    #[test]
    fn test_score_setters() {
        let mut sas = StringAndScores::new("test", false);
        sas.set_ngram_score(5.5);
        sas.set_score_threshold(2.0);
        assert_eq!(sas.get_ngram_score(), 5.5);
        assert_eq!(sas.get_score_threshold(), 2.0);
        assert!(sas.is_score_above_threshold());
    }

    #[test]
    fn test_score_not_above_threshold_by_default() {
        let sas = StringAndScores::new("test", false);
        assert!(!sas.is_score_above_threshold());
    }

    #[test]
    fn test_equality_based_on_original_string() {
        let a = StringAndScores::new("same", false);
        let b = StringAndScores::new("same", true);
        assert_eq!(a, b);

        let c = StringAndScores::new("different", false);
        assert_ne!(a, c);
    }

    #[test]
    fn test_summary_to_string() {
        let mut sas = StringAndScores::new("hi", false);
        sas.set_ngram_score(3.0);
        assert_eq!(sas.summary_to_string(), "3\thi");
    }

    #[test]
    fn test_display() {
        let sas = StringAndScores::new("ab", false);
        let s = sas.to_string();
        assert!(s.contains("OrigString =ab"));
        assert!(s.contains("ScoredString =ab"));
        assert!(s.contains("ASCII =97 98"));
    }
}
