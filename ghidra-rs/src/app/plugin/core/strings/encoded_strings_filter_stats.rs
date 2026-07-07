use std::collections::HashMap;

/// Holds counts of reasons for filter rejection in the encoded strings analysis.
///
/// This struct tracks various statistics about strings that were filtered out
/// during the encoding analysis process, including errors, invalid characters,
/// and script-related rejections.
#[derive(Debug, Clone)]
pub struct EncodedStringsFilterStats {
    /// Total count
    pub total: i32,
    /// Count of codec errors
    pub codec_errors: i32,
    /// Count of non-standard control characters
    pub non_std_ctrl_chars: i32,
    /// Count of failed string model validations
    pub failed_string_model: i32,
    /// Count of rejections due to string length
    pub string_length: i32,
    /// Count of rejections due to required scripts
    pub required_scripts: i32,
    /// Count of other script rejections
    pub other_scripts: i32,
    /// Count of Latin script occurrences
    pub latin_script: i32,
    /// Count of common script occurrences
    pub common_script: i32,
    /// Map of Unicode script ordinals to occurrence counts
    pub found_script_counts: HashMap<i32, i32>,
}

impl EncodedStringsFilterStats {
    /// Creates a new empty EncodedStringsFilterStats with all counts set to 0.
    pub fn new() -> Self {
        Self {
            total: 0,
            codec_errors: 0,
            non_std_ctrl_chars: 0,
            failed_string_model: 0,
            string_length: 0,
            required_scripts: 0,
            other_scripts: 0,
            latin_script: 0,
            common_script: 0,
            found_script_counts: HashMap::new(),
        }
    }

    /// Returns the total count of filters from the advanced options categories.
    ///
    /// This includes: codec_errors, non_std_ctrl_chars, failed_string_model, and string_length.
    pub fn get_total_for_advanced_options(&self) -> i32 {
        self.codec_errors
            + self.non_std_ctrl_chars
            + self.failed_string_model
            + self.string_length
    }

    /// Returns the total count of all omitted strings.
    ///
    /// This includes: codec_errors, non_std_ctrl_chars, failed_string_model, string_length,
    /// and required_scripts.
    pub fn get_total_omitted(&self) -> i32 {
        self.codec_errors
            + self.non_std_ctrl_chars
            + self.failed_string_model
            + self.string_length
            + self.required_scripts
    }
}

impl Default for EncodedStringsFilterStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default_values() {
        let stats = EncodedStringsFilterStats::new();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.codec_errors, 0);
        assert_eq!(stats.non_std_ctrl_chars, 0);
        assert_eq!(stats.failed_string_model, 0);
        assert_eq!(stats.string_length, 0);
        assert_eq!(stats.required_scripts, 0);
        assert_eq!(stats.other_scripts, 0);
        assert_eq!(stats.latin_script, 0);
        assert_eq!(stats.common_script, 0);
        assert!(stats.found_script_counts.is_empty());
    }

    #[test]
    fn test_default_trait() {
        let stats = EncodedStringsFilterStats::default();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.codec_errors, 0);
    }

    #[test]
    fn test_clone() {
        let mut stats1 = EncodedStringsFilterStats::new();
        stats1.total = 42;
        stats1.codec_errors = 5;
        stats1.found_script_counts.insert(1, 10);

        let stats2 = stats1.clone();

        assert_eq!(stats2.total, 42);
        assert_eq!(stats2.codec_errors, 5);
        assert_eq!(stats2.found_script_counts.get(&1), Some(&10));
    }

    #[test]
    fn test_clone_independence() {
        let mut stats1 = EncodedStringsFilterStats::new();
        stats1.found_script_counts.insert(1, 10);

        let mut stats2 = stats1.clone();
        stats2.found_script_counts.insert(2, 20);

        // Verify stats1 wasn't modified
        assert_eq!(stats1.found_script_counts.len(), 1);
        assert_eq!(stats2.found_script_counts.len(), 2);
    }

    #[test]
    fn test_get_total_for_advanced_options() {
        let mut stats = EncodedStringsFilterStats::new();
        stats.codec_errors = 5;
        stats.non_std_ctrl_chars = 3;
        stats.failed_string_model = 2;
        stats.string_length = 4;
        // required_scripts shouldn't be included
        stats.required_scripts = 100;

        assert_eq!(stats.get_total_for_advanced_options(), 14);
    }

    #[test]
    fn test_get_total_omitted() {
        let mut stats = EncodedStringsFilterStats::new();
        stats.codec_errors = 5;
        stats.non_std_ctrl_chars = 3;
        stats.failed_string_model = 2;
        stats.string_length = 4;
        stats.required_scripts = 10;
        // other_scripts shouldn't be included
        stats.other_scripts = 100;

        assert_eq!(stats.get_total_omitted(), 24);
    }

    #[test]
    fn test_found_script_counts() {
        let mut stats = EncodedStringsFilterStats::new();
        stats.found_script_counts.insert(0, 5); // COMMON script
        stats.found_script_counts.insert(1, 10); // LATIN script
        stats.found_script_counts.insert(2, 3); // GREEK script

        assert_eq!(stats.found_script_counts.get(&0), Some(&5));
        assert_eq!(stats.found_script_counts.get(&1), Some(&10));
        assert_eq!(stats.found_script_counts.get(&2), Some(&3));
    }

    #[test]
    fn test_clone_preserves_all_fields() {
        let mut stats1 = EncodedStringsFilterStats::new();
        stats1.total = 100;
        stats1.codec_errors = 10;
        stats1.non_std_ctrl_chars = 5;
        stats1.failed_string_model = 3;
        stats1.string_length = 2;
        stats1.required_scripts = 15;
        stats1.other_scripts = 8;
        stats1.latin_script = 50;
        stats1.common_script = 40;
        stats1.found_script_counts.insert(0, 40);
        stats1.found_script_counts.insert(1, 50);

        let stats2 = stats1.clone();

        assert_eq!(stats2.total, 100);
        assert_eq!(stats2.codec_errors, 10);
        assert_eq!(stats2.non_std_ctrl_chars, 5);
        assert_eq!(stats2.failed_string_model, 3);
        assert_eq!(stats2.string_length, 2);
        assert_eq!(stats2.required_scripts, 15);
        assert_eq!(stats2.other_scripts, 8);
        assert_eq!(stats2.latin_script, 50);
        assert_eq!(stats2.common_script, 40);
        assert_eq!(stats2.found_script_counts.len(), 2);
    }

    #[test]
    fn test_zero_counts() {
        let stats = EncodedStringsFilterStats::new();
        assert_eq!(stats.get_total_for_advanced_options(), 0);
        assert_eq!(stats.get_total_omitted(), 0);
    }
}
