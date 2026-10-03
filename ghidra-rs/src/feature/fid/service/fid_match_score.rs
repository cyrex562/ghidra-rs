//! Port of `ghidra.feature.fid.service.FidMatchScore`.

use crate::feature::fid::db::function_record::FunctionRecord;
use crate::feature::fid::plugin::hash_lookup_list_mode::HashLookupListMode;

/// Interface abstracting a potential function match and its score.
pub trait FidMatchScore {
    /// Returns the function record of the potential match.
    fn get_function_record(&self) -> &FunctionRecord;

    /// Returns the number of code units in just the potential function.
    fn get_primary_function_code_unit_score(&self) -> f32;

    /// Returns the type of hash match for the potential function.
    fn get_primary_function_match_mode(&self) -> HashLookupListMode;

    /// Returns the accumulated matching code units in child (inferior, callee) functions.
    fn get_child_function_code_unit_score(&self) -> f32;

    /// Returns the accumulated matching code units in parent (superior, caller) functions.
    fn get_parent_function_code_unit_score(&self) -> f32;

    /// Returns the overall score (higher is better).
    fn get_overall_score(&self) -> f32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockFunctionRecord;

    impl Default for MockFunctionRecord {
        fn default() -> Self {
            Self
        }
    }

    struct MockMatch {
        function_record: MockFunctionRecord,
        primary_code_unit_score: f32,
        primary_match_mode: HashLookupListMode,
        child_code_unit_score: f32,
        parent_code_unit_score: f32,
    }

    impl FidMatchScore for MockMatch {
        fn get_function_record(&self) -> &FunctionRecord {
            unimplemented!("Mock does not have FunctionRecord")
        }

        fn get_primary_function_code_unit_score(&self) -> f32 {
            self.primary_code_unit_score
        }

        fn get_primary_function_match_mode(&self) -> HashLookupListMode {
            self.primary_match_mode
        }

        fn get_child_function_code_unit_score(&self) -> f32 {
            self.child_code_unit_score
        }

        fn get_parent_function_code_unit_score(&self) -> f32 {
            self.parent_code_unit_score
        }

        fn get_overall_score(&self) -> f32 {
            self.primary_code_unit_score
                + self.child_code_unit_score
                + self.parent_code_unit_score
        }
    }

    #[test]
    fn test_overall_score_calculation() {
        let mock = MockMatch {
            function_record: MockFunctionRecord::default(),
            primary_code_unit_score: 10.0,
            primary_match_mode: HashLookupListMode::Full,
            child_code_unit_score: 5.0,
            parent_code_unit_score: 3.0,
        };

        assert_eq!(mock.get_overall_score(), 18.0);
        assert_eq!(mock.get_primary_function_code_unit_score(), 10.0);
        assert_eq!(mock.get_child_function_code_unit_score(), 5.0);
        assert_eq!(mock.get_parent_function_code_unit_score(), 3.0);
        assert_eq!(
            mock.get_primary_function_match_mode(),
            HashLookupListMode::Full
        );
    }

    #[test]
    fn test_score_with_zero_values() {
        let mock = MockMatch {
            function_record: MockFunctionRecord::default(),
            primary_code_unit_score: 0.0,
            primary_match_mode: HashLookupListMode::Specific,
            child_code_unit_score: 0.0,
            parent_code_unit_score: 0.0,
        };

        assert_eq!(mock.get_overall_score(), 0.0);
    }

    #[test]
    fn test_score_with_fractional_values() {
        let mock = MockMatch {
            function_record: MockFunctionRecord::default(),
            primary_code_unit_score: 1.5,
            primary_match_mode: HashLookupListMode::Full,
            child_code_unit_score: 2.3,
            parent_code_unit_score: 0.2,
        };

        let expected = 1.5 + 2.3 + 0.2;
        assert!((mock.get_overall_score() - expected).abs() < 0.0001);
    }
}
