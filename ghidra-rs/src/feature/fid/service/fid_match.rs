//! Port of `ghidra.feature.fid.service.FidMatch`.

use crate::feature::fid::db::library_record::LibraryRecord;
use crate::feature::fid::service::fid_match_score::FidMatchScore;
use crate::program::model::address::Address;

/// A container that holds the results of a FidService search, comprised of the full path
/// within the storage API where it's located. Extends FidMatchScore with location information.
pub trait FidMatch: FidMatchScore {
    /// Returns the actual entry point of the matched function (in the searched program,
    /// not the FID library).
    fn get_matched_function_entry_point(&self) -> Address;

    /// Returns the library record for the potential match.
    fn get_library_record(&self) -> &LibraryRecord;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::plugin::hash_lookup_list_mode::HashLookupListMode;

    struct MockLibraryRecord;
    struct MockFunctionRecord;
    struct MockAddressSpace;

    struct MockMatch {
        score: f32,
    }

    impl FidMatchScore for MockMatch {
        fn get_function_record(&self) -> &crate::feature::fid::db::function_record::FunctionRecord {
            unimplemented!("Mock does not provide FunctionRecord")
        }

        fn get_primary_function_code_unit_score(&self) -> f32 {
            self.score
        }

        fn get_primary_function_match_mode(&self) -> HashLookupListMode {
            HashLookupListMode::Full
        }

        fn get_child_function_code_unit_score(&self) -> f32 {
            5.0
        }

        fn get_parent_function_code_unit_score(&self) -> f32 {
            3.0
        }

        fn get_overall_score(&self) -> f32 {
            self.score + 5.0 + 3.0
        }
    }

    impl FidMatch for MockMatch {
        fn get_matched_function_entry_point(&self) -> Address {
            unimplemented!("Mock does not provide Address")
        }

        fn get_library_record(&self) -> &LibraryRecord {
            unimplemented!("Mock does not provide LibraryRecord")
        }
    }

    #[test]
    fn test_fid_match_is_trait_object() {
        let mock = MockMatch { score: 10.0 };

        // Verify FidMatchScore methods are accessible through FidMatch trait
        assert_eq!(mock.get_primary_function_code_unit_score(), 10.0);
        assert_eq!(mock.get_child_function_code_unit_score(), 5.0);
        assert_eq!(mock.get_parent_function_code_unit_score(), 3.0);
        assert_eq!(mock.get_overall_score(), 18.0);

        // FidMatch extends FidMatchScore, so a struct implementing FidMatch
        // automatically has all FidMatchScore methods available
        let _match: &dyn FidMatch = &mock;
    }
}
