//! Port of `ghidra.feature.fid.service.FidMatchImpl`.

use std::fmt;

use crate::feature::fid::db::function_record::FunctionRecord;
use crate::feature::fid::db::library_record::LibraryRecord;
use crate::feature::fid::plugin::hash_lookup_list_mode::HashLookupListMode;
use crate::feature::fid::service::fid_match::FidMatch;
use crate::feature::fid::service::fid_match_score::FidMatchScore;
use crate::program::model::address::Address;

/// A [`FidMatchScore`] that can also be rendered as text.
///
/// Java's `scoreDelegate` field is typed as the plain `FidMatchScore` interface, but
/// [`FidMatchImpl::toString`]'s body (`scoreDelegate + " @ " + functionEntryPoint`) implicitly
/// calls `scoreDelegate.toString()` -- inherited from `java.lang.Object`, not declared by the
/// `FidMatchScore` interface itself, and overridden by every real implementor (e.g. `HashMatch`,
/// not yet ported). This crate's [`FidMatchScore`] trait (already ported elsewhere, mirroring the
/// Java interface exactly) therefore has no `Display`/`toString` requirement either, so
/// `FidMatchImpl` needs its own combined bound to hold a delegate it can both forward scoring
/// calls to *and* format. Blanket-implemented for anything satisfying both, so any existing
/// [`FidMatchScore`] implementor that also implements [`fmt::Display`] works here with no changes.
pub trait FidMatchScoreDisplay: FidMatchScore + fmt::Display {}
impl<T: FidMatchScore + fmt::Display> FidMatchScoreDisplay for T {}

/// Implementation of the [`FidMatch`] trait: a matched library/function pair, with the actual
/// scoring delegated to a wrapped [`FidMatchScore`].
///
/// Port of `ghidra.feature.fid.service.FidMatchImpl`. Java's class (and its sole constructor) are
/// package-private; kept `pub` here since Rust has no package-private visibility tier narrower
/// than the crate (matching this project's established convention, e.g.
/// [`FunctionVariableData`](crate::app::plugin::core::function::editor::FunctionVariableData)).
pub struct FidMatchImpl {
    library: LibraryRecord,
    function_entry_point: Address,
    score_delegate: Box<dyn FidMatchScoreDisplay>,
}

impl FidMatchImpl {
    /// Java: `FidMatchImpl(LibraryRecord library, Address functionEntryPoint, FidMatchScore
    /// score)`.
    pub fn new(
        library: LibraryRecord,
        function_entry_point: Address,
        score: Box<dyn FidMatchScoreDisplay>,
    ) -> Self {
        Self { library, function_entry_point, score_delegate: score }
    }
}

impl FidMatchScore for FidMatchImpl {
    /// Java: `getFunctionRecord()`, delegating to `scoreDelegate`.
    fn get_function_record(&self) -> &FunctionRecord {
        self.score_delegate.get_function_record()
    }

    /// Java: `getPrimaryFunctionCodeUnitScore()`, delegating to `scoreDelegate`.
    fn get_primary_function_code_unit_score(&self) -> f32 {
        self.score_delegate.get_primary_function_code_unit_score()
    }

    /// Java: `getPrimaryFunctionMatchMode()`, delegating to `scoreDelegate`.
    fn get_primary_function_match_mode(&self) -> HashLookupListMode {
        self.score_delegate.get_primary_function_match_mode()
    }

    /// Java: `getChildFunctionCodeUnitScore()`, delegating to `scoreDelegate`.
    fn get_child_function_code_unit_score(&self) -> f32 {
        self.score_delegate.get_child_function_code_unit_score()
    }

    /// Java: `getParentFunctionCodeUnitScore()`, delegating to `scoreDelegate`.
    fn get_parent_function_code_unit_score(&self) -> f32 {
        self.score_delegate.get_parent_function_code_unit_score()
    }

    /// Java: `getOverallScore()`, delegating to `scoreDelegate`.
    fn get_overall_score(&self) -> f32 {
        self.score_delegate.get_overall_score()
    }
}

impl FidMatch for FidMatchImpl {
    /// Java: `getMatchedFunctionEntryPoint()`.
    fn get_matched_function_entry_point(&self) -> Address {
        self.function_entry_point.clone()
    }

    /// Java: `getLibraryRecord()`.
    fn get_library_record(&self) -> &LibraryRecord {
        &self.library
    }
}

impl fmt::Display for FidMatchImpl {
    /// Java: `toString()`, `return scoreDelegate + " @ " + functionEntryPoint;`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {}", self.score_delegate, self.function_entry_point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::db::fid_db::test_support::minimal_fid_db;
    use crate::feature::seam_stubs::{StringRecord, StringsTable};
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// Minimal `LibraryRecord`, built the same way as
    /// [`crate::feature::fid::service::fid_populate_result`]'s own test helper.
    fn library_record(id: i64) -> LibraryRecord {
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String; 8],
            vec![
                "LibraryFamilyName".to_string(),
                "LibraryVersion".to_string(),
                "LibraryVariant".to_string(),
                "GhidraVersion".to_string(),
                "GhidraLanguageID".to_string(),
                "GhidraLanguageVersion".to_string(),
                "GhidraLanguageMinorVersion".to_string(),
                "GhidraCompilerSpecID".to_string(),
            ],
            vec![],
        ));
        let record = DBRecord::new(schema, Field::Long(Some(id)));
        LibraryRecord::new(record)
    }

    struct FakeStringsTable {
        strings: Mutex<HashMap<i64, String>>,
    }

    impl StringsTable for FakeStringsTable {
        fn lookup_string(&self, id: i64) -> Option<StringRecord> {
            self.strings.lock().unwrap().get(&id).cloned().map(|v| StringRecord::new(id, v))
        }
    }

    fn function_record_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Function ID".to_string(),
            vec![
                FieldType::Short,
                FieldType::Long,
                FieldType::Byte,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Byte,
            ],
            vec![
                "Code Unit Size".to_string(),
                "Full Hash".to_string(),
                "Specific Hash Additional Size".to_string(),
                "Specific Hash".to_string(),
                "Library ID".to_string(),
                "Name ID".to_string(),
                "Entry Point".to_string(),
                "Domain Path ID".to_string(),
                "Flags".to_string(),
            ],
            vec![],
        ))
    }

    /// Builds a minimal, real `FunctionRecord` (not a mock) since [`FidMatchScore`] requires
    /// returning a genuine `&FunctionRecord`, matching the approach already established by
    /// [`crate::feature::fid::db::function_record`]'s own tests.
    fn function_record(id: i64) -> FunctionRecord {
        let strings_table = Arc::new(FakeStringsTable { strings: Mutex::new(HashMap::new()) });
        let fid_db = minimal_fid_db(strings_table);
        let record = DBRecord::new(function_record_schema(), Field::Long(Some(id)));
        FunctionRecord::new(fid_db, record)
    }

    /// A [`FidMatchScore`] + [`fmt::Display`] test double standing in for `HashMatch` (the real
    /// Java implementor, not yet ported), whose scores are fixed constants threaded through from
    /// its fields, similar to `fid_match_score.rs`'s and `fid_match.rs`'s own `MockMatch` test
    /// doubles.
    struct TestScore {
        function_record: FunctionRecord,
        primary: f32,
        mode: HashLookupListMode,
        child: f32,
        parent: f32,
    }

    impl FidMatchScore for TestScore {
        fn get_function_record(&self) -> &FunctionRecord {
            &self.function_record
        }
        fn get_primary_function_code_unit_score(&self) -> f32 {
            self.primary
        }
        fn get_primary_function_match_mode(&self) -> HashLookupListMode {
            self.mode
        }
        fn get_child_function_code_unit_score(&self) -> f32 {
            self.child
        }
        fn get_parent_function_code_unit_score(&self) -> f32 {
            self.parent
        }
        fn get_overall_score(&self) -> f32 {
            self.primary + self.child + self.parent
        }
    }

    impl fmt::Display for TestScore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "score({:.1})", self.get_overall_score())
        }
    }

    fn make_match(entry: Address) -> FidMatchImpl {
        let score = TestScore {
            function_record: function_record(1),
            primary: 10.0,
            mode: HashLookupListMode::Full,
            child: 5.0,
            parent: 3.0,
        };
        FidMatchImpl::new(library_record(7), entry, Box::new(score))
    }

    #[test]
    fn get_library_record_returns_the_constructed_library() {
        let m = make_match(addr(0x1000));
        assert_eq!(m.get_library_record().get_library_id(), 7);
    }

    #[test]
    fn get_matched_function_entry_point_returns_the_constructed_address() {
        let entry = addr(0x401000);
        let m = make_match(entry.clone());
        assert_eq!(m.get_matched_function_entry_point(), entry);
    }

    #[test]
    fn score_accessors_delegate_to_the_wrapped_score() {
        let m = make_match(addr(0x2000));
        assert_eq!(m.get_primary_function_code_unit_score(), 10.0);
        assert_eq!(m.get_primary_function_match_mode(), HashLookupListMode::Full);
        assert_eq!(m.get_child_function_code_unit_score(), 5.0);
        assert_eq!(m.get_parent_function_code_unit_score(), 3.0);
        assert_eq!(m.get_overall_score(), 18.0);
    }

    #[test]
    fn get_function_record_delegates_to_the_wrapped_score() {
        let m = make_match(addr(0x2000));
        assert_eq!(m.get_function_record().get_id(), 1);
    }

    #[test]
    fn display_matches_the_delegates_display_followed_by_the_entry_point() {
        let entry = addr(0x3000);
        let m = make_match(entry.clone());
        assert_eq!(m.to_string(), format!("score(18.0) @ {}", entry));
    }

    #[test]
    fn usable_as_a_fid_match_trait_object() {
        let m: Box<dyn FidMatch> = Box::new(make_match(addr(0x4000)));
        assert_eq!(m.get_overall_score(), 18.0);
        assert_eq!(m.get_library_record().get_library_id(), 7);
    }
}
