//! Port of `ghidra.feature.fid.service.HashMatch`.

use std::fmt;

use crate::feature::fid::db::function_record::FunctionRecord;
use crate::feature::fid::plugin::hash_lookup_list_mode::HashLookupListMode;
use crate::feature::fid::service::fid_match_score::FidMatchScore;

/// The implementation class of [`FidMatchScore`].
///
/// Port of `ghidra.feature.fid.service.HashMatch`.
pub struct HashMatch {
    function_record: FunctionRecord,
    primary_function_code_unit_score: f32,
    primary_function_match_mode: HashLookupListMode,
    child_function_code_unit_score: f32,
    parent_function_code_unit_score: f32,
}

impl HashMatch {
    /// Port of `HashMatch(FunctionRecord, float, HashLookupListMode, float, float)`.
    pub fn new(
        function_record: FunctionRecord,
        primary_function_code_unit_score: f32,
        primary_function_match_mode: HashLookupListMode,
        child_function_code_unit_score: f32,
        parent_function_code_unit_score: f32,
    ) -> Self {
        Self {
            function_record,
            primary_function_code_unit_score,
            primary_function_match_mode,
            child_function_code_unit_score,
            parent_function_code_unit_score,
        }
    }
}

impl FidMatchScore for HashMatch {
    fn get_function_record(&self) -> &FunctionRecord {
        &self.function_record
    }

    fn get_primary_function_code_unit_score(&self) -> f32 {
        self.primary_function_code_unit_score
    }

    fn get_primary_function_match_mode(&self) -> HashLookupListMode {
        self.primary_function_match_mode
    }

    fn get_child_function_code_unit_score(&self) -> f32 {
        self.child_function_code_unit_score
    }

    fn get_parent_function_code_unit_score(&self) -> f32 {
        self.parent_function_code_unit_score
    }

    fn get_overall_score(&self) -> f32 {
        self.primary_function_code_unit_score
            + self.child_function_code_unit_score
            + self.parent_function_code_unit_score
    }
}

impl fmt::Display for HashMatch {
    /// Port of `toString()`:
    /// `String.format("%.1f - %.1f (%s)/%.1f/%.1f %s", getOverallScore(),
    /// primaryFunctionCodeUnitScore, primaryFunctionMatchMode, childFunctionCodeUnitScore,
    /// parentFunctionCodeUnitScore, functionRecord.toString())`.
    ///
    /// `%s` on a Java enum renders its constant name verbatim (`FULL`/`SPECIFIC`, not Rust's
    /// `Debug`-derived `Full`/`Specific`), so this maps [`HashLookupListMode`] to that exact text
    /// rather than using `{:?}`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self.primary_function_match_mode {
            HashLookupListMode::Full => "FULL",
            HashLookupListMode::Specific => "SPECIFIC",
        };
        write!(
            f,
            "{:.1} - {:.1} ({})/{:.1}/{:.1} {}",
            self.get_overall_score(),
            self.primary_function_code_unit_score,
            mode,
            self.child_function_code_unit_score,
            self.parent_function_code_unit_score,
            self.function_record,
        )
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

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

    /// Builds a minimal, real `FunctionRecord` (not a mock), matching the approach used by
    /// `fid_match_impl.rs`'s own tests.
    fn function_record(id: i64) -> FunctionRecord {
        let strings_table = Arc::new(FakeStringsTable { strings: Mutex::new(HashMap::new()) });
        let fid_db = minimal_fid_db(strings_table);
        let record = DBRecord::new(function_record_schema(), Field::Long(Some(id)));
        FunctionRecord::new(fid_db, record)
    }

    fn make_match(
        primary: f32,
        mode: HashLookupListMode,
        child: f32,
        parent: f32,
    ) -> HashMatch {
        HashMatch::new(function_record(1), primary, mode, child, parent)
    }

    #[test]
    fn accessors_return_constructed_values() {
        let m = make_match(10.0, HashLookupListMode::Full, 5.0, 3.0);
        assert_eq!(m.get_primary_function_code_unit_score(), 10.0);
        assert_eq!(m.get_primary_function_match_mode(), HashLookupListMode::Full);
        assert_eq!(m.get_child_function_code_unit_score(), 5.0);
        assert_eq!(m.get_parent_function_code_unit_score(), 3.0);
        assert_eq!(m.get_function_record().get_id(), 1);
    }

    #[test]
    fn overall_score_sums_the_three_components() {
        let m = make_match(10.0, HashLookupListMode::Full, 5.0, 3.0);
        assert_eq!(m.get_overall_score(), 18.0);
    }

    #[test]
    fn overall_score_with_zero_values() {
        let m = make_match(0.0, HashLookupListMode::Specific, 0.0, 0.0);
        assert_eq!(m.get_overall_score(), 0.0);
    }

    #[test]
    fn display_matches_java_string_format() {
        let m = make_match(10.0, HashLookupListMode::Full, 5.0, 3.0);
        let expected = format!("18.0 - 10.0 (FULL)/5.0/3.0 {}", m.get_function_record());
        assert_eq!(m.to_string(), expected);
    }

    #[test]
    fn display_renders_specific_mode_uppercase() {
        let m = make_match(1.5, HashLookupListMode::Specific, 2.3, 0.2);
        assert!(m.to_string().contains("(SPECIFIC)"));
    }

    #[test]
    fn display_rounds_to_one_decimal_place() {
        // 1.26 is unambiguously above the 1.25 halfway point, so it rounds up to "1.3" the same
        // way under any rounding rule -- avoids relying on a specific tie-breaking behavior.
        let m = make_match(1.26, HashLookupListMode::Full, 0.0, 0.0);
        assert!(m.to_string().starts_with("1.3 - 1.3 "));
    }

    #[test]
    fn usable_as_a_fid_match_score_trait_object() {
        let m: Box<dyn FidMatchScore> = Box::new(make_match(10.0, HashLookupListMode::Full, 5.0, 3.0));
        assert_eq!(m.get_overall_score(), 18.0);
    }
}
