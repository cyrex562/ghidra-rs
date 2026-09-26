//! Port of `ghidra.feature.fid.db.FidDBUtils`.
//!
//! Currently this class only contains the helper methods that calculate "hash smash" values for
//! parent/child call relationships. See [`RelationsTable`](super::relations_table::RelationsTable)
//! for more information.

use crate::feature::fid::hash::fid_hash_quad::FidHashQuad;
use crate::generic::hash::FNV1a64MessageDigest;

use super::function_record::FunctionRecord;

/// Generate the hash smash for a superior id/inferior full hash.
///
/// Java: `generateSuperiorFullHashSmash(FunctionRecord, FunctionRecord)`.
pub fn generate_superior_full_hash_smash(
    superior_function: &FunctionRecord,
    inferior_function: &FunctionRecord,
) -> i64 {
    generate_superior_full_hash_smash_quad(superior_function, inferior_function)
}

/// Generate the hash smash for a superior full hash/inferior id.
///
/// Java: `generateInferiorFullHashSmash(FunctionRecord, FunctionRecord)`.
pub fn generate_inferior_full_hash_smash(
    superior_function: &FunctionRecord,
    inferior_function: &FunctionRecord,
) -> i64 {
    generate_inferior_full_hash_smash_quad(superior_function, inferior_function)
}

/// Generate the hash smash for a superior id/inferior full hash.
///
/// Java: `generateSuperiorFullHashSmash(FunctionRecord, FidHashQuad)`, the overload used when
/// only a hash quad (not a resolved `FunctionRecord`) is known for the inferior side.
pub fn generate_superior_full_hash_smash_quad(
    superior_function: &FunctionRecord,
    inferior_function: &dyn FidHashQuad,
) -> i64 {
    let hash_value =
        superior_function.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME); // Improve bit diversity on key
    hash_value ^ inferior_function.full_hash()
}

/// Generate the hash smash for a superior full hash/inferior id.
///
/// Java: `generateInferiorFullHashSmash(FidHashQuad, FunctionRecord)`, the overload used when
/// only a hash quad is known for the superior side.
pub fn generate_inferior_full_hash_smash_quad(
    superior_function: &dyn FidHashQuad,
    inferior_function: &FunctionRecord,
) -> i64 {
    let hash_value =
        inferior_function.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME); // Improve bit diversity on key
    hash_value ^ superior_function.full_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::db::fid_db::test_support::minimal_fid_db;
    use crate::feature::seam_stubs::StringsTable;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use std::sync::Arc;

    struct NoopStringsTable;
    impl StringsTable for NoopStringsTable {
        fn lookup_string(
            &self,
            _id: i64,
        ) -> Option<crate::feature::fid::db::string_record::StringRecord> {
            None
        }
    }

    /// Column layout mirrored from `FunctionsTable`, matching
    /// [`crate::feature::fid::db::function_record`]'s own copy.
    const FULL_HASH_COL: usize = 1;
    const LIBRARY_ID_COL: usize = 4;

    fn function_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            6,
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

    fn build_function_record(key: i64, full_hash: i64) -> FunctionRecord {
        let fid_db = minimal_fid_db(Arc::new(NoopStringsTable));
        let mut record = DBRecord::new(function_schema(), Field::Long(Some(key)));
        record.set_long(FULL_HASH_COL, full_hash);
        record.set_long(LIBRARY_ID_COL, 1);
        FunctionRecord::new(fid_db, record)
    }

    #[test]
    fn superior_smash_matches_java_fnv1a64_prime_arithmetic() {
        // Java: hashValue = superiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME;
        //       return hashValue ^ inferiorFunction.getFullHash();
        let caller = build_function_record(42, 0x1234_5678_9abc_def0);
        let callee = build_function_record(99, 0x0fed_cba9_8765_4321);
        let expected = (caller.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME))
            ^ callee.full_hash();
        assert_eq!(generate_superior_full_hash_smash(&caller, &callee), expected);
    }

    #[test]
    fn inferior_smash_matches_java_fnv1a64_prime_arithmetic() {
        // Java: hashValue = inferiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME;
        //       return hashValue ^ superiorFunction.getFullHash();
        let caller = build_function_record(42, 0x1234_5678_9abc_def0);
        let callee = build_function_record(99, 0x0fed_cba9_8765_4321);
        let expected = (callee.get_key().wrapping_mul(FNV1a64MessageDigest::FNV_64_PRIME))
            ^ caller.full_hash();
        assert_eq!(generate_inferior_full_hash_smash(&caller, &callee), expected);
    }

    #[test]
    fn quad_overloads_agree_with_the_function_record_overloads() {
        let caller = build_function_record(7, 0xaaaa_bbbb_cccc_dddd_u64 as i64);
        let callee = build_function_record(11, 0x1111_2222_3333_4444);

        assert_eq!(
            generate_superior_full_hash_smash(&caller, &callee),
            generate_superior_full_hash_smash_quad(&caller, &callee),
        );
        assert_eq!(
            generate_inferior_full_hash_smash(&caller, &callee),
            generate_inferior_full_hash_smash_quad(&caller, &callee),
        );
    }
}
