//! Port of `ghidra.feature.fid.db.FunctionRecord`.

use crate::feature::fid::db::fid_db::FidDB;
use crate::feature::fid::hash::fid_hash_quad::FidHashQuad;
use crate::framework::db::record::DBRecord;
use crate::program::database::db_object::{DbObject, DbObjectState};

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Column layout of the `FunctionsTable`, mirrored here since `FunctionRecord` reads its fields
/// by index (Java: `import static ghidra.feature.fid.db.FunctionsTable.*`).
const CODE_UNIT_SIZE_COL: usize = 0;
const FULL_HASH_COL: usize = 1;
const SPECIFIC_HASH_ADDITIONAL_SIZE_COL: usize = 2;
const SPECIFIC_HASH_COL: usize = 3;
const LIBRARY_ID_COL: usize = 4;
const NAME_ID_COL: usize = 5;
const ENTRY_POINT_COL: usize = 6;
const DOMAIN_PATH_ID_COL: usize = 7;
const FLAGS_COL: usize = 8;

pub const HAS_TERMINATOR_FLAG: i32 = 1;
pub const AUTO_PASS_FLAG: i32 = 2;
pub const AUTO_FAIL_FLAG: i32 = 4;
pub const FORCE_SPECIFIC_FLAG: i32 = 8;
pub const FORCE_RELATION_FLAG: i32 = 16;

/// Java: `NumericUtilities.toHexString(long)`. `NumericUtilities` is a stateless static utility
/// class (not ported), so this two-line body is mirrored here directly rather than through a stub
/// trait, the same way [`super::relations_table`] mirrors `FidDBUtils`'s hash-smash helpers.
fn to_hex_string(value: i64) -> String {
    format!("0x{:x}", value as u64)
}

/// Represents a function record in the FID database.
///
/// Port of `ghidra.feature.fid.db.FunctionRecord`. Java's `FunctionRecord extends DbObject
/// implements FidHashQuad`; the Rust equivalent embeds a [`DbObjectState`] and implements both
/// [`DbObject`] and [`FidHashQuad`] rather than inheriting from a base class.
pub struct FunctionRecord {
    state: DbObjectState,
    /// All values are stored in the record instead of memoized.
    record: DBRecord,
    /// Need a reference to the FidDb because all strings are stored via foreign key
    /// (considerable duplication of string values).
    fid_db: Arc<FidDB>,
}

impl FunctionRecord {
    /// Package-private constructor, to be called from `FunctionsTable` exclusively.
    ///
    /// `fid_db` is the database that owns `record` (used for string references); `record` is the
    /// record backing this function.
    pub(crate) fn new(fid_db: Arc<FidDB>, record: DBRecord) -> Self {
        let key = record.get_key().get_long_value();
        Self { state: DbObjectState::new(key), record, fid_db }
    }

    /// Returns the database that owns this record.
    pub fn get_fid_db(&self) -> Arc<FidDB> {
        Arc::clone(&self.fid_db)
    }

    /// Returns the name.
    pub fn get_name(&self) -> String {
        let name_id = self.record.get_long(NAME_ID_COL).unwrap_or(0);
        self.fid_db
            .get_strings_table()
            .and_then(|table| table.lookup_string(name_id))
            .map(|s| s.get_value())
            .unwrap_or_default()
    }

    /// Returns the entry point (memory address).
    pub fn get_entry_point(&self) -> i64 {
        self.record.get_long(ENTRY_POINT_COL).unwrap_or(0)
    }

    /// Returns the domain path in the project upon library creation.
    pub fn get_domain_path(&self) -> String {
        let domain_path_id = self.record.get_long(DOMAIN_PATH_ID_COL).unwrap_or(0);
        self.fid_db
            .get_strings_table()
            .and_then(|table| table.lookup_string(domain_path_id))
            .map(|s| s.get_value())
            .unwrap_or_default()
    }

    fn flag(&self, mask: i32) -> bool {
        let flags = self.record.get_byte(FLAGS_COL).unwrap_or(0) as i32;
        (flags & mask) != 0
    }

    /// Returns whether auto-analysis found a terminator within the flow of the function body.
    pub fn has_terminator(&self) -> bool {
        self.flag(HAS_TERMINATOR_FLAG)
    }

    /// Returns true if this function should automatically pass the code unit threshold.
    pub fn auto_pass(&self) -> bool {
        self.flag(AUTO_PASS_FLAG)
    }

    /// Returns true if this function should automatically fail the code unit threshold.
    pub fn auto_fail(&self) -> bool {
        self.flag(AUTO_FAIL_FLAG)
    }

    /// Returns true if this record can only be matched if the specific hash matches.
    pub fn is_force_specific(&self) -> bool {
        self.flag(FORCE_SPECIFIC_FLAG)
    }

    /// Returns true if this record can only be matched if one of the function's parent/child
    /// relations also matches.
    pub fn is_force_relation(&self) -> bool {
        self.flag(FORCE_RELATION_FLAG)
    }

    /// Returns the record id (primary key).
    pub fn get_id(&self) -> i64 {
        self.record.get_key().get_long_value()
    }

    /// Returns the library id for this function.
    pub fn get_library_id(&self) -> i64 {
        self.record.get_long(LIBRARY_ID_COL).unwrap_or(0)
    }

    /// Java's `FunctionRecord.getID()` is defined as `record.getKey()`, which is also
    /// `DbObject.getKey()`, so both accessors return the same value.
    pub fn get_key(&self) -> i64 {
        self.get_id()
    }
}

impl DbObject for FunctionRecord {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// Never need to refresh...this database object is immutable.
    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        false
    }
}

impl FidHashQuad for FunctionRecord {
    /// Returns the full hash size.
    fn code_unit_size(&self) -> i16 {
        self.record.get_field(CODE_UNIT_SIZE_COL).get_long_value() as i16
    }

    /// Returns the full hash.
    fn full_hash(&self) -> i64 {
        self.record.get_long(FULL_HASH_COL).unwrap_or(0)
    }

    /// Returns the specific hash additional size.
    fn specific_hash_additional_size(&self) -> i8 {
        self.record.get_byte(SPECIFIC_HASH_ADDITIONAL_SIZE_COL).unwrap_or(0)
    }

    /// Returns the specific hash.
    fn specific_hash(&self) -> i64 {
        self.record.get_long(SPECIFIC_HASH_COL).unwrap_or(0)
    }
}

impl fmt::Debug for FunctionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionRecord").field("id", &self.get_id()).finish()
    }
}

impl fmt::Display for FunctionRecord {
    /// Overridden Display (Java: `toString`) to help debugging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {} ({})", to_hex_string(self.get_id()), self.get_name(), to_hex_string(self.get_library_id()))
    }
}

impl PartialEq for FunctionRecord {
    /// Overridden equals (Java: `equals`) to support collections.
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for FunctionRecord {}

impl Hash for FunctionRecord {
    /// Overridden hashCode (Java: `hashCode`) to support collections.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_id().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::db::fid_db::test_support::minimal_fid_db;
    use crate::feature::seam_stubs::StringRecord;
    use crate::feature::seam_stubs::StringsTable;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeStringsTable {
        strings: Mutex<HashMap<i64, String>>,
    }

    impl StringsTable for FakeStringsTable {
        fn lookup_string(&self, id: i64) -> Option<StringRecord> {
            self.strings.lock().unwrap().get(&id).cloned().map(StringRecord::new)
        }
    }

    fn schema() -> Arc<Schema> {
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

    fn build_function_record(key: i64) -> FunctionRecord {
        let mut strings = HashMap::new();
        strings.insert(1, "memcpy".to_string());
        strings.insert(2, "/lib/libc".to_string());
        let strings_table = Arc::new(FakeStringsTable { strings: Mutex::new(strings) });
        let fid_db = minimal_fid_db(strings_table);

        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_field(CODE_UNIT_SIZE_COL, Field::Short(Some(4)));
        record.set_long(FULL_HASH_COL, 0x1234_5678_9abc_def0_u64 as i64);
        record.set_byte(SPECIFIC_HASH_ADDITIONAL_SIZE_COL, 2);
        record.set_long(SPECIFIC_HASH_COL, 0x0fed_cba9_8765_4321_u64 as i64);
        record.set_long(LIBRARY_ID_COL, 7);
        record.set_long(NAME_ID_COL, 1);
        record.set_long(ENTRY_POINT_COL, 0x401000);
        record.set_long(DOMAIN_PATH_ID_COL, 2);
        record.set_byte(FLAGS_COL, (HAS_TERMINATOR_FLAG | AUTO_PASS_FLAG) as i8);

        FunctionRecord::new(fid_db, record)
    }

    #[test]
    fn accessors_read_expected_columns() {
        let func = build_function_record(42);
        assert_eq!(func.get_id(), 42);
        assert_eq!(func.get_key(), 42);
        assert_eq!(func.code_unit_size(), 4);
        assert_eq!(func.full_hash(), 0x1234_5678_9abc_def0_u64 as i64);
        assert_eq!(func.specific_hash_additional_size(), 2);
        assert_eq!(func.specific_hash(), 0x0fed_cba9_8765_4321_u64 as i64);
        assert_eq!(func.get_library_id(), 7);
        assert_eq!(func.get_entry_point(), 0x401000);
        assert_eq!(func.get_name(), "memcpy");
        assert_eq!(func.get_domain_path(), "/lib/libc");
    }

    #[test]
    fn flags_are_decoded_from_the_flags_column() {
        let func = build_function_record(1);
        // Java: HAS_TERMINATOR_FLAG | AUTO_PASS_FLAG was written, the other two were not.
        assert!(func.has_terminator());
        assert!(func.auto_pass());
        assert!(!func.auto_fail());
        assert!(!func.is_force_specific());
        assert!(!func.is_force_relation());
    }

    #[test]
    fn display_matches_java_to_string() {
        let func = build_function_record(0x10);
        // Java: NumericUtilities.toHexString(getID()) + " - " + getName() + " (" +
        // NumericUtilities.toHexString(getLibraryID()) + ")"
        assert_eq!(func.to_string(), "0x10 - memcpy (0x7)");
    }

    #[test]
    fn equality_and_hash_are_based_on_id_only() {
        let a = build_function_record(5);
        let b = build_function_record(5);
        let c = build_function_record(6);
        assert_eq!(a, b);
        assert_ne!(a, c);

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(a);
        assert!(!set.insert(b), "records with the same id should collide as duplicates");
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn missing_string_lookup_falls_back_to_empty_string() {
        let strings_table = Arc::new(FakeStringsTable { strings: Mutex::new(HashMap::new()) });
        let fid_db = minimal_fid_db(strings_table);
        let record = DBRecord::new(schema(), Field::Long(Some(1)));
        let func = FunctionRecord::new(fid_db, record);
        assert_eq!(func.get_name(), "");
        assert_eq!(func.get_domain_path(), "");
    }
}
