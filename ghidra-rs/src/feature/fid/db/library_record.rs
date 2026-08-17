use crate::framework::db::record::DBRecord;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_id::LanguageID;
use std::fmt;

/// Column layout of the `LibrariesTable`, mirrored here since `LibraryRecord` reads its
/// fields by index (Java: `import static ghidra.feature.fid.db.LibrariesTable.*`).
const LIBRARY_FAMILY_NAME_COL: usize = 0;
const LIBRARY_VERSION_COL: usize = 1;
const LIBRARY_VARIANT_COL: usize = 2;
const GHIDRA_VERSION_COL: usize = 3;
const GHIDRA_LANGUAGE_ID_COL: usize = 4;
const GHIDRA_LANGUAGE_VERSION_COL: usize = 5;
const GHIDRA_LANGUAGE_MINOR_VERSION_COL: usize = 6;
const GHIDRA_COMPILER_SPEC_ID_COL: usize = 7;

/// Represents a library record in the FID database.
pub struct LibraryRecord {
    /// The record is stored, no memoization is performed.
    record: DBRecord,
}

impl LibraryRecord {
    /// Creates a new library record.
    ///
    /// `record` is the database record on which to base this library.
    pub fn new(record: DBRecord) -> Self {
        Self { record }
    }

    /// Returns the library primary key.
    pub fn get_library_id(&self) -> i64 {
        self.record.get_key().get_long_value()
    }

    /// Returns the library family name.
    pub fn get_library_family_name(&self) -> &str {
        self.record.get_string(LIBRARY_FAMILY_NAME_COL).unwrap_or("")
    }

    /// Returns the library version string.
    pub fn get_library_version(&self) -> &str {
        self.record.get_string(LIBRARY_VERSION_COL).unwrap_or("")
    }

    /// Returns the library variant string.
    pub fn get_library_variant(&self) -> &str {
        self.record.get_string(LIBRARY_VARIANT_COL).unwrap_or("")
    }

    /// Returns the Ghidra version string (used to create the library).
    pub fn get_ghidra_version(&self) -> &str {
        self.record.get_string(GHIDRA_VERSION_COL).unwrap_or("")
    }

    /// Returns the Ghidra LanguageID (used to create the library).
    pub fn get_ghidra_language_id(&self) -> LanguageID {
        LanguageID::new(self.record.get_string(GHIDRA_LANGUAGE_ID_COL).unwrap_or(""))
            .expect("stored language id is never empty")
    }

    /// Returns the Ghidra language version (used to create the library).
    pub fn get_ghidra_language_version(&self) -> i32 {
        self.record.get_int(GHIDRA_LANGUAGE_VERSION_COL).unwrap_or(0)
    }

    /// Returns the Ghidra language minor version (used to create the library).
    pub fn get_ghidra_language_minor_version(&self) -> i32 {
        self.record.get_int(GHIDRA_LANGUAGE_MINOR_VERSION_COL).unwrap_or(0)
    }

    /// Returns the Ghidra CompilerSpecID (used to create the library).
    pub fn get_ghidra_compiler_spec_id(&self) -> CompilerSpecID {
        CompilerSpecID::new(self.record.get_string(GHIDRA_COMPILER_SPEC_ID_COL))
    }
}

impl fmt::Display for LibraryRecord {
    /// Overridden Display (Java: `toString`) for pretty printing the library whilst debugging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.get_library_family_name(),
            self.get_library_version(),
            self.get_library_variant()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::Field;
    use crate::framework::db::schema::Schema;
    use std::sync::Arc;

    fn build_record() -> DBRecord {
        let schema = Arc::new(Schema::new(
            0,
            crate::framework::db::field::FieldType::Long,
            "Key".to_string(),
            vec![
                crate::framework::db::field::FieldType::String,
                crate::framework::db::field::FieldType::String,
                crate::framework::db::field::FieldType::String,
                crate::framework::db::field::FieldType::String,
                crate::framework::db::field::FieldType::String,
                crate::framework::db::field::FieldType::Int,
                crate::framework::db::field::FieldType::Int,
                crate::framework::db::field::FieldType::String,
            ],
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
        let mut record = DBRecord::new(schema, Field::Long(Some(42)));
        record.set_string(LIBRARY_FAMILY_NAME_COL, Some("libc".to_string()));
        record.set_string(LIBRARY_VERSION_COL, Some("2.31".to_string()));
        record.set_string(LIBRARY_VARIANT_COL, Some("glibc".to_string()));
        record.set_string(GHIDRA_VERSION_COL, Some("11.0".to_string()));
        record.set_string(GHIDRA_LANGUAGE_ID_COL, Some("x86:LE:64:default".to_string()));
        record.set_int(GHIDRA_LANGUAGE_VERSION_COL, 2);
        record.set_int(GHIDRA_LANGUAGE_MINOR_VERSION_COL, 1);
        record.set_string(GHIDRA_COMPILER_SPEC_ID_COL, Some("gcc".to_string()));
        record
    }

    #[test]
    fn accessors_read_expected_columns() {
        let lib = LibraryRecord::new(build_record());
        assert_eq!(lib.get_library_id(), 42);
        assert_eq!(lib.get_library_family_name(), "libc");
        assert_eq!(lib.get_library_version(), "2.31");
        assert_eq!(lib.get_library_variant(), "glibc");
        assert_eq!(lib.get_ghidra_version(), "11.0");
        assert_eq!(lib.get_ghidra_language_id().get_id_as_string(), "x86:LE:64:default");
        assert_eq!(lib.get_ghidra_language_version(), 2);
        assert_eq!(lib.get_ghidra_language_minor_version(), 1);
        assert_eq!(lib.get_ghidra_compiler_spec_id().get_id_as_string(), "gcc");
    }

    #[test]
    fn display_matches_java_to_string() {
        let lib = LibraryRecord::new(build_record());
        assert_eq!(lib.to_string(), "libc 2.31 glibc");
    }
}
