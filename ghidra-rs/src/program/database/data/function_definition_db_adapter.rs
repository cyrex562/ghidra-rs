//! Port of `ghidra.program.database.data.FunctionDefinitionDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects and migrates between concrete
//! version-specific implementations (`FunctionDefinitionDBAdapterV0`/`V1`/`V2`/`NoTable`). Those
//! concrete adapters have not been ported yet, so this port only models the abstract instance API
//! each version implements, as an object-safe trait; the version-selection/upgrade logic belongs
//! with whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, Field};
use crate::program::model::data::generic_calling_convention::GenericCallingConvention;
use crate::program::model::lang::compiler_spec::CALLING_CONVENTION_UNKNOWN;
use crate::program::util::DBRecordAdapter;
use crate::util::UniversalID;

/// Name of the database table used to store function signature definition data types.
pub const FUNCTION_DEF_TABLE_NAME: &str = "Function Definitions";

/// Column index of the function definition's name, as defined by `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_NAME_COL: usize = 0;

/// Column index of the function definition's comment, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_COMMENT_COL: usize = 1;

/// Column index of the function definition's category ID, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_CAT_ID_COL: usize = 2;

/// Column index of the function definition's return data type ID, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_RETURN_ID_COL: usize = 3;

/// Column index of the function definition's flags (vararg/noreturn), as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_FLAGS_COL: usize = 4;

/// Column index of the function definition's calling convention ID, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_CALLCONV_COL: usize = 5;

/// Column index of the function definition's source archive ID, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL: usize = 6;

/// Column index of the function definition's universal data type ID, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_SOURCE_DT_ID_COL: usize = 7;

/// Column index of the function definition's source sync time, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_SOURCE_SYNC_TIME_COL: usize = 8;

/// Column index of the function definition's last change time, as defined by
/// `FunctionDefinitionDBAdapterV2`.
pub const FUNCTION_DEF_LAST_CHANGE_TIME_COL: usize = 9;

/// Bit 0 of the flags column: flag for "has vararg".
pub const FUNCTION_DEF_VARARG_FLAG: u8 = 0x1;

/// Bit 1 of the flags column: flag for "has noreturn" (added with V2).
pub const FUNCTION_DEF_NORETURN_FLAG: u8 = 0x2;

/// Adapter to access the Function Signature Definition database table.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDBAdapter`.
pub trait FunctionDefinitionDBAdapter: DBRecordAdapter {
    /// Creates a database record for a function signature definition data type.
    ///
    /// `name` is the unique name for this data type, `comments` are comments about this data
    /// type, `category_id` is the ID for the category that contains this data type,
    /// `return_dt_id` is the ID of the data type that is returned by this function definition,
    /// `has_no_return` is true if this function definition has noreturn enabled, `has_var_args`
    /// is true if this function definition has a variable length argument list,
    /// `calling_convention_id` is the calling convention ID, `source_archive_id` is the ID for
    /// the source archive where this data type originated, `source_data_type_id` is the ID of
    /// the associated data type in the source archive, and `last_change_time` is the time this
    /// data type was last changed.
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        name: &str,
        comments: Option<&str>,
        category_id: i64,
        return_dt_id: i64,
        has_no_return: bool,
        has_var_args: bool,
        calling_convention_id: u8,
        source_archive_id: i64,
        source_data_type_id: i64,
        last_change_time: i64,
    ) -> io::Result<DBRecord>;

    /// Gets a function signature definition data type record from the database based on its ID,
    /// or `None` if not found.
    fn get_record(&self, function_def_id: i64) -> io::Result<Option<DBRecord>>;

    /// Removes the function definition data type record with the specified ID. Returns `true`
    /// if the record is removed.
    fn remove_record(&mut self, function_def_id: i64) -> io::Result<bool>;

    /// Updates the function definition data type table with the provided record.
    ///
    /// `set_last_change_time` indicates whether the last change time in the record should be
    /// updated to the current time before the record is put into the database.
    fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()>;

    /// Deletes the function definition data type table from the database with the specified
    /// database handle.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Gets the IDs (as `Field::Long` values) of all function definition data types contained in
    /// the category with the given ID.
    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>>;

    /// Gets the IDs (as `Field::Long` values) of all function definition data types derived from
    /// the source data type archive with the given ID.
    fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>>;

    /// Get the function definition record whose source archive ID and data type ID match the
    /// specified universal IDs, or `None` if not found.
    fn get_record_with_ids(
        &self,
        source_id: UniversalID,
        datatype_id: UniversalID,
    ) -> io::Result<Option<DBRecord>>;

    /// Determine if the calling convention ID within record reflects a Generic Calling
    /// Convention ordinal (i.e., true if the V1 adapter is in use for read-only mode). See
    /// [`get_generic_calling_convention_name`] for Generic Calling Convention name lookup.
    fn uses_generic_calling_convention_id(&self) -> bool {
        false
    }
}

/// Get old `GenericCallingConvention` name for specified ordinal value.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDBAdapter.getGenericCallingConventionName`.
pub fn get_generic_calling_convention_name(ordinal: i32) -> String {
    let generic_calling_convention = GenericCallingConvention::from_ordinal(ordinal as usize);
    if generic_calling_convention != GenericCallingConvention::Unknown {
        generic_calling_convention.declaration_name().to_string()
    } else {
        CALLING_CONVENTION_UNKNOWN.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, RecordIterator, Schema};
    use std::cell::RefCell;
    use std::sync::Arc;

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    struct MockFunctionDefinitionDBAdapter {
        schema: Arc<Schema>,
        records: RefCell<Vec<DBRecord>>,
        next_key: RefCell<i64>,
        deleted: RefCell<bool>,
    }

    impl MockFunctionDefinitionDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                2,
                FieldType::Long,
                "Data Type ID".to_string(),
                vec![
                    FieldType::String,
                    FieldType::String,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Byte,
                    FieldType::Byte,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                    FieldType::Long,
                ],
                vec![
                    "Name".to_string(),
                    "Comment".to_string(),
                    "Category ID".to_string(),
                    "Return Type ID".to_string(),
                    "Flags".to_string(),
                    "Call Conv ID".to_string(),
                    "Source Archive ID".to_string(),
                    "Source Data Type ID".to_string(),
                    "Source Sync Time".to_string(),
                    "Last Change Time".to_string(),
                ],
                vec![],
            ));
            MockFunctionDefinitionDBAdapter {
                schema,
                records: RefCell::new(Vec::new()),
                next_key: RefCell::new(0),
                deleted: RefCell::new(false),
            }
        }
    }

    impl DBRecordAdapter for MockFunctionDefinitionDBAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: self.records.borrow().clone().into_iter(),
            }))
        }

        fn get_record_count(&self) -> usize {
            self.records.borrow().len()
        }
    }

    impl FunctionDefinitionDBAdapter for MockFunctionDefinitionDBAdapter {
        fn create_record(
            &mut self,
            name: &str,
            comments: Option<&str>,
            category_id: i64,
            return_dt_id: i64,
            has_no_return: bool,
            has_var_args: bool,
            calling_convention_id: u8,
            source_archive_id: i64,
            source_data_type_id: i64,
            last_change_time: i64,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.borrow_mut();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_field(FUNCTION_DEF_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(
                FUNCTION_DEF_COMMENT_COL,
                Field::String(comments.map(str::to_string)),
            );
            rec.set_field(FUNCTION_DEF_CAT_ID_COL, Field::Long(Some(category_id)));
            rec.set_field(FUNCTION_DEF_RETURN_ID_COL, Field::Long(Some(return_dt_id)));
            let mut flags = 0u8;
            if has_var_args {
                flags |= FUNCTION_DEF_VARARG_FLAG;
            }
            if has_no_return {
                flags |= FUNCTION_DEF_NORETURN_FLAG;
            }
            rec.set_field(FUNCTION_DEF_FLAGS_COL, Field::Byte(Some(flags as i8)));
            rec.set_field(
                FUNCTION_DEF_CALLCONV_COL,
                Field::Byte(Some(calling_convention_id as i8)),
            );
            rec.set_field(
                FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive_id)),
            );
            rec.set_field(
                FUNCTION_DEF_SOURCE_DT_ID_COL,
                Field::Long(Some(source_data_type_id)),
            );
            rec.set_field(FUNCTION_DEF_SOURCE_SYNC_TIME_COL, Field::Long(Some(0)));
            rec.set_field(
                FUNCTION_DEF_LAST_CHANGE_TIME_COL,
                Field::Long(Some(last_change_time)),
            );
            self.records.borrow_mut().push(rec.clone());
            Ok(rec)
        }

        fn get_record(&self, function_def_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| r.get_key() == &Field::Long(Some(function_def_id)))
                .cloned())
        }

        fn update_record(
            &mut self,
            record: &DBRecord,
            set_last_change_time: bool,
        ) -> io::Result<()> {
            let mut records = self.records.borrow_mut();
            if let Some(existing) = records.iter_mut().find(|r| r.get_key() == record.get_key()) {
                *existing = record.clone();
                if set_last_change_time {
                    existing.set_field(FUNCTION_DEF_LAST_CHANGE_TIME_COL, Field::Long(Some(999)));
                }
            }
            Ok(())
        }

        fn remove_record(&mut self, function_def_id: i64) -> io::Result<bool> {
            let mut records = self.records.borrow_mut();
            let len_before = records.len();
            records.retain(|r| r.get_key() != &Field::Long(Some(function_def_id)));
            Ok(records.len() != len_before)
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            *self.deleted.borrow_mut() = true;
            self.records.borrow_mut().clear();
            Ok(())
        }

        fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(FUNCTION_DEF_CAT_ID_COL), Field::Long(Some(v)) if *v == category_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .filter(|r| {
                    matches!(r.get_field(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
                })
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn get_record_with_ids(
            &self,
            source_id: UniversalID,
            datatype_id: UniversalID,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .borrow()
                .iter()
                .find(|r| {
                    matches!(r.get_field(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
                        && matches!(r.get_field(FUNCTION_DEF_SOURCE_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                })
                .cloned())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_function_definitions() {
        let mut adapter: Box<dyn FunctionDefinitionDBAdapter> =
            Box::new(MockFunctionDefinitionDBAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);
        assert!(!adapter.uses_generic_calling_convention_id());

        let created = adapter
            .create_record("foo", Some("a function"), 5, 42, false, true, 3, 10, 20, 100)
            .unwrap();
        assert_eq!(created.get_key(), &Field::Long(Some(0)));
        adapter
            .create_record("bar", None, 5, 43, true, false, 4, 10, 21, 100)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 2);

        let fetched = adapter
            .get_record(0)
            .unwrap()
            .expect("record should exist");
        assert_eq!(
            fetched.get_field(FUNCTION_DEF_NAME_COL),
            &Field::String(Some("foo".to_string()))
        );
        assert_eq!(
            fetched.get_field(FUNCTION_DEF_FLAGS_COL),
            &Field::Byte(Some(FUNCTION_DEF_VARARG_FLAG as i8))
        );

        let ids_in_category = adapter.get_record_ids_in_category(5).unwrap();
        assert_eq!(ids_in_category.len(), 2);

        let ids_for_archive = adapter.get_record_ids_for_source_archive(10).unwrap();
        assert_eq!(ids_for_archive.len(), 2);

        let by_ids = adapter
            .get_record_with_ids(UniversalID::new(10), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        assert_eq!(by_ids.get_key(), &Field::Long(Some(1)));

        let mut updated = fetched.clone();
        updated.set_field(FUNCTION_DEF_NAME_COL, Field::String(Some("renamed".to_string())));
        adapter.update_record(&updated, true).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(FUNCTION_DEF_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );
        assert_eq!(
            refetched.get_field(FUNCTION_DEF_LAST_CHANGE_TIME_COL),
            &Field::Long(Some(999))
        );

        let removed = adapter.remove_record(0).unwrap();
        assert!(removed);
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.get_record(0).unwrap().is_none());

        {
            let mut iter = adapter.get_records().unwrap();
            assert!(iter.has_next());
            let first = iter.next().unwrap().expect("record present");
            assert_eq!(first.get_key(), &Field::Long(Some(1)));
        }

        let mut handle = DBHandle::new().unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn generic_calling_convention_name_lookup() {
        assert_eq!(get_generic_calling_convention_name(0), "unknown");
        assert_eq!(get_generic_calling_convention_name(1), "__stdcall");
        assert_eq!(get_generic_calling_convention_name(2), "__cdecl");
        assert_eq!(get_generic_calling_convention_name(999), "unknown");
    }
}
