//! Port of `ghidra.program.database.function.FunctionTagMappingAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`,
//! plus the private `findReadOnlyAdapter` helper and the `upgrade` migration helper it delegates
//! to) selects and migrates between concrete version-specific implementations (currently just
//! `FunctionTagMappingAdapterV0`, with `FunctionTagMappingAdapterNoTable` as a read-only
//! fallback). Neither concrete adapter has been ported yet, so this port only models the abstract
//! instance API they implement, as an object-safe trait; the version-selection/upgrade logic
//! belongs with whichever type ends up owning the concrete adapters. This follows the same
//! convention already used for
//! [`FunctionAdapter`](crate::program::database::function::FunctionAdapter) and
//! [`FunctionTagAdapter`](crate::program::database::function::FunctionTagAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `TABLE_NAME`/`CURRENT_VERSION` constants, since they describe a
//! concrete table layout used only by the not-yet-ported `FunctionTagMappingAdapterV0` class
//! itself, rather than this trait's dynamic-dispatch surface -- left for whichever concrete
//! subclass is ported first.
//!
//! Kept, unlike those table-layout constants: the column-index constants (`FUNCTION_ID_COL`,
//! `TAG_ID_COL`), the same reasoning that kept `FunctionAdapter`'s
//! `RETURN_DATA_TYPE_ID_COL`..`RETURN_STORAGE_COL` and `FunctionTagAdapter`'s `NAME_COL`/
//! `COMMENT_COL`.
//!
//! Java's overloaded `removeFunctionTagRecord` (one overload taking a function id and a tag id,
//! returning `boolean`; the other taking just a tag id, returning `void`) is split into two
//! distinctly-named methods, since Rust traits do not support overloading by argument arity:
//! [`FunctionTagMappingAdapter::remove_function_tag_record`] and
//! [`FunctionTagMappingAdapter::remove_function_tag_records_for_tag`].

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

/// Column index into the [`crate::program::model::symbol::SymbolTable`] table for the function
/// half of a mapping record. Stands in for `FunctionTagMappingAdapter.FUNCTION_ID_COL`.
pub const FUNCTION_ID_COL: usize = 0;
/// Column index into the [`FunctionTagAdapter`](crate::program::database::function::FunctionTagAdapter)
/// table for the tag half of a mapping record. Stands in for
/// `FunctionTagMappingAdapter.TAG_ID_COL`.
pub const TAG_ID_COL: usize = 1;

/// Database adapter that maps function tags to individual functions. This table consists of two
/// columns, each of which is an index into the
/// [`FunctionTagAdapter`](crate::program::database::function::FunctionTagAdapter) and
/// [`SymbolTable`](crate::program::model::symbol::SymbolTable) respectively.
///
/// Port of `ghidra.program.database.function.FunctionTagMappingAdapter`. See the module docs for
/// what was intentionally left out (the static factory/version-upgrade logic and the concrete
/// table-layout constants) and how the overloaded `removeFunctionTagRecord` was split.
pub trait FunctionTagMappingAdapter {
    /// Returns all table entries associated with the given function ID. This effectively gives a
    /// list of all the tags for a function.
    ///
    /// `function_id` is an index into the `SymbolTable` table.
    ///
    /// Stands in for `FunctionTagMappingAdapter.getRecordsByFunctionID(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn get_records_by_function_id(&self, function_id: i64) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Searches this table for any entry matching the given function and tag ID.
    ///
    /// `function_id` is an index into the `SymbolTable` table; `tag_id` is an index into the
    /// `FunctionTagAdapter` table.
    ///
    /// Stands in for `FunctionTagMappingAdapter.getRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn get_record(&self, function_id: i64, tag_id: i64) -> io::Result<Option<DBRecord>>;

    /// Creates a new record with the given function and tag IDs.
    ///
    /// Stands in for `FunctionTagMappingAdapter.createFunctionTagRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn create_function_tag_record(&mut self, function_id: i64, tag_id: i64) -> io::Result<DBRecord>;

    /// Removes the record with the given function and tag IDs. There should be at most one of
    /// these. Returns `true` if the remove was performed.
    ///
    /// Stands in for the two-argument overload of
    /// `FunctionTagMappingAdapter.removeFunctionTagRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn remove_function_tag_record(&mut self, function_id: i64, tag_id: i64) -> io::Result<bool>;

    /// Removes all records containing the given tag ID. This should be called whenever a tag is
    /// being deleted from the system.
    ///
    /// `tag_id` is an index into the `FunctionTagAdapter` table.
    ///
    /// Stands in for the single-argument overload of
    /// `FunctionTagMappingAdapter.removeFunctionTagRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn remove_function_tag_records_for_tag(&mut self, tag_id: i64) -> io::Result<()>;

    /// Determines if the specified tag ID has been applied to a function.
    ///
    /// Stands in for `FunctionTagMappingAdapter.isTagAssigned(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn is_tag_assigned(&self, id: i64) -> io::Result<bool>;

    /// Returns an iterator over all the records in this table.
    ///
    /// Stands in for the protected `FunctionTagMappingAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Long, FieldType::Long],
            vec!["Function ID".to_string(), "Tag ID".to_string()],
            vec![],
        ))
    }

    struct VecRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.as_slice().first().is_some()
        }
    }

    /// A minimal in-memory `FunctionTagMappingAdapter`, exercising object-safety and the
    /// create/get/remove/query-by-function/query-by-tag contract described by the Java class.
    struct MockFunctionTagMappingAdapter {
        records: Vec<DBRecord>,
        next_key: i64,
    }

    impl MockFunctionTagMappingAdapter {
        fn new() -> Self {
            MockFunctionTagMappingAdapter {
                records: Vec::new(),
                next_key: 0,
            }
        }
    }

    impl FunctionTagMappingAdapter for MockFunctionTagMappingAdapter {
        fn get_records_by_function_id(&self, function_id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .iter()
                .filter(|record| record.get_long(FUNCTION_ID_COL) == Some(function_id))
                .cloned()
                .collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_record(&self, function_id: i64, tag_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .iter()
                .find(|record| {
                    record.get_long(FUNCTION_ID_COL) == Some(function_id)
                        && record.get_long(TAG_ID_COL) == Some(tag_id)
                })
                .cloned())
        }

        fn create_function_tag_record(&mut self, function_id: i64, tag_id: i64) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_long(FUNCTION_ID_COL, function_id);
            record.set_long(TAG_ID_COL, tag_id);
            self.records.push(record.clone());
            Ok(record)
        }

        fn remove_function_tag_record(&mut self, function_id: i64, tag_id: i64) -> io::Result<bool> {
            let before = self.records.len();
            self.records.retain(|record| {
                !(record.get_long(FUNCTION_ID_COL) == Some(function_id)
                    && record.get_long(TAG_ID_COL) == Some(tag_id))
            });
            Ok(self.records.len() != before)
        }

        fn remove_function_tag_records_for_tag(&mut self, tag_id: i64) -> io::Result<()> {
            self.records
                .retain(|record| record.get_long(TAG_ID_COL) != Some(tag_id));
            Ok(())
        }

        fn is_tag_assigned(&self, id: i64) -> io::Result<bool> {
            Ok(self
                .records
                .iter()
                .any(|record| record.get_long(TAG_ID_COL) == Some(id)))
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(VecRecordIterator {
                records: self.records.clone().into_iter(),
            }))
        }
    }

    #[test]
    fn object_safe_and_tracks_function_tag_mappings() {
        let mut adapter: Box<dyn FunctionTagMappingAdapter> =
            Box::new(MockFunctionTagMappingAdapter::new());

        assert!(!adapter.is_tag_assigned(100).unwrap());
        assert!(adapter.get_record(1, 100).unwrap().is_none());

        adapter.create_function_tag_record(1, 100).unwrap();
        adapter.create_function_tag_record(1, 200).unwrap();
        adapter.create_function_tag_record(2, 100).unwrap();

        assert!(adapter.is_tag_assigned(100).unwrap());
        assert!(adapter.get_record(1, 100).unwrap().is_some());
        assert!(adapter.get_record(1, 300).unwrap().is_none());

        {
            let mut count = 0;
            let mut iter = adapter.get_records_by_function_id(1).unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 2);
        }

        {
            let mut count = 0;
            let mut iter = adapter.get_records().unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 3);
        }

        let removed = adapter.remove_function_tag_record(1, 100).unwrap();
        assert!(removed);
        assert!(adapter.get_record(1, 100).unwrap().is_none());
        assert!(adapter.is_tag_assigned(100).unwrap());

        let removed_again = adapter.remove_function_tag_record(1, 100).unwrap();
        assert!(!removed_again);

        adapter.remove_function_tag_records_for_tag(100).unwrap();
        assert!(!adapter.is_tag_assigned(100).unwrap());

        {
            let mut count = 0;
            let mut iter = adapter.get_records().unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 1);
        }
    }
}
