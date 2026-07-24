//! Port of `ghidra.program.database.function.FunctionTagAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`,
//! plus the private `findReadOnlyAdapter` helper and the `upgrade` migration helper it delegates
//! to) selects and migrates between concrete version-specific implementations
//! (currently just `FunctionTagAdapterV0`). That concrete adapter has not been ported yet, so this
//! port only models the abstract instance API it implements, as an object-safe trait; the
//! version-selection/upgrade logic belongs with whichever type ends up owning the concrete
//! adapter. This follows the same convention already used for
//! [`FunctionAdapter`](crate::program::database::function::FunctionAdapter) and
//! [`SymbolDatabaseAdapter`](crate::program::database::symbol::SymbolDatabaseAdapter). This trait
//! was itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `TABLE_NAME`/`CURRENT_VERSION` constants, since they describe a
//! concrete table layout used only by the not-yet-ported `FunctionTagAdapterV0` class itself,
//! rather than this trait's dynamic-dispatch surface -- left for whichever concrete subclass is
//! ported first.
//!
//! Kept, unlike those table-layout constants: the column-index constants (`NAME_COL`,
//! `COMMENT_COL`). Unlike the table-layout constants, these are read and written directly by
//! `ghidra.program.database.function.FunctionTagDB` (a real caller outside the
//! `FunctionTagAdapter*` hierarchy, not yet ported) to read/update a tag record's name and
//! comment, so they are part of this type's genuine public API surface -- the same reasoning that
//! kept `FunctionAdapter`'s `RETURN_DATA_TYPE_ID_COL`..`RETURN_STORAGE_COL` and friends.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

/// Column index for a function tag record's name. Stands in for
/// `FunctionTagAdapter.NAME_COL`.
pub const NAME_COL: usize = 0;
/// Column index for a function tag record's comment. Stands in for
/// `FunctionTagAdapter.COMMENT_COL`.
pub const COMMENT_COL: usize = 1;

/// This represents a table that stores all possible function tags available for use.
/// The table consists of two columns: one for the tag name, and one indicating
/// whether this tag is modifiable.
///
/// Non-modifiable tags cannot be deleted or edited by any user. These are typically
/// tags that have been pre-loaded via some external mechanism and need to be
/// preserved as originally defined.
///
/// Port of `ghidra.program.database.function.FunctionTagAdapter`. See the module docs for what
/// was intentionally left out (the static factory/version-upgrade logic and the concrete
/// table-layout constants).
pub trait FunctionTagAdapter {
    /// Returns all tag records in the database.
    ///
    /// Stands in for `FunctionTagAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns a record matching the given tag name, or `None` if not found.
    ///
    /// Stands in for `FunctionTagAdapter.getRecord(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record_by_name(&self, tag: &str) -> io::Result<Option<DBRecord>>;

    /// Returns the tag record with the given id, or `None` if not found.
    ///
    /// Stands in for `FunctionTagAdapter.getRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>>;

    /// Creates a tag record with the given tag name.
    ///
    /// Stands in for `FunctionTagAdapter.createTagRecord(String, String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_tag_record(&mut self, tag: &str, comment: &str) -> io::Result<DBRecord>;

    /// Updates the database record for a tag.
    ///
    /// Stands in for `FunctionTagAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Removes the tag with the given id from the database.
    ///
    /// Stands in for `FunctionTagAdapter.removeTagRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_tag_record(&mut self, id: i64) -> io::Result<()>;

    /// Returns the total number of tags in the database.
    ///
    /// Stands in for `FunctionTagAdapter.getNumTags()`.
    fn get_num_tags(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String, FieldType::String],
            vec!["Tag Name".to_string(), "Comment".to_string()],
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

    /// A minimal in-memory `FunctionTagAdapter`, exercising object-safety and the record
    /// create/get/update/remove/iterate contract described by the Java class.
    struct MockFunctionTagAdapter {
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockFunctionTagAdapter {
        fn new() -> Self {
            MockFunctionTagAdapter {
                records: BTreeMap::new(),
                next_key: 0,
            }
        }
    }

    impl FunctionTagAdapter for MockFunctionTagAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_record_by_name(&self, tag: &str) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .values()
                .find(|record| record.get_string(NAME_COL) == Some(tag))
                .cloned())
        }

        fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&id).cloned())
        }

        fn create_tag_record(&mut self, tag: &str, comment: &str) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_string(NAME_COL, Some(tag.to_string()));
            record.set_string(COMMENT_COL, Some(comment.to_string()));
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = match record.get_key() {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn remove_tag_record(&mut self, id: i64) -> io::Result<()> {
            self.records.remove(&id);
            Ok(())
        }

        fn get_num_tags(&self) -> i32 {
            self.records.len() as i32
        }
    }

    #[test]
    fn object_safe_and_tracks_tag_records() {
        let mut adapter: Box<dyn FunctionTagAdapter> = Box::new(MockFunctionTagAdapter::new());

        assert_eq!(adapter.get_num_tags(), 0);
        assert!(adapter.get_record(0).unwrap().is_none());
        assert!(adapter.get_record_by_name("BADCODE").unwrap().is_none());

        let rec1 = adapter.create_tag_record("BADCODE", "known bad code").unwrap();
        adapter.create_tag_record("HAS_UNIMPLEMENTED", "unimplemented instructions").unwrap();
        assert_eq!(adapter.get_num_tags(), 2);
        assert_eq!(rec1.get_string(NAME_COL), Some("BADCODE"));

        let by_name = adapter.get_record_by_name("BADCODE").unwrap().unwrap();
        assert_eq!(by_name.get_string(COMMENT_COL), Some("known bad code"));

        let mut updated = by_name;
        updated.set_string(COMMENT_COL, Some("updated comment".to_string()));
        adapter.update_record(&updated).unwrap();
        let refetched = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(refetched.get_string(COMMENT_COL), Some("updated comment"));

        {
            let mut count = 0;
            let mut iter = adapter.get_records().unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 2);
        }

        adapter.remove_tag_record(1).unwrap();
        assert_eq!(adapter.get_num_tags(), 1);
        assert!(adapter.get_record(1).unwrap().is_none());
    }
}
