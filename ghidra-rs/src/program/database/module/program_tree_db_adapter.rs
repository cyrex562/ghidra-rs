//! Port of `ghidra.program.database.module.ProgramTreeDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects and
//! constructs the single concrete implementation (`ProgramTreeDBAdapterV0`). That concrete
//! adapter has not been ported yet, so this port only models the abstract instance API it
//! implements, as an object-safe trait; the version-selection logic belongs with whichever type
//! ends up owning the concrete adapter(s). This follows the same convention already used for
//! [`ParentChildDBAdapter`](crate::program::database::module::ParentChildDBAdapter) and
//! [`ModuleDBAdapter`](crate::program::database::module::ModuleDBAdapter). This trait was itself
//! selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

/// DB table name for the program tree table. Stands in for
/// `ProgramTreeDBAdapter.PROGRAM_TREE_TABLE_NAME`.
pub const PROGRAM_TREE_TABLE_NAME: &str = "Trees";

/// Column index for a tree record's name. Stands in for `ProgramTreeDBAdapter.TREE_NAME_COL`
/// (aliasing `ProgramTreeDBAdapterV0.V0_TREE_NAME_COL`).
pub const TREE_NAME_COL: usize = 0;
/// Column index for a tree record's modification number. Stands in for
/// `ProgramTreeDBAdapter.MODIFICATION_NUM_COL` (aliasing
/// `ProgramTreeDBAdapterV0.V0_MODIFICATION_NUM_COL`).
pub const MODIFICATION_NUM_COL: usize = 1;

/// Adapter for accessing records in the program's Tree table.
///
/// Port of `ghidra.program.database.module.ProgramTreeDBAdapter`. See the module docs for what
/// was intentionally left out (the static factory/version-selection logic).
pub trait ProgramTreeDBAdapter {
    /// Creates a new record for the Tree table.
    ///
    /// Stands in for `ProgramTreeDBAdapter.createRecord(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_record(&mut self, name: &str) -> io::Result<DBRecord>;

    /// Deletes the record for the specified tree ID. Returns `true` if the tree record was
    /// successfully deleted.
    ///
    /// Stands in for `ProgramTreeDBAdapter.deleteRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_record(&mut self, tree_id: i64) -> io::Result<bool>;

    /// Gets the record for the given tree ID, or `None` if not found.
    ///
    /// Stands in for `ProgramTreeDBAdapter.getRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record(&self, tree_id: i64) -> io::Result<Option<DBRecord>>;

    /// Gets the record for the tree with the given name, or `None` if not found.
    ///
    /// Stands in for `ProgramTreeDBAdapter.getRecord(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>>;

    /// Gets an iterator over all tree records.
    ///
    /// Stands in for `ProgramTreeDBAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Updates the tree table with the given record.
    ///
    /// Stands in for `ProgramTreeDBAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct TreeRow {
        name: String,
        modification_num: i64,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String, FieldType::Long],
            vec!["Name".to_string(), "Modification Number".to_string()],
            vec![],
        ))
    }

    struct MockProgramTreeDBAdapter {
        rows: BTreeMap<i64, TreeRow>,
        next_key: i64,
    }

    impl MockProgramTreeDBAdapter {
        fn new() -> Self {
            MockProgramTreeDBAdapter {
                rows: BTreeMap::new(),
                next_key: 0,
            }
        }

        fn build_record(&self, key: i64, row: &TreeRow) -> DBRecord {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_string(TREE_NAME_COL, Some(row.name.clone()));
            record.set_long(MODIFICATION_NUM_COL, row.modification_num);
            record
        }
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

    impl ProgramTreeDBAdapter for MockProgramTreeDBAdapter {
        fn create_record(&mut self, name: &str) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let row = TreeRow {
                name: name.to_string(),
                modification_num: 0,
            };
            let record = self.build_record(key, &row);
            self.rows.insert(key, row);
            Ok(record)
        }

        fn delete_record(&mut self, tree_id: i64) -> io::Result<bool> {
            Ok(self.rows.remove(&tree_id).is_some())
        }

        fn get_record(&self, tree_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.get(&tree_id).map(|row| self.build_record(tree_id, row)))
        }

        fn get_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
            let found = self.rows.iter().find(|(_, row)| row.name == name);
            Ok(found.map(|(key, row)| self.build_record(*key, row)))
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .rows
                .iter()
                .map(|(key, row)| self.build_record(*key, row))
                .collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = match record.get_key() {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            let name = match record.get_field(TREE_NAME_COL) {
                Field::String(Some(v)) => v.clone(),
                _ => String::new(),
            };
            let modification_num = match record.get_field(MODIFICATION_NUM_COL) {
                Field::Long(Some(v)) => *v,
                _ => 0,
            };
            self.rows.insert(
                key,
                TreeRow {
                    name,
                    modification_num,
                },
            );
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn ProgramTreeDBAdapter> = Box::new(MockProgramTreeDBAdapter::new());

        assert!(adapter.get_record(0).unwrap().is_none());

        let rec1 = adapter.create_record("root").unwrap();
        let rec2 = adapter.create_record("other").unwrap();
        assert_ne!(rec1.get_key(), rec2.get_key());

        let fetched = adapter.get_record_by_name("root").unwrap();
        assert!(fetched.is_some());

        let mut updated = fetched.unwrap();
        updated.set_long(MODIFICATION_NUM_COL, 7);
        adapter.update_record(&updated).unwrap();

        let key = match updated.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        let refetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(MODIFICATION_NUM_COL),
            &Field::Long(Some(7))
        );

        {
            let mut iter = adapter.get_records().unwrap();
            let mut count = 0;
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 2);
        }

        let other_key = match rec2.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        assert!(adapter.delete_record(other_key).unwrap());
        assert!(adapter.get_record_by_name("other").unwrap().is_none());
    }
}
