//! Port of `ghidra.program.database.module.ModuleDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects and
//! constructs the concrete implementation (`ModuleDBAdapterV1`, upgrading from `ModuleDBAdapterV0`
//! when needed). Those concrete adapters have not been ported yet, so this port only models the
//! abstract instance API it implements, as an object-safe trait; the version-selection/upgrade
//! logic belongs with whichever type ends up owning the concrete adapter(s). This follows the same
//! convention already used for
//! [`FragmentDBAdapter`](crate::program::database::module::FragmentDBAdapter) and
//! [`ParentChildDBAdapter`](crate::program::database::module::ParentChildDBAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

/// DB table name prefix for the program tree module table. Stands in for
/// `ModuleDBAdapter.MODULE_TABLE_NAME`.
pub const MODULE_TABLE_NAME: &str = "Module Table";

/// Column index for a module record's name. Stands in for `ModuleDBAdapter.MODULE_NAME_COL`
/// (aliasing `ModuleDBAdapterV1.V1_MODULE_NAME_COL`).
pub const MODULE_NAME_COL: usize = 0;
/// Column index for a module record's comments. Stands in for
/// `ModuleDBAdapter.MODULE_COMMENTS_COL` (aliasing `ModuleDBAdapterV1.V1_MODULE_COMMENTS_COL`).
pub const MODULE_COMMENTS_COL: usize = 1;
/// Column index for a module record's child count. Stands in for
/// `ModuleDBAdapter.MODULE_CHILD_COUNT_COL` (aliasing
/// `ModuleDBAdapterV1.V1_MODULE_CHILD_COUNT_COL`).
pub const MODULE_CHILD_COUNT_COL: usize = 2;

/// Builds the per-tree module table name. Stands in for `ModuleDBAdapter.getTableName(long)`.
pub fn get_table_name(tree_id: i64) -> String {
    format!("{MODULE_TABLE_NAME}{tree_id}")
}

/// Adapter for accessing records in a program tree's Module table.
///
/// Port of `ghidra.program.database.module.ModuleDBAdapter`. See the module docs for what was
/// intentionally left out (the static factory/version-selection/upgrade logic).
pub trait ModuleDBAdapter {
    /// Creates a new module record with the given name, as a child of the module with key
    /// `parent_module_id`.
    ///
    /// Stands in for `ModuleDBAdapter.createModuleRecord(long, String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_module_record(&mut self, parent_module_id: i64, name: &str) -> io::Result<DBRecord>;

    /// Gets the module record with the given key, or `None` if there is no such record.
    ///
    /// Stands in for `ModuleDBAdapter.getModuleRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_module_record(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Gets the module record with the given name, or `None` if there is no such record.
    ///
    /// Stands in for `ModuleDBAdapter.getModuleRecord(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_module_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>>;

    /// Gets an iterator over all module records in the table.
    ///
    /// Stands in for `ModuleDBAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Updates the given module record in the table.
    ///
    /// Stands in for `ModuleDBAdapter.updateModuleRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_module_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Removes the module record with the given key. Returns `true` if a record was removed.
    ///
    /// Stands in for `ModuleDBAdapter.removeModuleRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_module_record(&mut self, child_id: i64) -> io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct ModuleRow {
        name: String,
        comments: Option<String>,
        child_count: i32,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String, FieldType::String, FieldType::Int],
            vec![
                "Name".to_string(),
                "Comments".to_string(),
                "Child Count".to_string(),
            ],
            vec![],
        ))
    }

    struct MockModuleDBAdapter {
        rows: BTreeMap<i64, ModuleRow>,
        next_key: i64,
    }

    impl MockModuleDBAdapter {
        fn new() -> Self {
            MockModuleDBAdapter {
                rows: BTreeMap::new(),
                next_key: 1,
            }
        }

        fn build_record(&self, key: i64, row: &ModuleRow) -> DBRecord {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_string(MODULE_NAME_COL, Some(row.name.clone()));
            record.set_string(MODULE_COMMENTS_COL, row.comments.clone());
            record.set_int(MODULE_CHILD_COUNT_COL, row.child_count);
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

    impl ModuleDBAdapter for MockModuleDBAdapter {
        fn create_module_record(
            &mut self,
            _parent_module_id: i64,
            name: &str,
        ) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let row = ModuleRow {
                name: name.to_string(),
                comments: None,
                child_count: 0,
            };
            let record = self.build_record(key, &row);
            self.rows.insert(key, row);
            Ok(record)
        }

        fn get_module_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.get(&key).map(|row| self.build_record(key, row)))
        }

        fn get_module_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
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

        fn update_module_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = match record.get_key() {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            let name = match record.get_field(MODULE_NAME_COL) {
                Field::String(Some(v)) => v.clone(),
                _ => String::new(),
            };
            let comments = match record.get_field(MODULE_COMMENTS_COL) {
                Field::String(v) => v.clone(),
                _ => None,
            };
            let child_count = match record.get_field(MODULE_CHILD_COUNT_COL) {
                Field::Int(Some(v)) => *v,
                _ => 0,
            };
            self.rows.insert(
                key,
                ModuleRow {
                    name,
                    comments,
                    child_count,
                },
            );
            Ok(())
        }

        fn remove_module_record(&mut self, child_id: i64) -> io::Result<bool> {
            Ok(self.rows.remove(&child_id).is_some())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn ModuleDBAdapter> = Box::new(MockModuleDBAdapter::new());

        assert!(adapter.get_module_record(1).unwrap().is_none());

        let rec1 = adapter.create_module_record(0, "root").unwrap();
        let rec2 = adapter.create_module_record(0, "child").unwrap();
        assert_ne!(rec1.get_key(), rec2.get_key());

        let fetched = adapter.get_module_record_by_name("root").unwrap();
        assert!(fetched.is_some());

        let mut updated = fetched.unwrap();
        updated.set_int(MODULE_CHILD_COUNT_COL, 3);
        adapter.update_module_record(&updated).unwrap();

        let key = match updated.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        let refetched = adapter.get_module_record(key).unwrap().unwrap();
        assert_eq!(
            refetched.get_field(MODULE_CHILD_COUNT_COL),
            &Field::Int(Some(3))
        );

        {
            let mut iter = adapter.get_records().unwrap();
            let mut count = 0;
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 2);
        }

        let child_key = match rec2.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        assert!(adapter.remove_module_record(child_key).unwrap());
        assert!(adapter
            .get_module_record_by_name("child")
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_table_name_appends_tree_id() {
        assert_eq!(get_table_name(5), "Module Table5");
    }
}
