//! Port of `ghidra.program.database.module.ParentChildDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects and
//! constructs the single concrete implementation (`ParentChildDBAdapterV0`). That concrete
//! adapter has not been ported yet, so this port only models the abstract instance API it
//! implements, as an object-safe trait; the version-selection logic belongs with whichever type
//! ends up owning the concrete adapter(s). This follows the same convention already used for
//! [`FragmentDBAdapter`](crate::program::database::module::FragmentDBAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, Field};

/// DB table name prefix for the program tree parent/child relationship table. Stands in for
/// `ParentChildDBAdapter.PARENT_CHILD_TABLE_NAME`.
pub const PARENT_CHILD_TABLE_NAME: &str = "Parent/Child Relationships";

/// Column index for a parent/child record's parent module ID. Stands in for
/// `ParentChildDBAdapter.PARENT_ID_COL` (aliasing `ParentChildDBAdapterV0.V0_PARENT_ID_COL`).
pub const PARENT_ID_COL: usize = 0;
/// Column index for a parent/child record's child ID. Stands in for
/// `ParentChildDBAdapter.CHILD_ID_COL` (aliasing `ParentChildDBAdapterV0.V0_CHILD_ID_COL`).
pub const CHILD_ID_COL: usize = 1;
/// Column index for a parent/child record's ordering value. Stands in for
/// `ParentChildDBAdapter.ORDER_COL` (aliasing `ParentChildDBAdapterV0.V0_ORDER_COL`).
pub const ORDER_COL: usize = 2;

/// Builds the per-tree parent/child relationship table name. Stands in for
/// `ParentChildDBAdapter.getTableName(long)`.
pub fn get_table_name(tree_id: i64) -> String {
    format!("{PARENT_CHILD_TABLE_NAME}{tree_id}")
}

/// Adapter for accessing records in a program tree's Parent/Child relationship table.
///
/// Port of `ghidra.program.database.module.ParentChildDBAdapter`. See the module docs for what
/// was intentionally left out (the static factory/version-selection logic).
pub trait ParentChildDBAdapter {
    /// Adds a new parent/child record. Module IDs are positive, fragment IDs must be negative.
    ///
    /// Stands in for `ParentChildDBAdapter.addParentChildRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_parent_child_record(
        &mut self,
        parent_module_id: i64,
        child_id: i64,
    ) -> io::Result<DBRecord>;

    /// Gets the parent/child record for the given parent/child pair, or `None` if there is no
    /// such record.
    ///
    /// Stands in for `ParentChildDBAdapter.getParentChildRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_parent_child_record(
        &self,
        parent_id: i64,
        child_id: i64,
    ) -> io::Result<Option<DBRecord>>;

    /// Gets the parent/child record for the given record key, or `None` if there is no such
    /// record.
    ///
    /// Stands in for `ParentChildDBAdapter.getParentChildRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_parent_child_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Updates the given parent/child record in the table.
    ///
    /// Stands in for `ParentChildDBAdapter.updateParentChildRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_parent_child_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Removes the parent/child record with the given key. Returns `true` if a record was
    /// removed.
    ///
    /// Stands in for `ParentChildDBAdapter.removeParentChildRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_parent_child_record(&mut self, key: i64) -> io::Result<bool>;

    /// Gets the parent/child record keys which correspond to those records containing the
    /// specified parent or child id, as determined by `index_col` ([`CHILD_ID_COL`] or
    /// [`PARENT_ID_COL`]).
    ///
    /// Stands in for `ParentChildDBAdapter.getParentChildKeys(long, int)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_parent_child_keys(&self, id: i64, index_col: usize) -> io::Result<Vec<Field>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct ParentChildRow {
        parent_id: i64,
        child_id: i64,
        order: i32,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Int],
            vec!["ParentID".to_string(), "ChildID".to_string(), "Order".to_string()],
            vec![],
        ))
    }

    struct MockParentChildDBAdapter {
        rows: BTreeMap<i64, ParentChildRow>,
        next_key: i64,
    }

    impl MockParentChildDBAdapter {
        fn new() -> Self {
            MockParentChildDBAdapter {
                rows: BTreeMap::new(),
                next_key: 1,
            }
        }

        fn build_record(&self, key: i64, row: &ParentChildRow) -> DBRecord {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_long(PARENT_ID_COL, row.parent_id);
            record.set_long(CHILD_ID_COL, row.child_id);
            record.set_int(ORDER_COL, row.order);
            record
        }
    }

    impl ParentChildDBAdapter for MockParentChildDBAdapter {
        fn add_parent_child_record(
            &mut self,
            parent_module_id: i64,
            child_id: i64,
        ) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let order = self
                .rows
                .values()
                .filter(|r| r.parent_id == parent_module_id)
                .count() as i32;
            let row = ParentChildRow {
                parent_id: parent_module_id,
                child_id,
                order,
            };
            let record = self.build_record(key, &row);
            self.rows.insert(key, row);
            Ok(record)
        }

        fn get_parent_child_record(
            &self,
            parent_id: i64,
            child_id: i64,
        ) -> io::Result<Option<DBRecord>> {
            let found = self
                .rows
                .iter()
                .find(|(_, row)| row.parent_id == parent_id && row.child_id == child_id);
            Ok(found.map(|(key, row)| self.build_record(*key, row)))
        }

        fn get_parent_child_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.get(&key).map(|row| self.build_record(key, row)))
        }

        fn update_parent_child_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = match record.get_key() {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            let parent_id = match record.get_field(PARENT_ID_COL) {
                Field::Long(Some(v)) => *v,
                _ => 0,
            };
            let child_id = match record.get_field(CHILD_ID_COL) {
                Field::Long(Some(v)) => *v,
                _ => 0,
            };
            let order = match record.get_field(ORDER_COL) {
                Field::Int(Some(v)) => *v,
                _ => 0,
            };
            self.rows.insert(
                key,
                ParentChildRow {
                    parent_id,
                    child_id,
                    order,
                },
            );
            Ok(())
        }

        fn remove_parent_child_record(&mut self, key: i64) -> io::Result<bool> {
            Ok(self.rows.remove(&key).is_some())
        }

        fn get_parent_child_keys(&self, id: i64, index_col: usize) -> io::Result<Vec<Field>> {
            let keys = self
                .rows
                .iter()
                .filter(|(_, row)| match index_col {
                    PARENT_ID_COL => row.parent_id == id,
                    CHILD_ID_COL => row.child_id == id,
                    _ => false,
                })
                .map(|(key, _)| Field::Long(Some(*key)))
                .collect();
            Ok(keys)
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let mut adapter: Box<dyn ParentChildDBAdapter> = Box::new(MockParentChildDBAdapter::new());

        assert!(adapter.get_parent_child_record_by_key(1).unwrap().is_none());

        let rec1 = adapter.add_parent_child_record(10, 20).unwrap();
        let rec2 = adapter.add_parent_child_record(10, -5).unwrap();
        assert_ne!(rec1.get_key(), rec2.get_key());

        let fetched = adapter.get_parent_child_record(10, 20).unwrap();
        assert!(fetched.is_some());

        let mut updated = fetched.unwrap();
        updated.set_int(ORDER_COL, 99);
        adapter.update_parent_child_record(&updated).unwrap();

        let key = match updated.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        let refetched = adapter
            .get_parent_child_record_by_key(key)
            .unwrap()
            .unwrap();
        assert_eq!(refetched.get_field(ORDER_COL), &Field::Int(Some(99)));

        let parent_keys = adapter.get_parent_child_keys(10, PARENT_ID_COL).unwrap();
        assert_eq!(parent_keys.len(), 2);

        let child_key = match rec2.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        assert!(adapter.remove_parent_child_record(child_key).unwrap());
        assert!(adapter
            .get_parent_child_keys(-5, CHILD_ID_COL)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn get_table_name_appends_tree_id() {
        assert_eq!(get_table_name(3), "Parent/Child Relationships3");
    }
}
