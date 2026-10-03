//! Port of `ghidra.program.database.module.ParentChildDBAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing a program tree's
//! Parent/Child relationship database table, backed by a live, writable [`Table`]. One table
//! exists per program tree, named via [`get_table_name`]. Child IDs are positive for module
//! children and negative for fragment children (a convention enforced by callers, not this
//! adapter -- see `ParentChildDBAdapter.addParentChildRecord`'s doc comment in Java).
//!
//! `get_parent_child_record` mirrors Java's two-step lookup (`findRecords` on the child-ID column,
//! then a linear filter by parent ID) as a single linear scan over both fields, which is
//! observably equivalent since this port's [`Table`] has no secondary-index support to begin
//! with.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::module::parent_child_db_adapter::{
    get_table_name, ParentChildDBAdapter, CHILD_ID_COL, ORDER_COL, PARENT_ID_COL,
};
use crate::util::exception::VersionException;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::Long, FieldType::Int],
        vec![
            "Parent ID".to_string(),
            "Child ID".to_string(),
            "Child Index".to_string(),
        ],
        vec![],
    ))
}

/// Version 0 (current) implementation for accessing a program tree's Parent/Child relationship
/// database table.
///
/// Port of `ghidra.program.database.module.ParentChildDBAdapterV0`.
pub struct ParentChildDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl ParentChildDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the program tree parent/child database table.
    ///
    /// If `create` is true, the table is created; otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        create: bool,
        tree_id: i64,
    ) -> Result<Self, VersionException> {
        let table_name = get_table_name(tree_id);
        let table = if create {
            handle
                .create_table(table_name, schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(ParentChildDBAdapterV0 { table })
    }
}

impl ParentChildDBAdapter for ParentChildDBAdapterV0 {
    fn add_parent_child_record(
        &mut self,
        parent_module_id: i64,
        child_id: i64,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.peek_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_field(PARENT_ID_COL, Field::Long(Some(parent_module_id)));
        record.set_field(CHILD_ID_COL, Field::Long(Some(child_id)));
        table.put_record(record.clone())?;
        table.ensure_next_key_at_least(key);
        Ok(record)
    }

    fn get_parent_child_record(
        &self,
        parent_id: i64,
        child_id: i64,
    ) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let matches_child =
                matches!(rec.get_field(CHILD_ID_COL), Field::Long(Some(v)) if *v == child_id);
            let matches_parent =
                matches!(rec.get_field(PARENT_ID_COL), Field::Long(Some(v)) if *v == parent_id);
            if matches_child && matches_parent {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn get_parent_child_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))
    }

    fn update_parent_child_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_parent_child_record(&mut self, key: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(key)))
    }

    fn get_parent_child_keys(&self, id: i64, index_col: usize) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(index_col), Field::Long(Some(v)) if *v == id) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handle() -> DBHandle {
        DBHandle::new().unwrap()
    }

    #[test]
    fn missing_table_without_create_is_an_error() {
        let mut handle = make_handle();
        assert!(ParentChildDBAdapterV0::new(&mut handle, false, 0).is_err());
    }

    #[test]
    fn add_and_get_parent_child_record() {
        let mut handle = make_handle();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, true, 0).unwrap();

        let rec1 = adapter.add_parent_child_record(1, 10).unwrap();
        let rec2 = adapter.add_parent_child_record(1, -5).unwrap();
        assert_ne!(rec1.get_key(), rec2.get_key());
        assert_eq!(rec1.get_field(ORDER_COL), &Field::Int(Some(0)));

        assert!(adapter.get_parent_child_record(1, 10).unwrap().is_some());
        assert!(adapter.get_parent_child_record(1, -5).unwrap().is_some());
        assert!(adapter.get_parent_child_record(2, 10).unwrap().is_none());

        let key = match rec1.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        assert!(adapter
            .get_parent_child_record_by_key(key)
            .unwrap()
            .is_some());
    }

    #[test]
    fn update_and_remove_parent_child_record() {
        let mut handle = make_handle();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, true, 0).unwrap();
        let mut rec = adapter.add_parent_child_record(1, 10).unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };

        rec.set_field(ORDER_COL, Field::Int(Some(7)));
        adapter.update_parent_child_record(&rec).unwrap();
        let fetched = adapter.get_parent_child_record_by_key(key).unwrap().unwrap();
        assert_eq!(fetched.get_field(ORDER_COL), &Field::Int(Some(7)));

        assert!(adapter.remove_parent_child_record(key).unwrap());
        assert!(adapter
            .get_parent_child_record_by_key(key)
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_parent_child_keys_filters_by_column() {
        let mut handle = make_handle();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, true, 0).unwrap();
        adapter.add_parent_child_record(1, 10).unwrap();
        adapter.add_parent_child_record(1, 11).unwrap();
        adapter.add_parent_child_record(2, 11).unwrap();

        assert_eq!(
            adapter.get_parent_child_keys(1, PARENT_ID_COL).unwrap().len(),
            2
        );
        assert_eq!(
            adapter.get_parent_child_keys(11, CHILD_ID_COL).unwrap().len(),
            2
        );
        assert!(adapter
            .get_parent_child_keys(99, PARENT_ID_COL)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn per_tree_table_names_do_not_collide() {
        let mut handle = make_handle();
        let mut a0 = ParentChildDBAdapterV0::new(&mut handle, true, 0).unwrap();
        let a1 = ParentChildDBAdapterV0::new(&mut handle, true, 1).unwrap();
        a0.add_parent_child_record(1, 10).unwrap();
        assert!(a1.get_parent_child_record(1, 10).unwrap().is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = make_handle();
        let adapter: Box<dyn ParentChildDBAdapter> =
            Box::new(ParentChildDBAdapterV0::new(&mut handle, true, 0).unwrap());
        assert!(adapter.get_parent_child_record_by_key(1).unwrap().is_none());
    }
}
