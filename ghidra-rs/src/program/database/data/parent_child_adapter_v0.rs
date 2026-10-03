//! Port of `ghidra.program.database.data.ParentChildDBAdapterV0`.
//!
//! Version 0 (current, and so far only live-writable) implementation for accessing the datatype
//! parent/child association table, backed by a live, writable [`Table`]. `NOTE`: use of a
//! table-name prefix was introduced with this adapter version.
//!
//! Unlike most other `V0` adapters ported in this batch, this one is *not* read-only: it is the
//! sole real (non-`NoTable`) implementation of [`ParentChildAdapter`], generating its own record
//! keys directly from the table's own key sequence (Java's `table.getKey()`; there is no
//! `DataTypeManagerDB`-style key-tagging here since this table's keys are purely internal to it).
//!
//! `remove_record` mirrors Java's `removeRecord`, which removes at most *one* matching
//! parent/child pair per call (it returns immediately after deleting the first match), so
//! duplicate associations created via repeated `create_record` calls require repeated
//! `remove_record` calls to fully clear.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::data::parent_child_adapter::{
    ParentChildAdapter, PARENT_CHILD_TABLE_NAME,
};
use crate::util::exception::VersionException;

/// Column index of the association's parent data type ID, as defined by
/// `ParentChildDBAdapterV0`.
const PARENT_COL: usize = 0;

/// Column index of the association's child data type ID, as defined by
/// `ParentChildDBAdapterV0`.
const CHILD_COL: usize = 1;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "KEY".to_string(),
        vec![FieldType::Long, FieldType::Long],
        vec!["Parent ID".to_string(), "Child ID".to_string()],
        vec![],
    ))
}

/// Version 0 implementation for accessing the datatype parent/child database table.
///
/// Port of `ghidra.program.database.data.ParentChildDBAdapterV0`.
pub struct ParentChildDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    needs_initializing: bool,
}

impl ParentChildDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the datatype parent/child database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{PARENT_CHILD_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(&table_name)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(ParentChildDBAdapterV0 {
            table,
            needs_initializing: false,
        })
    }

    /// Marks this adapter's table as needing initialization (e.g. following an upgrade that
    /// created the table fresh but hasn't yet populated it).
    pub fn set_needs_initializing(&mut self) {
        self.needs_initializing = true;
    }
}

impl ParentChildAdapter for ParentChildDBAdapterV0 {
    fn needs_initializing(&self) -> bool {
        self.needs_initializing
    }

    fn create_record(&mut self, parent_id: i64, child_id: i64) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_field(PARENT_COL, Field::Long(Some(parent_id)));
        record.set_field(CHILD_COL, Field::Long(Some(child_id)));
        table.put_record(record)
    }

    fn remove_record(&mut self, parent_id: i64, child_id: i64) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut matched_key = None;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(CHILD_COL), Field::Long(Some(v)) if *v == child_id)
                && matches!(rec.get_field(PARENT_COL), Field::Long(Some(v)) if *v == parent_id)
            {
                matched_key = Some(rec.get_key().clone());
                break;
            }
        }
        drop(iter);
        if let Some(key) = matched_key {
            table.delete_record(&key)?;
        }
        Ok(())
    }

    fn get_child_ids(&self, parent_id: i64) -> io::Result<HashSet<i64>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut child_ids = HashSet::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(p)) = rec.get_field(PARENT_COL) {
                if *p == parent_id {
                    if let Field::Long(Some(c)) = rec.get_field(CHILD_COL) {
                        child_ids.insert(*c);
                    }
                }
            }
        }
        Ok(child_ids)
    }

    fn get_parent_ids(&self, child_id: i64) -> io::Result<HashSet<i64>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut parent_ids = HashSet::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(c)) = rec.get_field(CHILD_COL) {
                if *c == child_id {
                    if let Field::Long(Some(p)) = rec.get_field(PARENT_COL) {
                        parent_ids.insert(*p);
                    }
                }
            }
        }
        Ok(parent_ids)
    }

    fn has_parent(&self, child_id: i64) -> io::Result<bool> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(CHILD_COL), Field::Long(Some(v)) if *v == child_id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn remove_all_records_for_parent(&mut self, parent_id: i64) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(PARENT_COL), Field::Long(Some(v)) if *v == parent_id) {
                keys.push(rec.get_key().clone());
            }
        }
        drop(iter);
        for key in keys {
            table.delete_record(&key)?;
        }
        Ok(())
    }

    fn remove_all_records_for_child(&mut self, child_id: i64) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(CHILD_COL), Field::Long(Some(v)) if *v == child_id) {
                keys.push(rec.get_key().clone());
            }
        }
        drop(iter);
        for key in keys {
            table.delete_record(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_and_track_associations() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, "", true).unwrap();

        assert!(!adapter.needs_initializing());

        adapter.create_record(1, 10).unwrap();
        adapter.create_record(1, 11).unwrap();
        adapter.create_record(2, 11).unwrap();

        let children_of_1 = adapter.get_child_ids(1).unwrap();
        assert_eq!(children_of_1, HashSet::from([10, 11]));

        let parents_of_11 = adapter.get_parent_ids(11).unwrap();
        assert_eq!(parents_of_11, HashSet::from([1, 2]));

        assert!(adapter.has_parent(10).unwrap());
        assert!(!adapter.has_parent(99).unwrap());
    }

    #[test]
    fn remove_record_removes_only_one_matching_duplicate() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, "", true).unwrap();

        adapter.create_record(1, 10).unwrap();
        adapter.create_record(1, 10).unwrap();

        adapter.remove_record(1, 10).unwrap();
        // One instance should remain.
        assert_eq!(adapter.get_child_ids(1).unwrap(), HashSet::from([10]));
        assert!(adapter.has_parent(10).unwrap());

        adapter.remove_record(1, 10).unwrap();
        assert!(adapter.get_child_ids(1).unwrap().is_empty());
        assert!(!adapter.has_parent(10).unwrap());
    }

    #[test]
    fn remove_all_records_for_parent_and_child() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, "", true).unwrap();

        adapter.create_record(1, 10).unwrap();
        adapter.create_record(1, 11).unwrap();
        adapter.create_record(2, 11).unwrap();

        adapter.remove_all_records_for_child(11).unwrap();
        assert!(!adapter.has_parent(11).unwrap());
        assert!(adapter.get_child_ids(2).unwrap().is_empty());
        assert_eq!(adapter.get_child_ids(1).unwrap(), HashSet::from([10]));

        adapter.remove_all_records_for_parent(1).unwrap();
        assert!(adapter.get_child_ids(1).unwrap().is_empty());
    }

    #[test]
    fn set_needs_initializing() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ParentChildDBAdapterV0::new(&mut handle, "", true).unwrap();
        assert!(!adapter.needs_initializing());
        adapter.set_needs_initializing();
        assert!(adapter.needs_initializing());
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = ParentChildDBAdapterV0::new(&mut handle, "", true).unwrap();
            adapter.create_record(1, 10).unwrap();
        }
        let adapter = ParentChildDBAdapterV0::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_child_ids(1).unwrap(), HashSet::from([10]));
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(ParentChildDBAdapterV0::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn ParentChildAdapter> =
            Box::new(ParentChildDBAdapterV0::new(&mut handle, "", true).unwrap());
        assert!(!adapter.needs_initializing());
    }
}
