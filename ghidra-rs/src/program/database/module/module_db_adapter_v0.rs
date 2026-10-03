//! Port of `ghidra.program.database.module.ModuleDBAdapterV0`.
//!
//! Version 0 (read-only) implementation for accessing a program tree's Module database table.
//! Its on-disk records only carry a name and comments; [`RecordTranslator::translate_record`]
//! upgrades each record to the current (version 1) shape by tallying the module's child-count
//! from the tree's Parent/Child table (mirrors `ModuleDBAdapterV1.V1_MODULE_SCHEMA`, matching
//! [`module_db_adapter::schema`]).
//!
//! All mutating operations (`create_module_record`, `update_module_record`,
//! `remove_module_record`) return an `Unsupported` I/O error, mirroring Java's
//! `UnsupportedOperationException`.
//!
//! Ownership note: Java stores a live reference to the tree's shared `ParentChildDBAdapter`
//! (owned elsewhere, by `ModuleManager`). Since no concrete shared owner has been wired up on the
//! Rust side yet, this port takes ownership of a boxed [`ParentChildDBAdapter`] trait object
//! instead of borrowing one; callers that need to share the same underlying table with other
//! adapters should hold their own handle to it as this integration matures.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{
    DBHandle, DBRecord, Field, FieldType, RecordIterator, RecordTranslator, Schema, Table,
};
use crate::program::database::module::module_db_adapter::{
    self, get_table_name as get_module_table_name, ModuleDBAdapter, MODULE_CHILD_COUNT_COL,
    MODULE_COMMENTS_COL, MODULE_NAME_COL,
};
use crate::program::database::module::parent_child_db_adapter::{ParentChildDBAdapter, PARENT_ID_COL};
use crate::util::exception::VersionException;

/// Column index of a version 0 module record's name. Same index as the current schema's
/// [`MODULE_NAME_COL`], per `ModuleDBAdapterV0.V0_MODULE_NAME_COL`.
const V0_MODULE_NAME_COL: usize = 0;
/// Column index of a version 0 module record's comments. Same index as the current schema's
/// [`MODULE_COMMENTS_COL`], per `ModuleDBAdapterV0.V0_MODULE_COMMENTS_COL`.
const V0_MODULE_COMMENTS_COL: usize = 1;

fn v0_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::String],
        vec!["Name".to_string(), "Comments".to_string()],
        vec![],
    ))
}

/// A `RecordIterator` over an eagerly-collected, already-translated set of records.
struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }
    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// Version 0 (read-only) implementation for accessing a program tree's Module database table.
///
/// Port of `ghidra.program.database.module.ModuleDBAdapterV0`.
pub struct ModuleDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    parent_child_adapter: Box<dyn ParentChildDBAdapter>,
}

impl ModuleDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the program tree module database table (read-only).
    pub fn new(
        handle: &DBHandle,
        tree_id: i64,
        parent_child_adapter: Box<dyn ParentChildDBAdapter>,
    ) -> Result<Self, VersionException> {
        let table_name = get_module_table_name(tree_id);
        let table = handle.get_table(&table_name).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {table_name}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != Self::VERSION {
            return Err(VersionException::with_upgradeable(false));
        }
        Ok(ModuleDBAdapterV0 {
            table,
            parent_child_adapter,
        })
    }
}

impl RecordTranslator for ModuleDBAdapterV0 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(module_db_adapter::schema(), old_record.get_key().clone());
        rec.set_field(
            MODULE_NAME_COL,
            old_record.get_field(V0_MODULE_NAME_COL).clone(),
        );
        rec.set_field(
            MODULE_COMMENTS_COL,
            old_record.get_field(V0_MODULE_COMMENTS_COL).clone(),
        );

        let module_key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => 0,
        };
        let keys = self
            .parent_child_adapter
            .get_parent_child_keys(module_key, PARENT_ID_COL)?;
        rec.set_field(MODULE_CHILD_COUNT_COL, Field::Int(Some(keys.len() as i32)));
        Ok(rec)
    }
}

impl ModuleDBAdapter for ModuleDBAdapterV0 {
    fn create_module_record(&mut self, _parent_module_id: i64, _name: &str) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records in Version 0",
        ))
    }

    fn get_module_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn get_module_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut found: Option<DBRecord> = None;
        let mut count = 0;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V0_MODULE_NAME_COL), Field::String(Some(v)) if v == name) {
                count += 1;
                if found.is_none() {
                    found = Some(rec);
                }
            }
        }
        if count > 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Found {count} modules named {name}"),
            ));
        }
        match found {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            translated.push(self.translate_record(rec)?);
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn update_module_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in Version 0",
        ))
    }

    fn remove_module_record(&mut self, _child_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot remove records in Version 0",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::module::parent_child_db_adapter_v0::ParentChildDBAdapterV0;

    fn make_handle_with_v0_table(tree_id: i64) -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(get_module_table_name(tree_id), v0_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        for name in ["root", "child-a"] {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            rec.set_field(V0_MODULE_NAME_COL, Field::String(Some(name.to_string())));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        let mut pc_handle = DBHandle::new().unwrap();
        let pc = Box::new(ParentChildDBAdapterV0::new(&mut pc_handle, true, 0).unwrap());
        assert!(ModuleDBAdapterV0::new(&handle, 0, pc).is_err());
    }

    #[test]
    fn get_record_translates_and_counts_children() {
        let mut handle = make_handle_with_v0_table(0);
        let mut pc = ParentChildDBAdapterV0::new(&mut handle, true, 0).unwrap();
        // Module key 0 ("root") has two children recorded in the parent/child table.
        pc.add_parent_child_record(0, 10).unwrap();
        pc.add_parent_child_record(0, 11).unwrap();

        let adapter = ModuleDBAdapterV0::new(&handle, 0, Box::new(pc)).unwrap();

        let rec = adapter.get_module_record(0).unwrap().expect("root exists");
        assert_eq!(
            rec.get_field(MODULE_NAME_COL),
            &Field::String(Some("root".to_string()))
        );
        assert_eq!(rec.get_field(MODULE_CHILD_COUNT_COL), &Field::Int(Some(2)));

        let child = adapter
            .get_module_record_by_name("child-a")
            .unwrap()
            .expect("child-a exists");
        assert_eq!(
            child.get_field(MODULE_CHILD_COUNT_COL),
            &Field::Int(Some(0))
        );

        assert!(adapter.get_module_record(999).unwrap().is_none());
        assert!(adapter
            .get_module_record_by_name("missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_records_translates_all() {
        let handle = make_handle_with_v0_table(0);
        let mut pc_handle = DBHandle::new().unwrap();
        let pc = ParentChildDBAdapterV0::new(&mut pc_handle, true, 0).unwrap();
        let adapter = ModuleDBAdapterV0::new(&handle, 0, Box::new(pc)).unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut count = 0;
        while let Some(rec) = iter.next().unwrap() {
            assert_eq!(rec.get_field(MODULE_CHILD_COUNT_COL), &Field::Int(Some(0)));
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v0_table(0);
        let mut pc_handle = DBHandle::new().unwrap();
        let pc = ParentChildDBAdapterV0::new(&mut pc_handle, true, 0).unwrap();
        let mut adapter = ModuleDBAdapterV0::new(&handle, 0, Box::new(pc)).unwrap();

        assert_eq!(
            adapter.create_module_record(0, "x").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let existing = adapter.get_module_record(0).unwrap().unwrap();
        assert_eq!(
            adapter.update_module_record(&existing).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_module_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v0_table(0);
        let mut pc_handle = DBHandle::new().unwrap();
        let pc = ParentChildDBAdapterV0::new(&mut pc_handle, true, 0).unwrap();
        let adapter: Box<dyn ModuleDBAdapter> =
            Box::new(ModuleDBAdapterV0::new(&handle, 0, Box::new(pc)).unwrap());
        assert!(adapter.get_module_record(0).unwrap().is_some());
    }
}
