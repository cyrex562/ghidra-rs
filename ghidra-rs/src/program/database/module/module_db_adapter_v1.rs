//! Port of `ghidra.program.database.module.ModuleDBAdapterV1`.
//!
//! Version 1 (current, and so far only live-writable) implementation for accessing a program
//! tree's Module database table, backed by a live, writable [`Table`]. Uses the shared "current"
//! schema exposed by [`module_db_adapter::schema`]. One table exists per program tree, named via
//! [`get_table_name`].

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::module::module_db_adapter::{
    self, get_table_name, ModuleDBAdapter, MODULE_NAME_COL,
};
use crate::util::exception::VersionException;

/// A `RecordIterator` over an eagerly-collected set of records.
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

/// Version 1 (current) implementation for accessing a program tree's Module database table.
///
/// Port of `ghidra.program.database.module.ModuleDBAdapterV1`.
pub struct ModuleDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl ModuleDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 1;

    /// Gets a version 1 adapter for the program tree module database table.
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
                .create_table(table_name, module_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(version < Self::VERSION));
            }
            table
        };
        Ok(ModuleDBAdapterV1 { table })
    }
}

impl ModuleDBAdapter for ModuleDBAdapterV1 {
    fn create_module_record(&mut self, _parent_module_id: i64, name: &str) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.peek_next_key();
        let mut record = DBRecord::new(module_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(MODULE_NAME_COL, Field::String(Some(name.to_string())));
        table.put_record(record.clone())?;
        table.ensure_next_key_at_least(key);
        Ok(record)
    }

    fn get_module_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))
    }

    fn get_module_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut found: Option<DBRecord> = None;
        let mut count = 0;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(MODULE_NAME_COL), Field::String(Some(v)) if v == name) {
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
        Ok(found)
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn update_module_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_module_record(&mut self, child_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(child_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::module::module_db_adapter::{
        MODULE_CHILD_COUNT_COL, MODULE_COMMENTS_COL,
    };

    fn make_handle() -> DBHandle {
        DBHandle::new().unwrap()
    }

    #[test]
    fn missing_table_without_create_is_an_error() {
        let mut handle = make_handle();
        assert!(ModuleDBAdapterV1::new(&mut handle, false, 0).is_err());
    }

    #[test]
    fn create_module_record_defaults_comments_and_child_count() {
        let mut handle = make_handle();
        let mut adapter = ModuleDBAdapterV1::new(&mut handle, true, 0).unwrap();

        let rec = adapter.create_module_record(0, "root").unwrap();
        assert_eq!(
            rec.get_field(MODULE_NAME_COL),
            &Field::String(Some("root".to_string()))
        );
        assert_eq!(rec.get_field(MODULE_COMMENTS_COL), &Field::String(None));
        assert_eq!(rec.get_field(MODULE_CHILD_COUNT_COL), &Field::Int(Some(0)));
    }

    #[test]
    fn get_module_record_by_key_and_name() {
        let mut handle = make_handle();
        let mut adapter = ModuleDBAdapterV1::new(&mut handle, true, 0).unwrap();
        let rec = adapter.create_module_record(0, "root").unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };

        assert!(adapter.get_module_record(key).unwrap().is_some());
        assert!(adapter.get_module_record(999).unwrap().is_none());
        assert!(adapter.get_module_record_by_name("root").unwrap().is_some());
        assert!(adapter
            .get_module_record_by_name("missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_module_record_by_name_errors_on_duplicates() {
        let mut handle = make_handle();
        let mut adapter = ModuleDBAdapterV1::new(&mut handle, true, 0).unwrap();
        adapter.create_module_record(0, "dup").unwrap();
        adapter.create_module_record(0, "dup").unwrap();
        assert!(adapter.get_module_record_by_name("dup").is_err());
    }

    #[test]
    fn update_and_remove_module_record() {
        let mut handle = make_handle();
        let mut adapter = ModuleDBAdapterV1::new(&mut handle, true, 0).unwrap();
        let mut rec = adapter.create_module_record(0, "root").unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };

        rec.set_field(MODULE_CHILD_COUNT_COL, Field::Int(Some(3)));
        adapter.update_module_record(&rec).unwrap();
        let fetched = adapter.get_module_record(key).unwrap().unwrap();
        assert_eq!(
            fetched.get_field(MODULE_CHILD_COUNT_COL),
            &Field::Int(Some(3))
        );

        assert!(adapter.remove_module_record(key).unwrap());
        assert!(adapter.get_module_record(key).unwrap().is_none());
    }

    #[test]
    fn get_records_returns_all() {
        let mut handle = make_handle();
        let mut adapter = ModuleDBAdapterV1::new(&mut handle, true, 0).unwrap();
        adapter.create_module_record(0, "a").unwrap();
        adapter.create_module_record(0, "b").unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = make_handle();
        let adapter: Box<dyn ModuleDBAdapter> =
            Box::new(ModuleDBAdapterV1::new(&mut handle, true, 0).unwrap());
        assert!(adapter.get_module_record(1).unwrap().is_none());
    }
}
