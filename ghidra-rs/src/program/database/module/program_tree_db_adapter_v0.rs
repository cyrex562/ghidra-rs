//! Port of `ghidra.program.database.module.ProgramTreeDBAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing the program's Tree
//! database table, backed by a live, writable [`Table`]. Unlike the per-tree Fragment/Module/
//! Parent-Child tables, there is exactly one Tree table per program, named
//! [`PROGRAM_TREE_TABLE_NAME`].

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::module::program_tree_db_adapter::{
    ProgramTreeDBAdapter, MODIFICATION_NUM_COL, PROGRAM_TREE_TABLE_NAME, TREE_NAME_COL,
};
use crate::util::exception::VersionException;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::Long],
        vec!["Name".to_string(), "Modification Number".to_string()],
        vec![],
    ))
}

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

/// Version 0 (current) implementation for accessing the program tree database table.
///
/// Port of `ghidra.program.database.module.ProgramTreeDBAdapterV0`.
pub struct ProgramTreeDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl ProgramTreeDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the program tree database table.
    ///
    /// If `create` is true, the table is created; otherwise an existing table is opened.
    pub fn new(handle: &mut DBHandle, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(PROGRAM_TREE_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(PROGRAM_TREE_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!(
                    "Missing Table: {PROGRAM_TREE_TABLE_NAME}"
                ))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(ProgramTreeDBAdapterV0 { table })
    }
}

impl ProgramTreeDBAdapter for ProgramTreeDBAdapterV0 {
    fn create_record(&mut self, name: &str) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.peek_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_field(TREE_NAME_COL, Field::String(Some(name.to_string())));
        record.set_field(MODIFICATION_NUM_COL, Field::Long(Some(0)));
        table.put_record(record.clone())?;
        table.ensure_next_key_at_least(key);
        Ok(record)
    }

    fn delete_record(&mut self, tree_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(tree_id)))
    }

    fn get_record(&self, tree_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(tree_id)))
    }

    fn get_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut found: Option<DBRecord> = None;
        let mut count = 0;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(TREE_NAME_COL), Field::String(Some(v)) if v == name) {
                count += 1;
                if found.is_none() {
                    found = Some(rec);
                }
            }
        }
        if count > 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Found {count} trees named {name}"),
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

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
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
        assert!(ProgramTreeDBAdapterV0::new(&mut handle, false).is_err());
    }

    #[test]
    fn create_and_get_record() {
        let mut handle = make_handle();
        let mut adapter = ProgramTreeDBAdapterV0::new(&mut handle, true).unwrap();

        let rec = adapter.create_record("Program Tree").unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };
        assert_eq!(
            rec.get_field(MODIFICATION_NUM_COL),
            &Field::Long(Some(0))
        );

        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(
            fetched.get_field(TREE_NAME_COL),
            &Field::String(Some("Program Tree".to_string()))
        );

        assert!(adapter
            .get_record_by_name("Program Tree")
            .unwrap()
            .is_some());
        assert!(adapter.get_record_by_name("nope").unwrap().is_none());
    }

    #[test]
    fn get_record_by_name_errors_on_duplicates() {
        let mut handle = make_handle();
        let mut adapter = ProgramTreeDBAdapterV0::new(&mut handle, true).unwrap();
        adapter.create_record("dup").unwrap();
        adapter.create_record("dup").unwrap();
        assert!(adapter.get_record_by_name("dup").is_err());
    }

    #[test]
    fn update_and_delete_record() {
        let mut handle = make_handle();
        let mut adapter = ProgramTreeDBAdapterV0::new(&mut handle, true).unwrap();
        let mut rec = adapter.create_record("Tree A").unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };

        rec.set_field(MODIFICATION_NUM_COL, Field::Long(Some(5)));
        adapter.update_record(&rec).unwrap();
        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(
            fetched.get_field(MODIFICATION_NUM_COL),
            &Field::Long(Some(5))
        );

        assert!(adapter.delete_record(key).unwrap());
        assert!(adapter.get_record(key).unwrap().is_none());
    }

    #[test]
    fn get_records_returns_all() {
        let mut handle = make_handle();
        let mut adapter = ProgramTreeDBAdapterV0::new(&mut handle, true).unwrap();
        adapter.create_record("A").unwrap();
        adapter.create_record("B").unwrap();

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
        let adapter: Box<dyn ProgramTreeDBAdapter> =
            Box::new(ProgramTreeDBAdapterV0::new(&mut handle, true).unwrap());
        assert!(adapter.get_record(0).unwrap().is_none());
    }
}
