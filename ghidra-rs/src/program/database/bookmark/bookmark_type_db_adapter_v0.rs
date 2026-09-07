//! Port of `ghidra.program.database.bookmark.BookmarkTypeDBAdapterV0`.
//!
//! The live, table-backed implementation of [`BookmarkTypeDbAdapter`]. Unlike most `V0` adapters
//! elsewhere in this port (which are read-only relics of a prior schema), this is schema version
//! 0 of the Bookmark Types table *and* still the only schema version that has ever existed for
//! it -- so it supports full create/read/delete, matching Java exactly.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, Table};
use crate::program::database::bookmark::bookmark_type_db_adapter::{
    schema, BookmarkTypeDbAdapter, BOOKMARK_TYPE_TABLE_NAME, TYPE_NAME_COL,
};
use crate::util::exception::VersionException;

/// The live, table-backed implementation of the Bookmark Types database adapter.
///
/// Port of `ghidra.program.database.bookmark.BookmarkTypeDBAdapterV0`.
pub struct BookmarkTypeDbAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl BookmarkTypeDbAdapterV0 {
    /// Creates (`create = true`) or opens (`create = false`) the Bookmark Types table. Port of
    /// `BookmarkTypeDBAdapterV0(DBHandle, boolean)`.
    ///
    /// # Errors
    /// Returns a [`VersionException`] if `create` is `false` and the table is missing (upgradeable)
    /// or exists at an incompatible schema version (not upgradeable), or if creating/reading the
    /// table failed for an I/O reason.
    pub fn new(handle: &mut DBHandle, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(BOOKMARK_TYPE_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(BOOKMARK_TYPE_TABLE_NAME)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != 0 {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(BookmarkTypeDbAdapterV0 { table })
    }
}

impl BookmarkTypeDbAdapter for BookmarkTypeDbAdapterV0 {
    fn get_records(&self) -> io::Result<Vec<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(records)
    }

    fn add_type(&mut self, type_id: i32, type_name: &str) -> io::Result<()> {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(type_id as i64)));
        rec.set_field(TYPE_NAME_COL, Field::String(Some(type_name.to_string())));
        self.table.write().unwrap().put_record(rec)
    }

    fn delete_record(&mut self, type_id: i64) -> io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(type_id)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_true_creates_the_table() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = BookmarkTypeDbAdapterV0::new(&mut handle, true).unwrap();
        assert!(adapter.get_records().unwrap().is_empty());
        assert!(handle.get_table(BOOKMARK_TYPE_TABLE_NAME).is_some());
    }

    #[test]
    fn create_false_without_a_table_is_upgradeable_version_exception() {
        let mut handle = DBHandle::new().unwrap();
        match BookmarkTypeDbAdapterV0::new(&mut handle, false) {
            Err(e) => assert!(e.is_upgradable()),
            Ok(_) => panic!("expected a VersionException"),
        }
    }

    #[test]
    fn create_false_opens_an_existing_table() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = BookmarkTypeDbAdapterV0::new(&mut handle, true).unwrap();
        adapter.add_type(0, "Note").unwrap();
        drop(adapter);

        let reopened = BookmarkTypeDbAdapterV0::new(&mut handle, false).unwrap();
        assert_eq!(reopened.get_type_ids().unwrap(), vec![0]);
    }

    #[test]
    fn add_type_and_get_records_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = BookmarkTypeDbAdapterV0::new(&mut handle, true).unwrap();
        adapter.add_type(0, "Note").unwrap();
        adapter.add_type(1, "Info").unwrap();

        let records = adapter.get_records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(adapter.get_type_ids().unwrap(), vec![0, 1]);

        let note = records
            .iter()
            .find(|r| r.get_key() == &Field::Long(Some(0)))
            .unwrap();
        assert_eq!(
            note.get_field(TYPE_NAME_COL),
            &Field::String(Some("Note".to_string()))
        );
    }

    #[test]
    fn delete_record_removes_the_type() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = BookmarkTypeDbAdapterV0::new(&mut handle, true).unwrap();
        adapter.add_type(0, "Note").unwrap();
        adapter.add_type(1, "Info").unwrap();

        adapter.delete_record(0).unwrap();
        assert_eq!(adapter.get_type_ids().unwrap(), vec![1]);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter: Box<dyn BookmarkTypeDbAdapter> =
            Box::new(BookmarkTypeDbAdapterV0::new(&mut handle, true).unwrap());
        adapter.add_type(3, "Warning").unwrap();
        assert_eq!(adapter.get_type_ids().unwrap(), vec![3]);
    }
}
