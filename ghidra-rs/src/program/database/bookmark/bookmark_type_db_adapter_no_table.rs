//! Port of `ghidra.program.database.bookmark.BookmarkTypeDBAdapterNoTable`.
//!
//! Used for a read-only version of a program that has no Bookmark Types table (i.e. bookmarks
//! were still stored as properties, pre-dating the dedicated tables this package now uses).
//!
//! Java's constructor takes an unused `DBHandle` and requires callers to invoke
//! `setOldBookmarkManager(OldBookmarkManager)` "prior to invoking any other method" to populate
//! `records` from `OldBookmarkManager.getTypeRecords()`. Since `OldBookmarkManager` is not yet
//! ported (see `orig_src/.../OldBookmarkManager.java`, `PORT_MANIFEST.tsv` row still `TODO`),
//! this port replaces that single-purpose setter with [`BookmarkTypeDbAdapterNoTable::set_records`],
//! which takes the already-extracted `Vec<DBRecord>` directly -- a future `OldBookmarkManager`
//! port only needs to call `get_type_records()` and forward the result here, exactly mirroring
//! the ordering Java's callers must already observe.

use std::io;

use crate::framework::db::DBRecord;
use crate::program::database::bookmark::bookmark_type_db_adapter::BookmarkTypeDbAdapter;

/// Adapter needed for a read-only version of a program which has no bookmark type table (legacy
/// property-based bookmarks).
///
/// Port of `ghidra.program.database.bookmark.BookmarkTypeDBAdapterNoTable`.
#[derive(Debug, Default)]
pub struct BookmarkTypeDbAdapterNoTable {
    records: Vec<DBRecord>,
}

impl BookmarkTypeDbAdapterNoTable {
    /// Creates a new, empty adapter. Port of `BookmarkTypeDBAdapterNoTable(DBHandle)` (the
    /// `DBHandle` parameter is unused in Java, so it is dropped here).
    pub fn new() -> Self {
        BookmarkTypeDbAdapterNoTable {
            records: Vec::new(),
        }
    }

    /// Populates this adapter's records, standing in for
    /// `setOldBookmarkManager(OldBookmarkManager)` -- see the module docs for why.
    pub fn set_records(&mut self, records: Vec<DBRecord>) {
        self.records = records;
    }
}

impl BookmarkTypeDbAdapter for BookmarkTypeDbAdapterNoTable {
    fn get_records(&self) -> io::Result<Vec<DBRecord>> {
        Ok(self.records.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use crate::program::database::bookmark::bookmark_type_db_adapter::{schema, TYPE_NAME_COL};

    fn record(id: i64, name: &str) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(id)));
        rec.set_field(TYPE_NAME_COL, Field::String(Some(name.to_string())));
        rec
    }

    #[test]
    fn starts_empty() {
        let adapter = BookmarkTypeDbAdapterNoTable::new();
        assert!(adapter.get_records().unwrap().is_empty());
        assert!(adapter.get_type_ids().unwrap().is_empty());
    }

    #[test]
    fn set_records_populates_get_records_and_type_ids() {
        let mut adapter = BookmarkTypeDbAdapterNoTable::new();
        adapter.set_records(vec![record(0, "Note"), record(1, "Info")]);
        let records = adapter.get_records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(adapter.get_type_ids().unwrap(), vec![0, 1]);
    }

    #[test]
    fn add_type_and_delete_record_are_unsupported() {
        let mut adapter = BookmarkTypeDbAdapterNoTable::new();
        assert_eq!(
            adapter.add_type(0, "Note").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.delete_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut adapter = BookmarkTypeDbAdapterNoTable::new();
        adapter.set_records(vec![record(5, "Analysis")]);
        let boxed: Box<dyn BookmarkTypeDbAdapter> = Box::new(adapter);
        assert_eq!(boxed.get_type_ids().unwrap(), vec![5]);
    }
}
