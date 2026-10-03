//! Port of `ghidra.program.database.sourcemap.SourceFileAdapterV0`.
//!
//! Initial (only) version of [`SourceFileAdapter`]. As in `FunctionTagAdapterV0`, the source file
//! table is transient in Java: it is created only when a source file is actually stored
//! (`createSourceFileRecord`'s private `getTable()` helper lazily calls `dbHandle.createTable` on
//! first use), and every read-only query degrades gracefully when the table doesn't exist yet
//! (`getRecords()` -> empty iterator, `getRecord(..)` -> `None`).
//!
//! Deviation from Java, following the precedent set by
//! [`FunctionTagAdapterV0`](crate::program::database::function::FunctionTagAdapterV0): this port
//! takes `Arc<RwLock<DBHandle>>` at construction (rather than a transiently-borrowed `&mut
//! DBHandle`) so the same handle can be reached again from
//! [`SourceFileAdapterV0::get_or_create_table`] at an arbitrary later call.
//!
//! Also left out, matching the same precedent: registering as a `DBListener` to refresh a stale
//! `Table` reference after an undo/redo restores the database (Java's `dbRestored`/`addListener`
//! machinery). This port's `DBHandle` has no `add_listener`/notification-dispatch mechanism yet --
//! there is nothing to register with.
//!
//! Deviation from Java for the "no secondary index support" convention used throughout this
//! DB-adapter family: `getRecord(SourceFile)` scans linearly instead of using `table.indexIterator`
//! on the path column (matching `FunctionTagAdapterV0::get_record_by_name`'s own precedent).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::sourcemap::source_file_adapter::{
    SourceFileAdapter, ID_COL, ID_TYPE_COL, PATH_COL, TABLE_NAME,
};
use crate::program::database::sourcemap::SourceFile;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Mirrors `SourceFileAdapterV0.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 0;

/// Build the source file table schema, as defined by `SourceFileAdapterV0.V0_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::String, FieldType::Byte, FieldType::Binary],
        vec!["Path".to_string(), "IdType".to_string(), "Identifier".to_string()],
        vec![PATH_COL],
    ))
}

struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
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
        self.records.len() > 0
    }
}

/// Initial (only) version of the [`SourceFileAdapter`].
///
/// Port of `ghidra.program.database.sourcemap.SourceFileAdapterV0`. See the module docs for the
/// `Arc<RwLock<DBHandle>>`-vs-transient-`&mut DBHandle` deviation and the omitted `DBListener`
/// registration.
pub struct SourceFileAdapterV0 {
    dbhandle: Arc<RwLock<DBHandle>>,
    /// Lazily-created; `None` means "table not yet needed" (mirrors Java's `table` field, which
    /// starts `null` and is filled in by the private `getTable()` helper on first write).
    table: Option<Arc<RwLock<Table>>>,
}

impl SourceFileAdapterV0 {
    /// Constructs a version-0 source file adapter. If `create` is `true`, table creation is
    /// deferred to the first write (mirroring Java: even the "create" path does not eagerly create
    /// the table, since the table is transient). If `create` is `false`, an existing table is
    /// opened if present.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if an existing table's schema version does not match
    /// [`SCHEMA_VERSION`].
    pub fn new(dbhandle: Arc<RwLock<DBHandle>>, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            None
        } else {
            let existing = dbhandle.read().unwrap().get_table(TABLE_NAME);
            match existing {
                None => None,
                Some(t) => {
                    let version = t.read().unwrap().get_schema().get_version();
                    if version != SCHEMA_VERSION {
                        return Err(VersionException::with_version_indicator(
                            VersionException::NEWER_VERSION,
                            false,
                        ));
                    }
                    Some(t)
                }
            }
        };
        Ok(SourceFileAdapterV0 { dbhandle, table })
    }

    /// Lazily creates the underlying table if it does not already exist. Stands in for the private
    /// `SourceFileAdapterV0.getTable()`.
    fn get_or_create_table(&mut self) -> io::Result<Arc<RwLock<Table>>> {
        if let Some(table) = &self.table {
            return Ok(table.clone());
        }
        let table = self
            .dbhandle
            .write()
            .unwrap()
            .create_table(TABLE_NAME.to_string(), schema())?;
        self.table = Some(table.clone());
        Ok(table)
    }
}

impl SourceFileAdapter for SourceFileAdapterV0 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let Some(table) = &self.table else {
            return Ok(Box::new(EmptyRecordIterator));
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_record(&self, source_file: &SourceFile) -> io::Result<Option<DBRecord>> {
        let Some(table) = &self.table else {
            return Ok(None);
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(PATH_COL) != Some(source_file.path()) {
                continue;
            }
            let Some(id_type_byte) = rec.get_byte(ID_TYPE_COL) else {
                continue;
            };
            if id_type_byte as u8 != source_file.id_type().index() {
                continue;
            }
            let Field::Binary(identifier) = rec.get_field(ID_COL) else {
                continue;
            };
            let identifier = identifier.clone().unwrap_or_default();
            if identifier == source_file.identifier() {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn get_record_by_id(&self, id: i64) -> io::Result<Option<DBRecord>> {
        let Some(table) = &self.table else {
            return Ok(None);
        };
        table.read().unwrap().get_record(&Field::Long(Some(id)))
    }

    fn create_source_file_record(&mut self, source_file: &SourceFile) -> io::Result<DBRecord> {
        if let Some(rec) = self.get_record(source_file)? {
            return Ok(rec);
        }
        let table = self.get_or_create_table()?;
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_field(PATH_COL, Field::String(Some(source_file.path().to_string())));
        rec.set_field(ID_TYPE_COL, Field::Byte(Some(source_file.id_type().index() as i8)));
        rec.set_field(ID_COL, Field::Binary(Some(source_file.identifier())));
        table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
    }

    fn remove_source_file_record(&mut self, id: i64) -> io::Result<bool> {
        let Some(table) = &self.table else {
            return Ok(false);
        };
        table.write().unwrap().delete_record(&Field::Long(Some(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::sourcemap::SourceFileIdType;

    fn adapter(create: bool) -> (Arc<RwLock<DBHandle>>, SourceFileAdapterV0) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = SourceFileAdapterV0::new(handle.clone(), create).unwrap();
        (handle, adapter)
    }

    fn source_file(path: &str) -> SourceFile {
        SourceFile::with_identifier(
            path,
            SourceFileIdType::Md5,
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        )
        .unwrap()
    }

    #[test]
    fn empty_adapter_degrades_gracefully_before_any_write() {
        let (_handle, adapter) = adapter(true);
        assert!(adapter.get_record_by_id(0).unwrap().is_none());
        assert!(adapter.get_record(&source_file("/a/b/c.c")).unwrap().is_none());
        let mut iter = adapter.get_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn create_source_file_record_lazily_creates_table_and_dedupes() {
        let (_handle, mut adapter) = adapter(true);
        let sf = source_file("/a/b/c.c");

        let rec1 = adapter.create_source_file_record(&sf).unwrap();
        let rec2 = adapter.create_source_file_record(&sf).unwrap();
        assert_eq!(rec1.get_key(), rec2.get_key(), "duplicate insert should reuse the record");

        let key = match rec1.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key field: {other:?}"),
        };

        let fetched = adapter.get_record_by_id(key).unwrap().expect("record should exist");
        assert_eq!(fetched.get_string(PATH_COL), Some("/a/b/c.c"));

        let fetched_by_source_file =
            adapter.get_record(&sf).unwrap().expect("record should be found by source file");
        assert_eq!(fetched_by_source_file.get_key(), rec1.get_key());

        let mut count = 0;
        let mut iter = adapter.get_records().unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn different_id_type_or_identifier_is_a_distinct_record() {
        let (_handle, mut adapter) = adapter(true);
        let path = "/same/path.c";
        let none_id = SourceFile::new(path).unwrap();
        let md5_id = source_file(path);

        let rec1 = adapter.create_source_file_record(&none_id).unwrap();
        let rec2 = adapter.create_source_file_record(&md5_id).unwrap();
        assert_ne!(rec1.get_key(), rec2.get_key());
    }

    #[test]
    fn remove_record_round_trip() {
        let (_handle, mut adapter) = adapter(true);
        let sf = source_file("/a/b/c.c");
        let rec = adapter.create_source_file_record(&sf).unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key field: {other:?}"),
        };

        assert!(adapter.remove_source_file_record(key).unwrap());
        assert!(!adapter.remove_source_file_record(key).unwrap());
        assert!(adapter.get_record_by_id(key).unwrap().is_none());
    }

    #[test]
    fn remove_record_without_table_returns_false() {
        let (_handle, mut adapter) = adapter(true);
        assert!(!adapter.remove_source_file_record(0).unwrap());
    }

    #[test]
    fn reopening_existing_table_preserves_records() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        {
            let mut adapter = SourceFileAdapterV0::new(handle.clone(), true).unwrap();
            adapter.create_source_file_record(&source_file("/a/b/c.c")).unwrap();
        }
        let reopened = SourceFileAdapterV0::new(handle, false).unwrap();
        let mut count = 0;
        let mut iter = reopened.get_records().unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_empty_not_an_error() {
        let (_handle, adapter) = adapter(false);
        let mut iter = adapter.get_records().unwrap();
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mut adapter: Box<dyn SourceFileAdapter> =
            Box::new(SourceFileAdapterV0::new(handle, true).unwrap());
        adapter.create_source_file_record(&source_file("/a/b/c.c")).unwrap();
        assert!(adapter.get_record(&source_file("/a/b/c.c")).unwrap().is_some());
    }
}
