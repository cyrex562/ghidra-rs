//! Port of `ghidra.program.database.function.FunctionTagAdapterV0`.
//!
//! Initial (only) version of [`FunctionTagAdapter`]. The function tags table is transient in
//! Java: it is created only when a tag is actually stored (`createTagRecord`/`updateRecord`'s
//! shared private `getTable()` helper lazily calls `dbHandle.createTable` on first use) and is
//! expected to sometimes not exist yet, in which case every read-only query degrades gracefully
//! (`getRecords()` -> `EmptyRecordIterator`, `getRecord(..)` -> `null`, `getNumTags()` -> `0`).
//!
//! Deviation from Java: `FunctionTagAdapter::create_tag_record`/`update_record` are `&mut self`
//! but take no `DBHandle` parameter, so a Rust port that only ever borrows `&mut DBHandle`
//! transiently (as every other adapter in this family does) cannot create the table lazily at an
//! arbitrary *later* call the way `FunctionTagAdapterV0.dbHandle` (a stored field) lets Java do.
//! This port instead takes `Arc<RwLock<DBHandle>>` at construction, letting the same handle be
//! reached again from inside [`FunctionTagAdapterV0::get_or_create_table`]. This is the first
//! adapter in this DB-adapter family with genuinely deferred (not just at-construction) table
//! creation, so it is also the first to need this.
//!
//! Also left out: registering as a `DBListener` to refresh a stale `Table` reference after an
//! undo/redo restores the database (Java's `dbRestored`/`addListener` machinery). This port's
//! [`DBHandle`] has no `add_listener`/notification-dispatch mechanism yet (see
//! [`crate::framework::db::db_listener::DBListener`], a standalone trait with nothing wired up to
//! call it) -- there is nothing to register with. `get_or_create_table` re-fetches from `dbhandle`
//! whenever `self.table` is `None`, so this only matters if a *previously found* table becomes
//! stale via an out-of-band restore, which this port cannot exercise yet either.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::function::function_tag_adapter::{
    FunctionTagAdapter, COMMENT_COL, NAME_COL,
};
use crate::util::exception::VersionException;

/// Name of the function tags database table. Mirrors `FunctionTagAdapter.TABLE_NAME`.
pub const TABLE_NAME: &str = "Function Tags";

/// Schema version implemented by this adapter. Mirrors `FunctionTagAdapterV0.SCHEMA_VERSION`
/// (which also serves as `FunctionTagAdapter.CURRENT_VERSION`, since this is the only version).
pub const SCHEMA_VERSION: i32 = 0;

/// Build the function tags table schema, as defined by `FunctionTagAdapterV0.V0_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::String, FieldType::String],
        vec!["Tag".to_string(), "Comment".to_string()],
        vec![],
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
        self.records.as_slice().first().is_some()
    }
}

/// Initial (only) version of the [`FunctionTagAdapter`].
///
/// Port of `ghidra.program.database.function.FunctionTagAdapterV0`. See the module docs for the
/// `Arc<RwLock<DBHandle>>`-vs-transient-`&mut DBHandle` deviation and the omitted `DBListener`
/// registration.
pub struct FunctionTagAdapterV0 {
    dbhandle: Arc<RwLock<DBHandle>>,
    /// Lazily-created; `None` means "table not yet needed" (mirrors Java's `table` field, which
    /// starts `null` and is filled in by the private `getTable()` helper on first write).
    table: Option<Arc<RwLock<Table>>>,
}

impl FunctionTagAdapterV0 {
    /// Constructs a version 0 function tags adapter. If `create` is `true`, table creation is
    /// deferred to the first write (mirroring Java: even the "create" path does not eagerly
    /// create the table, since the table is transient). If `create` is `false`, an existing table
    /// is opened if present.
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
        Ok(FunctionTagAdapterV0 { dbhandle, table })
    }

    /// Lazily creates the underlying table if it does not already exist. Stands in for the
    /// private `FunctionTagAdapterV0.getTable()`.
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

impl FunctionTagAdapter for FunctionTagAdapterV0 {
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

    fn get_record_by_name(&self, tag: &str) -> io::Result<Option<DBRecord>> {
        let Some(table) = &self.table else {
            return Ok(None);
        };
        // NOTE: could consider either keeping all tags in memory or using an indexed column
        // (matches the Java implementation's own comment; this port's `Table` has no secondary
        // index support either, matching the rest of this DB-adapter family's convention).
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(NAME_COL) == Some(tag) {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
        let Some(table) = &self.table else {
            return Ok(None);
        };
        table.read().unwrap().get_record(&Field::Long(Some(id)))
    }

    fn create_tag_record(&mut self, tag: &str, comment: &str) -> io::Result<DBRecord> {
        // See if there is already a record for this tag name. If so, just return that one.
        if let Some(existing) = self.get_record_by_name(tag)? {
            return Ok(existing);
        }
        let table = self.get_or_create_table()?;
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_string(NAME_COL, Some(tag.to_string()));
        rec.set_string(COMMENT_COL, Some(comment.to_string()));
        self.update_record(&rec)?;
        Ok(rec)
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        let table = self.get_or_create_table()?;
        let result = table.write().unwrap().put_record(record.clone());
        result
    }

    fn remove_tag_record(&mut self, id: i64) -> io::Result<()> {
        if let Some(table) = &self.table {
            table.write().unwrap().delete_record(&Field::Long(Some(id)))?;
        }
        Ok(())
    }

    fn get_num_tags(&self) -> i32 {
        match &self.table {
            None => 0,
            Some(table) => table.read().unwrap().get_record_count() as i32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(create: bool) -> (Arc<RwLock<DBHandle>>, FunctionTagAdapterV0) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = FunctionTagAdapterV0::new(handle.clone(), create).unwrap();
        (handle, adapter)
    }

    #[test]
    fn empty_adapter_degrades_gracefully_before_any_write() {
        let (_handle, adapter) = adapter(true);
        assert_eq!(adapter.get_num_tags(), 0);
        assert!(adapter.get_record(0).unwrap().is_none());
        assert!(adapter.get_record_by_name("BADCODE").unwrap().is_none());
        let mut iter = adapter.get_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn create_tag_record_lazily_creates_table_and_dedupes_by_name() {
        let (_handle, mut adapter) = adapter(true);
        let rec1 = adapter.create_tag_record("BADCODE", "known bad code").unwrap();
        assert_eq!(rec1.get_string(NAME_COL), Some("BADCODE"));
        assert_eq!(adapter.get_num_tags(), 1);

        // Creating the same tag name again returns the existing record rather than duplicating.
        let rec1_again = adapter.create_tag_record("BADCODE", "different comment").unwrap();
        assert_eq!(rec1_again.get_key(), rec1.get_key());
        assert_eq!(adapter.get_num_tags(), 1);

        adapter.create_tag_record("HAS_UNIMPLEMENTED", "unimplemented instructions").unwrap();
        assert_eq!(adapter.get_num_tags(), 2);
    }

    #[test]
    fn update_and_remove_round_trip() {
        let (_handle, mut adapter) = adapter(true);
        let rec = adapter.create_tag_record("BADCODE", "known bad code").unwrap();

        let mut updated = rec.clone();
        updated.set_string(COMMENT_COL, Some("updated comment".to_string()));
        adapter.update_record(&updated).unwrap();

        let key = updated.get_key().get_long_value();
        let refetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(refetched.get_string(COMMENT_COL), Some("updated comment"));

        adapter.remove_tag_record(key).unwrap();
        assert!(adapter.get_record(key).unwrap().is_none());
        assert_eq!(adapter.get_num_tags(), 0);
    }

    #[test]
    fn reopening_existing_table_preserves_records() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        {
            let mut adapter = FunctionTagAdapterV0::new(handle.clone(), true).unwrap();
            adapter.create_tag_record("BADCODE", "known bad code").unwrap();
        }
        let reopened = FunctionTagAdapterV0::new(handle, false).unwrap();
        assert_eq!(reopened.get_num_tags(), 1);
        assert!(reopened.get_record_by_name("BADCODE").unwrap().is_some());
    }

    #[test]
    fn opening_missing_table_without_create_is_empty_not_an_error() {
        let (_handle, adapter) = adapter(false);
        assert_eq!(adapter.get_num_tags(), 0);
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mut adapter: Box<dyn FunctionTagAdapter> =
            Box::new(FunctionTagAdapterV0::new(handle, true).unwrap());
        adapter.create_tag_record("BADCODE", "known bad code").unwrap();
        assert_eq!(adapter.get_num_tags(), 1);
    }
}
