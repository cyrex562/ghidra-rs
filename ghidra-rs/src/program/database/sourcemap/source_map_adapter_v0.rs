//! Port of `ghidra.program.database.sourcemap.SourceMapAdapterV0`.
//!
//! Initial (only) version of [`SourceMapAdapter`]. As with `SourceFileAdapterV0`, the source map
//! table is transient in Java (created lazily on first write) and every read-only query degrades
//! gracefully when the table doesn't exist yet.
//!
//! Deviation from Java, following the same `FunctionTagAdapterV0`/`SourceFileAdapterV0` precedent:
//! this port takes `Arc<RwLock<DBHandle>>` at construction for deferred table creation, and does
//! not register as a `DBListener` (this port's `DBHandle` has no `add_listener` mechanism yet).
//!
//! Deviation from Java for the "no secondary index support" convention used throughout this
//! DB-adapter family: `getSourceMapRecordIterator`/`getRecordsForSourceFile` (which use
//! `AddressIndexPrimaryKeyIterator`/`table.indexIterator` in Java) scan linearly and sort/filter in
//! memory instead, matching the reference `MockSourceMapAdapter` in
//! [`SourceMapAdapter`](crate::program::database::sourcemap::source_map_adapter)'s own tests for
//! `get_source_map_record_iterator`'s "before"/"after" semantics.
//!
//! `moveAddressRange`'s use of `DatabaseTableUtils.updateIndexedAddressField` (a utility not ported
//! to this crate as a standalone type) is reimplemented directly: entries whose decoded base
//! address falls in `[from_addr, from_addr + length)` are shifted by the same offset applied to
//! `to_addr`, matching the same in-range/preserve-offset behavior the Java utility provides.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::AddressMap;
use crate::program::database::sourcemap::source_map_adapter::{
    MoveAddressRangeError, SourceMapAdapter, BASE_ADDR_COL, FILE_LINE_COL, LENGTH_COL, TABLE_NAME,
};
use crate::program::model::address::Address;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Schema version implemented by this adapter. Mirrors `SourceMapAdapterV0.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 0;

/// Build the source map table schema, as defined by `SourceMapAdapterV0.V0_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::Long, FieldType::Long, FieldType::Long],
        vec!["fileAndLine".to_string(), "baseAddress".to_string(), "length".to_string()],
        vec![FILE_LINE_COL, BASE_ADDR_COL],
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

/// Initial (only) version of the [`SourceMapAdapter`].
///
/// Port of `ghidra.program.database.sourcemap.SourceMapAdapterV0`. See the module docs for what
/// was left out and how `moveAddressRange` was reimplemented.
pub struct SourceMapAdapterV0 {
    dbhandle: Arc<RwLock<DBHandle>>,
    /// Lazily-created; `None` means "table not yet needed".
    table: Option<Arc<RwLock<Table>>>,
    addr_map: Arc<dyn AddressMap>,
}

impl SourceMapAdapterV0 {
    /// Constructs a version-0 source map adapter. If `create` is `true`, table creation is
    /// deferred to the first write. If `create` is `false`, an existing table is opened if
    /// present.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if an existing table's schema version does not match
    /// [`SCHEMA_VERSION`].
    pub fn new(
        dbhandle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
    ) -> Result<Self, VersionException> {
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
        Ok(SourceMapAdapterV0 { dbhandle, table, addr_map })
    }

    /// Lazily creates the underlying table if it does not already exist. Stands in for the private
    /// `SourceMapAdapterV0.getTable()`.
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

impl SourceMapAdapter for SourceMapAdapterV0 {
    fn remove_record(&mut self, key: i64) -> io::Result<bool> {
        let Some(table) = &self.table else {
            return Ok(false);
        };
        table.write().unwrap().delete_record(&Field::Long(Some(key)))
    }

    fn get_source_map_record_iterator(
        &self,
        addr: &Address,
        before: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let Some(table) = &self.table else {
            return Ok(Box::new(EmptyRecordIterator));
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            let Some(key) = rec.get_long(BASE_ADDR_COL) else {
                continue;
            };
            let base = self.addr_map.decode_address(key);
            let keep = if before { &base < addr } else { &base >= addr };
            if keep {
                entries.push((base, rec));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let records: Vec<DBRecord> = entries.into_iter().map(|(_, rec)| rec).collect();
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_records_for_source_file(
        &self,
        file_id: i64,
        min_line: i32,
        max_line: i32,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let Some(table) = &self.table else {
            return Ok(Box::new(EmptyRecordIterator));
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            let Some(file_line) = rec.get_long(FILE_LINE_COL) else {
                continue;
            };
            let rec_file_id = file_line >> 32;
            let rec_line = (file_line & 0xFFFF_FFFF) as i32;
            if rec_file_id == file_id && rec_line >= min_line && rec_line <= max_line {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn add_map_entry(
        &mut self,
        file_id: i64,
        line_num: i32,
        base_addr: &Address,
        length: i64,
    ) -> io::Result<DBRecord> {
        let table = self.get_or_create_table()?;
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        let file_line = (file_id << 32) | (line_num as i64 & 0xFFFF_FFFF);
        rec.set_long(FILE_LINE_COL, file_line);
        let addr_key = self.addr_map.get_key(base_addr, true);
        rec.set_long(BASE_ADDR_COL, addr_key);
        rec.set_long(LENGTH_COL, length);
        table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
    }

    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        let Some(table) = self.table.clone() else {
            return Ok(());
        };
        monitor.check_cancelled()?;
        let from_off = from_addr.offset();
        let to_off = to_addr.offset();
        let mut table = table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_update = Vec::new();
        while let Some(mut rec) = iter.next()? {
            monitor.check_cancelled()?;
            let Some(key) = rec.get_long(BASE_ADDR_COL) else {
                continue;
            };
            let base = self.addr_map.decode_address(key);
            if base.space() != from_addr.space() {
                continue;
            }
            let off = base.offset();
            if off < from_off || off >= from_off + length {
                continue;
            }
            let new_addr = to_addr.space().address(to_off + (off - from_off));
            let new_key = self.addr_map.get_key(&new_addr, true);
            rec.set_long(BASE_ADDR_COL, new_key);
            to_update.push(rec);
        }
        drop(iter);
        for rec in to_update {
            table.put_record(rec)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};
    use crate::util::task::DummyMonitor;

    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }

        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap {
                space: self.space.clone(),
            })
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap { space: ram_space() })
    }

    fn addr(offset: i64) -> Address {
        ram_space().address(offset)
    }

    fn adapter(create: bool) -> (Arc<RwLock<DBHandle>>, SourceMapAdapterV0) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = SourceMapAdapterV0::new(handle.clone(), addr_map(), create).unwrap();
        (handle, adapter)
    }

    #[test]
    fn empty_adapter_degrades_gracefully_before_any_write() {
        let (_handle, adapter) = adapter(true);
        let mut iter = adapter.get_source_map_record_iterator(&addr(0), false).unwrap();
        assert!(iter.next().unwrap().is_none());
        let mut iter = adapter.get_records_for_source_file(1, 0, 100).unwrap();
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn add_map_entry_lazily_creates_table_and_round_trips() {
        let (_handle, mut adapter) = adapter(true);
        let rec = adapter.add_map_entry(1, 10, &addr(0x1000), 0x10).unwrap();
        assert_eq!(rec.get_long(LENGTH_COL), Some(0x10));
        assert_eq!(rec.get_long(BASE_ADDR_COL), Some(0x1000));

        let mut iter = adapter.get_records_for_source_file(1, 10, 10).unwrap();
        let fetched = iter.next().unwrap().expect("record present");
        assert_eq!(fetched.get_key(), rec.get_key());
    }

    #[test]
    fn get_records_for_source_file_respects_line_bounds_and_file_id() {
        let (_handle, mut adapter) = adapter(true);
        adapter.add_map_entry(1, 5, &addr(0x100), 4).unwrap();
        adapter.add_map_entry(1, 15, &addr(0x200), 4).unwrap();
        adapter.add_map_entry(2, 5, &addr(0x300), 4).unwrap();

        let mut count = 0;
        let mut iter = adapter.get_records_for_source_file(1, 0, 10).unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);

        let mut count = 0;
        let mut iter = adapter.get_records_for_source_file(1, 0, i32::MAX).unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn get_source_map_record_iterator_before_and_after() {
        let (_handle, mut adapter) = adapter(true);
        adapter.add_map_entry(1, 1, &addr(0x100), 4).unwrap();
        adapter.add_map_entry(1, 2, &addr(0x200), 4).unwrap();
        adapter.add_map_entry(1, 3, &addr(0x300), 4).unwrap();

        let mut before = Vec::new();
        let mut iter = adapter.get_source_map_record_iterator(&addr(0x200), true).unwrap();
        while let Some(rec) = iter.next().unwrap() {
            before.push(rec.get_long(BASE_ADDR_COL).unwrap());
        }
        assert_eq!(before, vec![0x100]);

        let mut after = Vec::new();
        let mut iter = adapter.get_source_map_record_iterator(&addr(0x200), false).unwrap();
        while let Some(rec) = iter.next().unwrap() {
            after.push(rec.get_long(BASE_ADDR_COL).unwrap());
        }
        assert_eq!(after, vec![0x200, 0x300]);
    }

    #[test]
    fn move_address_range_shifts_entries_in_range_only() {
        let (_handle, mut adapter) = adapter(true);
        let rec1 = adapter.add_map_entry(1, 1, &addr(0x1000), 4).unwrap();
        let rec2 = adapter.add_map_entry(1, 2, &addr(0x2000), 4).unwrap();

        adapter
            .move_address_range(&addr(0x1000), &addr(0x5000), 0x100, &DummyMonitor)
            .unwrap();

        let key1 = match rec1.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key: {other:?}"),
        };
        let key2 = match rec2.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key: {other:?}"),
        };

        let moved = adapter
            .table
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key1)))
            .unwrap()
            .unwrap();
        assert_eq!(moved.get_long(BASE_ADDR_COL), Some(0x5000));

        let unmoved = adapter
            .table
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key2)))
            .unwrap()
            .unwrap();
        assert_eq!(unmoved.get_long(BASE_ADDR_COL), Some(0x2000));
    }

    #[test]
    fn remove_record_round_trip() {
        let (_handle, mut adapter) = adapter(true);
        let rec = adapter.add_map_entry(1, 1, &addr(0x1000), 4).unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key: {other:?}"),
        };
        assert!(adapter.remove_record(key).unwrap());
        assert!(!adapter.remove_record(key).unwrap());
    }

    #[test]
    fn reopening_existing_table_preserves_records() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        {
            let mut adapter = SourceMapAdapterV0::new(handle.clone(), addr_map(), true).unwrap();
            adapter.add_map_entry(1, 1, &addr(0x1000), 4).unwrap();
        }
        let reopened = SourceMapAdapterV0::new(handle, addr_map(), false).unwrap();
        let mut count = 0;
        let mut iter = reopened.get_records_for_source_file(1, 0, i32::MAX).unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let mut adapter: Box<dyn SourceMapAdapter> =
            Box::new(SourceMapAdapterV0::new(handle, addr_map(), true).unwrap());
        adapter.add_map_entry(1, 1, &addr(0x1000), 4).unwrap();
        let mut iter = adapter.get_records_for_source_file(1, 0, i32::MAX).unwrap();
        assert!(iter.next().unwrap().is_some());
    }
}
