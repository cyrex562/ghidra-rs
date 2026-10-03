//! Port of `ghidra.program.database.code.CommentsDBAdapterV1`.
//!
//! Where Java uses `AddressKeyIterator`/`AddressKeyRecordIterator`/`AddressRecordDeleter`/
//! `DatabaseTableUtils.updateAddressKey` -- all backed by `Table`'s secondary indexes -- this
//! port's [`Table`] has no secondary-index support, so every such lookup scans linearly instead,
//! decoding each candidate record's address through the real `AddressMap` and filtering/sorting
//! in memory. Same observable result, just O(n) rather than indexed (matching the convention
//! already established by `CompositeDBAdapterV5V6`/`SymbolDatabaseAdapterV5`/
//! `CommentHistoryAdapterV0` and others in this DB-adapter family).
//!
//! [`RecordIterator`] has no `previous()` (unlike Java's `db.RecordIterator`), so "iterate
//! backward from end" is modeled by yielding records in descending-address order from `next()`
//! rather than by a separate reverse cursor method -- same observable traversal order.
//! [`AddressKeyIteratorLike`] *does* model both directions (mirroring the real `DBLongIterator`
//! surface Java's `AddressKeyIterator` implements), so `get_keys`/`get_keys_in_range` return a
//! genuinely bidirectional cursor instead.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::comments_db_adapter::{
    self, CommentsDBAdapter, MoveAddressRangeError, COMMENTS_TABLE_NAME, CURRENT_VERSION,
};
use crate::program::database::map::AddressMap;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

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

/// A bidirectional cursor over a sorted set of address keys, positioned so that `next()`/
/// `previous()` walk forward/backward from the constructed starting point. Stands in for
/// `ghidra.program.database.map.AddressKeyIterator`.
struct VecAddressKeyIterator {
    keys: Vec<i64>,
    /// Index of the element `next()` would return; the element `previous()` would return is at
    /// `pos - 1`.
    pos: usize,
}

impl VecAddressKeyIterator {
    /// `keys` must be sorted ascending. `pos = 0` starts the cursor before the first element
    /// (for forward iteration); `pos = keys.len()` starts it after the last element (for
    /// backward iteration).
    fn new(keys: Vec<i64>, forward: bool) -> Self {
        let pos = if forward { 0 } else { keys.len() };
        VecAddressKeyIterator { keys, pos }
    }
}

impl AddressKeyIteratorLike for VecAddressKeyIterator {
    fn has_next(&mut self) -> bool {
        self.pos < self.keys.len()
    }

    fn has_previous(&mut self) -> bool {
        self.pos > 0
    }

    fn next(&mut self) -> Option<i64> {
        if self.pos < self.keys.len() {
            let v = self.keys[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }

    fn previous(&mut self) -> Option<i64> {
        if self.pos > 0 {
            self.pos -= 1;
            Some(self.keys[self.pos])
        } else {
            None
        }
    }
}

/// Version 1 adapter for the comments table.
///
/// Port of `ghidra.program.database.code.CommentsDBAdapterV1`. See the module docs for the
/// indexed-lookup deviations.
pub struct CommentsDBAdapterV1 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl CommentsDBAdapterV1 {
    /// Constructs a new Version 1 comments adapter. `addr_map` is used to generate keys for
    /// addresses; `create` is `true` to create a new table, `false` to load an existing one.
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table was not found (when `create` is `false`) or has
    /// an unexpected schema version.
    pub fn new(
        handle: &mut crate::framework::db::DBHandle,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(COMMENTS_TABLE_NAME.to_string(), comments_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(COMMENTS_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {COMMENTS_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != CURRENT_VERSION {
                if version < CURRENT_VERSION {
                    return Err(VersionException::with_upgradeable(true));
                }
                return Err(VersionException::with_version_indicator(
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
            table
        };
        Ok(CommentsDBAdapterV1 { table, addr_map })
    }

    /// Collects, decodes, and address-sorts every record for which `filter` returns `true`.
    fn collect_sorted_by_address(
        &self,
        filter: impl Fn(&Address) -> bool,
    ) -> io::Result<Vec<(Address, DBRecord)>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(key)) = rec.get_key() {
                let addr = self.addr_map.decode_address(*key);
                if filter(&addr) {
                    entries.push((addr, rec));
                }
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

impl CommentsDBAdapter for CommentsDBAdapterV1 {
    fn get_record_count(&self) -> io::Result<i32> {
        Ok(self.table.read().unwrap().get_record_count() as i32)
    }

    fn get_record(&self, addr: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(addr)))
    }

    fn create_record(
        &mut self,
        addr: i64,
        comment_col: usize,
        comment: &str,
    ) -> io::Result<DBRecord> {
        let mut record = DBRecord::new(comments_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_field(comment_col, Field::String(Some(comment.to_string())));
        self.table.write().unwrap().put_record(record.clone())?;
        Ok(record)
    }

    fn delete_record(&mut self, addr: i64) -> io::Result<bool> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(addr)))
    }

    fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool> {
        let entries = self.collect_sorted_by_address(|addr| addr >= start && addr <= end)?;
        let mut table = self.table.write().unwrap();
        let mut removed_any = false;
        for (_, rec) in entries {
            if table.delete_record(rec.get_key())? {
                removed_any = true;
            }
        }
        Ok(removed_any)
    }

    fn update_record(&mut self, comment_rec: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(comment_rec.clone())
    }

    fn get_records_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let mut entries = self.collect_sorted_by_address(|addr| addr >= start && addr <= end)?;
        if !at_start {
            entries.reverse();
        }
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let entries = self.collect_sorted_by_address(|_| true)?;
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    fn get_keys_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let entries = self.collect_sorted_by_address(|addr| addr >= start && addr <= end)?;
        let keys: Vec<i64> = entries
            .into_iter()
            .filter_map(|(_, rec)| match rec.get_key() {
                Field::Long(Some(v)) => Some(*v),
                _ => None,
            })
            .collect();
        Ok(Box::new(VecAddressKeyIterator::new(keys, at_start)))
    }

    fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn get_records_from(&self, addr: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        let entries = self.collect_sorted_by_address(|a| a >= addr)?;
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    fn get_keys(
        &self,
        set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let entries = self.collect_sorted_by_address(|addr| match set {
            Some(set) => set.contains(addr),
            None => true,
        })?;
        let keys: Vec<i64> = entries
            .into_iter()
            .filter_map(|(_, rec)| match rec.get_key() {
                Field::Long(Some(v)) => Some(*v),
                _ => None,
            })
            .collect();
        Ok(Box::new(VecAddressKeyIterator::new(keys, forward)))
    }

    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        let entries = self.collect_sorted_by_address(|addr| {
            addr >= from_addr && addr.offset() < from_addr.offset() + length
        })?;
        let mut table = self.table.write().unwrap();
        for (addr, mut rec) in entries {
            table.delete_record(rec.get_key())?;
            let new_addr = to_addr.add_wrap(addr.offset() - from_addr.offset());
            let new_key = self.addr_map.get_key(&new_addr, true);
            rec.set_key(Field::Long(Some(new_key)));
            table.put_record(rec)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBHandle;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, KeyRange};

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
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
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

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap {
            space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
        })
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[test]
    fn create_and_get_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 0);

        adapter.create_record(0x1000, comments_db_adapter::EOL_COMMENT_COL, "hi").unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 1);

        let rec = adapter.get_record(0x1000).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(comments_db_adapter::EOL_COMMENT_COL),
            &Field::String(Some("hi".to_string()))
        );
        assert!(adapter.get_record(0x2000).unwrap().is_none());
    }

    #[test]
    fn get_records_are_address_sorted() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_record(0x3000, comments_db_adapter::EOL_COMMENT_COL, "c").unwrap();
        adapter.create_record(0x1000, comments_db_adapter::EOL_COMMENT_COL, "a").unwrap();
        adapter.create_record(0x2000, comments_db_adapter::EOL_COMMENT_COL, "b").unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut vals = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            if let Field::String(Some(s)) = rec.get_field(comments_db_adapter::EOL_COMMENT_COL) {
                vals.push(s.clone());
            }
        }
        assert_eq!(vals, vec!["a", "b", "c"]);
    }

    #[test]
    fn get_records_in_range_respects_at_start_direction() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_record(0x1000, comments_db_adapter::EOL_COMMENT_COL, "a").unwrap();
        adapter.create_record(0x2000, comments_db_adapter::EOL_COMMENT_COL, "b").unwrap();

        let space = space();
        let mut forward = adapter
            .get_records_in_range(&space.address(0x1000), &space.address(0x2000), true)
            .unwrap();
        let first = forward.next().unwrap().unwrap();
        assert_eq!(
            first.get_field(comments_db_adapter::EOL_COMMENT_COL),
            &Field::String(Some("a".to_string()))
        );

        let mut backward = adapter
            .get_records_in_range(&space.address(0x1000), &space.address(0x2000), false)
            .unwrap();
        let first_back = backward.next().unwrap().unwrap();
        assert_eq!(
            first_back.get_field(comments_db_adapter::EOL_COMMENT_COL),
            &Field::String(Some("b".to_string()))
        );
    }

    #[test]
    fn get_keys_bidirectional_cursor() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_record(0x1000, comments_db_adapter::EOL_COMMENT_COL, "a").unwrap();
        adapter.create_record(0x2000, comments_db_adapter::EOL_COMMENT_COL, "b").unwrap();

        let mut fwd = adapter.get_keys(None, true).unwrap();
        assert_eq!(fwd.next(), Some(0x1000));
        assert_eq!(fwd.next(), Some(0x2000));
        assert_eq!(fwd.next(), None);

        let mut bwd = adapter.get_keys(None, false).unwrap();
        assert_eq!(bwd.previous(), Some(0x2000));
        assert_eq!(bwd.previous(), Some(0x1000));
        assert_eq!(bwd.previous(), None);
    }

    #[test]
    fn delete_records_removes_only_in_range() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_record(0x1000, comments_db_adapter::EOL_COMMENT_COL, "a").unwrap();
        adapter.create_record(0x2000, comments_db_adapter::EOL_COMMENT_COL, "b").unwrap();
        adapter.create_record(0x3000, comments_db_adapter::EOL_COMMENT_COL, "c").unwrap();

        let space = space();
        let deleted = adapter
            .delete_records(&space.address(0x1500), &space.address(0x2500))
            .unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count().unwrap(), 2);
    }

    #[test]
    fn move_address_range_relocates_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_record(0x1000, comments_db_adapter::EOL_COMMENT_COL, "a").unwrap();

        let space = space();
        adapter
            .move_address_range(
                &space.address(0x1000),
                &space.address(0x5000),
                0x100,
                &crate::util::task::DummyMonitor,
            )
            .unwrap();

        assert!(adapter.get_record(0x1000).unwrap().is_none());
        let moved = adapter.get_record(0x5000).unwrap().expect("record should have moved");
        assert_eq!(
            moved.get_field(comments_db_adapter::EOL_COMMENT_COL),
            &Field::String(Some("a".to_string()))
        );
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(CommentsDBAdapterV1::new(&mut handle, addr_map(), false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn CommentsDBAdapter> =
            Box::new(CommentsDBAdapterV1::new(&mut handle, addr_map(), true).unwrap());
        assert_eq!(adapter.get_record_count().unwrap(), 0);
    }
}
