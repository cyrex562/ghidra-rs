//! Port of `ghidra.program.database.symbol.LabelHistoryAdapterV0`.
//!
//! Version 0 of the Label History adapter, backed by a live, writable [`Table`].
//!
//! Also re-declares the `LabelHistoryAdapter.LABEL_HISTORY_TABLE_NAME`/column-index constants
//! locally (matching the module's own `pub` re-declarations), since
//! [`LabelHistoryAdapter`](crate::program::database::symbol::LabelHistoryAdapter)'s own port
//! already exposes these as `pub const`s, reused here directly.

use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::AddressMap;
use crate::program::database::symbol::label_history_adapter::{
    LabelHistoryRangeError, HISTORY_ACTION_COL, HISTORY_ADDR_COL, HISTORY_DATE_COL,
    HISTORY_LABEL_COL, HISTORY_USER_COL, LABEL_HISTORY_TABLE_NAME,
};
use crate::program::database::symbol::LabelHistoryAdapter;
use crate::program::model::address::Address;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;
use crate::util::SystemUtilities;

/// Schema version implemented by this adapter.
pub const CURRENT_VERSION: i32 = 0;

/// Build the label history table schema, as defined by `LabelHistoryAdapter.LABEL_HISTORY_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::Long,
            FieldType::Byte,
            FieldType::String,
            FieldType::String,
            FieldType::Long,
        ],
        vec![
            "Address".to_string(),
            "Action".to_string(),
            "Labels".to_string(),
            "User".to_string(),
            "Date".to_string(),
        ],
        vec![],
    ))
}

/// Version 0 of the Label History adapter.
///
/// Port of `ghidra.program.database.symbol.LabelHistoryAdapterV0`. The upgrade helper
/// (`LabelHistoryAdapterV0.upgrade`) is left out, matching the convention already established for
/// the `VariableStorageDBAdapter`/`EquateDBAdapter`/`EquateRefDBAdapter` families' version-select
/// logic living with whichever concrete type owns adapter selection.
pub struct LabelHistoryAdapterV0 {
    table: Arc<RwLock<Table>>,
    user_name: String,
}

impl LabelHistoryAdapterV0 {
    /// Constructs a new adapter. If `create` is `true`, the label history table is created,
    /// otherwise an existing table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table that is missing or whose
    /// schema version does not match [`CURRENT_VERSION`].
    pub fn new(handle: &mut DBHandle, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(LABEL_HISTORY_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(LABEL_HISTORY_TABLE_NAME).ok_or_else(|| {
                VersionException::with_upgradeable(true)
            })?;
            if table.read().unwrap().get_schema().get_version() != CURRENT_VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(LabelHistoryAdapterV0 {
            table,
            user_name: SystemUtilities::get_user_name(),
        })
    }
}

impl LabelHistoryAdapter for LabelHistoryAdapterV0 {
    fn create_record(&mut self, addr: i64, action_id: i8, label_str: &str) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_long(HISTORY_ADDR_COL, addr);
        record.set_byte(HISTORY_ACTION_COL, action_id);
        record.set_string(HISTORY_LABEL_COL, Some(label_str.to_string()));
        record.set_string(HISTORY_USER_COL, Some(self.user_name.clone()));
        record.set_long(
            HISTORY_DATE_COL,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
        );
        table.put_record(record)
    }

    fn get_records_by_address(&self, addr: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        // The Java adapter uses an indexed lookup (`table.indexIterator`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(HISTORY_ADDR_COL) == Some(addr) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
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

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn move_address(&mut self, old_addr: i64, new_addr: i64) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_update = Vec::new();
        while let Some(mut rec) = iter.next()? {
            if rec.get_long(HISTORY_ADDR_COL) == Some(old_addr) {
                rec.set_long(HISTORY_ADDR_COL, new_addr);
                to_update.push(rec);
            }
        }
        drop(iter);
        for rec in to_update {
            table.put_record(rec)?;
        }
        Ok(())
    }

    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        _addr_map: &dyn AddressMap,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), LabelHistoryRangeError> {
        // Simplification: the Java version threads its `AddressMap` through
        // `DatabaseTableUtils.updateIndexedAddressField`, which translates the raw `ADDR_COL`
        // values through the map on each comparison. Like the sibling adapters in this family
        // (`EquateRefDBAdapterV1`), this port treats the stored column values as directly
        // comparable to `Address::offset()` instead.
        let from = from_addr.offset();
        let to = to_addr.offset();
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_update = Vec::new();
        while let Some(mut rec) = iter.next()? {
            if let Some(a) = rec.get_long(HISTORY_ADDR_COL) {
                if a >= from && a < from + length {
                    rec.set_long(HISTORY_ADDR_COL, a - from + to);
                    to_update.push(rec);
                }
            }
        }
        drop(iter);
        for rec in to_update {
            table.put_record(rec)?;
        }
        Ok(())
    }

    fn delete_address_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        _addr_map: &dyn AddressMap,
        do_not_delete: Option<&BTreeSet<Address>>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), LabelHistoryRangeError> {
        let start = start_addr.offset();
        let end = end_addr.offset();
        let space = start_addr.space().clone();
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_delete = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(a) = rec.get_long(HISTORY_ADDR_COL) {
                if a < start || a > end {
                    continue;
                }
                let keep = do_not_delete
                    .map(|set| set.contains(&space.address(a)))
                    .unwrap_or(false);
                if !keep {
                    to_delete.push(rec.get_key().clone());
                }
            }
        }
        drop(iter);
        for key in to_delete {
            table.delete_record(&key)?;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    struct NoopAddressMap {
        base: Address,
    }
    impl AddressMap for NoopAddressMap {
        fn get_key(&self, _addr: &Address, _create: bool) -> i64 {
            0
        }
        fn get_absolute_encoding(&self, _addr: &Address, _create: bool) -> i64 {
            0
        }
        fn find_key_range(
            &self,
            _key_range_list: &[crate::program::model::address::KeyRange],
            _addr: Option<&Address>,
        ) -> i32 {
            -1
        }
        fn decode_address(&self, _value: i64) -> Address {
            self.base.clone()
        }
        fn get_address_factory(
            &self,
        ) -> Option<std::sync::Arc<dyn crate::program::model::address::AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<crate::program::model::address::KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn crate::program::model::address::AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<crate::program::model::address::KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(NoopAddressMap {
                base: self.base.clone(),
            })
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            self.base.clone()
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn create_and_read_records_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = LabelHistoryAdapterV0::new(&mut handle, true).unwrap();
        adapter.create_record(0x1000, 0, "foo").unwrap();
        adapter.create_record(0x1000, 1, "bar").unwrap();
        adapter.create_record(0x2000, 0, "baz").unwrap();

        assert_eq!(adapter.get_record_count(), 3);

        let mut seen = 0;
        {
            let mut iter = adapter.get_records_by_address(0x1000).unwrap();
            while iter.next().unwrap().is_some() {
                seen += 1;
            }
        }
        assert_eq!(seen, 2);

        let mut all_seen = 0;
        {
            let mut iter = adapter.get_all_records().unwrap();
            while let Some(rec) = iter.next().unwrap() {
                assert!(rec.get_string(HISTORY_USER_COL).is_some());
                all_seen += 1;
            }
        }
        assert_eq!(all_seen, 3);
    }

    #[test]
    fn move_address_relocates_matching_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = LabelHistoryAdapterV0::new(&mut handle, true).unwrap();
        adapter.create_record(0x1000, 0, "foo").unwrap();
        adapter.create_record(0x1000, 1, "bar").unwrap();

        adapter.move_address(0x1000, 0x1500).unwrap();

        assert!(adapter
            .get_records_by_address(0x1000)
            .unwrap()
            .next()
            .unwrap()
            .is_none());
        let mut moved = 0;
        {
            let mut iter = adapter.get_records_by_address(0x1500).unwrap();
            while iter.next().unwrap().is_some() {
                moved += 1;
            }
        }
        assert_eq!(moved, 2);
    }

    #[test]
    fn move_address_range_shifts_matching_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = LabelHistoryAdapterV0::new(&mut handle, true).unwrap();
        adapter.create_record(0x1000, 0, "keep").unwrap();
        adapter.create_record(0x2000, 0, "outside").unwrap();

        let addr_map = NoopAddressMap { base: addr(0) };
        adapter
            .move_address_range(&addr(0x1000), &addr(0x5000), 0x100, &addr_map, &DummyMonitor)
            .unwrap();

        assert!(adapter
            .get_records_by_address(0x1000)
            .unwrap()
            .next()
            .unwrap()
            .is_none());
        assert!(adapter
            .get_records_by_address(0x5000)
            .unwrap()
            .next()
            .unwrap()
            .is_some());
        assert!(adapter
            .get_records_by_address(0x2000)
            .unwrap()
            .next()
            .unwrap()
            .is_some());
    }

    #[test]
    fn delete_address_range_respects_do_not_delete_set() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = LabelHistoryAdapterV0::new(&mut handle, true).unwrap();
        adapter.create_record(0x1000, 0, "keep").unwrap();
        adapter.create_record(0x1010, 0, "drop").unwrap();
        assert_eq!(adapter.get_record_count(), 2);

        let addr_map = NoopAddressMap { base: addr(0) };
        let mut keep_set = BTreeSet::new();
        keep_set.insert(addr(0x1000));

        adapter
            .delete_address_range(&addr(0x1000), &addr(0x1020), &addr_map, Some(&keep_set), &DummyMonitor)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter
            .get_records_by_address(0x1000)
            .unwrap()
            .next()
            .unwrap()
            .is_some());
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(LabelHistoryAdapterV0::new(&mut handle, false).is_err());
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = LabelHistoryAdapterV0::new(&mut handle, true).unwrap();
            adapter.create_record(1, 0, "x").unwrap();
        }
        let adapter = LabelHistoryAdapterV0::new(&mut handle, false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn LabelHistoryAdapter> =
            Box::new(LabelHistoryAdapterV0::new(&mut handle, true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}
