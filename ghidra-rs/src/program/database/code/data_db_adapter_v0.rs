//! Port of `ghidra.program.database.code.DataDBAdapterV0`.
//!
//! Where Java uses `AddressKeyIterator`/`AddressKeyRecordIterator`/`AddressRecordDeleter`/
//! `DatabaseTableUtils.updateAddressKey` -- all backed by `Table`'s secondary indexes -- this
//! port's [`Table`] has no secondary-index support, so every such lookup scans linearly instead,
//! decoding each candidate record's address through the real `AddressMap` and filtering/sorting
//! in memory. Same observable result, just O(n) rather than indexed (matching the convention
//! already established by `CommentsDBAdapterV1`/`CompositeDBAdapterV5V6` and others in this
//! DB-adapter family).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::data_db_adapter::{
    self, DataDBAdapter, MoveAddressRangeError, DATA_TABLE_NAME, DATA_TYPE_ID_COL,
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

/// A bidirectional cursor over a sorted set of address keys. Stands in for
/// `ghidra.program.database.map.AddressKeyIterator`.
struct VecAddressKeyIterator {
    keys: Vec<i64>,
    pos: usize,
}

impl VecAddressKeyIterator {
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

/// Version 0 implementation for the Data table.
///
/// Port of `ghidra.program.database.code.DataDBAdapterV0`. See the module docs for the
/// indexed-lookup deviations.
pub struct DataDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl DataDBAdapterV0 {
    /// Constructs a new Version 0 data adapter. `addr_map` is used to generate keys for
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
                .create_table(DATA_TABLE_NAME.to_string(), data_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(DATA_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {DATA_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != 0 {
                return Err(VersionException::with_version_indicator(
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
            table
        };
        Ok(DataDBAdapterV0 { table, addr_map })
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

impl DataDBAdapter for DataDBAdapterV0 {
    fn get_record_at_or_after(&self, start: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|addr| addr >= start)?;
        Ok(entries.into_iter().next().map(|(_, rec)| rec))
    }

    fn get_record_after(&self, start: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|addr| addr > start)?;
        Ok(entries.into_iter().next().map(|(_, rec)| rec))
    }

    fn get_record(&self, start: &Address) -> io::Result<Option<DBRecord>> {
        let key = self.addr_map.get_key(start, false);
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn get_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn get_record_before(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|a| a < addr)?;
        Ok(entries.into_iter().next_back().map(|(_, rec)| rec))
    }

    fn get_records_from(
        &self,
        addr: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let entries = if forward {
            self.collect_sorted_by_address(|a| a >= addr)?
        } else {
            let mut e = self.collect_sorted_by_address(|a| a <= addr)?;
            e.reverse();
            e
        };
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
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

    fn delete_record(&mut self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

    fn create_data(&mut self, addr: &Address, data_type_id: i64) -> io::Result<DBRecord> {
        let key = self.addr_map.get_key(addr, true);
        let mut record = DBRecord::new(data_db_adapter::schema(), Field::Long(Some(key)));
        record.set_field(DATA_TYPE_ID_COL, Field::Long(Some(data_type_id)));
        self.table.write().unwrap().put_record(record.clone())?;
        Ok(record)
    }

    fn get_record_count(&self) -> io::Result<i32> {
        Ok(self.table.read().unwrap().get_record_count() as i32)
    }

    fn get_record_at_or_before(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|a| a <= addr)?;
        Ok(entries.into_iter().next_back().map(|(_, rec)| rec))
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

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let entries = self.collect_sorted_by_address(|_| true)?;
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
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

    fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
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

    fn get_records_in_set(
        &self,
        set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let mut entries = self.collect_sorted_by_address(|addr| match set {
            Some(set) => set.contains(addr),
            None => true,
        })?;
        if !forward {
            entries.reverse();
        }
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
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
        let mut adapter = DataDBAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        let addr1 = space.address(0x1000);

        assert_eq!(adapter.get_record_count().unwrap(), 0);
        adapter.create_data(&addr1, 7).unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 1);

        let rec = adapter.get_record(&addr1).unwrap().expect("record should exist");
        assert_eq!(rec.get_field(DATA_TYPE_ID_COL), &Field::Long(Some(7)));

        let by_key = adapter.get_record_by_key(addr1.offset()).unwrap().unwrap();
        assert_eq!(by_key.get_field(DATA_TYPE_ID_COL), &Field::Long(Some(7)));
    }

    #[test]
    fn navigation_before_after_and_at_or() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = DataDBAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        adapter.create_data(&space.address(0x1000), 1).unwrap();
        adapter.create_data(&space.address(0x2000), 2).unwrap();

        let addr15 = space.address(0x1500);
        let at_or_after = adapter.get_record_at_or_after(&addr15).unwrap().unwrap();
        assert_eq!(at_or_after.get_key(), &Field::Long(Some(0x2000)));

        let at_or_before = adapter.get_record_at_or_before(&addr15).unwrap().unwrap();
        assert_eq!(at_or_before.get_key(), &Field::Long(Some(0x1000)));

        let after = adapter.get_record_after(&space.address(0x1000)).unwrap().unwrap();
        assert_eq!(after.get_key(), &Field::Long(Some(0x2000)));

        let before = adapter.get_record_before(&space.address(0x2000)).unwrap().unwrap();
        assert_eq!(before.get_key(), &Field::Long(Some(0x1000)));
    }

    #[test]
    fn get_records_from_respects_direction() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = DataDBAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        adapter.create_data(&space.address(0x1000), 1).unwrap();
        adapter.create_data(&space.address(0x2000), 2).unwrap();
        adapter.create_data(&space.address(0x3000), 3).unwrap();

        let mut fwd = adapter.get_records_from(&space.address(0x2000), true).unwrap();
        let mut fwd_keys = Vec::new();
        while let Some(rec) = fwd.next().unwrap() {
            fwd_keys.push(rec.get_key().clone());
        }
        assert_eq!(fwd_keys, vec![Field::Long(Some(0x2000)), Field::Long(Some(0x3000))]);

        let mut bwd = adapter.get_records_from(&space.address(0x2000), false).unwrap();
        let mut bwd_keys = Vec::new();
        while let Some(rec) = bwd.next().unwrap() {
            bwd_keys.push(rec.get_key().clone());
        }
        assert_eq!(bwd_keys, vec![Field::Long(Some(0x2000)), Field::Long(Some(0x1000))]);
    }

    #[test]
    fn move_address_range_relocates_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = DataDBAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        adapter.create_data(&space.address(0x1000), 9).unwrap();

        adapter
            .move_address_range(
                &space.address(0x1000),
                &space.address(0x5000),
                0x100,
                &crate::util::task::DummyMonitor,
            )
            .unwrap();

        assert!(adapter.get_record(&space.address(0x1000)).unwrap().is_none());
        let moved = adapter.get_record(&space.address(0x5000)).unwrap().expect("should have moved");
        assert_eq!(moved.get_field(DATA_TYPE_ID_COL), &Field::Long(Some(9)));
    }

    #[test]
    fn delete_record_and_delete_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = DataDBAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        adapter.create_data(&space.address(0x1000), 1).unwrap();
        adapter.create_data(&space.address(0x2000), 2).unwrap();

        adapter.delete_record(0x1000).unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 1);

        adapter.create_data(&space.address(0x1000), 1).unwrap();
        let deleted = adapter
            .delete_records(&space.address(0x1000), &space.address(0x1500))
            .unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count().unwrap(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(DataDBAdapterV0::new(&mut handle, addr_map(), false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn DataDBAdapter> =
            Box::new(DataDBAdapterV0::new(&mut handle, addr_map(), true).unwrap());
        assert_eq!(adapter.get_record_count().unwrap(), 0);
    }
}
