//! Port of `ghidra.program.database.code.InstDBAdapterV1`.
//!
//! Where Java uses `AddressKeyIterator`/`AddressKeyRecordIterator`/`AddressRecordDeleter`/
//! `DatabaseTableUtils.updateAddressKey` -- all backed by `Table`'s secondary indexes -- this
//! port's [`Table`] has no secondary-index support, so every such lookup scans linearly instead,
//! decoding each candidate record's address through the real `AddressMap` and filtering/sorting
//! in memory. Same observable result, just O(n) rather than indexed (matching the convention
//! already established by `DataDBAdapterV0`/`CommentsDBAdapterV1` and others in this DB-adapter
//! family).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::inst_db_adapter::{
    self, InstDBAdapter, MoveAddressRangeError, CURRENT_VERSION, FLAGS_COL, INSTRUCTION_TABLE_NAME,
    PROTO_ID_COL,
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

/// Version 1 (current) adapter for the instruction table.
///
/// Port of `ghidra.program.database.code.InstDBAdapterV1`. See the module docs for the
/// indexed-lookup deviations.
pub struct InstDBAdapterV1 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl InstDBAdapterV1 {
    /// Constructs a new Version 1 instruction adapter. `addr_map` is used to generate keys for
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
                .create_table(INSTRUCTION_TABLE_NAME.to_string(), inst_db_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(INSTRUCTION_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {INSTRUCTION_TABLE_NAME}"))
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
        Ok(InstDBAdapterV1 { table, addr_map })
    }

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

impl InstDBAdapter for InstDBAdapterV1 {
    fn create_instruction(&mut self, addr: i64, proto_id: i32, flags: u8) -> io::Result<()> {
        let mut record = DBRecord::new(inst_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_field(PROTO_ID_COL, Field::Int(Some(proto_id)));
        record.set_field(FLAGS_COL, Field::Byte(Some(flags as i8)));
        self.table.write().unwrap().put_record(record)
    }

    fn update_flags(&mut self, addr: i64, flags: u8) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        if let Some(mut rec) = table.get_record(&Field::Long(Some(addr)))? {
            rec.set_field(FLAGS_COL, Field::Byte(Some(flags as i8)));
            table.put_record(rec)?;
        }
        Ok(())
    }

    fn delete_record(&mut self, addr: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(addr)))?;
        Ok(())
    }

    fn get_record_at_or_after(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|a| a >= addr)?;
        Ok(entries.into_iter().next().map(|(_, rec)| rec))
    }

    fn get_record_after(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|a| a > addr)?;
        Ok(entries.into_iter().next().map(|(_, rec)| rec))
    }

    fn get_record_by_key(&self, addr: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(addr)))
    }

    fn get_record(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let key = self.addr_map.get_key(addr, false);
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    fn get_record_before(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let entries = self.collect_sorted_by_address(|a| a < addr)?;
        Ok(entries.into_iter().next_back().map(|(_, rec)| rec))
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

    fn get_keys(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let entries = self.collect_sorted_by_address(|addr| addr_set.contains(addr))?;
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
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let mut entries = self.collect_sorted_by_address(|addr| set.contains(addr))?;
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

    fn delete_all(&mut self) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            keys.push(rec.get_key().clone());
        }
        drop(iter);
        for key in keys {
            table.delete_record(&key)?;
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
        let mut adapter = InstDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        let addr1 = space.address(0x1000);

        assert_eq!(adapter.get_record_count().unwrap(), 0);
        adapter.create_instruction(addr1.offset(), 7, 0x01).unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 1);

        let rec = adapter.get_record(&addr1).unwrap().expect("record should exist");
        assert_eq!(rec.get_field(PROTO_ID_COL), &Field::Int(Some(7)));
        assert_eq!(rec.get_field(FLAGS_COL), &Field::Byte(Some(0x01)));
    }

    #[test]
    fn update_flags_modifies_existing_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = InstDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_instruction(0x1000, 5, 0x00).unwrap();

        adapter.update_flags(0x1000, 0x7f).unwrap();
        let rec = adapter.get_record_by_key(0x1000).unwrap().unwrap();
        assert_eq!(rec.get_field(FLAGS_COL), &Field::Byte(Some(0x7f)));
        assert_eq!(rec.get_field(PROTO_ID_COL), &Field::Int(Some(5)));
    }

    #[test]
    fn navigation_before_after_and_at_or() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = InstDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        adapter.create_instruction(0x1000, 1, 0).unwrap();
        adapter.create_instruction(0x2000, 2, 0).unwrap();

        let addr15 = space.address(0x1500);
        assert_eq!(
            adapter.get_record_at_or_after(&addr15).unwrap().unwrap().get_key(),
            &Field::Long(Some(0x2000))
        );
        assert_eq!(
            adapter.get_record_at_or_before(&addr15).unwrap().unwrap().get_key(),
            &Field::Long(Some(0x1000))
        );
    }

    #[test]
    fn move_address_range_and_delete_all() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = InstDBAdapterV1::new(&mut handle, addr_map(), true).unwrap();
        let space = space();
        adapter.create_instruction(0x1000, 9, 0).unwrap();

        adapter
            .move_address_range(
                &space.address(0x1000),
                &space.address(0x5000),
                0x100,
                &crate::util::task::DummyMonitor,
            )
            .unwrap();
        assert!(adapter.get_record(&space.address(0x1000)).unwrap().is_none());
        assert!(adapter.get_record(&space.address(0x5000)).unwrap().is_some());

        adapter.delete_all().unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 0);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(InstDBAdapterV1::new(&mut handle, addr_map(), false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn InstDBAdapter> =
            Box::new(InstDBAdapterV1::new(&mut handle, addr_map(), true).unwrap());
        assert_eq!(adapter.get_record_count().unwrap(), 0);
    }
}
