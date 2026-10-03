//! Port of `ghidra.program.database.code.InstDBAdapterV0`.
//!
//! Version 0's on-disk schema only has the `Proto ID` column (no `Flags`); this adapter reads
//! through that legacy table and converts each record into the current (version 1) record shape
//! on the fly, with `Flags` always `0`, exactly as Java's `adaptRecord` does. Records are
//! read-only: every mutating method is rejected with an `Unsupported` error, matching Java's
//! `UnsupportedOperationException`s.
//!
//! Java decodes addresses through `addrMap.getOldAddressMap()` (the pre-upgrade address
//! encoding), not the current map -- this port does the same.
//!
//! Where Java uses `AddressKeyIterator`/`AddressKeyRecordIterator` (backed by `Table`'s secondary
//! indexes), this port's [`Table`] has no secondary-index support, so both scan linearly instead,
//! matching the convention already established by `InstDBAdapterV1` and others in this DB-adapter
//! family.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::inst_db_adapter::{
    self, InstDBAdapter, MoveAddressRangeError, FLAGS_COL, INSTRUCTION_TABLE_NAME, PROTO_ID_COL,
};
use crate::program::database::map::AddressMap;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Legacy (version 0) column index for the prototype ID (the table's only column).
const V0_PROTO_ID_COLUMN: usize = 0;

/// Converts a legacy (version 0) record -- `[Proto ID]` -- into the current (version 1) record
/// shape, `Flags` always `0`. Stands in for `InstDBAdapterV0.adaptRecord(DBRecord)`.
fn adapt_record(rec_v0: &DBRecord) -> DBRecord {
    let mut record = DBRecord::new(inst_db_adapter::schema(), rec_v0.get_key().clone());
    record.set_field(PROTO_ID_COL, rec_v0.get_field(V0_PROTO_ID_COLUMN).clone());
    record.set_field(FLAGS_COL, Field::Byte(Some(0)));
    record
}

/// A `RecordIterator` over an eagerly-collected, already-converted set of records.
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

/// A bidirectional cursor over a sorted set of (legacy) address keys. See
/// [`InstDBAdapterV1`](crate::program::database::code::inst_db_adapter_v1::InstDBAdapterV1)'s
/// module docs for why this models both directions while [`RecordIterator`] does not.
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

/// Version 0 adapter for the instruction table.
///
/// Port of `ghidra.program.database.code.InstDBAdapterV0`. See the module docs for the
/// record-conversion and read-only deviations.
pub struct InstDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl InstDBAdapterV0 {
    /// Constructs a new Version 0 instruction adapter, opening the existing instruction table
    /// from `handle`. `addr_map` is Java's post-upgrade map; this constructor takes its
    /// [`AddressMap::get_old_address_map`] internally, mirroring `addrMap.getOldAddressMap()`.
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table does not exist or is not schema version 0.
    pub fn new(
        handle: &crate::framework::db::DBHandle,
        addr_map: &dyn AddressMap,
    ) -> Result<Self, VersionException> {
        let table = handle.get_table(INSTRUCTION_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {INSTRUCTION_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(VersionException::with_version_indicator(
                VersionException::NEWER_VERSION,
                false,
            ));
        }
        Ok(InstDBAdapterV0 {
            table,
            addr_map: Arc::from(addr_map.get_old_address_map()),
        })
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
                    entries.push((addr, adapt_record(&rec)));
                }
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Cannot modify records with old schema")
}

impl InstDBAdapter for InstDBAdapterV0 {
    fn create_instruction(&mut self, _addr: i64, _proto_id: i32, _flags: u8) -> io::Result<()> {
        Err(unsupported())
    }

    fn update_flags(&mut self, _addr: i64, _flags: u8) -> io::Result<()> {
        Err(unsupported())
    }

    fn delete_record(&mut self, _addr: i64) -> io::Result<()> {
        Err(unsupported())
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
        Ok(self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(addr)))?
            .map(|rec| adapt_record(&rec)))
    }

    fn get_record(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
        let key = self.addr_map.get_key(addr, false);
        self.get_record_by_key(key)
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

    fn delete_records(&mut self, _start: &Address, _end: &Address) -> io::Result<bool> {
        Err(unsupported())
    }

    fn put_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
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
        _from_addr: &Address,
        _to_addr: &Address,
        _length: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        Err(MoveAddressRangeError::Io(unsupported()))
    }

    fn delete_all(&mut self) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, FieldType, Schema};
    use crate::program::model::address::{AddressSpace, AddressSpaceType, KeyRange};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Address".to_string(),
            vec![FieldType::Int],
            vec!["Proto ID".to_string()],
            vec![],
        ))
    }

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

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn setup_table(handle: &mut DBHandle, key: i64, proto_id: i32) {
        let table = handle
            .create_table(INSTRUCTION_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut record = DBRecord::new(v0_schema(), Field::Long(Some(key)));
        record.set_field(V0_PROTO_ID_COLUMN, Field::Int(Some(proto_id)));
        table.write().unwrap().put_record(record).unwrap();
    }

    #[test]
    fn get_record_converts_legacy_column_and_zeroes_flags() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x1000, 42);
        let addr_map = IdentityAddressMap { space: space() };
        let adapter = InstDBAdapterV0::new(&handle, &addr_map).unwrap();

        let rec = adapter
            .get_record(&space().address(0x1000))
            .unwrap()
            .expect("record should exist");
        assert_eq!(rec.get_field(PROTO_ID_COL), &Field::Int(Some(42)));
        assert_eq!(rec.get_field(FLAGS_COL), &Field::Byte(Some(0)));
    }

    #[test]
    fn mutations_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x1000, 1);
        let addr_map = IdentityAddressMap { space: space() };
        let mut adapter = InstDBAdapterV0::new(&handle, &addr_map).unwrap();

        assert_eq!(
            adapter.create_instruction(0x2000, 2, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(adapter.delete_all().unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(adapter.update_flags(0x1000, 1).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn get_records_converts_every_record_in_address_order() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x2000, 2);
        {
            let table = handle.get_table(INSTRUCTION_TABLE_NAME).unwrap();
            let mut record = DBRecord::new(v0_schema(), Field::Long(Some(0x1000)));
            record.set_field(V0_PROTO_ID_COLUMN, Field::Int(Some(1)));
            table.write().unwrap().put_record(record).unwrap();
        }
        let addr_map = IdentityAddressMap { space: space() };
        let adapter = InstDBAdapterV0::new(&handle, &addr_map).unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut proto_ids = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            if let Field::Int(Some(v)) = rec.get_field(PROTO_ID_COL) {
                proto_ids.push(*v);
            }
            assert_eq!(rec.get_field(FLAGS_COL), &Field::Byte(Some(0)));
        }
        assert_eq!(proto_ids, vec![1, 2]);
    }

    #[test]
    fn opening_wrong_version_table_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(INSTRUCTION_TABLE_NAME.to_string(), inst_db_adapter::schema())
            .unwrap();
        let addr_map = IdentityAddressMap { space: space() };
        assert!(InstDBAdapterV0::new(&handle, &addr_map).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x1000, 1);
        let addr_map = IdentityAddressMap { space: space() };
        let adapter: Box<dyn InstDBAdapter> =
            Box::new(InstDBAdapterV0::new(&handle, &addr_map).unwrap());
        assert_eq!(adapter.get_record_count().unwrap(), 1);
    }
}
