//! Port of `ghidra.program.database.symbol.EquateRefDBAdapterV1`.
//!
//! Implementation for version 1 (current) of the equate references table, backed by a live,
//! writable [`Table`].
//!
//! Also re-declares the `EquateRefDBAdapter.EQUATE_REFS_TABLE_NAME`/`REFS_SCHEMA`/column-index
//! constants locally, since
//! [`EquateRefDBAdapter`](crate::program::database::symbol::EquateRefDBAdapter)'s own port
//! intentionally left the table-layout constants out.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::symbol::{EquateRefDBAdapter, MoveAddressRangeError};
use crate::program::model::address::{Address, AddressSetView};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the equate references database table.
pub const EQUATE_REFS_TABLE_NAME: &str = "Equate References";
/// Column index of the referenced equate's ID. Mirrors `EquateRefDBAdapter.EQUATE_ID_COL`.
pub const EQUATE_ID_COL: usize = 0;
/// Column index of the reference's address (database-key encoding). Mirrors
/// `EquateRefDBAdapter.ADDR_COL`.
pub const ADDR_COL: usize = 1;
/// Column index of the reference's operand index. Mirrors `EquateRefDBAdapter.OP_INDEX_COL`.
pub const OP_INDEX_COL: usize = 2;
/// Column index of the reference's dynamic hash value. Mirrors `EquateRefDBAdapter.HASH_COL`.
pub const HASH_COL: usize = 3;
/// Schema version implemented by this adapter.
pub const CURRENT_VERSION: i32 = 1;

/// Build the current equate references table schema, as defined by
/// `EquateRefDBAdapter.REFS_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::Long,
            FieldType::Long,
            FieldType::Short,
            FieldType::Long,
        ],
        vec![
            "Equate ID".to_string(),
            "Equate Reference".to_string(),
            "Operand Index".to_string(),
            "Varnode Hash".to_string(),
        ],
        vec![],
    ))
}

/// Implementation for version 1 (current) of the equate references table.
///
/// Port of `ghidra.program.database.symbol.EquateRefDBAdapterV1`. Simplification: the Java
/// constructor also takes an `AddressMap`, used only by
/// `getIteratorForAddresses(Address[Range]/AddressSetView)`/`moveAddressRange` to translate
/// between `Address`es and the raw database-key encoding stored in `ADDR_COL`. Since the trait's
/// `create_reference`/other methods already take that encoding as a plain `i64` (the caller does
/// the translating), this port treats stored `ADDR_COL` values as directly comparable to
/// `Address::offset()` instead of holding an `AddressMap`, matching the simplification already
/// used by [`EquateRefDBAdapter`](crate::program::database::symbol::EquateRefDBAdapter)'s own
/// test mock.
pub struct EquateRefDBAdapterV1 {
    table: Arc<RwLock<Table>>,
}

impl EquateRefDBAdapterV1 {
    /// Constructor. If `create` is `true`, the equate references table is created, otherwise an
    /// existing table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table that is missing or whose
    /// schema version does not match [`CURRENT_VERSION`].
    pub fn new(handle: &mut DBHandle, create: bool) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(EQUATE_REFS_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(EQUATE_REFS_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {EQUATE_REFS_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != CURRENT_VERSION {
                if version < CURRENT_VERSION {
                    return Err(VersionException::with_upgradeable(true));
                }
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(EquateRefDBAdapterV1 { table })
    }

    /// Collects and sorts the distinct addresses (database-key encoding) satisfying `predicate`,
    /// backing the several `get_iterator_for_addresses*` methods. The Java adapter uses an
    /// `AddressIndexKeyIterator` (indexed lookup) for these; this port's `Table` has no
    /// secondary-index support, so this scans linearly instead. Same observable result, just
    /// O(n) rather than indexed.
    fn addresses_matching(&self, predicate: impl Fn(i64) -> bool) -> io::Result<Vec<i64>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut addrs = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(a) = rec.get_long(ADDR_COL) {
                if predicate(a) {
                    addrs.push(a);
                }
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        Ok(addrs)
    }
}

struct VecLongIterator {
    values: Vec<i64>,
    pos: isize,
}

impl VecLongIterator {
    fn new(values: Vec<i64>) -> Self {
        Self { values, pos: -1 }
    }
}

impl crate::framework::db::DBLongIterator for VecLongIterator {
    fn has_next(&mut self) -> io::Result<bool> {
        Ok(self.pos + 1 < self.values.len() as isize)
    }

    fn has_previous(&mut self) -> io::Result<bool> {
        Ok(self.pos >= 0)
    }

    fn next(&mut self) -> io::Result<i64> {
        let next = self.pos + 1;
        if next >= self.values.len() as isize {
            return Err(io::Error::new(io::ErrorKind::Other, "no next element"));
        }
        self.pos = next;
        Ok(self.values[self.pos as usize])
    }

    fn previous(&mut self) -> io::Result<i64> {
        if self.pos < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "no previous element"));
        }
        let val = self.values[self.pos as usize];
        self.pos -= 1;
        Ok(val)
    }

    fn delete(&mut self) -> io::Result<bool> {
        Ok(false)
    }
}

impl EquateRefDBAdapter for EquateRefDBAdapterV1 {
    fn create_reference(
        &mut self,
        addr: i64,
        op_index: i16,
        dynamic_hash: i64,
        equate_name_id: i64,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_long(ADDR_COL, addr);
        record.set_field(OP_INDEX_COL, Field::Short(Some(op_index)));
        record.set_long(HASH_COL, dynamic_hash);
        record.set_long(EQUATE_ID_COL, equate_name_id);
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such equate reference"))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
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
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_record_keys_for_addr(&self, addr: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(ADDR_COL) == Some(addr) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn get_record_keys_for_equate_id(&self, equate_id: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(EQUATE_ID_COL) == Some(equate_id) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }

    fn get_iterator_for_addresses(&self) -> io::Result<Box<dyn crate::framework::db::DBLongIterator>> {
        let addrs = self.addresses_matching(|_| true)?;
        Ok(Box::new(VecLongIterator::new(addrs)))
    }

    fn get_iterator_for_addresses_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> io::Result<Box<dyn crate::framework::db::DBLongIterator>> {
        let (start, end) = (start.offset(), end.offset());
        let addrs = self.addresses_matching(|a| a >= start && a <= end)?;
        Ok(Box::new(VecLongIterator::new(addrs)))
    }

    fn get_iterator_for_addresses_in_set(
        &self,
        set: &dyn AddressSetView,
    ) -> io::Result<Box<dyn crate::framework::db::DBLongIterator>> {
        let ranges: Vec<(i64, i64)> = set
            .address_ranges()
            .map(|r| (r.min_address().offset(), r.max_address().offset()))
            .collect();
        let addrs = self.addresses_matching(|a| ranges.iter().any(|(min, max)| a >= *min && a <= *max))?;
        Ok(Box::new(VecLongIterator::new(addrs)))
    }

    fn get_iterator_for_addresses_from(
        &self,
        start: &Address,
    ) -> io::Result<Box<dyn crate::framework::db::DBLongIterator>> {
        let start = start.offset();
        let addrs = self.addresses_matching(|a| a >= start)?;
        Ok(Box::new(VecLongIterator::new(addrs)))
    }

    fn remove_record(&mut self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        let from = from_addr.offset();
        let to = to_addr.offset();
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut updated = Vec::new();
        while let Some(mut rec) = iter.next()? {
            if let Some(a) = rec.get_long(ADDR_COL) {
                if a >= from && a < from + length {
                    rec.set_long(ADDR_COL, a - from + to);
                    updated.push(rec);
                }
            }
        }
        drop(iter);
        for rec in updated {
            table.put_record(rec)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBLongIterator;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn create_lookup_and_remove_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EquateRefDBAdapterV1::new(&mut handle, true).unwrap();

        let record = adapter.create_reference(0x1000, 0, 0, 42).unwrap();
        let key = record.get_key().get_long_value();

        assert_eq!(adapter.get_record_count(), 1);
        let keys_for_addr = adapter.get_record_keys_for_addr(0x1000).unwrap();
        assert_eq!(keys_for_addr.len(), 1);
        let keys_for_equate = adapter.get_record_keys_for_equate_id(42).unwrap();
        assert_eq!(keys_for_equate.len(), 1);

        let fetched = adapter.get_record(key).unwrap();
        assert_eq!(fetched.get_long(ADDR_COL), Some(0x1000));

        adapter.remove_record(key).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.get_record(key).is_err());
    }

    #[test]
    fn move_address_range_shifts_matching_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EquateRefDBAdapterV1::new(&mut handle, true).unwrap();
        adapter.create_reference(0x1000, 0, 0, 1).unwrap();
        adapter.create_reference(0x2000, 0, 0, 2).unwrap();

        adapter
            .move_address_range(&addr(0x1000), &addr(0x5000), 0x100, &DummyMonitor)
            .unwrap();

        let mut iter = adapter.get_iterator_for_addresses().unwrap();
        let mut seen = Vec::new();
        while iter.has_next().unwrap() {
            seen.push(iter.next().unwrap());
        }
        assert_eq!(seen, vec![0x2000, 0x5000]);
    }

    #[test]
    fn address_range_and_set_iteration() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = EquateRefDBAdapterV1::new(&mut handle, true).unwrap();
        adapter.create_reference(0x100, 0, 0, 1).unwrap();
        adapter.create_reference(0x200, 1, 7, 2).unwrap();
        adapter.create_reference(0x300, 0, 0, 3).unwrap();

        let mut ranged = adapter
            .get_iterator_for_addresses_in_range(&addr(0x150), &addr(0x250))
            .unwrap();
        let mut ranged_seen = Vec::new();
        while ranged.has_next().unwrap() {
            ranged_seen.push(ranged.next().unwrap());
        }
        assert_eq!(ranged_seen, vec![0x200]);

        let mut from = adapter.get_iterator_for_addresses_from(&addr(0x200)).unwrap();
        let mut from_seen = Vec::new();
        while from.has_next().unwrap() {
            from_seen.push(from.next().unwrap());
        }
        assert_eq!(from_seen, vec![0x200, 0x300]);

        let mut set = AddressSet::new();
        set.add_range(&addr(0x0), &addr(0x150));
        let mut in_set = adapter.get_iterator_for_addresses_in_set(&set).unwrap();
        let mut in_set_seen = Vec::new();
        while in_set.has_next().unwrap() {
            in_set_seen.push(in_set.next().unwrap());
        }
        assert_eq!(in_set_seen, vec![0x100]);
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = EquateRefDBAdapterV1::new(&mut handle, true).unwrap();
            adapter.create_reference(1, 0, 0, 1).unwrap();
        }
        let adapter = EquateRefDBAdapterV1::new(&mut handle, false).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(EquateRefDBAdapterV1::new(&mut handle, false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn EquateRefDBAdapter> =
            Box::new(EquateRefDBAdapterV1::new(&mut handle, true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}
