//! Port of `ghidra.program.database.symbol.EquateRefDBAdapterV0`.
//!
//! Read-only implementation for version 0 of the equate references table: version 0 records only
//! have three columns (no dynamic-hash column), so every record this adapter returns is converted
//! on the fly into the current (V1) four-column layout, with `HASH_COL` defaulted to `0`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBLongIterator, DBRecord, Field, RecordIterator, Table};
use crate::program::database::symbol::equate_ref_db_adapter_v1::{
    self, ADDR_COL, EQUATE_ID_COL, HASH_COL, OP_INDEX_COL,
};
use crate::program::database::symbol::{EquateRefDBAdapter, MoveAddressRangeError};
use crate::program::model::address::{Address, AddressSetView};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the equate references database table (shared with [`EquateRefDBAdapterV1`](crate::program::database::symbol::EquateRefDBAdapterV1)).
pub const EQUATE_REFS_TABLE_NAME: &str = equate_ref_db_adapter_v1::EQUATE_REFS_TABLE_NAME;

/// Column index of the referenced equate's ID in the version 0 record layout.
pub const V0_EQUATE_ID_COL: usize = 0;
/// Column index of the reference's address in the version 0 record layout.
pub const V0_ADDR_COL: usize = 1;
/// Column index of the reference's operand index in the version 0 record layout.
pub const V0_OP_INDEX_COL: usize = 2;

fn convert_v0_record(record: &DBRecord) -> DBRecord {
    let mut converted = DBRecord::new(equate_ref_db_adapter_v1::schema(), record.get_key().clone());
    converted.set_long(EQUATE_ID_COL, record.get_long(V0_EQUATE_ID_COL).unwrap_or_default());
    converted.set_long(ADDR_COL, record.get_long(V0_ADDR_COL).unwrap_or_default());
    if let Field::Short(op_index) = record.get_field(V0_OP_INDEX_COL) {
        converted.set_field(OP_INDEX_COL, Field::Short(*op_index));
    }
    converted.set_long(HASH_COL, 0);
    converted
}

/// Read-only implementation for version 0 of the equate references table.
///
/// Port of `ghidra.program.database.symbol.EquateRefDBAdapterV0`.
pub struct EquateRefDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl EquateRefDBAdapterV0 {
    /// Opens an existing version 0 equate references table.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing or its schema version is not 0.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(EQUATE_REFS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {EQUATE_REFS_TABLE_NAME}"))
        })?;
        if table.read().unwrap().get_schema().get_version() != 0 {
            return Err(VersionException::with_upgradeable(false));
        }
        Ok(EquateRefDBAdapterV0 { table })
    }
}

impl EquateRefDBAdapter for EquateRefDBAdapterV0 {
    fn create_reference(
        &mut self,
        _addr: i64,
        _op_index: i16,
        _dynamic_hash: i64,
        _equate_name_id: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "version 0 equate references table is read-only",
        ))
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        let record = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such equate reference"))?;
        Ok(convert_v0_record(&record))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(convert_v0_record(&rec));
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
            if rec.get_long(V0_ADDR_COL) == Some(addr) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }

    fn update_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "version 0 equate references table is read-only",
        ))
    }

    fn get_record_keys_for_equate_id(&self, equate_id: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut keys = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(V0_EQUATE_ID_COL) == Some(equate_id) {
                keys.push(rec.get_key().clone());
            }
        }
        Ok(keys)
    }

    fn get_iterator_for_addresses(&self) -> io::Result<Box<dyn DBLongIterator>> {
        self.get_iterator_for_addresses_matching(|_| true)
    }

    fn get_iterator_for_addresses_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> io::Result<Box<dyn DBLongIterator>> {
        let (start, end) = (start.offset(), end.offset());
        self.get_iterator_for_addresses_matching(move |a| a >= start && a <= end)
    }

    fn get_iterator_for_addresses_in_set(
        &self,
        set: &dyn AddressSetView,
    ) -> io::Result<Box<dyn DBLongIterator>> {
        let ranges: Vec<(i64, i64)> = set
            .address_ranges()
            .map(|r| (r.min_address().offset(), r.max_address().offset()))
            .collect();
        self.get_iterator_for_addresses_matching(move |a| {
            ranges.iter().any(|(min, max)| a >= *min && a <= *max)
        })
    }

    fn get_iterator_for_addresses_from(&self, start: &Address) -> io::Result<Box<dyn DBLongIterator>> {
        let start = start.offset();
        self.get_iterator_for_addresses_matching(move |a| a >= start)
    }

    fn remove_record(&mut self, _key: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "version 0 equate references table is read-only",
        ))
    }

    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        Err(MoveAddressRangeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "version 0 equate references table is read-only",
        )))
    }
}

struct VecLongIterator {
    values: Vec<i64>,
    pos: isize,
}

impl DBLongIterator for VecLongIterator {
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

impl EquateRefDBAdapterV0 {
    fn get_iterator_for_addresses_matching(
        &self,
        predicate: impl Fn(i64) -> bool,
    ) -> io::Result<Box<dyn DBLongIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut addrs = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(a) = rec.get_long(V0_ADDR_COL) {
                if predicate(a) {
                    addrs.push(a);
                }
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        Ok(Box::new(VecLongIterator { values: addrs, pos: -1 }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Short],
            vec![
                "Equate ID".to_string(),
                "Equate Reference".to_string(),
                "Operand Index".to_string(),
            ],
            vec![],
        ))
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn setup_handle() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(EQUATE_REFS_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut table = table.write().unwrap();
        for (equate_id, addr, op_index) in [(1i64, 0x1000i64, 0i16), (2, 0x2000, 1)] {
            let key = table.get_next_key();
            let mut record = DBRecord::new(v0_schema(), Field::Long(Some(key)));
            record.set_long(V0_EQUATE_ID_COL, equate_id);
            record.set_long(V0_ADDR_COL, addr);
            record.set_field(V0_OP_INDEX_COL, Field::Short(Some(op_index)));
            table.put_record(record).unwrap();
        }
        drop(table);
        handle
    }

    #[test]
    fn reads_and_converts_v0_records_to_current_layout() {
        let handle = setup_handle();
        let adapter = EquateRefDBAdapterV0::new(&handle).unwrap();

        assert_eq!(adapter.get_record_count(), 2);
        let keys = adapter.get_record_keys_for_equate_id(1).unwrap();
        assert_eq!(keys.len(), 1);

        let record = adapter.get_record(keys[0].get_long_value()).unwrap();
        assert_eq!(record.get_long(ADDR_COL), Some(0x1000));
        assert_eq!(record.get_long(HASH_COL), Some(0));
        assert_eq!(record.get_field(OP_INDEX_COL), &Field::Short(Some(0)));
    }

    #[test]
    fn address_iteration_and_lookup() {
        let handle = setup_handle();
        let adapter = EquateRefDBAdapterV0::new(&handle).unwrap();

        let keys_for_addr = adapter.get_record_keys_for_addr(0x2000).unwrap();
        assert_eq!(keys_for_addr.len(), 1);

        let mut iter = adapter.get_iterator_for_addresses().unwrap();
        let mut seen = Vec::new();
        while iter.has_next().unwrap() {
            seen.push(iter.next().unwrap());
        }
        assert_eq!(seen, vec![0x1000, 0x2000]);

        let mut ranged = adapter
            .get_iterator_for_addresses_in_range(&addr(0x1500), &addr(0x2500))
            .unwrap();
        let mut ranged_seen = Vec::new();
        while ranged.has_next().unwrap() {
            ranged_seen.push(ranged.next().unwrap());
        }
        assert_eq!(ranged_seen, vec![0x2000]);
    }

    #[test]
    fn mutations_are_unsupported() {
        let handle = setup_handle();
        let mut adapter = EquateRefDBAdapterV0::new(&handle).unwrap();
        assert!(adapter.create_reference(0, 0, 0, 0).is_err());
        let dummy = DBRecord::new(equate_ref_db_adapter_v1::schema(), Field::Long(Some(0)));
        assert!(adapter.update_record(&dummy).is_err());
        assert!(adapter.remove_record(0).is_err());
    }

    #[test]
    fn opening_missing_or_wrong_version_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        assert!(EquateRefDBAdapterV0::new(&handle).is_err());

        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                EQUATE_REFS_TABLE_NAME.to_string(),
                equate_ref_db_adapter_v1::schema(),
            )
            .unwrap();
        assert!(EquateRefDBAdapterV0::new(&handle).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = setup_handle();
        let adapter: Box<dyn EquateRefDBAdapter> = Box::new(EquateRefDBAdapterV0::new(&handle).unwrap());
        assert_eq!(adapter.get_record_count(), 2);
    }
}
