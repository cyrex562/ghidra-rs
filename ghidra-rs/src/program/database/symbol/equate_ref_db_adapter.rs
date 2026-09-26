//! Port of `ghidra.program.database.symbol.EquateRefDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers it delegates to) selects between and migrates
//! concrete version-specific implementations (`EquateRefDBAdapterV0`, `EquateRefDBAdapterV1`).
//! Those concrete adapters have not been ported yet, so this port only models the abstract
//! instance API each version implements, as an object-safe trait; the version-selection/upgrade
//! logic belongs with whichever type ends up owning the concrete adapters. This follows the same
//! convention already used for
//! [`EquateDBAdapter`](crate::program::database::symbol::EquateDBAdapter) and
//! [`LabelHistoryAdapter`](crate::program::database::symbol::LabelHistoryAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `EQUATE_REFS_TABLE_NAME`/`REFS_SCHEMA`/column-index (`EQUATE_ID_COL`/
//! `ADDR_COL`/`OP_INDEX_COL`/`HASH_COL`) constants, since they describe a concrete table layout
//! rather than this trait's dynamic-dispatch surface; left for whichever concrete subclass is
//! ported first.

use std::io;

use crate::framework::db::{DBLongIterator, DBRecord, Field, RecordIterator};
use crate::program::model::address::{Address, AddressSetView};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error returned by [`EquateRefDBAdapter::move_address_range`], mirroring the Java method's
/// `throws CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum MoveAddressRangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter to access records in the equate references table.
///
/// Port of `ghidra.program.database.symbol.EquateRefDBAdapter`. See the module docs for what was
/// intentionally left out (the static factory and table-layout constants).
pub trait EquateRefDBAdapter {
    /// Create a reference to an equate. `addr` is the database-key encoding of the reference
    /// address, `op_index` is the operand index, `dynamic_hash` is the dynamic hash associated
    /// with the constant varnode, and `equate_name_id` is the ID of the referenced equate.
    ///
    /// Stands in for `EquateRefDBAdapter.createReference(long, short, long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_reference(
        &mut self,
        addr: i64,
        op_index: i16,
        dynamic_hash: i64,
        equate_name_id: i64,
    ) -> io::Result<DBRecord>;

    /// Get the record for the given key.
    ///
    /// Stands in for `EquateRefDBAdapter.getRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record(&self, key: i64) -> io::Result<DBRecord>;

    /// Get an iterator over all the equate reference records.
    ///
    /// Stands in for `EquateRefDBAdapter.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns record count.
    ///
    /// Stands in for `EquateRefDBAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Get the keys of the records for the given address (database-key encoding).
    ///
    /// Stands in for `EquateRefDBAdapter.getRecordKeysForAddr(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record_keys_for_addr(&self, addr: i64) -> io::Result<Vec<Field>>;

    /// Update the table with the given record.
    ///
    /// Stands in for `EquateRefDBAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Get the keys of the records that have the given equate ID.
    ///
    /// Stands in for `EquateRefDBAdapter.getRecordKeysForEquateID(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_record_keys_for_equate_id(&self, equate_id: i64) -> io::Result<Vec<Field>>;

    /// Get an iterator over all the reference addresses (database-key encoding).
    ///
    /// Stands in for `EquateRefDBAdapter.getIteratorForAddresses()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_iterator_for_addresses(&self) -> io::Result<Box<dyn DBLongIterator>>;

    /// Get an iterator over the reference addresses in the range `[start, end]`.
    ///
    /// Stands in for `EquateRefDBAdapter.getIteratorForAddresses(Address, Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_iterator_for_addresses_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> io::Result<Box<dyn DBLongIterator>>;

    /// Get an iterator over the reference addresses contained in `set`.
    ///
    /// Stands in for `EquateRefDBAdapter.getIteratorForAddresses(AddressSetView)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_iterator_for_addresses_in_set(
        &self,
        set: &dyn AddressSetView,
    ) -> io::Result<Box<dyn DBLongIterator>>;

    /// Get an iterator over the reference addresses starting at (and including) `start`.
    ///
    /// Stands in for `EquateRefDBAdapter.getIteratorForAddresses(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_iterator_for_addresses_from(&self, start: &Address) -> io::Result<Box<dyn DBLongIterator>>;

    /// Remove the record with the given key.
    ///
    /// Stands in for `EquateRefDBAdapter.removeRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_record(&mut self, key: i64) -> io::Result<()>;

    /// Update the addresses in all records to reflect the movement of a memory block. `from_addr`
    /// is the minimum address of the original block being moved, `to_addr` is the new minimum
    /// address after the move, and `length` is the number of bytes in the block being moved.
    ///
    /// Stands in for `EquateRefDBAdapter.moveAddressRange(Address, Address, long, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is cancelled or there was a problem accessing the
    /// database.
    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::collections::HashMap;
    use std::sync::Arc;

    const EQUATE_ID_COL: usize = 0;
    const ADDR_COL: usize = 1;
    const OP_INDEX_COL: usize = 2;
    const HASH_COL: usize = 3;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
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

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
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

    struct MockEquateRefDBAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockEquateRefDBAdapter {
        fn new() -> Self {
            MockEquateRefDBAdapter {
                schema: test_schema(),
                records: HashMap::new(),
                next_key: 0,
            }
        }
    }

    impl EquateRefDBAdapter for MockEquateRefDBAdapter {
        fn create_reference(
            &mut self,
            addr: i64,
            op_index: i16,
            dynamic_hash: i64,
            equate_name_id: i64,
        ) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_long(EQUATE_ID_COL, equate_name_id);
            record.set_long(ADDR_COL, addr);
            record.set_field(OP_INDEX_COL, Field::Short(Some(op_index)));
            record.set_long(HASH_COL, dynamic_hash);
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn get_record(&self, key: i64) -> io::Result<DBRecord> {
            self.records
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such equate reference"))
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self.records.values().cloned().collect();
            records.sort_by_key(|r| r.get_key().get_long_value());
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn get_record_keys_for_addr(&self, addr: i64) -> io::Result<Vec<Field>> {
            let mut keys: Vec<Field> = self
                .records
                .values()
                .filter(|r| r.get_long(ADDR_COL) == Some(addr))
                .map(|r| r.get_key().clone())
                .collect();
            keys.sort_by_key(|f| f.get_long_value());
            Ok(keys)
        }

        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn get_record_keys_for_equate_id(&self, equate_id: i64) -> io::Result<Vec<Field>> {
            let mut keys: Vec<Field> = self
                .records
                .values()
                .filter(|r| r.get_long(EQUATE_ID_COL) == Some(equate_id))
                .map(|r| r.get_key().clone())
                .collect();
            keys.sort_by_key(|f| f.get_long_value());
            Ok(keys)
        }

        fn get_iterator_for_addresses(&self) -> io::Result<Box<dyn DBLongIterator>> {
            let mut addrs: Vec<i64> = self
                .records
                .values()
                .map(|r| r.get_long(ADDR_COL).unwrap())
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            Ok(Box::new(VecLongIterator::new(addrs)))
        }

        fn get_iterator_for_addresses_in_range(
            &self,
            start: &Address,
            end: &Address,
        ) -> io::Result<Box<dyn DBLongIterator>> {
            let (start, end) = (start.offset(), end.offset());
            let mut addrs: Vec<i64> = self
                .records
                .values()
                .map(|r| r.get_long(ADDR_COL).unwrap())
                .filter(|a| *a >= start && *a <= end)
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            Ok(Box::new(VecLongIterator::new(addrs)))
        }

        fn get_iterator_for_addresses_in_set(
            &self,
            set: &dyn AddressSetView,
        ) -> io::Result<Box<dyn DBLongIterator>> {
            let sp = space();
            let mut addrs: Vec<i64> = self
                .records
                .values()
                .map(|r| r.get_long(ADDR_COL).unwrap())
                .filter(|a| set.contains(&Address::new(sp.clone(), *a)))
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            Ok(Box::new(VecLongIterator::new(addrs)))
        }

        fn get_iterator_for_addresses_from(
            &self,
            start: &Address,
        ) -> io::Result<Box<dyn DBLongIterator>> {
            let start = start.offset();
            let mut addrs: Vec<i64> = self
                .records
                .values()
                .map(|r| r.get_long(ADDR_COL).unwrap())
                .filter(|a| *a >= start)
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            Ok(Box::new(VecLongIterator::new(addrs)))
        }

        fn remove_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
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
            for record in self.records.values_mut() {
                if let Some(a) = record.get_long(ADDR_COL) {
                    if a >= from && a < from + length {
                        record.set_long(ADDR_COL, a - from + to);
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn create_lookup_and_remove_round_trip() {
        let mut adapter = MockEquateRefDBAdapter::new();
        let record = adapter.create_reference(0x1000, 0, 0, 42).unwrap();
        let key = record.get_key().get_long_value();

        assert_eq!(adapter.get_record_count(), 1);

        let keys_for_addr = adapter.get_record_keys_for_addr(0x1000).unwrap();
        assert_eq!(keys_for_addr.len(), 1);
        assert_eq!(keys_for_addr[0].get_long_value(), key);

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
        let mut adapter = MockEquateRefDBAdapter::new();
        adapter.create_reference(0x1000, 0, 0, 1).unwrap();
        adapter.create_reference(0x2000, 0, 0, 2).unwrap();

        adapter
            .move_address_range(&addr(0x1000), &addr(0x5000), 0x100, &DummyMonitor)
            .unwrap();

        let mut addrs: Vec<i64> = adapter
            .records
            .values()
            .map(|r| r.get_long(ADDR_COL).unwrap())
            .collect();
        addrs.sort_unstable();
        assert_eq!(addrs, vec![0x2000, 0x5000]);
    }

    #[test]
    fn object_safety_and_address_iteration() {
        let mut adapter: Box<dyn EquateRefDBAdapter> = Box::new(MockEquateRefDBAdapter::new());

        adapter.create_reference(0x100, 0, 0, 1).unwrap();
        adapter.create_reference(0x200, 1, 7, 2).unwrap();

        let mut iter = adapter.get_iterator_for_addresses().unwrap();
        let mut seen = Vec::new();
        while iter.has_next().unwrap() {
            seen.push(iter.next().unwrap());
        }
        assert_eq!(seen, vec![0x100, 0x200]);

        let mut ranged = adapter
            .get_iterator_for_addresses_in_range(&addr(0x150), &addr(0x250))
            .unwrap();
        let mut ranged_seen = Vec::new();
        while ranged.has_next().unwrap() {
            ranged_seen.push(ranged.next().unwrap());
        }
        assert_eq!(ranged_seen, vec![0x200]);
    }
}
