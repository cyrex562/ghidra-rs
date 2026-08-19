//! Port of `ghidra.program.database.code.DataDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`DataDBAdapterV0`). Those concrete adapters have not been ported yet, so this
//! port only models the abstract instance API each version implements, as an object-safe trait;
//! the version-selection/upgrade logic belongs with whichever type ends up owning the concrete
//! adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::model::address::{Address, AddressSetView};
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// DB table name for the data table. Stands in for `DataDBAdapter.DATA_TABLE_NAME`.
pub const DATA_TABLE_NAME: &str = "Data";

/// Data type ID column index. Stands in for `DataDBAdapter.DATA_TYPE_ID_COL`.
pub const DATA_TYPE_ID_COL: usize = 0;

/// Error returned by [`DataDBAdapter::move_address_range`], mirroring the Java method's `throws
/// CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum MoveAddressRangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter to access the Data table.
///
/// Port of `ghidra.program.database.code.DataDBAdapter`.
pub trait DataDBAdapter {
    /// Get the record at or after the given start address.
    fn get_record_at_or_after(&self, start: &Address) -> io::Result<Option<DBRecord>>;

    /// Get the record after the given start address.
    fn get_record_after(&self, start: &Address) -> io::Result<Option<DBRecord>>;

    /// Get the record at the given start address.
    fn get_record(&self, start: &Address) -> io::Result<Option<DBRecord>>;

    /// Get the record at the given key. Stands in for `DataDBAdapter.getRecord(long)`.
    fn get_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>>;

    /// Get the record before the given address `addr`.
    fn get_record_before(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Get a record iterator starting at the given address `addr`. Stands in for
    /// `DataDBAdapter.getRecords(Address, boolean)`.
    fn get_records_from(
        &self,
        addr: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get a record iterator over the given range. Stands in for `DataDBAdapter.getRecords(
    /// Address, Address, boolean)`.
    fn get_records_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Delete the record for the given key.
    fn delete_record(&mut self, key: i64) -> io::Result<()>;

    /// Create a data record for `addr` with the given data type ID.
    fn create_data(&mut self, addr: &Address, data_type_id: i64) -> io::Result<DBRecord>;

    /// Get the number of records in the data table.
    fn get_record_count(&self) -> io::Result<i32>;

    /// Get the record at or before the given address `addr`.
    fn get_record_at_or_before(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Get an iterator over the keys in the data table in the given range, positioned at `start`
    /// if `at_start` is `true`. Stands in for `DataDBAdapter.getKeys(Address, Address,
    /// boolean)`.
    fn get_keys_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Get a record iterator over all records in the data table.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Deletes all records in the given range. Returns `true` if at least one record was
    /// deleted.
    fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool>;

    /// Puts the given record into the database.
    fn put_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Returns an iterator over the keys that fall within the given address set. `set` of `None`
    /// means all defined memory. Stands in for `DataDBAdapter.getKeys(AddressSetView,
    /// boolean)`.
    fn get_keys(
        &self,
        set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Returns a record iterator over all records that fall within the given address set. `set`
    /// of `None` means all defined memory. Stands in for `DataDBAdapter.getRecords(
    /// AddressSetView, boolean)`.
    fn get_records_in_set(
        &self,
        set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Update the addresses in all records to reflect the movement of a memory block: `from_addr`
    /// is the minimum address of the original block being moved, `to_addr` is the new minimum
    /// address after the move, and `length` is the number of bytes in the block.
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
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::BTreeMap;

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

    struct MockAddressKeyIterator {
        keys: std::vec::IntoIter<i64>,
    }

    impl AddressKeyIteratorLike for MockAddressKeyIterator {
        fn has_next(&mut self) -> bool {
            self.keys.len() > 0
        }

        fn has_previous(&mut self) -> bool {
            false
        }

        fn next(&mut self) -> Option<i64> {
            self.keys.next()
        }

        fn previous(&mut self) -> Option<i64> {
            None
        }
    }

    struct MockDataDBAdapter {
        schema: std::sync::Arc<crate::framework::db::Schema>,
        records: BTreeMap<i64, DBRecord>,
    }

    impl MockDataDBAdapter {
        fn new() -> Self {
            use crate::framework::db::{FieldType, Schema};

            let schema = std::sync::Arc::new(Schema::new(
                0,
                FieldType::Long,
                "Address".to_string(),
                vec![FieldType::Long],
                vec!["Data Type ID".to_string()],
                vec![],
            ));
            MockDataDBAdapter {
                schema,
                records: BTreeMap::new(),
            }
        }
    }

    impl DataDBAdapter for MockDataDBAdapter {
        fn get_record_at_or_after(&self, start: &Address) -> io::Result<Option<DBRecord>> {
            let start = start.offset();
            Ok(self
                .records
                .range(start..)
                .next()
                .map(|(_, v)| v.clone()))
        }

        fn get_record_after(&self, start: &Address) -> io::Result<Option<DBRecord>> {
            let start = start.offset();
            Ok(self
                .records
                .range((start + 1)..)
                .next()
                .map(|(_, v)| v.clone()))
        }

        fn get_record(&self, start: &Address) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&start.offset()).cloned())
        }

        fn get_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&key).cloned())
        }

        fn get_record_before(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
            let addr = addr.offset();
            Ok(self
                .records
                .range(..addr)
                .next_back()
                .map(|(_, v)| v.clone()))
        }

        fn get_records_from(
            &self,
            addr: &Address,
            forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let addr = addr.offset();
            let records: Vec<DBRecord> = if forward {
                self.records.range(addr..).map(|(_, v)| v.clone()).collect()
            } else {
                self.records
                    .range(..=addr)
                    .rev()
                    .map(|(_, v)| v.clone())
                    .collect()
            };
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_records_in_range(
            &self,
            start: &Address,
            end: &Address,
            _at_start: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let start = start.offset();
            let end = end.offset();
            let records: Vec<DBRecord> = self
                .records
                .iter()
                .filter(|(k, _)| **k >= start && **k <= end)
                .map(|(_, v)| v.clone())
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn delete_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
            Ok(())
        }

        fn create_data(&mut self, addr: &Address, data_type_id: i64) -> io::Result<DBRecord> {
            use crate::framework::db::Field;

            let key = addr.offset();
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            rec.set_field(DATA_TYPE_ID_COL, Field::Long(Some(data_type_id)));
            self.records.insert(key, rec.clone());
            Ok(rec)
        }

        fn get_record_count(&self) -> io::Result<i32> {
            Ok(self.records.len() as i32)
        }

        fn get_record_at_or_before(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
            let addr = addr.offset();
            Ok(self
                .records
                .range(..=addr)
                .next_back()
                .map(|(_, v)| v.clone()))
        }

        fn get_keys_in_range(
            &self,
            start: &Address,
            end: &Address,
            _at_start: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            let start = start.offset();
            let end = end.offset();
            let keys: Vec<i64> = self
                .records
                .keys()
                .filter(|k| **k >= start && **k <= end)
                .copied()
                .collect();
            Ok(Box::new(MockAddressKeyIterator {
                keys: keys.into_iter(),
            }))
        }

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool> {
            let start = start.offset();
            let end = end.offset();
            let before = self.records.len();
            self.records.retain(|k, _| *k < start || *k > end);
            Ok(self.records.len() != before)
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            if let crate::framework::db::Field::Long(Some(key)) = record.get_key() {
                self.records.insert(*key, record.clone());
            }
            Ok(())
        }

        fn get_keys(
            &self,
            _set: Option<&dyn AddressSetView>,
            _forward: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            let keys: Vec<i64> = self.records.keys().copied().collect();
            Ok(Box::new(MockAddressKeyIterator {
                keys: keys.into_iter(),
            }))
        }

        fn get_records_in_set(
            &self,
            _set: Option<&dyn AddressSetView>,
            _forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
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
            let moved: Vec<(i64, DBRecord)> = self
                .records
                .iter()
                .filter(|(k, _)| **k >= from && **k < from + length)
                .map(|(k, v)| (*k - from + to, v.clone()))
                .collect();
            self.records.retain(|k, _| *k < from || *k >= from + length);
            for (new_key, mut rec) in moved {
                rec.set_key(crate::framework::db::Field::Long(Some(new_key)));
                self.records.insert(new_key, rec);
            }
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut adapter: Box<dyn DataDBAdapter> = Box::new(MockDataDBAdapter::new());

        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x2000);

        assert_eq!(adapter.get_record_count().unwrap(), 0);

        adapter.create_data(&addr1, 7).unwrap();
        adapter.create_data(&addr2, 42).unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 2);

        let rec = adapter.get_record(&addr1).unwrap().unwrap();
        assert_eq!(
            rec.get_field(DATA_TYPE_ID_COL),
            &crate::framework::db::Field::Long(Some(7))
        );

        let by_key = adapter.get_record_by_key(addr2.offset()).unwrap().unwrap();
        assert_eq!(
            by_key.get_field(DATA_TYPE_ID_COL),
            &crate::framework::db::Field::Long(Some(42))
        );

        let after = adapter.get_record_after(&addr1).unwrap().unwrap();
        assert_eq!(after.get_key(), &crate::framework::db::Field::Long(Some(addr2.offset())));

        let before = adapter.get_record_before(&addr2).unwrap().unwrap();
        assert_eq!(before.get_key(), &crate::framework::db::Field::Long(Some(addr1.offset())));

        // Move addr1's record from 0x1000 to 0x1500, a range containing only addr1.
        let from = space.address(0x1000);
        let to = space.address(0x1500);
        adapter
            .move_address_range(&from, &to, 0x10, &crate::util::task::DummyMonitor)
            .unwrap();
        assert!(adapter.get_record(&addr1).unwrap().is_none());
        let moved = adapter.get_record_by_key(0x1500).unwrap().unwrap();
        assert_eq!(
            moved.get_field(DATA_TYPE_ID_COL),
            &crate::framework::db::Field::Long(Some(7))
        );

        let deleted = adapter.delete_records(&to, &to).unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count().unwrap(), 1);
    }
}
