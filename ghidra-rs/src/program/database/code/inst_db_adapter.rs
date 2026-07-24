//! Port of `ghidra.program.database.code.InstDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`InstDBAdapterV0`/`InstDBAdapterV1`). Those concrete adapters have not been
//! ported yet, so this port only models the abstract instance API each version implements, as an
//! object-safe trait; the version-selection/upgrade logic belongs with whichever type ends up
//! owning the concrete adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::model::address::{Address, AddressSetView};
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// DB table name for the instruction table. Stands in for
/// `InstDBAdapter.INSTRUCTION_TABLE_NAME`.
pub const INSTRUCTION_TABLE_NAME: &str = "Instructions";

/// Prototype ID column index. Stands in for `InstDBAdapter.PROTO_ID_COL`.
pub const PROTO_ID_COL: usize = 0;
/// Flags column index. Stands in for `InstDBAdapter.FLAGS_COL`.
pub const FLAGS_COL: usize = 1;

/// Error returned by [`InstDBAdapter::move_address_range`], mirroring the Java method's `throws
/// CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum MoveAddressRangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter that accesses the instruction table.
///
/// Port of `ghidra.program.database.code.InstDBAdapter`.
pub trait InstDBAdapter {
    /// Create a new instruction record. Stands in for `InstDBAdapter.createInstruction(long, int,
    /// byte)`.
    fn create_instruction(&mut self, addr: i64, proto_id: i32, flags: u8) -> io::Result<()>;

    /// Sets the flags column in the record at `addr` to the given flags byte.
    fn update_flags(&mut self, addr: i64, flags: u8) -> io::Result<()>;

    /// Remove the instruction record at `addr` (a database key).
    fn delete_record(&mut self, addr: i64) -> io::Result<()>;

    /// Returns the next record at or after the given address, or `None` if there is none.
    fn get_record_at_or_after(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Returns the next record after the given address, or `None` if there is none.
    fn get_record_after(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Returns the record at the given key, or `None` if none exists. Stands in for
    /// `InstDBAdapter.getRecord(long)`.
    fn get_record_by_key(&self, addr: i64) -> io::Result<Option<DBRecord>>;

    /// Returns the record at the given address, or `None` if none exists. Stands in for
    /// `InstDBAdapter.getRecord(Address)`.
    fn get_record(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Returns the record just before the given address, or `None` if none exists.
    fn get_record_before(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Returns a record iterator over the records in `[start, end]`, positioned at `start` if
    /// `at_start` is `true`. Stands in for `InstDBAdapter.getRecords(Address, Address, boolean)`.
    fn get_records_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns an iterator over all records. Stands in for `InstDBAdapter.getRecords()`.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns the total number of records in this adapter.
    fn get_record_count(&self) -> io::Result<i32>;

    /// Returns the next record at or before the given address, or `None` if there is none.
    fn get_record_at_or_before(&self, addr: &Address) -> io::Result<Option<DBRecord>>;

    /// Returns an iterator over the keys in the given range, positioned at `start` if `at_start`
    /// is `true`. Stands in for `InstDBAdapter.getKeys(Address, Address, boolean)`.
    fn get_keys_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Deletes all records in the given range. Returns `true` if at least one record was deleted.
    fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool>;

    /// Adds or updates the given record.
    fn put_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Returns a record iterator starting at `addr`, positioned before `addr` if `forward` is
    /// `true`, otherwise after. Stands in for `InstDBAdapter.getRecords(Address, boolean)`.
    fn get_records_from(
        &self,
        addr: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns an iterator over the keys that fall within the given address set, in the given
    /// direction. Stands in for `InstDBAdapter.getKeys(AddressSetView, boolean)`.
    fn get_keys(
        &self,
        addr_set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Returns a record iterator over the given address set, positioned before the first address
    /// if `forward` is `true`, otherwise after the last address. Stands in for
    /// `InstDBAdapter.getRecords(AddressSetView, boolean)`.
    fn get_records_in_set(
        &self,
        set: &dyn AddressSetView,
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

    /// Deletes all records in this table.
    fn delete_all(&mut self) -> io::Result<()>;
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

    struct MockInstDBAdapter {
        schema: std::sync::Arc<crate::framework::db::Schema>,
        records: BTreeMap<i64, DBRecord>,
    }

    impl MockInstDBAdapter {
        fn new() -> Self {
            use crate::framework::db::{FieldType, Schema};

            let schema = std::sync::Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Address".to_string(),
                vec![FieldType::Int, FieldType::Byte],
                vec!["Proto ID".to_string(), "Flags".to_string()],
                vec![],
            ));
            MockInstDBAdapter {
                schema,
                records: BTreeMap::new(),
            }
        }
    }

    impl InstDBAdapter for MockInstDBAdapter {
        fn create_instruction(&mut self, addr: i64, proto_id: i32, flags: u8) -> io::Result<()> {
            use crate::framework::db::Field;

            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(addr)));
            rec.set_field(PROTO_ID_COL, Field::Int(Some(proto_id)));
            rec.set_field(FLAGS_COL, Field::Byte(Some(flags as i8)));
            self.records.insert(addr, rec);
            Ok(())
        }

        fn update_flags(&mut self, addr: i64, flags: u8) -> io::Result<()> {
            use crate::framework::db::Field;

            if let Some(rec) = self.records.get_mut(&addr) {
                rec.set_field(FLAGS_COL, Field::Byte(Some(flags as i8)));
            }
            Ok(())
        }

        fn delete_record(&mut self, addr: i64) -> io::Result<()> {
            self.records.remove(&addr);
            Ok(())
        }

        fn get_record_at_or_after(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
            let addr = addr.offset();
            Ok(self.records.range(addr..).next().map(|(_, v)| v.clone()))
        }

        fn get_record_after(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
            let addr = addr.offset();
            Ok(self
                .records
                .range((addr + 1)..)
                .next()
                .map(|(_, v)| v.clone()))
        }

        fn get_record_by_key(&self, addr: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&addr).cloned())
        }

        fn get_record(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&addr.offset()).cloned())
        }

        fn get_record_before(&self, addr: &Address) -> io::Result<Option<DBRecord>> {
            let addr = addr.offset();
            Ok(self
                .records
                .range(..addr)
                .next_back()
                .map(|(_, v)| v.clone()))
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

        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
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

        fn get_keys(
            &self,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
            let keys: Vec<i64> = self.records.keys().copied().collect();
            Ok(Box::new(MockAddressKeyIterator {
                keys: keys.into_iter(),
            }))
        }

        fn get_records_in_set(
            &self,
            _set: &dyn AddressSetView,
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

        fn delete_all(&mut self) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut adapter: Box<dyn InstDBAdapter> = Box::new(MockInstDBAdapter::new());

        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x2000);

        assert_eq!(adapter.get_record_count().unwrap(), 0);

        adapter.create_instruction(addr1.offset(), 7, 0x01).unwrap();
        adapter.create_instruction(addr2.offset(), 42, 0x02).unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 2);

        let rec = adapter.get_record(&addr1).unwrap().unwrap();
        assert_eq!(
            rec.get_field(PROTO_ID_COL),
            &crate::framework::db::Field::Int(Some(7))
        );

        adapter.update_flags(addr1.offset(), 0x03).unwrap();
        let updated = adapter.get_record_by_key(addr1.offset()).unwrap().unwrap();
        assert_eq!(
            updated.get_field(FLAGS_COL),
            &crate::framework::db::Field::Byte(Some(0x03))
        );

        let after = adapter.get_record_after(&addr1).unwrap().unwrap();
        assert_eq!(
            after.get_key(),
            &crate::framework::db::Field::Long(Some(addr2.offset()))
        );

        let before = adapter.get_record_before(&addr2).unwrap().unwrap();
        assert_eq!(
            before.get_key(),
            &crate::framework::db::Field::Long(Some(addr1.offset()))
        );

        // Move addr1's record from 0x1000 to 0x1500, a range containing only addr1.
        let from = space.address(0x1000);
        let to = space.address(0x1500);
        adapter
            .move_address_range(&from, &to, 0x10, &crate::util::task::DummyMonitor)
            .unwrap();
        assert!(adapter.get_record(&addr1).unwrap().is_none());
        let moved = adapter.get_record_by_key(0x1500).unwrap().unwrap();
        assert_eq!(
            moved.get_field(PROTO_ID_COL),
            &crate::framework::db::Field::Int(Some(7))
        );

        let deleted = adapter.delete_records(&to, &to).unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count().unwrap(), 1);

        adapter.delete_all().unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 0);
    }
}
