//! Port of `ghidra.program.database.symbol.LabelHistoryAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter` helper it delegates to) selects and migrates between concrete
//! version-specific implementations (`LabelHistoryAdapterV0`, `LabelHistoryAdapterNoTable`).
//! Those concrete adapters have not been ported yet, so this port only models the abstract
//! instance API each version implements, as an object-safe trait; the version-selection/upgrade
//! logic belongs with whichever type ends up owning the concrete adapters. This follows the same
//! convention already used for
//! [`VariableStorageDBAdapter`](crate::program::database::symbol::VariableStorageDBAdapter) and
//! [`CommentsDBAdapter`](crate::program::database::code::CommentsDBAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.

use std::collections::BTreeSet;
use std::io;

use crate::framework::db::RecordIterator;
use crate::program::database::map::AddressMap;
use crate::program::model::address::Address;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// DB table name for the label history table. Stands in for
/// `LabelHistoryAdapter.LABEL_HISTORY_TABLE_NAME`.
pub const LABEL_HISTORY_TABLE_NAME: &str = "Label History";

/// Column index for the address of a label history record. Stands in for
/// `LabelHistoryAdapter.HISTORY_ADDR_COL`.
pub const HISTORY_ADDR_COL: usize = 0;
/// Column index for the action (add/remove/rename) of a label history record. Stands in for
/// `LabelHistoryAdapter.HISTORY_ACTION_COL`.
pub const HISTORY_ACTION_COL: usize = 1;
/// Column index for the labels string of a label history record. Stands in for
/// `LabelHistoryAdapter.HISTORY_LABEL_COL`.
pub const HISTORY_LABEL_COL: usize = 2;
/// Column index for the user name of a label history record. Stands in for
/// `LabelHistoryAdapter.HISTORY_USER_COL`.
pub const HISTORY_USER_COL: usize = 3;
/// Column index for the date of a label history record. Stands in for
/// `LabelHistoryAdapter.HISTORY_DATE_COL`.
pub const HISTORY_DATE_COL: usize = 4;

/// Error returned by [`LabelHistoryAdapter::move_address_range`] and
/// [`LabelHistoryAdapter::delete_address_range`], mirroring the Java methods' `throws
/// CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum LabelHistoryRangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter for the Label History table.
///
/// Port of `ghidra.program.database.symbol.LabelHistoryAdapter`. See the module docs for what
/// was intentionally left out (the static factory and version-upgrade logic).
pub trait LabelHistoryAdapter {
    /// Create a label history record. `addr` is the database-key encoding of the address,
    /// `action_id` is either ADD, REMOVE, or RENAME, and `label_str` holds the current labels at
    /// the given address.
    ///
    /// Stands in for `LabelHistoryAdapter.createRecord(long, byte, String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_record(&mut self, addr: i64, action_id: i8, label_str: &str) -> io::Result<()>;

    /// Get an iterator over records with the given address (database-key encoding).
    ///
    /// Stands in for `LabelHistoryAdapter.getRecordsByAddress(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records_by_address(&self, addr: i64) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get an iterator over all records.
    ///
    /// Stands in for `LabelHistoryAdapter.getAllRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns number of history records.
    ///
    /// Stands in for `LabelHistoryAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Update the address in all records to reflect the movement of a symbol address.
    /// `old_addr`/`new_addr` are the original/new symbol address keys.
    ///
    /// Stands in for `LabelHistoryAdapter.moveAddress(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn move_address(&mut self, old_addr: i64, new_addr: i64) -> io::Result<()>;

    /// Update the addresses in all records to reflect the movement of a memory block: `from_addr`
    /// is the minimum address of the original block being moved, `to_addr` is the new minimum
    /// address after the move, `length` is the number of bytes in the block, and `addr_map` is
    /// the address map used to translate addresses to/from database keys.
    ///
    /// Stands in for `LabelHistoryAdapter.moveAddressRange(Address, Address, long, AddressMap,
    /// TaskMonitor)`.
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
        addr_map: &dyn AddressMap,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), LabelHistoryRangeError>;

    /// Delete all records which contain addresses within `[start_addr, end_addr]`. `do_not_delete`
    /// is the set of addresses where the label history should NOT be deleted; `None` indicates
    /// that all records in the range should be deleted.
    ///
    /// Stands in for `LabelHistoryAdapter.deleteAddressRange(Address, Address, AddressMap,
    /// Set<Address>, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is cancelled or there was a problem accessing the
    /// database.
    fn delete_address_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        addr_map: &dyn AddressMap,
        do_not_delete: Option<&BTreeSet<Address>>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), LabelHistoryRangeError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct HistoryRow {
        addr: i64,
        action_id: i8,
        label_str: String,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long, FieldType::Byte, FieldType::String],
            vec![
                "Address".to_string(),
                "Action".to_string(),
                "Labels".to_string(),
            ],
            vec![],
        ))
    }

    struct MockRecordIterator {
        rows: std::vec::IntoIter<HistoryRow>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<crate::framework::db::DBRecord>> {
            Ok(self.rows.next().map(|row| {
                use crate::framework::db::{DBRecord, Field};

                let mut record = DBRecord::new(test_schema(), Field::Long(Some(row.addr)));
                record.set_long(HISTORY_ADDR_COL, row.addr);
                record.set_byte(HISTORY_ACTION_COL, row.action_id);
                record.set_string(HISTORY_LABEL_COL, Some(row.label_str.clone()));
                record
            }))
        }

        fn has_next(&self) -> bool {
            self.rows.len() > 0
        }
    }

    struct MockLabelHistoryAdapter {
        rows: BTreeMap<i64, Vec<HistoryRow>>,
    }

    impl MockLabelHistoryAdapter {
        fn new() -> Self {
            MockLabelHistoryAdapter {
                rows: BTreeMap::new(),
            }
        }
    }

    impl LabelHistoryAdapter for MockLabelHistoryAdapter {
        fn create_record(&mut self, addr: i64, action_id: i8, label_str: &str) -> io::Result<()> {
            self.rows.entry(addr).or_default().push(HistoryRow {
                addr,
                action_id,
                label_str: label_str.to_string(),
            });
            Ok(())
        }

        fn get_records_by_address(&self, addr: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
            let rows = self.rows.get(&addr).cloned().unwrap_or_default();
            Ok(Box::new(MockRecordIterator {
                rows: rows.into_iter(),
            }))
        }

        fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let rows: Vec<HistoryRow> = self.rows.values().flatten().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                rows: rows.into_iter(),
            }))
        }

        fn get_record_count(&self) -> i32 {
            self.rows.values().map(|v| v.len() as i32).sum()
        }

        fn move_address(&mut self, old_addr: i64, new_addr: i64) -> io::Result<()> {
            if let Some(mut rows) = self.rows.remove(&old_addr) {
                for row in &mut rows {
                    row.addr = new_addr;
                }
                self.rows.entry(new_addr).or_default().extend(rows);
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
            let from = from_addr.offset();
            let to = to_addr.offset();
            let moved: Vec<(i64, Vec<HistoryRow>)> = self
                .rows
                .iter()
                .filter(|(k, _)| **k >= from && **k < from + length)
                .map(|(k, v)| (*k - from + to, v.clone()))
                .collect();
            self.rows.retain(|k, _| *k < from || *k >= from + length);
            for (new_addr, mut rows) in moved {
                for row in &mut rows {
                    row.addr = new_addr;
                }
                self.rows.entry(new_addr).or_default().extend(rows);
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
            self.rows.retain(|k, _| {
                if *k < start || *k > end {
                    return true;
                }
                if let Some(keep) = do_not_delete {
                    keep.contains(&space.address(*k))
                } else {
                    false
                }
            });
            Ok(())
        }
    }

    #[test]
    fn create_move_and_count_round_trip() {
        let mut adapter = MockLabelHistoryAdapter::new();
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

        adapter.move_address(0x1000, 0x1500).unwrap();
        assert_eq!(
            adapter
                .get_records_by_address(0x1000)
                .unwrap()
                .next()
                .unwrap()
                .is_none(),
            true
        );
        let mut moved_seen = 0;
        {
            let mut iter = adapter.get_records_by_address(0x1500).unwrap();
            while iter.next().unwrap().is_some() {
                moved_seen += 1;
            }
        }
        assert_eq!(moved_seen, 2);
    }

    #[test]
    fn object_safety_and_delete_range_respects_do_not_delete_set() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut adapter: Box<dyn LabelHistoryAdapter> = Box::new(MockLabelHistoryAdapter::new());

        adapter.create_record(0x1000, 0, "keep").unwrap();
        adapter.create_record(0x1010, 0, "drop").unwrap();
        assert_eq!(adapter.get_record_count(), 2);

        let start = space.address(0x1000);
        let end = space.address(0x1020);
        let mut keep_set = BTreeSet::new();
        keep_set.insert(space.address(0x1000));

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
            ) -> Option<std::sync::Arc<dyn crate::program::model::address::AddressFactory>>
            {
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
        let noop_map = NoopAddressMap {
            base: space.address(0),
        };

        adapter
            .delete_address_range(&start, &end, &noop_map, Some(&keep_set), &DummyMonitor)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 1);
        let remaining = adapter
            .get_records_by_address(0x1000)
            .unwrap()
            .next()
            .unwrap();
        assert!(remaining.is_some());
    }
}
