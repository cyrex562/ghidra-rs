//! Port of `ghidra.program.database.code.CommentsDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`CommentsDBAdapterV0`/`CommentsDBAdapterV1`). Those concrete adapters have
//! not been ported yet, so this port only models the abstract instance API each version
//! implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This trait was itself selected as a
//! dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::model::address::{Address, AddressSetView};
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// DB table name for the comments table. Stands in for
/// `CommentsDBAdapter.COMMENTS_TABLE_NAME`.
pub const COMMENTS_TABLE_NAME: &str = "Comments";

/// Comment column index for EOL comments. Stands in for `CommentsDBAdapter.EOL_COMMENT_COL`
/// (`CommentType.EOL.ordinal()`).
pub const EOL_COMMENT_COL: usize = 0;
/// Comment column index for pre comments. Stands in for `CommentsDBAdapter.PRE_COMMENT_COL`
/// (`CommentType.PRE.ordinal()`).
pub const PRE_COMMENT_COL: usize = 1;
/// Comment column index for post comments. Stands in for `CommentsDBAdapter.POST_COMMENT_COL`
/// (`CommentType.POST.ordinal()`).
pub const POST_COMMENT_COL: usize = 2;
/// Comment column index for plate comments. Stands in for `CommentsDBAdapter.PLATE_COMMENT_COL`
/// (`CommentType.PLATE.ordinal()`).
pub const PLATE_COMMENT_COL: usize = 3;
/// Comment column index for repeatable comments. Stands in for
/// `CommentsDBAdapter.REPEATABLE_COMMENT_COL` (`CommentType.REPEATABLE.ordinal()`).
pub const REPEATABLE_COMMENT_COL: usize = 4;
/// Number of comment columns. Stands in for `CommentsDBAdapter.COMMENT_COL_COUNT`.
pub const COMMENT_COL_COUNT: usize = 5;

/// Error returned by [`CommentsDBAdapter::move_address_range`], mirroring the Java method's
/// `throws CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum MoveAddressRangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter to access the comments table for code units. The primary key for the table is the
/// address. The record contains all of the comment types: Pre, Post, EOL, Plate, and Repeatable.
///
/// Port of `ghidra.program.database.code.CommentsDBAdapter`.
pub trait CommentsDBAdapter {
    /// Returns the number of comment records.
    fn get_record_count(&self) -> io::Result<i32>;

    /// Get the record at the given address (database key), or `None` if there is no comment
    /// record there.
    fn get_record(&self, addr: i64) -> io::Result<Option<DBRecord>>;

    /// Create a comment record for the given comment type/column.
    fn create_record(
        &mut self,
        addr: i64,
        comment_col: usize,
        comment: &str,
    ) -> io::Result<DBRecord>;

    /// Delete the record at the given address. Returns `true` if the record was deleted.
    fn delete_record(&mut self, addr: i64) -> io::Result<bool>;

    /// Delete the records in the given range. Returns `true` if at least one record was removed
    /// in the range.
    fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool>;

    /// Update the record with the comments from the given record.
    fn update_record(&mut self, comment_rec: &DBRecord) -> io::Result<()>;

    /// Returns a record iterator over the records in `[start, end]`, positioned at `start` if
    /// `at_start` is `true`. Stands in for `CommentsDBAdapter.getRecords(Address, Address,
    /// boolean)`.
    fn get_records_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Gets an iterator of all comment records in the program. Stands in for
    /// `CommentsDBAdapter.getRecords()`.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get the keys in the given range, positioned at `start` if `at_start` is `true`. Stands in
    /// for `CommentsDBAdapter.getKeys(Address, Address, boolean)`.
    fn get_keys_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

    /// Puts the given record into the table.
    fn put_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Returns a record iterator starting with the record at `addr`. Stands in for
    /// `CommentsDBAdapter.getRecords(Address)`.
    fn get_records_from(&self, addr: &Address) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns an address key iterator over the given address set in the given direction. `set`
    /// of `None` means all defined memory. Stands in for `CommentsDBAdapter.getKeys(
    /// AddressSetView, boolean)`.
    fn get_keys(
        &self,
        set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>>;

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

    struct MockCommentsDBAdapter {
        schema: std::sync::Arc<crate::framework::db::Schema>,
        records: BTreeMap<i64, DBRecord>,
    }

    impl MockCommentsDBAdapter {
        fn new() -> Self {
            use crate::framework::db::{FieldType, Schema};

            let schema = std::sync::Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Address".to_string(),
                vec![
                    FieldType::String,
                    FieldType::String,
                    FieldType::String,
                    FieldType::String,
                    FieldType::String,
                ],
                vec![
                    "EOL".to_string(),
                    "Pre".to_string(),
                    "Post".to_string(),
                    "Plate".to_string(),
                    "Repeatable".to_string(),
                ],
                vec![],
            ));
            MockCommentsDBAdapter {
                schema,
                records: BTreeMap::new(),
            }
        }
    }

    impl CommentsDBAdapter for MockCommentsDBAdapter {
        fn get_record_count(&self) -> io::Result<i32> {
            Ok(self.records.len() as i32)
        }

        fn get_record(&self, addr: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&addr).cloned())
        }

        fn create_record(
            &mut self,
            addr: i64,
            comment_col: usize,
            comment: &str,
        ) -> io::Result<DBRecord> {
            use crate::framework::db::Field;

            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(addr)));
            rec.set_field(comment_col, Field::String(Some(comment.to_string())));
            self.records.insert(addr, rec.clone());
            Ok(rec)
        }

        fn delete_record(&mut self, addr: i64) -> io::Result<bool> {
            Ok(self.records.remove(&addr).is_some())
        }

        fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool> {
            let start = start.offset();
            let end = end.offset();
            let before = self.records.len();
            self.records.retain(|k, _| *k < start || *k > end);
            Ok(self.records.len() != before)
        }

        fn update_record(&mut self, comment_rec: &DBRecord) -> io::Result<()> {
            if let crate::framework::db::Field::Long(Some(key)) = comment_rec.get_key() {
                self.records.insert(*key, comment_rec.clone());
            }
            Ok(())
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

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            self.update_record(record)
        }

        fn get_records_from(&self, addr: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
            let addr = addr.offset();
            let records: Vec<DBRecord> = self
                .records
                .iter()
                .filter(|(k, _)| **k >= addr)
                .map(|(_, v)| v.clone())
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
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
        let mut adapter: Box<dyn CommentsDBAdapter> = Box::new(MockCommentsDBAdapter::new());

        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x2000);

        assert_eq!(adapter.get_record_count().unwrap(), 0);

        adapter
            .create_record(addr1.offset(), EOL_COMMENT_COL, "hello")
            .unwrap();
        adapter
            .create_record(addr2.offset(), PLATE_COMMENT_COL, "plate comment")
            .unwrap();
        assert_eq!(adapter.get_record_count().unwrap(), 2);

        let rec = adapter.get_record(addr1.offset()).unwrap().unwrap();
        assert_eq!(
            rec.get_field(EOL_COMMENT_COL),
            &crate::framework::db::Field::String(Some("hello".to_string()))
        );

        let count = {
            let mut it = adapter.get_records().unwrap();
            let mut count = 0;
            while it.next().unwrap().is_some() {
                count += 1;
            }
            count
        };
        assert_eq!(count, 2);

        // Move addr1's record from 0x1000 to 0x1500, a range containing only addr1.
        let from = space.address(0x1000);
        let to = space.address(0x1500);
        adapter
            .move_address_range(&from, &to, 0x10, &crate::util::task::DummyMonitor)
            .unwrap();
        assert!(adapter.get_record(addr1.offset()).unwrap().is_none());
        let moved = adapter.get_record(0x1500).unwrap().unwrap();
        assert_eq!(
            moved.get_field(EOL_COMMENT_COL),
            &crate::framework::db::Field::String(Some("hello".to_string()))
        );

        let deleted = adapter.delete_record(0x1500).unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count().unwrap(), 1);
    }
}
