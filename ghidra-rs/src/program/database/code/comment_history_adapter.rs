//! Port of `ghidra.program.database.code.CommentHistoryAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter` helper and `upgrade` migration routine it delegates to) selects
//! and migrates between concrete version-specific implementations (`CommentHistoryAdapterV0`,
//! `CommentHistoryAdapterNoTable`). Those concrete adapters have not been ported yet, so this port
//! only models the abstract instance API each version implements, as an object-safe trait; the
//! version-selection/upgrade logic belongs with whichever type ends up owning the concrete
//! adapters. This follows the same convention already used for
//! [`InstDBAdapter`](crate::program::database::code::InstDBAdapter) and
//! [`LabelHistoryAdapter`](crate::program::database::symbol::LabelHistoryAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::model::address::Address;

/// DB table name for the comment history table. Stands in for
/// `CommentHistoryAdapter.COMMENT_HISTORY_TABLE_NAME`.
pub const COMMENT_HISTORY_TABLE_NAME: &str = "Comment History";

/// Column index for the address of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_ADDRESS_COL`.
pub const HISTORY_ADDRESS_COL: usize = 0;
/// Column index for the comment type of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_TYPE_COL`.
pub const HISTORY_TYPE_COL: usize = 1;
/// Column index for the first position of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_POS1_COL`.
pub const HISTORY_POS1_COL: usize = 2;
/// Column index for the second position of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_POS2_COL`.
pub const HISTORY_POS2_COL: usize = 3;
/// Column index for the changed comment string of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_STRING_COL`.
pub const HISTORY_STRING_COL: usize = 4;
/// Column index for the user name of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_USER_COL`.
pub const HISTORY_USER_COL: usize = 5;
/// Column index for the date of a comment history record. Stands in for
/// `CommentHistoryAdapter.HISTORY_DATE_COL`.
pub const HISTORY_DATE_COL: usize = 6;

/// Adapter for accessing records in the Comment History table.
///
/// Port of `ghidra.program.database.code.CommentHistoryAdapter`. See the module docs for what was
/// intentionally left out (the static factory and version-upgrade logic).
pub trait CommentHistoryAdapter {
    /// Returns the record count.
    ///
    /// Stands in for `CommentHistoryAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Create a comment history record. `addr` is the database-key encoding of the address of the
    /// changed record, `comment_type` is one of the `CodeManager` comment-type constants, `pos1`
    /// and `pos2` describe the position of the change, `data` holds the string from the comment
    /// change, and `date` is the date of the history entry.
    ///
    /// Stands in for `CommentHistoryAdapter.createRecord(long, byte, int, int, String, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        addr: i64,
        comment_type: i8,
        pos1: i32,
        pos2: i32,
        data: &str,
        date: i64,
    ) -> io::Result<()>;

    /// Update record.
    ///
    /// Stands in for `CommentHistoryAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_record(&mut self, rec: &DBRecord) -> io::Result<()>;

    /// Delete the records in the given range. Returns `true` if at least one record was removed
    /// in the range.
    ///
    /// Stands in for `CommentHistoryAdapter.deleteRecords(Address, Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool>;

    /// Get an iterator over records with the given address.
    ///
    /// Stands in for `CommentHistoryAdapter.getRecordsByAddress(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_records_by_address(&self, addr: &Address) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get an iterator over all records.
    ///
    /// Stands in for `CommentHistoryAdapter.getAllRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::BTreeMap;

    #[derive(Debug, Clone)]
    struct HistoryRow {
        addr: i64,
        comment_type: i8,
        pos1: i32,
        pos2: i32,
        data: String,
        date: i64,
    }

    fn test_schema() -> std::sync::Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};

        std::sync::Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::Long,
                FieldType::Byte,
                FieldType::Int,
                FieldType::Int,
                FieldType::String,
                FieldType::String,
                FieldType::Long,
            ],
            vec![
                "Address".to_string(),
                "Comment Type".to_string(),
                "Pos1".to_string(),
                "Pos2".to_string(),
                "String Data".to_string(),
                "User".to_string(),
                "Date".to_string(),
            ],
            vec![],
        ))
    }

    struct MockRecordIterator {
        rows: std::vec::IntoIter<HistoryRow>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.rows.next().map(|row| {
                use crate::framework::db::Field;

                let mut record = DBRecord::new(test_schema(), Field::Long(Some(row.addr)));
                record.set_long(HISTORY_ADDRESS_COL, row.addr);
                record.set_byte(HISTORY_TYPE_COL, row.comment_type);
                record.set_int(HISTORY_POS1_COL, row.pos1);
                record.set_int(HISTORY_POS2_COL, row.pos2);
                record.set_string(HISTORY_STRING_COL, Some(row.data.clone()));
                record.set_long(HISTORY_DATE_COL, row.date);
                record
            }))
        }

        fn has_next(&self) -> bool {
            self.rows.len() > 0
        }
    }

    struct MockCommentHistoryAdapter {
        rows: BTreeMap<i64, Vec<HistoryRow>>,
    }

    impl MockCommentHistoryAdapter {
        fn new() -> Self {
            MockCommentHistoryAdapter {
                rows: BTreeMap::new(),
            }
        }
    }

    impl CommentHistoryAdapter for MockCommentHistoryAdapter {
        fn get_record_count(&self) -> i32 {
            self.rows.values().map(|v| v.len() as i32).sum()
        }

        fn create_record(
            &mut self,
            addr: i64,
            comment_type: i8,
            pos1: i32,
            pos2: i32,
            data: &str,
            date: i64,
        ) -> io::Result<()> {
            self.rows.entry(addr).or_default().push(HistoryRow {
                addr,
                comment_type,
                pos1,
                pos2,
                data: data.to_string(),
                date,
            });
            Ok(())
        }

        fn update_record(&mut self, rec: &DBRecord) -> io::Result<()> {
            use crate::framework::db::Field;

            let addr = match rec.get_field(HISTORY_ADDRESS_COL) {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            let comment_type = match rec.get_field(HISTORY_TYPE_COL) {
                Field::Byte(Some(v)) => *v,
                _ => 0,
            };
            let pos1 = match rec.get_field(HISTORY_POS1_COL) {
                Field::Int(Some(v)) => *v,
                _ => 0,
            };
            let pos2 = match rec.get_field(HISTORY_POS2_COL) {
                Field::Int(Some(v)) => *v,
                _ => 0,
            };
            let data = match rec.get_field(HISTORY_STRING_COL) {
                Field::String(Some(v)) => v.clone(),
                _ => String::new(),
            };
            let date = match rec.get_field(HISTORY_DATE_COL) {
                Field::Long(Some(v)) => *v,
                _ => 0,
            };
            self.rows.entry(addr).or_default().push(HistoryRow {
                addr,
                comment_type,
                pos1,
                pos2,
                data,
                date,
            });
            Ok(())
        }

        fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool> {
            let start = start.offset();
            let end = end.offset();
            let before = self.rows.len();
            self.rows.retain(|k, _| *k < start || *k > end);
            Ok(self.rows.len() != before)
        }

        fn get_records_by_address(
            &self,
            addr: &Address,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let rows = self.rows.get(&addr.offset()).cloned().unwrap_or_default();
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
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut adapter: Box<dyn CommentHistoryAdapter> =
            Box::new(MockCommentHistoryAdapter::new());

        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x2000);

        assert_eq!(adapter.get_record_count(), 0);

        adapter
            .create_record(addr1.offset(), 0, 0, 5, "hello", 111)
            .unwrap();
        adapter
            .create_record(addr2.offset(), 1, 0, 3, "world", 222)
            .unwrap();
        assert_eq!(adapter.get_record_count(), 2);

        let mut seen = 0;
        {
            let mut iter = adapter.get_records_by_address(&addr1).unwrap();
            while let Some(rec) = iter.next().unwrap() {
                assert_eq!(
                    rec.get_field(HISTORY_STRING_COL),
                    &crate::framework::db::Field::String(Some("hello".to_string()))
                );
                seen += 1;
            }
        }
        assert_eq!(seen, 1);

        {
            let mut all = adapter.get_all_records().unwrap();
            let mut total = 0;
            while all.next().unwrap().is_some() {
                total += 1;
            }
            assert_eq!(total, 2);
        }

        // Round-trip a record through update_record.
        let updated_rec = {
            let mut iter = adapter.get_records_by_address(&addr2).unwrap();
            iter.next().unwrap().unwrap()
        };
        adapter.update_record(&updated_rec).unwrap();
        assert_eq!(adapter.get_record_count(), 3);

        let deleted = adapter.delete_records(&addr1, &addr1).unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count(), 2);

        let not_deleted = adapter.delete_records(&addr1, &addr1).unwrap();
        assert!(!not_deleted);
    }
}
