//! Port of `ghidra.program.database.code.CommentHistoryAdapterNoTable`.
//!
//! Adapter needed for a read-only version of a program that is not going to be upgraded, and
//! there is no comment history table in the program.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::code::comment_history_adapter::CommentHistoryAdapter;
use crate::program::model::address::Address;

/// A `RecordIterator` that never yields any records, used in place of the unported
/// `ghidra.program.database.util.EmptyRecordIterator`, mirroring the convention already used by
/// e.g. [`LabelHistoryAdapterNoTable`](crate::program::database::symbol::LabelHistoryAdapterNoTable).
struct EmptyRecordIterator;

impl RecordIterator for EmptyRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(None)
    }

    fn has_next(&self) -> bool {
        false
    }
}

/// Adapter needed for a read-only version of a program that is not going to be upgraded, and
/// there is no comment history table in the program.
///
/// Port of `ghidra.program.database.code.CommentHistoryAdapterNoTable`.
#[derive(Debug, Default)]
pub struct CommentHistoryAdapterNoTable;

impl CommentHistoryAdapterNoTable {
    /// Constructs a new no-table adapter. The Java class has an implicit no-arg constructor.
    pub fn new() -> Self {
        CommentHistoryAdapterNoTable
    }
}

impl CommentHistoryAdapter for CommentHistoryAdapterNoTable {
    fn get_record_count(&self) -> i32 {
        0
    }

    fn create_record(
        &mut self,
        _addr: i64,
        _comment_type: i8,
        _pos1: i32,
        _pos2: i32,
        _data: &str,
        _date: i64,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no comment history table exists",
        ))
    }

    fn update_record(&mut self, _rec: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no comment history table exists",
        ))
    }

    fn delete_records(&mut self, _start: &Address, _end: &Address) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no comment history table exists",
        ))
    }

    fn get_records_by_address(&self, _addr: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }

    fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(EmptyRecordIterator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn lookups_are_empty_or_zero() {
        let adapter = CommentHistoryAdapterNoTable::new();
        assert_eq!(adapter.get_record_count(), 0);

        let mut iter = adapter.get_all_records().unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut iter = adapter.get_records_by_address(&space.address(0x1000)).unwrap();
        assert!(!iter.has_next());
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn mutations_are_unsupported() {
        let mut adapter = CommentHistoryAdapterNoTable::new();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        assert_eq!(
            adapter
                .create_record(0x1000, 0, 0, 5, "hello", 111)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter
                .delete_records(&space.address(0), &space.address(0x100))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut adapter: Box<dyn CommentHistoryAdapter> =
            Box::new(CommentHistoryAdapterNoTable::new());
        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.create_record(0, 0, 0, 0, "x", 0).is_err());
    }
}
