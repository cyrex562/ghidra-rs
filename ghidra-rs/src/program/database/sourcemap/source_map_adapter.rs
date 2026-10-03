//! Port of `ghidra.program.database.sourcemap.SourceMapAdapter`.
//!
//! The Java type is an abstract class whose static factory method `getAdapter` selects and
//! constructs a concrete version-specific implementation (`SourceMapAdapterV0`). That concrete
//! adapter has not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/construction logic (which
//! depends on the unported `SourceMapAdapterV0`) belongs with whichever type ends up owning the
//! concrete adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use thiserror::Error;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::model::address::Address;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// DB table name for the source map table. Stands in for `SourceMapAdapter.TABLE_NAME`.
pub const TABLE_NAME: &str = "SourceMap";

/// Source map record column index for the source file id / line number pair. Stands in for
/// `SourceMapAdapter.FILE_LINE_COL` (`SourceMapAdapterV0.V0_FILE_LINE_COL`).
pub const FILE_LINE_COL: usize = 0;
/// Source map record column index for the base address. Stands in for
/// `SourceMapAdapter.BASE_ADDR_COL` (`SourceMapAdapterV0.V0_BASE_ADDR_COL`).
pub const BASE_ADDR_COL: usize = 1;
/// Source map record column index for the range length. Stands in for
/// `SourceMapAdapter.LENGTH_COL` (`SourceMapAdapterV0.V0_LENGTH_COL`).
pub const LENGTH_COL: usize = 2;

/// Error produced by [`SourceMapAdapter::move_address_range`], mirroring the Java method's
/// `throws CancelledException, IOException`.
#[derive(Debug, Error)]
pub enum MoveAddressRangeError {
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Adapter to access the Source Map table.
///
/// Each entry in the table corresponds to a single `SourceMapEntry` and so records a source file,
/// a line number, a base address, and a length. There are a number of restrictions on a
/// `SourceMapEntry`; it is the responsibility of `SourceFileManager` to enforce these
/// restrictions.
///
/// Port of `ghidra.program.database.sourcemap.SourceMapAdapter`.
pub trait SourceMapAdapter {
    /// Removes a record from the table, returning `true` if the record was deleted successfully.
    /// Stands in for `SourceMapAdapter.removeRecord(long)`.
    fn remove_record(&mut self, key: i64) -> io::Result<bool>;

    /// Returns a record iterator based at `addr`. If `before` is `true`, the initial position is
    /// before `addr`, otherwise after. Stands in for
    /// `SourceMapAdapter.getSourceMapRecordIterator(Address, boolean)`.
    fn get_source_map_record_iterator(
        &self,
        addr: &Address,
        before: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns a record iterator over all records for the source file with id `file_id`, subject
    /// to the line bounds `min_line` and `max_line`. Stands in for
    /// `SourceMapAdapter.getRecordsForSourceFile(long, int, int)`.
    fn get_records_for_source_file(
        &self,
        file_id: i64,
        min_line: i32,
        max_line: i32,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Adds an entry to the source map table. This method assumes that no address in the
    /// associated range has already been associated with this source file and line number.
    /// Stands in for `SourceMapAdapter.addMapEntry(long, int, Address, long)`.
    fn add_map_entry(
        &mut self,
        file_id: i64,
        line_num: i32,
        base_addr: &Address,
        length: i64,
    ) -> io::Result<DBRecord>;

    /// Updates all appropriate entries in the table when an address range is moved. Stands in for
    /// `SourceMapAdapter.moveAddressRange(Address, Address, long, TaskMonitor)`.
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
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Long],
            vec!["FileLine".to_string(), "BaseAddr".to_string(), "Length".to_string()],
            vec![FILE_LINE_COL],
        ))
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

    /// Mirrors `SourceMapAdapterV0`'s in-memory semantics closely enough to exercise the trait's
    /// contract: entries are keyed by base address offset, and `move_address_range` shifts every
    /// entry whose base address falls within the moved range.
    struct MockSourceMapAdapter {
        schema: Arc<Schema>,
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockSourceMapAdapter {
        fn new() -> Self {
            MockSourceMapAdapter {
                schema: schema(),
                records: BTreeMap::new(),
                next_key: 0,
            }
        }
    }

    impl SourceMapAdapter for MockSourceMapAdapter {
        fn remove_record(&mut self, key: i64) -> io::Result<bool> {
            Ok(self.records.remove(&key).is_some())
        }

        fn get_source_map_record_iterator(
            &self,
            addr: &Address,
            before: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let cutoff = addr.offset();
            let mut records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|rec| {
                    let base = rec.get_long(BASE_ADDR_COL).unwrap_or(0);
                    if before {
                        base < cutoff
                    }
                    else {
                        base >= cutoff
                    }
                })
                .cloned()
                .collect();
            records.sort_by_key(|rec| rec.get_long(BASE_ADDR_COL).unwrap_or(0));
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_records_for_source_file(
            &self,
            file_id: i64,
            min_line: i32,
            max_line: i32,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|rec| {
                    let file_line = rec.get_long(FILE_LINE_COL).unwrap_or(0);
                    let rec_file_id = file_line >> 32;
                    let rec_line = (file_line & 0xFFFF_FFFF) as i32;
                    rec_file_id == file_id && rec_line >= min_line && rec_line <= max_line
                })
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn add_map_entry(
            &mut self,
            file_id: i64,
            line_num: i32,
            base_addr: &Address,
            length: i64,
        ) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            let file_line = (file_id << 32) | (line_num as i64 & 0xFFFF_FFFF);
            rec.set_field(FILE_LINE_COL, Field::Long(Some(file_line)));
            rec.set_field(BASE_ADDR_COL, Field::Long(Some(base_addr.offset())));
            rec.set_field(LENGTH_COL, Field::Long(Some(length)));
            self.records.insert(key, rec.clone());
            Ok(rec)
        }

        fn move_address_range(
            &mut self,
            from_addr: &Address,
            to_addr: &Address,
            length: i64,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), MoveAddressRangeError> {
            monitor.check_cancelled()?;
            let from = from_addr.offset();
            let to = to_addr.offset();
            for rec in self.records.values_mut() {
                let base = rec.get_long(BASE_ADDR_COL).unwrap_or(0);
                if base >= from && base < from + length {
                    rec.set_field(BASE_ADDR_COL, Field::Long(Some(base - from + to)));
                }
            }
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_moves_entries_in_range() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut adapter: Box<dyn SourceMapAdapter> = Box::new(MockSourceMapAdapter::new());

        let base1 = space.address(0x1000);
        let base2 = space.address(0x2000);
        let rec1 = adapter.add_map_entry(1, 10, &base1, 0x10).unwrap();
        let rec2 = adapter.add_map_entry(1, 20, &base2, 0x10).unwrap();

        let monitor = DummyMonitor;
        let from = space.address(0x1000);
        let to = space.address(0x5000);
        adapter.move_address_range(&from, &to, 0x100, &monitor).unwrap();

        let key1 = match rec1.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key field: {other:?}"),
        };
        let key2 = match rec2.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key field: {other:?}"),
        };

        let mut count = 0;
        {
            let mut iter = adapter
                .get_source_map_record_iterator(&space.address(0), false)
                .unwrap();
            while let Some(_rec) = iter.next().unwrap() {
                count += 1;
            }
        }
        assert_eq!(count, 2);

        let moved = adapter
            .get_records_for_source_file(1, 10, 10)
            .unwrap()
            .next()
            .unwrap()
            .expect("moved record should still be found by file/line");
        assert_eq!(moved.get_key(), &Field::Long(Some(key1)));
        assert_eq!(moved.get_long(BASE_ADDR_COL), Some(0x5000));

        let unmoved = adapter
            .get_records_for_source_file(1, 20, 20)
            .unwrap()
            .next()
            .unwrap()
            .expect("out-of-range record should be unaffected");
        assert_eq!(unmoved.get_key(), &Field::Long(Some(key2)));
        assert_eq!(unmoved.get_long(BASE_ADDR_COL), Some(0x2000));

        assert!(adapter.remove_record(key1).unwrap());
        assert!(!adapter.remove_record(key1).unwrap());
    }
}
