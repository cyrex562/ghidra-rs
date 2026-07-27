//! Port of `ghidra.program.database.oldfunction.OldFunctionDBAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`)
//! selects between two concrete version-specific implementations (`OldFunctionDBAdapterV0`,
//! `OldFunctionDBAdapterV1`), retrying against the older version on an upgradable
//! `VersionException`. Those concrete adapters have not been ported yet, so this port only models
//! the abstract instance API each version implements, as an object-safe trait; the
//! version-selection logic belongs with whichever type ends up owning the concrete adapters. This
//! follows the same convention already used for
//! [`FunctionAdapter`](crate::program::database::function::FunctionAdapter). This trait was itself
//! selected as a dependency-cycle cut-point.
//!
//! Also left out: the `FUNCTIONS_SCHEMA` constant, since it describes a concrete table layout
//! (delegated to `OldFunctionDBAdapterV1.V1_FUNCTIONS_SCHEMA`) used only by the not-yet-ported
//! `OldFunctionDBAdapterV0`/`V1` classes themselves, rather than this trait's dynamic-dispatch
//! surface -- left for whichever concrete subclass is ported first.
//!
//! Kept, unlike that table-layout constant: the column-index constants
//! (`RETURN_DATA_TYPE_ID_COL`..`REPEATABLE_COMMENT_COL`). Unlike `FUNCTIONS_SCHEMA`, these are read
//! directly by `ghidra.program.database.oldfunction.OldFunctionDataDB` (a real caller outside the
//! `OldFunctionDBAdapter*` hierarchy, not yet ported) to interpret a function record's columns, so
//! they are part of this type's genuine public API surface -- the same reasoning that kept
//! `FunctionAdapter`'s `RETURN_DATA_TYPE_ID_COL` and friends.
//!
//! The protected `addrMap` field (set once via the constructor and read by subclasses) is exposed
//! as [`OldFunctionDBAdapter::get_address_map`], mirroring
//! [`FunctionAdapter::get_address_map`](crate::program::database::function::FunctionAdapter::get_address_map).

use std::io;

use crate::framework::db::{DBHandle, DBRecord, RecordIterator};
use crate::program::database::map::AddressMap;

/// Column index for a function record's return data type ID. Stands in for
/// `OldFunctionDBAdapter.RETURN_DATA_TYPE_ID_COL`.
pub const RETURN_DATA_TYPE_ID_COL: usize = 0;
/// Column index for a function record's stack depth. Stands in for
/// `OldFunctionDBAdapter.STACK_DEPTH_COL`.
pub const STACK_DEPTH_COL: usize = 1;
/// Column index for a function record's stack parameter offset. Stands in for
/// `OldFunctionDBAdapter.STACK_PARAM_OFFSET_COL`.
pub const STACK_PARAM_OFFSET_COL: usize = 2;
/// Column index for a function record's stack return offset. Stands in for
/// `OldFunctionDBAdapter.STACK_RETURN_OFFSET_COL`.
pub const STACK_RETURN_OFFSET_COL: usize = 3;
/// Column index for a function record's stack frame local size. Stands in for
/// `OldFunctionDBAdapter.STACK_LOCAL_SIZE_COL`.
pub const STACK_LOCAL_SIZE_COL: usize = 4;
/// Column index for a function record's repeatable comment. Stands in for
/// `OldFunctionDBAdapter.REPEATABLE_COMMENT_COL`.
pub const REPEATABLE_COMMENT_COL: usize = 5;

/// Database adapter for old (pre-migration) functions.
///
/// Port of `ghidra.program.database.oldfunction.OldFunctionDBAdapter`. See the module docs for
/// what was intentionally left out (the static factory/version-upgrade logic and the concrete
/// table-layout constant).
pub trait OldFunctionDBAdapter {
    /// Deletes this adapter's underlying table from `handle`.
    ///
    /// Stands in for the protected `OldFunctionDBAdapter.deleteTable(DBHandle)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Returns a count of function records.
    ///
    /// Stands in for `OldFunctionDBAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Gets a function record, or `None` if there is no record for `function_key`.
    ///
    /// Stands in for `OldFunctionDBAdapter.getFunctionRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>>;

    /// Gets an iterator over all function records.
    ///
    /// Stands in for `OldFunctionDBAdapter.iterateFunctionRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Gets the map used to convert addresses to longs and longs to addresses.
    ///
    /// Stands in for the protected `OldFunctionDBAdapter.addrMap` field.
    fn get_address_map(&self) -> &dyn AddressMap;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Entry Point".to_string(),
            vec![
                FieldType::Long,
                FieldType::Int,
                FieldType::Int,
                FieldType::Int,
                FieldType::Int,
                FieldType::String,
            ],
            vec![
                "Return DataType ID".to_string(),
                "StackDepth".to_string(),
                "StackParamOffset".to_string(),
                "StackReturnOffset".to_string(),
                "StackLocalSize".to_string(),
                "RepeatableComment".to_string(),
            ],
            vec![],
        ))
    }

    struct VecRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.as_slice().first().is_some()
        }
    }

    /// A minimal in-memory `OldFunctionDBAdapter`, exercising object-safety and the record
    /// get/count/iterate contract described by the Java class.
    struct MockOldFunctionDBAdapter {
        records: BTreeMap<i64, DBRecord>,
    }

    impl MockOldFunctionDBAdapter {
        fn new() -> Self {
            MockOldFunctionDBAdapter {
                records: BTreeMap::new(),
            }
        }

        fn insert(&mut self, key: i64, return_data_type_id: i64, stack_depth: i32) {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(key)));
            record.set_long(RETURN_DATA_TYPE_ID_COL, return_data_type_id);
            record.set_int(STACK_DEPTH_COL, stack_depth);
            self.records.insert(key, record);
        }
    }

    impl OldFunctionDBAdapter for MockOldFunctionDBAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&function_key).cloned())
        }

        fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_address_map(&self) -> &dyn AddressMap {
            unimplemented!("mock does not exercise get_address_map")
        }
    }

    #[test]
    fn object_safe_and_tracks_function_records() {
        let mut mock = MockOldFunctionDBAdapter::new();
        mock.insert(1, 42, 8);
        mock.insert(2, 43, 16);

        let adapter: Box<dyn OldFunctionDBAdapter> = Box::new(mock);

        assert_eq!(adapter.get_record_count(), 2);

        let fetched = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(fetched.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));
        assert_eq!(fetched.get_int(STACK_DEPTH_COL), Some(8));

        assert!(adapter.get_function_record(99).unwrap().is_none());

        let mut count = 0;
        let mut iter = adapter.iterate_function_records().unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn delete_table_clears_all_records() {
        let mut mock = MockOldFunctionDBAdapter::new();
        mock.insert(1, 42, 8);
        assert_eq!(mock.get_record_count(), 1);

        let mut handle = DBHandle::new().unwrap();
        mock.delete_table(&mut handle).unwrap();
        assert_eq!(mock.get_record_count(), 0);
    }
}
