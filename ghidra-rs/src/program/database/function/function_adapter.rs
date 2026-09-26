//! Port of `ghidra.program.database.function.FunctionAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`,
//! plus the private `findReadOnlyAdapter` helper and the `upgrade` migration helper it delegates
//! to) selects and migrates between concrete version-specific implementations
//! (`FunctionAdapterV0`..`V3`). Those concrete adapters have not been ported yet, so this port
//! only models the abstract instance API each version implements, as an object-safe trait; the
//! version-selection/upgrade logic belongs with whichever type ends up owning the concrete
//! adapters. This follows the same convention already used for
//! [`SymbolDatabaseAdapter`](crate::program::database::symbol::SymbolDatabaseAdapter) and
//! [`ProgramTreeDBAdapter`](crate::program::database::module::ProgramTreeDBAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `FUNCTIONS_TABLE_NAME`/`FUNCTION_SCHEMA`/`CURRENT_VERSION` constants,
//! since they describe a concrete table layout used only by the not-yet-ported `FunctionAdapterV0`
//! .. `V3` classes themselves, rather than this trait's dynamic-dispatch surface -- left for
//! whichever concrete subclass is ported first.
//!
//! Kept, unlike those table-layout constants: the column-index constants
//! (`RETURN_DATA_TYPE_ID_COL`..`RETURN_STORAGE_COL`), the function-flag bit constants
//! (`FUNCTION_VARARG_FLAG`..`FUNCTION_SIGNATURE_SOURCE_SHIFT`), and
//! [`get_signature_source_flag_bits`]. Unlike the table-layout constants, these are read and
//! written directly by `ghidra.program.database.function.FunctionDB` (a real caller outside the
//! `FunctionAdapter*` hierarchy, not yet ported) to interpret a function record's flags byte, so
//! they are part of this type's genuine public API surface -- the same reasoning that kept
//! `SymbolDatabaseAdapter`'s `SYMBOL_SOURCE_LO_BITS`/`get_source_type_flags_bits` and friends.
//!
//! The protected `addrMap` field (set once via the constructor and read by subclasses) is exposed
//! as [`FunctionAdapter::get_address_map`], mirroring how
//! [`TreeManager::get_address_map`](crate::program::database::module::TreeManager::get_address_map)
//! stands in for an analogous protected/private field elsewhere in this package.
//!
//! The nested `TranslatedRecordIterator` class (which adapts a raw `RecordIterator` by running
//! each record through the owning adapter's `translateRecord`) is ported as the free-standing
//! [`TranslatedRecordIterator`] struct, generic over any `&dyn FunctionAdapter` rather than tied to
//! a `this` reference, since Rust has no implicit outer-class capture.

use std::io;

use crate::framework::db::{DBHandle, DBRecord, RecordIterator};
use crate::program::database::map::AddressMap;
use crate::program::model::symbol::SourceType;

/// Column index for a function record's return data type ID. Stands in for
/// `FunctionAdapter.RETURN_DATA_TYPE_ID_COL`.
pub const RETURN_DATA_TYPE_ID_COL: usize = 0;
/// Column index for a function record's stack purge size. Stands in for
/// `FunctionAdapter.STACK_PURGE_COL`.
pub const STACK_PURGE_COL: usize = 1;
/// Column index for a function record's stack return offset. Stands in for
/// `FunctionAdapter.STACK_RETURN_OFFSET_COL`.
pub const STACK_RETURN_OFFSET_COL: usize = 2;
/// Column index for a function record's stack frame local size. Stands in for
/// `FunctionAdapter.STACK_LOCAL_SIZE_COL`.
pub const STACK_LOCAL_SIZE_COL: usize = 3;
/// Column index for a function record's flags byte. Stands in for
/// `FunctionAdapter.FUNCTION_FLAGS_COL`.
pub const FUNCTION_FLAGS_COL: usize = 4;
/// Column index for a function record's calling convention ID. Stands in for
/// `FunctionAdapter.CALLING_CONVENTION_ID_COL`.
pub const CALLING_CONVENTION_ID_COL: usize = 5;
/// Column index for a function record's serialized return storage. Stands in for
/// `FunctionAdapter.RETURN_STORAGE_COL`.
pub const RETURN_STORAGE_COL: usize = 6;

/// Bit 0 of the function flags byte: flag for "has vararg". Stands in for
/// `FunctionAdapter.FUNCTION_VARARG_FLAG`.
pub const FUNCTION_VARARG_FLAG: u8 = 0x1;
/// Bit 1 of the function flags byte: flag for "is inline". Stands in for
/// `FunctionAdapter.FUNCTION_INLINE_FLAG`.
pub const FUNCTION_INLINE_FLAG: u8 = 0x2;
/// Bit 2 of the function flags byte: flag for "has no return". Stands in for
/// `FunctionAdapter.FUNCTION_NO_RETURN_FLAG`.
pub const FUNCTION_NO_RETURN_FLAG: u8 = 0x4;
/// Bit 3 of the function flags byte: flag for "has custom storage". Stands in for
/// `FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG`.
pub const FUNCTION_CUSTOM_PARAM_STORAGE_FLAG: u8 = 0x8;
/// Bits 4-6 of the function flags byte: storage for the signature's [`SourceType`]. Stands in for
/// `FunctionAdapter.FUNCTION_SIGNATURE_SOURCE`.
pub const FUNCTION_SIGNATURE_SOURCE: u8 = 0x70;
/// Bit shift for the signature-[`SourceType`] flag storage. Stands in for
/// `FunctionAdapter.FUNCTION_SIGNATURE_SOURCE_SHIFT`.
pub const FUNCTION_SIGNATURE_SOURCE_SHIFT: u32 = 4;

/// Value limit based upon 3-bit storage capacity. Stands in for
/// `FunctionAdapter.MAX_SOURCE_VALUE`.
const MAX_SOURCE_VALUE: i32 = 7;

/// Encodes `signature_source`'s storage ID into the shifted flag bits used by
/// [`FUNCTION_SIGNATURE_SOURCE`] within a function record's flags byte.
///
/// Stands in for `FunctionAdapter.getSignatureSourceFlagBits(SourceType)`.
///
/// # Errors
///
/// Returns an error if `signature_source`'s storage ID exceeds [`MAX_SOURCE_VALUE`] (mirrors the
/// Java method's unchecked `RuntimeException`).
pub fn get_signature_source_flag_bits(signature_source: SourceType) -> Result<u8, String> {
    let source_type_id = signature_source.storage_id();
    if source_type_id > MAX_SOURCE_VALUE {
        return Err(format!("Unsupported SourceType storage ID: {source_type_id}"));
    }
    Ok(((source_type_id as u32) << FUNCTION_SIGNATURE_SOURCE_SHIFT) as u8)
}

/// Database adapter for functions.
///
/// Port of `ghidra.program.database.function.FunctionAdapter`. See the module docs for what was
/// intentionally left out (the static factory/version-upgrade logic and the concrete table-layout
/// constants).
pub trait FunctionAdapter {
    /// Gets an iterator over all function records.
    ///
    /// Stands in for `FunctionAdapter.iterateFunctionRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Deletes this adapter's underlying table from `handle`.
    ///
    /// Stands in for `FunctionAdapter.deleteTable(DBHandle)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Gets the version of this adapter's underlying table schema.
    ///
    /// Stands in for `FunctionAdapter.getVersion()`.
    fn get_version(&self) -> i32;

    /// Returns a count of function records.
    ///
    /// Stands in for `FunctionAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Removes a function record.
    ///
    /// Stands in for `FunctionAdapter.removeFunctionRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_function_record(&mut self, function_key: i64) -> io::Result<()>;

    /// Gets a function record, or `None` if there is no record for `function_key`.
    ///
    /// Stands in for `FunctionAdapter.getFunctionRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>>;

    /// Update/insert the specified function record.
    ///
    /// Stands in for `FunctionAdapter.updateFunctionRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_function_record(&mut self, function_record: &DBRecord) -> io::Result<()>;

    /// Creates a new function record for the given symbol ID and return data type ID.
    ///
    /// Stands in for `FunctionAdapter.createFunctionRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_function_record(&mut self, symbol_id: i64, return_data_type_id: i64) -> io::Result<DBRecord>;

    /// Translates an older-schema-version function record to the current schema version.
    ///
    /// Stands in for `FunctionAdapter.translateRecord(DBRecord)`.
    fn translate_record(&self, record: DBRecord) -> DBRecord;

    /// Gets the map used to convert addresses to longs and longs to addresses.
    ///
    /// Stands in for the protected `FunctionAdapter.addrMap` field.
    fn get_address_map(&self) -> &dyn AddressMap;
}

/// Wraps a raw [`RecordIterator`], running each yielded record through `adapter`'s
/// [`FunctionAdapter::translate_record`].
///
/// Port of `FunctionAdapter.TranslatedRecordIterator`. See the module docs for why this is a
/// free-standing struct rather than a nested class tied to an implicit `this`.
pub struct TranslatedRecordIterator<'a> {
    adapter: &'a dyn FunctionAdapter,
    inner: Box<dyn RecordIterator + 'a>,
}

impl<'a> TranslatedRecordIterator<'a> {
    /// Creates a new iterator adapting `inner`'s records via `adapter`'s `translate_record`.
    pub fn new(adapter: &'a dyn FunctionAdapter, inner: Box<dyn RecordIterator + 'a>) -> Self {
        TranslatedRecordIterator { adapter, inner }
    }
}

impl<'a> RecordIterator for TranslatedRecordIterator<'a> {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.inner.next()?.map(|record| self.adapter.translate_record(record)))
    }

    fn has_next(&self) -> bool {
        self.inner.has_next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            3,
            FieldType::Long,
            "ID".to_string(),
            vec![
                FieldType::Long,
                FieldType::Int,
                FieldType::Int,
                FieldType::Int,
                FieldType::Byte,
                FieldType::Byte,
                FieldType::String,
            ],
            vec![
                "Return DataType ID".to_string(),
                "StackPurge".to_string(),
                "StackReturnOffset".to_string(),
                "StackLocalSize".to_string(),
                "Flags".to_string(),
                "Calling Convention ID".to_string(),
                "Return Storage".to_string(),
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

    /// A minimal in-memory `FunctionAdapter`, exercising object-safety and the record
    /// create/get/update/remove/iterate contract described by the Java class. Its
    /// `translate_record` bumps `RETURN_DATA_TYPE_ID_COL` by 1000, simulating an older-version
    /// adapter's record translation.
    struct MockFunctionAdapter {
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockFunctionAdapter {
        fn new() -> Self {
            MockFunctionAdapter {
                records: BTreeMap::new(),
                next_key: 0,
            }
        }
    }

    impl FunctionAdapter for MockFunctionAdapter {
        fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }

        fn get_version(&self) -> i32 {
            3
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn remove_function_record(&mut self, function_key: i64) -> io::Result<()> {
            self.records.remove(&function_key);
            Ok(())
        }

        fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&function_key).cloned())
        }

        fn update_function_record(&mut self, function_record: &DBRecord) -> io::Result<()> {
            let key = match function_record.get_key() {
                Field::Long(Some(v)) => *v,
                _ => return Ok(()),
            };
            self.records.insert(key, function_record.clone());
            Ok(())
        }

        fn create_function_record(&mut self, symbol_id: i64, return_data_type_id: i64) -> io::Result<DBRecord> {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(symbol_id)));
            record.set_long(RETURN_DATA_TYPE_ID_COL, return_data_type_id);
            record.set_byte(
                FUNCTION_FLAGS_COL,
                get_signature_source_flag_bits(SourceType::Default).unwrap() as i8,
            );
            self.records.insert(symbol_id, record.clone());
            self.next_key = self.next_key.max(symbol_id + 1);
            Ok(record)
        }

        fn translate_record(&self, record: DBRecord) -> DBRecord {
            let mut translated = record;
            let old = translated.get_long(RETURN_DATA_TYPE_ID_COL).unwrap_or(0);
            translated.set_long(RETURN_DATA_TYPE_ID_COL, old + 1000);
            translated
        }

        fn get_address_map(&self) -> &dyn AddressMap {
            unimplemented!("mock does not exercise get_address_map")
        }
    }

    #[test]
    fn object_safe_and_tracks_function_records() {
        let mut adapter: Box<dyn FunctionAdapter> = Box::new(MockFunctionAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.get_function_record(0).unwrap().is_none());

        let rec1 = adapter.create_function_record(1, 42).unwrap();
        adapter.create_function_record(2, 43).unwrap();
        assert_eq!(adapter.get_record_count(), 2);
        assert_eq!(rec1.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));

        let fetched = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(fetched.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));

        let mut updated = fetched;
        updated.set_int(STACK_PURGE_COL, 8);
        adapter.update_function_record(&updated).unwrap();
        let refetched = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(refetched.get_int(STACK_PURGE_COL), Some(8));

        {
            let mut count = 0;
            let mut iter = adapter.iterate_function_records().unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 2);
        }

        adapter.remove_function_record(2).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.get_function_record(2).unwrap().is_none());
    }

    #[test]
    fn translated_record_iterator_runs_records_through_translate_record() {
        let mut mock = MockFunctionAdapter::new();
        mock.create_function_record(1, 10).unwrap();
        mock.create_function_record(2, 20).unwrap();

        let inner = mock.iterate_function_records().unwrap();
        let mut translated_iter = TranslatedRecordIterator::new(&mock, inner);

        let mut seen = Vec::new();
        while let Some(rec) = translated_iter.next().unwrap() {
            seen.push(rec.get_long(RETURN_DATA_TYPE_ID_COL).unwrap());
        }
        seen.sort();
        assert_eq!(seen, vec![1010, 1020]);
    }

    #[test]
    fn get_signature_source_flag_bits_shifts_storage_id_into_place() {
        // SourceType::Analysis has storage ID 0.
        assert_eq!(
            get_signature_source_flag_bits(SourceType::Analysis).unwrap(),
            0
        );
        // SourceType::AI has storage ID 4, so bits land at (4 << 4) = 0x40, fitting within the
        // FUNCTION_SIGNATURE_SOURCE (0x70) mask.
        let bits = get_signature_source_flag_bits(SourceType::AI).unwrap();
        assert_eq!(bits, 0x40);
        assert_eq!(bits & !FUNCTION_SIGNATURE_SOURCE, 0);
    }
}
