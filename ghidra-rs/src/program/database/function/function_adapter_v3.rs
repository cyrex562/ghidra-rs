//! Port of `ghidra.program.database.function.FunctionAdapterV3`.
//!
//! Version 3 (current) implementation for accessing the function database table, backed by a
//! live, writable [`Table`]. Mirrors the shape already established by
//! [`SymbolDatabaseAdapterV5`](crate::program::database::symbol::SymbolDatabaseAdapterV5) and
//! [`ThunkFunctionAdapterV0`](crate::program::database::function::ThunkFunctionAdapterV0).
//!
//! This version introduced the Return Storage column (upgraded from older versions by
//! `FunctionManagerDB.programReady`, not yet ported) and dropped the parameter-offset column in
//! favor of deriving that value from the calling convention; it also added the custom-storage-flag
//! and signature-source-type function flags. [`FUNCTIONS_TABLE_NAME`]/[`schema`] (this concrete
//! table's layout) are defined here rather than on the abstract
//! [`FunctionAdapter`](crate::program::database::function::FunctionAdapter) trait, matching that
//! trait's own documented reasoning for leaving them out (they describe a concrete table, not the
//! trait's dynamic-dispatch surface) -- `FunctionAdapterV0`/`V1`/`V2` reuse [`schema`] as their
//! `translateRecord` target schema, exactly like the Java classes reference
//! `FunctionAdapter.FUNCTION_SCHEMA`.
//!
//! `deleteTable`/`translateRecord` are unconditional `UnsupportedOperationException`s in Java
//! (the current version's table is dropped by whichever caller manages schema migration, not by
//! this adapter, and there is no older schema to translate *from* here). `delete_table` reports
//! [`io::ErrorKind::Unsupported`] (matching the `io::Result`-returning trait method); Java's
//! unchecked-exception `translateRecord` override has no such conversion available (the trait
//! method returns a bare `DBRecord`, not a `Result`), so [`FunctionAdapterV3::translate_record`]
//! panics instead, documented on the impl.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::data::calling_convention_db_adapter::UNKNOWN_CALLING_CONVENTION_ID;
use crate::program::database::function::function_adapter::{
    get_signature_source_flag_bits, FunctionAdapter, CALLING_CONVENTION_ID_COL,
    FUNCTION_FLAGS_COL, RETURN_DATA_TYPE_ID_COL, STACK_PURGE_COL,
};
use crate::program::database::map::AddressMap;
use crate::program::model::listing::function::UNKNOWN_STACK_DEPTH_CHANGE;
use crate::program::model::symbol::SourceType;
use crate::util::exception::VersionException;

/// Name of the function database table. Mirrors `FunctionAdapter.FUNCTIONS_TABLE_NAME`.
pub const FUNCTIONS_TABLE_NAME: &str = "Function Data";

/// Schema version implemented by this adapter. Mirrors `FunctionAdapterV3.SCHEMA_VERSION` (which
/// also serves as `FunctionAdapter.CURRENT_VERSION`).
pub const SCHEMA_VERSION: i32 = 3;

/// Build the current function table schema, as defined by `FunctionAdapter.FUNCTION_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
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

/// Version 3 (current) implementation for accessing the function database table.
///
/// Port of `ghidra.program.database.function.FunctionAdapterV3`.
pub struct FunctionAdapterV3 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl FunctionAdapterV3 {
    /// Gets a version 3 adapter for the function table. If `create` is `true`, the table is
    /// created, otherwise an existing table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table that is missing, older
    /// (upgradable), or newer than [`SCHEMA_VERSION`].
    pub fn new(
        handle: &mut DBHandle,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(FUNCTIONS_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(FUNCTIONS_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {FUNCTIONS_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != SCHEMA_VERSION {
                if version < SCHEMA_VERSION {
                    return Err(VersionException::with_upgradeable(true));
                }
                return Err(VersionException::with_version_indicator(
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
            table
        };
        Ok(FunctionAdapterV3 { table, addr_map })
    }
}

impl FunctionAdapter for FunctionAdapterV3 {
    fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    /// Port of `FunctionAdapterV3.deleteTable(DBHandle)`: unconditionally unsupported.
    fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "deleteTable is not supported for the current function table version",
        ))
    }

    fn get_version(&self) -> i32 {
        SCHEMA_VERSION
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn remove_function_record(&mut self, function_key: i64) -> io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(function_key)))?;
        Ok(())
    }

    fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(function_key)))
    }

    fn update_function_record(&mut self, function_record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(function_record.clone())
    }

    fn create_function_record(&mut self, symbol_id: i64, return_data_type_id: i64) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(symbol_id)));
        let flag_bits = get_signature_source_flag_bits(SourceType::Default)
            .map_err(|msg| io::Error::new(io::ErrorKind::InvalidData, msg))?;
        rec.set_byte(FUNCTION_FLAGS_COL, flag_bits as i8);
        rec.set_long(RETURN_DATA_TYPE_ID_COL, return_data_type_id);
        rec.set_byte(CALLING_CONVENTION_ID_COL, UNKNOWN_CALLING_CONVENTION_ID as i8);
        rec.set_int(STACK_PURGE_COL, UNKNOWN_STACK_DEPTH_CHANGE);
        self.table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
    }

    /// Port of `FunctionAdapterV3.translateRecord(DBRecord)`: unconditionally unsupported. Unlike
    /// [`FunctionAdapterV3::delete_table`], the trait method this implements
    /// (`FunctionAdapter::translate_record`) returns a bare `DBRecord` with no `Result`, so this
    /// panics rather than erroring, matching the unchecked `UnsupportedOperationException` Java
    /// throws (the current schema version has no older record shape to translate from).
    ///
    /// # Panics
    /// Always.
    fn translate_record(&self, _record: DBRecord) -> DBRecord {
        panic!("translateRecord is not supported for the current function table version");
    }

    fn get_address_map(&self) -> &dyn AddressMap {
        self.addr_map.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };

    struct TestAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for TestAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(TestAddressMap { space: self.space.clone() })
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    pub(crate) fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(TestAddressMap { space: ram_space() })
    }

    #[test]
    fn create_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionAdapterV3::new(&mut handle, addr_map(), true).unwrap();
        assert_eq!(adapter.get_version(), 3);
        assert_eq!(adapter.get_record_count(), 0);

        let rec = adapter.create_function_record(1, 42).unwrap();
        assert_eq!(rec.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));
        assert_eq!(rec.get_int(STACK_PURGE_COL), Some(UNKNOWN_STACK_DEPTH_CHANGE));
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(fetched.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));

        adapter.remove_function_record(1).unwrap();
        assert!(adapter.get_function_record(1).unwrap().is_none());
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn delete_table_and_translate_record_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = FunctionAdapterV3::new(&mut handle, addr_map(), true).unwrap();
        let mut other_handle = DBHandle::new().unwrap();
        assert_eq!(
            adapter.delete_table(&mut other_handle).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    #[should_panic(expected = "translateRecord is not supported")]
    fn translate_record_panics() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = FunctionAdapterV3::new(&mut handle, addr_map(), true).unwrap();
        let rec = DBRecord::new(schema(), Field::Long(Some(1)));
        let _ = adapter.translate_record(rec);
    }

    #[test]
    fn reopening_missing_table_reports_version_exception() {
        let mut handle = DBHandle::new().unwrap();
        match FunctionAdapterV3::new(&mut handle, addr_map(), false) {
            Ok(_) => panic!("expected a VersionException for a missing table"),
            Err(_) => {}
        }
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn FunctionAdapter> =
            Box::new(FunctionAdapterV3::new(&mut handle, addr_map(), true).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
    }
}
