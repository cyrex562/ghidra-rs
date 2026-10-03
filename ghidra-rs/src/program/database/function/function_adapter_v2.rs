//! Port of `ghidra.program.database.function.FunctionAdapterV2`.
//!
//! Read-only legacy adapter for the version 2 function table layout, which dropped a stack
//! parameter offset column (superseded by [`FunctionAdapterV3`]'s calling-convention-derived
//! value) relative to version 3's current schema, and had no calling-convention/return-storage
//! columns worth carrying forward untranslated. Every record is translated to the current
//! [`function_adapter_v3::schema`] shape on read via [`FunctionAdapterV2::translate_record`],
//! mirroring `FunctionAdapterV2.translateRecord(DBRecord)` exactly (including OR-ing in
//! [`crate::program::database::function::function_adapter::FUNCTION_CUSTOM_PARAM_STORAGE_FLAG`],
//! since custom variable storage was implicit -- not yet a toggleable flag -- at this schema
//! version). All mutating operations (`create`/`update`/`remove`) report
//! [`io::ErrorKind::Unsupported`], matching Java's unconditional `UnsupportedOperationException`;
//! `delete_table` is the one mutating operation this version *does* support, deferring to
//! [`DBHandle::delete_table`].
//!
//! This version's own column layout (`V2_*_COL` constants below) is private, matching Java's
//! `private static final` fields of the same name.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::function::function_adapter::{
    FunctionAdapter, TranslatedRecordIterator, CALLING_CONVENTION_ID_COL, FUNCTION_CUSTOM_PARAM_STORAGE_FLAG,
    FUNCTION_FLAGS_COL, RETURN_DATA_TYPE_ID_COL, STACK_LOCAL_SIZE_COL, STACK_PURGE_COL,
    STACK_RETURN_OFFSET_COL,
};
use crate::program::database::function::function_adapter_v3::{schema, FUNCTIONS_TABLE_NAME};
use crate::program::database::map::AddressMap;
use crate::util::exception::VersionException;

const V2_RETURN_DATA_TYPE_ID_COL: usize = 0;
const V2_STACK_PURGE_COL: usize = 1;
#[allow(dead_code)] // Mirrors Java's commented-out/unused V2_STACK_PARAM_OFFSET_COL: kept for
                     // documentation of the historical column layout, not read by translate_record.
const V2_STACK_PARAM_OFFSET_COL: usize = 2;
const V2_STACK_RETURN_OFFSET_COL: usize = 3;
const V2_STACK_LOCAL_SIZE_COL: usize = 4;
const V2_FUNCTION_FLAGS_COL: usize = 5;
const V2_CALLING_CONVENTION_ID_COL: usize = 6;

/// Schema version implemented by this adapter. Mirrors `FunctionAdapterV2.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 2;

/// Read-only legacy adapter for the version 2 function table layout.
///
/// Port of `ghidra.program.database.function.FunctionAdapterV2`.
pub struct FunctionAdapterV2 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl FunctionAdapterV2 {
    /// Opens an existing version 2 function table for read-only/upgrade access.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing, older (upgradable), or newer than
    /// [`SCHEMA_VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
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
        Ok(FunctionAdapterV2 { table, addr_map })
    }
}

impl FunctionAdapter for FunctionAdapterV2 {
    fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(TranslatedRecordIterator::new(
            self,
            Box::new(FixedRecordIterator { records: records.into_iter() }),
        )))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(FUNCTIONS_TABLE_NAME);
        Ok(())
    }

    fn get_version(&self) -> i32 {
        SCHEMA_VERSION
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn remove_function_record(&mut self, _function_key: i64) -> io::Result<()> {
        Err(unsupported())
    }

    fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
        let old = self.table.read().unwrap().get_record(&Field::Long(Some(function_key)))?;
        Ok(old.map(|rec| self.translate_record(rec)))
    }

    fn update_function_record(&mut self, _function_record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    fn create_function_record(&mut self, _symbol_id: i64, _return_data_type_id: i64) -> io::Result<DBRecord> {
        Err(unsupported())
    }

    /// Port of `FunctionAdapterV2.translateRecord(DBRecord)`.
    fn translate_record(&self, record: DBRecord) -> DBRecord {
        let entry_point_key = record.get_key().get_long_value();
        let mut new_record = DBRecord::new(schema(), Field::Long(Some(entry_point_key)));
        new_record.set_long(
            RETURN_DATA_TYPE_ID_COL,
            record.get_long(V2_RETURN_DATA_TYPE_ID_COL).unwrap_or(0),
        );
        new_record.set_int(STACK_PURGE_COL, record.get_int(V2_STACK_PURGE_COL).unwrap_or(0));
        new_record.set_int(
            STACK_RETURN_OFFSET_COL,
            record.get_int(V2_STACK_RETURN_OFFSET_COL).unwrap_or(0),
        );
        new_record.set_int(
            STACK_LOCAL_SIZE_COL,
            record.get_int(V2_STACK_LOCAL_SIZE_COL).unwrap_or(0),
        );
        let old_flags = record.get_byte(V2_FUNCTION_FLAGS_COL).unwrap_or(0);
        new_record.set_byte(
            FUNCTION_FLAGS_COL,
            old_flags | (FUNCTION_CUSTOM_PARAM_STORAGE_FLAG as i8),
        );
        new_record.set_byte(
            CALLING_CONVENTION_ID_COL,
            record.get_byte(V2_CALLING_CONVENTION_ID_COL).unwrap_or(0),
        );
        new_record.set_string(crate::program::database::function::function_adapter::RETURN_STORAGE_COL, None);
        new_record
    }

    fn get_address_map(&self) -> &dyn AddressMap {
        self.addr_map.as_ref()
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not supported for the version 2 function table")
}

struct FixedRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for FixedRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.as_slice().first().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
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

    fn addr_map() -> Arc<dyn AddressMap> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Arc::new(TestAddressMap { space })
    }

    fn v2_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            SCHEMA_VERSION,
            FieldType::Long,
            "ID".to_string(),
            vec![
                FieldType::Long,
                FieldType::Int,
                FieldType::Int,
                FieldType::Int,
                FieldType::Int,
                FieldType::Byte,
                FieldType::Byte,
            ],
            vec![
                "Return DataType ID".to_string(),
                "StackPurge".to_string(),
                "StackParamOffset".to_string(),
                "StackReturnOffset".to_string(),
                "StackLocalSize".to_string(),
                "Flags".to_string(),
                "Calling Convention ID".to_string(),
            ],
            vec![],
        ))
    }

    fn seed_v2_table(handle: &mut DBHandle) {
        let table = handle.create_table(FUNCTIONS_TABLE_NAME.to_string(), v2_schema()).unwrap();
        let mut rec = DBRecord::new(v2_schema(), Field::Long(Some(1)));
        rec.set_long(V2_RETURN_DATA_TYPE_ID_COL, 42);
        rec.set_int(V2_STACK_PURGE_COL, 8);
        rec.set_int(V2_STACK_RETURN_OFFSET_COL, 4);
        rec.set_int(V2_STACK_LOCAL_SIZE_COL, 16);
        rec.set_byte(V2_FUNCTION_FLAGS_COL, 0x1); // vararg flag set
        rec.set_byte(V2_CALLING_CONVENTION_ID_COL, 3);
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn translate_record_maps_old_columns_and_sets_custom_storage_flag() {
        let mut handle = DBHandle::new().unwrap();
        seed_v2_table(&mut handle);
        let adapter = FunctionAdapterV2::new(&handle, addr_map()).unwrap();

        let translated = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(translated.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));
        assert_eq!(translated.get_int(STACK_PURGE_COL), Some(8));
        assert_eq!(translated.get_int(STACK_RETURN_OFFSET_COL), Some(4));
        assert_eq!(translated.get_int(STACK_LOCAL_SIZE_COL), Some(16));
        assert_eq!(
            translated.get_byte(FUNCTION_FLAGS_COL),
            Some(0x1 | FUNCTION_CUSTOM_PARAM_STORAGE_FLAG as i8)
        );
        assert_eq!(translated.get_byte(CALLING_CONVENTION_ID_COL), Some(3));
        assert_eq!(
            translated.get_string(crate::program::database::function::function_adapter::RETURN_STORAGE_COL),
            None
        );
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        seed_v2_table(&mut handle);
        let mut adapter = FunctionAdapterV2::new(&handle, addr_map()).unwrap();
        assert_eq!(
            adapter.create_function_record(1, 1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_function_record(1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let rec = DBRecord::new(schema(), Field::Long(Some(1)));
        assert_eq!(
            adapter.update_function_record(&rec).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn delete_table_removes_the_underlying_table() {
        let mut handle = DBHandle::new().unwrap();
        seed_v2_table(&mut handle);
        let mut adapter = FunctionAdapterV2::new(&handle, addr_map()).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(FUNCTIONS_TABLE_NAME).is_none());
    }

    #[test]
    fn iterate_function_records_translates_every_record() {
        let mut handle = DBHandle::new().unwrap();
        seed_v2_table(&mut handle);
        let adapter = FunctionAdapterV2::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.iterate_function_records().unwrap();
        let rec = iter.next().unwrap().unwrap();
        assert_eq!(rec.get_long(RETURN_DATA_TYPE_ID_COL), Some(42));
        assert!(iter.next().unwrap().is_none());
    }
}
