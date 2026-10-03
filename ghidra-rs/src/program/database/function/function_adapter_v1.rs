//! Port of `ghidra.program.database.function.FunctionAdapterV1`.
//!
//! Read-only legacy adapter for the version 1 function table layout, one step further back than
//! [`FunctionAdapterV2`](crate::program::database::function::FunctionAdapterV2): this version has
//! no calling-convention column at all (translated records get
//! [`CALLING_CONVENTION_ID_COL`](crate::program::database::function::function_adapter::CALLING_CONVENTION_ID_COL)
//! hard-coded to `0`), but is otherwise structurally identical to version 2. See
//! [`FunctionAdapterV2`]'s module docs for the shared rationale (translate-on-read, unsupported
//! mutations, supported `delete_table`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::function::function_adapter::{
    FunctionAdapter, TranslatedRecordIterator, CALLING_CONVENTION_ID_COL, FUNCTION_CUSTOM_PARAM_STORAGE_FLAG,
    FUNCTION_FLAGS_COL, RETURN_DATA_TYPE_ID_COL, RETURN_STORAGE_COL, STACK_LOCAL_SIZE_COL, STACK_PURGE_COL,
    STACK_RETURN_OFFSET_COL,
};
use crate::program::database::function::function_adapter_v3::{schema, FUNCTIONS_TABLE_NAME};
use crate::program::database::map::AddressMap;
use crate::util::exception::VersionException;

const V1_RETURN_DATA_TYPE_ID_COL: usize = 0;
const V1_STACK_PURGE_COL: usize = 1;
#[allow(dead_code)] // Mirrors Java's unused V1_STACK_PARAM_OFFSET_COL; see FunctionAdapterV2.
const V1_STACK_PARAM_OFFSET_COL: usize = 2;
const V1_STACK_RETURN_OFFSET_COL: usize = 3;
const V1_STACK_LOCAL_SIZE_COL: usize = 4;
const V1_FUNCTION_FLAGS_COL: usize = 5;

/// Schema version implemented by this adapter. Mirrors `FunctionAdapterV1.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 1;

/// Read-only legacy adapter for the version 1 function table layout.
///
/// Port of `ghidra.program.database.function.FunctionAdapterV1`.
pub struct FunctionAdapterV1 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl FunctionAdapterV1 {
    /// Opens an existing version 1 function table for read-only/upgrade access.
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
        Ok(FunctionAdapterV1 { table, addr_map })
    }
}

impl FunctionAdapter for FunctionAdapterV1 {
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

    /// Port of `FunctionAdapterV1.translateRecord(DBRecord)`.
    fn translate_record(&self, record: DBRecord) -> DBRecord {
        let entry_point_key = record.get_key().get_long_value();
        let mut new_record = DBRecord::new(schema(), Field::Long(Some(entry_point_key)));
        new_record.set_long(
            RETURN_DATA_TYPE_ID_COL,
            record.get_long(V1_RETURN_DATA_TYPE_ID_COL).unwrap_or(0),
        );
        new_record.set_int(STACK_PURGE_COL, record.get_int(V1_STACK_PURGE_COL).unwrap_or(0));
        new_record.set_int(
            STACK_RETURN_OFFSET_COL,
            record.get_int(V1_STACK_RETURN_OFFSET_COL).unwrap_or(0),
        );
        new_record.set_int(
            STACK_LOCAL_SIZE_COL,
            record.get_int(V1_STACK_LOCAL_SIZE_COL).unwrap_or(0),
        );
        let old_flags = record.get_byte(V1_FUNCTION_FLAGS_COL).unwrap_or(0);
        new_record.set_byte(
            FUNCTION_FLAGS_COL,
            old_flags | (FUNCTION_CUSTOM_PARAM_STORAGE_FLAG as i8),
        );
        new_record.set_byte(CALLING_CONVENTION_ID_COL, 0);
        new_record.set_string(RETURN_STORAGE_COL, None);
        new_record
    }

    fn get_address_map(&self) -> &dyn AddressMap {
        self.addr_map.as_ref()
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not supported for the version 1 function table")
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

    fn v1_schema() -> Arc<Schema> {
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
            ],
            vec![
                "Return DataType ID".to_string(),
                "StackPurge".to_string(),
                "StackParamOffset".to_string(),
                "StackReturnOffset".to_string(),
                "StackLocalSize".to_string(),
                "Flags".to_string(),
            ],
            vec![],
        ))
    }

    fn seed_v1_table(handle: &mut DBHandle) {
        let table = handle.create_table(FUNCTIONS_TABLE_NAME.to_string(), v1_schema()).unwrap();
        let mut rec = DBRecord::new(v1_schema(), Field::Long(Some(1)));
        rec.set_long(V1_RETURN_DATA_TYPE_ID_COL, 7);
        rec.set_int(V1_STACK_PURGE_COL, 4);
        rec.set_int(V1_STACK_RETURN_OFFSET_COL, 8);
        rec.set_int(V1_STACK_LOCAL_SIZE_COL, 24);
        rec.set_byte(V1_FUNCTION_FLAGS_COL, 0x2); // inline flag set
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn translate_record_maps_old_columns_and_zeroes_calling_convention() {
        let mut handle = DBHandle::new().unwrap();
        seed_v1_table(&mut handle);
        let adapter = FunctionAdapterV1::new(&handle, addr_map()).unwrap();

        let translated = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(translated.get_long(RETURN_DATA_TYPE_ID_COL), Some(7));
        assert_eq!(translated.get_int(STACK_PURGE_COL), Some(4));
        assert_eq!(translated.get_int(STACK_RETURN_OFFSET_COL), Some(8));
        assert_eq!(translated.get_int(STACK_LOCAL_SIZE_COL), Some(24));
        assert_eq!(
            translated.get_byte(FUNCTION_FLAGS_COL),
            Some(0x2 | FUNCTION_CUSTOM_PARAM_STORAGE_FLAG as i8)
        );
        assert_eq!(translated.get_byte(CALLING_CONVENTION_ID_COL), Some(0));
        assert_eq!(translated.get_string(RETURN_STORAGE_COL), None);
    }

    #[test]
    fn mutating_operations_are_unsupported_but_delete_table_works() {
        let mut handle = DBHandle::new().unwrap();
        seed_v1_table(&mut handle);
        let mut adapter = FunctionAdapterV1::new(&handle, addr_map()).unwrap();
        assert_eq!(
            adapter.create_function_record(1, 1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_function_record(1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(FUNCTIONS_TABLE_NAME).is_none());
    }
}
