//! Port of `ghidra.program.database.function.FunctionAdapterV0`.
//!
//! Read-only legacy adapter for the version 0 (original) function table layout: no flags column
//! at all yet, so translated records get
//! [`FUNCTION_CUSTOM_PARAM_STORAGE_FLAG`](crate::program::database::function::function_adapter::FUNCTION_CUSTOM_PARAM_STORAGE_FLAG)
//! as the *entire* flags byte (there is no old flags value to OR it into, unlike
//! [`FunctionAdapterV1`](crate::program::database::function::FunctionAdapterV1)/
//! [`FunctionAdapterV2`](crate::program::database::function::FunctionAdapterV2)) and
//! [`CALLING_CONVENTION_ID_COL`](crate::program::database::function::function_adapter::CALLING_CONVENTION_ID_COL)
//! hard-coded to `0`. See [`FunctionAdapterV2`]'s module docs for the shared rationale
//! (translate-on-read, unsupported mutations, supported `delete_table`).
//!
//! The version check in the Java constructor collapses the older/newer distinction the other
//! versions make into a single non-upgradable mismatch (`throw new VersionException(false)`,
//! i.e. [`VersionException::UNKNOWN_VERSION`]) rather than branching on `version <
//! SCHEMA_VERSION`/`NEWER_VERSION` -- ported here as-is, since version 0 is already the oldest
//! schema (there is no older version for the upgradable branch to make sense for).

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

const V0_RETURN_DATA_TYPE_ID_COL: usize = 0;
const V0_STACK_PURGE_COL: usize = 1;
#[allow(dead_code)] // Mirrors Java's unused V0_STACK_PARAM_OFFSET_COL; see FunctionAdapterV2.
const V0_STACK_PARAM_OFFSET_COL: usize = 2;
const V0_STACK_RETURN_OFFSET_COL: usize = 3;
const V0_STACK_LOCAL_SIZE_COL: usize = 4;

/// Schema version implemented by this adapter. Mirrors `FunctionAdapterV0.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 0;

/// Read-only legacy adapter for the version 0 (original) function table layout.
///
/// Port of `ghidra.program.database.function.FunctionAdapterV0`.
pub struct FunctionAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl FunctionAdapterV0 {
    /// Opens an existing version 0 function table for read-only/upgrade access.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing or its schema version does not
    /// match [`SCHEMA_VERSION`] (see the module docs for why this collapses to a single
    /// "unknown version" indicator rather than branching on older/newer).
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(FUNCTIONS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {FUNCTIONS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != SCHEMA_VERSION {
            return Err(VersionException::with_upgradeable(false));
        }
        Ok(FunctionAdapterV0 { table, addr_map })
    }
}

impl FunctionAdapter for FunctionAdapterV0 {
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

    /// Port of `FunctionAdapterV0.translateRecord(DBRecord)`.
    fn translate_record(&self, record: DBRecord) -> DBRecord {
        let entry_point_key = record.get_key().get_long_value();
        let mut new_record = DBRecord::new(schema(), Field::Long(Some(entry_point_key)));
        new_record.set_long(
            RETURN_DATA_TYPE_ID_COL,
            record.get_long(V0_RETURN_DATA_TYPE_ID_COL).unwrap_or(0),
        );
        new_record.set_int(STACK_PURGE_COL, record.get_int(V0_STACK_PURGE_COL).unwrap_or(0));
        new_record.set_int(
            STACK_RETURN_OFFSET_COL,
            record.get_int(V0_STACK_RETURN_OFFSET_COL).unwrap_or(0),
        );
        new_record.set_int(
            STACK_LOCAL_SIZE_COL,
            record.get_int(V0_STACK_LOCAL_SIZE_COL).unwrap_or(0),
        );
        new_record.set_byte(FUNCTION_FLAGS_COL, FUNCTION_CUSTOM_PARAM_STORAGE_FLAG as i8);
        new_record.set_byte(CALLING_CONVENTION_ID_COL, 0);
        new_record.set_string(RETURN_STORAGE_COL, None);
        new_record
    }

    fn get_address_map(&self) -> &dyn AddressMap {
        self.addr_map.as_ref()
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not supported for the version 0 function table")
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

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            SCHEMA_VERSION,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Long, FieldType::Int, FieldType::Int, FieldType::Int, FieldType::Int],
            vec![
                "Return DataType ID".to_string(),
                "StackPurge".to_string(),
                "StackParamOffset".to_string(),
                "StackReturnOffset".to_string(),
                "StackLocalSize".to_string(),
            ],
            vec![],
        ))
    }

    fn seed_v0_table(handle: &mut DBHandle) {
        let table = handle.create_table(FUNCTIONS_TABLE_NAME.to_string(), v0_schema()).unwrap();
        let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(1)));
        rec.set_long(V0_RETURN_DATA_TYPE_ID_COL, 5);
        rec.set_int(V0_STACK_PURGE_COL, 2);
        rec.set_int(V0_STACK_RETURN_OFFSET_COL, 4);
        rec.set_int(V0_STACK_LOCAL_SIZE_COL, 12);
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn translate_record_sets_custom_storage_flag_unconditionally() {
        let mut handle = DBHandle::new().unwrap();
        seed_v0_table(&mut handle);
        let adapter = FunctionAdapterV0::new(&handle, addr_map()).unwrap();

        let translated = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(translated.get_long(RETURN_DATA_TYPE_ID_COL), Some(5));
        assert_eq!(translated.get_int(STACK_PURGE_COL), Some(2));
        assert_eq!(translated.get_int(STACK_RETURN_OFFSET_COL), Some(4));
        assert_eq!(translated.get_int(STACK_LOCAL_SIZE_COL), Some(12));
        assert_eq!(
            translated.get_byte(FUNCTION_FLAGS_COL),
            Some(FUNCTION_CUSTOM_PARAM_STORAGE_FLAG as i8)
        );
        assert_eq!(translated.get_byte(CALLING_CONVENTION_ID_COL), Some(0));
    }

    #[test]
    fn version_mismatch_reports_unknown_version_indicator() {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(
                FUNCTIONS_TABLE_NAME.to_string(),
                Arc::new(Schema::new(
                    99,
                    FieldType::Long,
                    "ID".to_string(),
                    vec![],
                    vec![],
                    vec![],
                )),
            )
            .unwrap();
        drop(table);
        let err = match FunctionAdapterV0::new(&handle, addr_map()) {
            Ok(_) => panic!("expected a VersionException for a schema mismatch"),
            Err(e) => e,
        };
        assert_eq!(err.version_indicator(), VersionException::UNKNOWN_VERSION);
    }

    #[test]
    fn mutating_operations_are_unsupported_but_delete_table_works() {
        let mut handle = DBHandle::new().unwrap();
        seed_v0_table(&mut handle);
        let mut adapter = FunctionAdapterV0::new(&handle, addr_map()).unwrap();
        assert_eq!(
            adapter.remove_function_record(1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(FUNCTIONS_TABLE_NAME).is_none());
    }
}
