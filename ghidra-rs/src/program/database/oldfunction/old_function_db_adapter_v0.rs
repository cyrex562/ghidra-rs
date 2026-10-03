//! Port of `ghidra.program.database.oldfunction.OldFunctionDBAdapterV0`.
//!
//! Read-only legacy adapter for the version 0 (original) old-function table layout: five columns
//! only (no `RepeatableComment` column yet), so [`translate_record`](OldFunctionDBAdapterV0::translate_record)
//! synthesizes an empty repeatable comment for every translated record, mirroring
//! `OldFunctionDBAdapterV0.translateRecord`'s `newRecord.setString(REPEATABLE_COMMENT_COL, "")`.
//! Opens the *same* table name as
//! [`OldFunctionDBAdapterV1`](crate::program::database::oldfunction::OldFunctionDBAdapterV1)
//! (`"Functions"`), distinguished only by the schema version stamped on the table -- exactly like
//! `OldFunctionDBAdapterV0`/`V1` do in Java.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::AddressMap;
use crate::program::database::oldfunction::old_function_db_adapter::{
    OldFunctionDBAdapter, REPEATABLE_COMMENT_COL, RETURN_DATA_TYPE_ID_COL, STACK_DEPTH_COL,
    STACK_LOCAL_SIZE_COL, STACK_PARAM_OFFSET_COL, STACK_RETURN_OFFSET_COL,
};
use crate::program::database::oldfunction::old_function_db_adapter_v1::{
    schema, FUNCTIONS_TABLE_NAME,
};
use crate::util::exception::VersionException;

const V0_RETURN_DATA_TYPE_ID_COL: usize = 0;
const V0_STACK_DEPTH_COL: usize = 1;
const V0_STACK_PARAM_OFFSET_COL: usize = 2;
const V0_STACK_RETURN_OFFSET_COL: usize = 3;
const V0_STACK_LOCAL_SIZE_COL: usize = 4;

/// Schema version implemented by this adapter. Mirrors the version checked by
/// `OldFunctionDBAdapterV0`'s constructor (`table.getSchema().getVersion() != 0`).
pub const SCHEMA_VERSION: i32 = 0;

/// Build the version 0 old-function table schema, matching `OldFunctionDBAdapterV0`'s
/// commented-out (but historically accurate) schema declaration: the same five columns as
/// [`schema`](crate::program::database::oldfunction::old_function_db_adapter_v1::schema) minus
/// `RepeatableComment`.
pub fn v0_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "Entry Point".to_string(),
        vec![FieldType::Long, FieldType::Int, FieldType::Int, FieldType::Int, FieldType::Int],
        vec![
            "Return DataType ID".to_string(),
            "StackDepth".to_string(),
            "StackParamOffset".to_string(),
            "StackReturnOffset".to_string(),
            "StackLocalSize".to_string(),
        ],
        vec![],
    ))
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

/// Read-only legacy adapter for the version 0 (original) old-function table layout.
///
/// Port of `ghidra.program.database.oldfunction.OldFunctionDBAdapterV0`.
pub struct OldFunctionDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl OldFunctionDBAdapterV0 {
    /// Opens an existing version 0 old-function table for read/upgrade access.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the table is missing or its schema version is not
    /// [`SCHEMA_VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(FUNCTIONS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {FUNCTIONS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != SCHEMA_VERSION {
            return Err(VersionException::with_message(format!(
                "Expected version 0 for table {FUNCTIONS_TABLE_NAME} but got {version}"
            )));
        }
        Ok(OldFunctionDBAdapterV0 { table, addr_map })
    }

    /// Port of `OldFunctionDBAdapterV0.translateRecord(DBRecord)`.
    fn translate_record(&self, old_record: DBRecord) -> DBRecord {
        let entry_point_key = old_record.get_key().get_long_value();
        let mut new_record = DBRecord::new(schema(), Field::Long(Some(entry_point_key)));
        new_record.set_long(
            RETURN_DATA_TYPE_ID_COL,
            old_record.get_long(V0_RETURN_DATA_TYPE_ID_COL).unwrap_or(0),
        );
        new_record.set_int(STACK_DEPTH_COL, old_record.get_int(V0_STACK_DEPTH_COL).unwrap_or(0));
        new_record.set_int(
            STACK_PARAM_OFFSET_COL,
            old_record.get_int(V0_STACK_PARAM_OFFSET_COL).unwrap_or(0),
        );
        new_record.set_int(
            STACK_RETURN_OFFSET_COL,
            old_record.get_int(V0_STACK_RETURN_OFFSET_COL).unwrap_or(0),
        );
        new_record.set_int(
            STACK_LOCAL_SIZE_COL,
            old_record.get_int(V0_STACK_LOCAL_SIZE_COL).unwrap_or(0),
        );
        new_record.set_string(REPEATABLE_COMMENT_COL, Some(String::new()));
        new_record
    }
}

impl OldFunctionDBAdapter for OldFunctionDBAdapterV0 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(FUNCTIONS_TABLE_NAME);
        Ok(())
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
        let old = self.table.read().unwrap().get_record(&Field::Long(Some(function_key)))?;
        Ok(old.map(|rec| self.translate_record(rec)))
    }

    fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(self.translate_record(rec));
        }
        Ok(Box::new(FixedRecordIterator { records: records.into_iter() }))
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

    fn addr_map() -> Arc<dyn AddressMap> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Arc::new(TestAddressMap { space })
    }

    fn seed_v0_table(handle: &mut DBHandle) {
        let table = handle.create_table(FUNCTIONS_TABLE_NAME.to_string(), v0_schema()).unwrap();
        let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(7)));
        rec.set_long(V0_RETURN_DATA_TYPE_ID_COL, 3);
        rec.set_int(V0_STACK_DEPTH_COL, 4);
        rec.set_int(V0_STACK_PARAM_OFFSET_COL, 8);
        rec.set_int(V0_STACK_RETURN_OFFSET_COL, 0);
        rec.set_int(V0_STACK_LOCAL_SIZE_COL, 20);
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn translate_record_synthesizes_empty_repeatable_comment() {
        let mut handle = DBHandle::new().unwrap();
        seed_v0_table(&mut handle);
        let adapter = OldFunctionDBAdapterV0::new(&handle, addr_map()).unwrap();

        let translated = adapter.get_function_record(7).unwrap().unwrap();
        assert_eq!(translated.get_long(RETURN_DATA_TYPE_ID_COL), Some(3));
        assert_eq!(translated.get_int(STACK_DEPTH_COL), Some(4));
        assert_eq!(translated.get_int(STACK_PARAM_OFFSET_COL), Some(8));
        assert_eq!(translated.get_int(STACK_RETURN_OFFSET_COL), Some(0));
        assert_eq!(translated.get_int(STACK_LOCAL_SIZE_COL), Some(20));
        assert_eq!(translated.get_string(REPEATABLE_COMMENT_COL), Some(""));

        assert!(adapter.get_function_record(99).unwrap().is_none());
    }

    #[test]
    fn iterate_function_records_translates_every_record() {
        let mut handle = DBHandle::new().unwrap();
        seed_v0_table(&mut handle);
        let adapter = OldFunctionDBAdapterV0::new(&handle, addr_map()).unwrap();

        let mut iter = adapter.iterate_function_records().unwrap();
        let mut count = 0;
        while let Some(rec) = iter.next().unwrap() {
            assert_eq!(rec.get_string(REPEATABLE_COMMENT_COL), Some(""));
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn version_mismatch_is_reported() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                FUNCTIONS_TABLE_NAME.to_string(),
                Arc::new(Schema::new(1, FieldType::Long, "ID".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        let err = match OldFunctionDBAdapterV0::new(&handle, addr_map()) {
            Ok(_) => panic!("expected version mismatch"),
            Err(e) => e,
        };
        assert!(!err.is_upgradable());
    }

    #[test]
    fn delete_table_removes_underlying_table() {
        let mut handle = DBHandle::new().unwrap();
        seed_v0_table(&mut handle);
        let mut adapter = OldFunctionDBAdapterV0::new(&handle, addr_map()).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(FUNCTIONS_TABLE_NAME).is_none());
    }
}
