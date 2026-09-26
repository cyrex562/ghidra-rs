//! Port of `ghidra.program.database.oldfunction.OldFunctionDBAdapterV1`.
//!
//! The current (version 1) implementation of [`OldFunctionDBAdapter`], backed by a live
//! [`Table`] whose layout matches [`OldFunctionDBAdapter`]'s own column constants exactly (no
//! translation needed, unlike [`OldFunctionDBAdapterV0`](crate::program::database::oldfunction::OldFunctionDBAdapterV0)).
//! [`FUNCTIONS_TABLE_NAME`]/[`schema`] describe this concrete table's layout, mirroring
//! `OldFunctionDBAdapterV1.FUNCTIONS_TABLE_NAME`/`V1_FUNCTIONS_SCHEMA`;
//! [`OldFunctionDBAdapterV0`](crate::program::database::oldfunction::OldFunctionDBAdapterV0)
//! reuses [`schema`] as its own `translateRecord` target, exactly like the Java class references
//! `OldFunctionDBAdapterV1.V1_FUNCTIONS_SCHEMA` via the abstract `OldFunctionDBAdapter`'s
//! `FUNCTIONS_SCHEMA` alias.
//!
//! `translateRecord` (an unconditional `UnsupportedOperationException` in Java, since there is no
//! older schema to translate *from* here) is not ported: it is not part of the
//! [`OldFunctionDBAdapter`] trait's surface (that trait only left the `getAdapter` factory and
//! this concrete table-layout constant out, not `translateRecord` -- `OldFunctionDBAdapterV0` is
//! the only version that needs it, as a private helper).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::AddressMap;
use crate::program::database::oldfunction::old_function_db_adapter::OldFunctionDBAdapter;
use crate::util::exception::VersionException;

/// Name of the old function database table. Mirrors `OldFunctionDBAdapterV1.FUNCTIONS_TABLE_NAME`
/// (and `OldFunctionDBAdapterV0.V0_FUNCTIONS_TABLE_NAME`, which names the same table).
pub const FUNCTIONS_TABLE_NAME: &str = "Functions";

/// Schema version implemented by this adapter. Mirrors `OldFunctionDBAdapterV1.SCHEMA_VERSION`.
pub const SCHEMA_VERSION: i32 = 1;

/// Build the current old-function table schema, as defined by
/// `OldFunctionDBAdapterV1.V1_FUNCTIONS_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
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

/// Current (version 1) implementation of [`OldFunctionDBAdapter`].
///
/// Port of `ghidra.program.database.oldfunction.OldFunctionDBAdapterV1`.
pub struct OldFunctionDBAdapterV1 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl OldFunctionDBAdapterV1 {
    /// Opens an existing version 1 old-function table for read access.
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
        Ok(OldFunctionDBAdapterV1 { table, addr_map })
    }
}

impl OldFunctionDBAdapter for OldFunctionDBAdapterV1 {
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(FUNCTIONS_TABLE_NAME);
        Ok(())
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(function_key)))
    }

    fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
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

    fn seed_table(handle: &mut DBHandle) {
        let table = handle.create_table(FUNCTIONS_TABLE_NAME.to_string(), schema()).unwrap();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(1)));
        rec.set_long(0, 5);
        rec.set_int(1, 8);
        rec.set_int(2, -4);
        rec.set_int(3, 0);
        rec.set_int(4, 16);
        rec.set_string(5, Some("hello".to_string()));
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn round_trips_records_without_translation() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let adapter = OldFunctionDBAdapterV1::new(&handle, addr_map()).unwrap();

        assert_eq!(adapter.get_record_count(), 1);
        let rec = adapter.get_function_record(1).unwrap().unwrap();
        assert_eq!(rec.get_long(0), Some(5));
        assert_eq!(rec.get_int(1), Some(8));
        assert_eq!(rec.get_string(5), Some("hello"));
        assert!(adapter.get_function_record(99).unwrap().is_none());

        let mut count = 0;
        let mut iter = adapter.iterate_function_records().unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn version_mismatch_is_reported() {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(
                FUNCTIONS_TABLE_NAME.to_string(),
                Arc::new(Schema::new(0, FieldType::Long, "ID".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        drop(table);
        let err = match OldFunctionDBAdapterV1::new(&handle, addr_map()) {
            Ok(_) => panic!("expected version mismatch"),
            Err(e) => e,
        };
        assert!(err.is_upgradable());
        assert_eq!(err.version_indicator(), VersionException::OLDER_VERSION);
    }

    #[test]
    fn delete_table_removes_underlying_table() {
        let mut handle = DBHandle::new().unwrap();
        seed_table(&mut handle);
        let mut adapter = OldFunctionDBAdapterV1::new(&handle, addr_map()).unwrap();
        adapter.delete_table(&mut handle).unwrap();
        assert!(handle.get_table(FUNCTIONS_TABLE_NAME).is_none());
    }
}
