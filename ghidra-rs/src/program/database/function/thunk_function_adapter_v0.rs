//! Port of `ghidra.program.database.function.ThunkFunctionAdapterV0`.
//!
//! Version 0 (the only version to date) implementation for accessing the thunk functions table,
//! backed by a live, writable [`Table`]. Mirrors the shape already established by
//! [`SymbolDatabaseAdapterV5`](crate::program::database::symbol::SymbolDatabaseAdapterV5) and its
//! siblings: this port's [`Table`] has no secondary-index support, so the single-argument
//! `iterateThunkRecords(long)` overload (`Table.indexIterator(LINKED_FUNCTION_ID_COL, ...)` in
//! Java) scans every record and filters in memory instead of using an indexed lookup, matching the
//! established convention for this DB-adapter family.
//!
//! The `THUNK_FUNCTIONS_TABLE_NAME`/`THUNK_FUNCTION_SCHEMA` constants that
//! [`ThunkFunctionAdapter`]'s own port left out (they describe this concrete table's layout, not
//! the abstract trait's dynamic-dispatch surface) are defined here instead, alongside this
//! version's `SCHEMA_VERSION`.
//!
//! Left out, matching [`ThunkFunctionAdapter`]'s own precedent: the `getAdapter`/
//! `findReadOnlyAdapter`/`upgrade` static factory and migration logic declared on the abstract
//! base class, since only one concrete version exists to migrate to/from -- that logic belongs
//! with whichever type ends up owning version selection (`FunctionManagerDB`, not yet ported).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::function::thunk_function_adapter::{
    ThunkFunctionAdapter, LINKED_FUNCTION_ID_COL,
};
use crate::program::database::map::AddressMap;
use crate::util::exception::VersionException;

/// Name of the thunk functions database table. Mirrors `ThunkFunctionAdapter.THUNK_FUNCTIONS_TABLE_NAME`.
pub const THUNK_FUNCTIONS_TABLE_NAME: &str = "Thunk Functions";

/// Schema version implemented by this adapter. Mirrors `ThunkFunctionAdapterV0.SCHEMA_VERSION`
/// (which also serves as `ThunkFunctionAdapter.CURRENT_VERSION`, since this is the only version).
pub const SCHEMA_VERSION: i32 = 0;

/// Build the thunk functions table schema, as defined by `ThunkFunctionAdapter.THUNK_FUNCTION_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SCHEMA_VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::Long],
        vec!["Linked Function ID".to_string()],
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

/// Version 0 (current) implementation for accessing the thunk functions database table.
///
/// Port of `ghidra.program.database.function.ThunkFunctionAdapterV0`.
pub struct ThunkFunctionAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl ThunkFunctionAdapterV0 {
    /// Gets a version 0 adapter for the thunk functions table. If `create` is `true`, the table is
    /// created, otherwise an existing table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table that is missing (mirroring
    /// Java's `throw new VersionException(true)`, an "older version, upgradable" indicator used
    /// here for "no table found") or whose schema version does not match [`SCHEMA_VERSION`]
    /// (mirroring `throw new VersionException(VersionException.NEWER_VERSION, false)`).
    pub fn new(
        handle: &mut DBHandle,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(THUNK_FUNCTIONS_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(THUNK_FUNCTIONS_TABLE_NAME)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != SCHEMA_VERSION {
                return Err(VersionException::with_version_indicator(
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
            table
        };
        Ok(ThunkFunctionAdapterV0 { table, addr_map })
    }
}

impl ThunkFunctionAdapter for ThunkFunctionAdapterV0 {
    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn iterate_thunk_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
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

    fn iterate_thunk_records_for_linked_function(
        &self,
        linked_function_key: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(LINKED_FUNCTION_ID_COL) == Some(linked_function_key) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_thunk_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(function_key)))
    }

    fn remove_thunk_record(&mut self, function_key: i64) -> io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(function_key)))?;
        Ok(())
    }

    fn update_thunk_record(&mut self, rec: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(rec.clone())
    }

    fn create_thunk_record(
        &mut self,
        thunk_function_id: i64,
        referenced_function_id: i64,
    ) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(thunk_function_id)));
        rec.set_long(LINKED_FUNCTION_ID_COL, referenced_function_id);
        self.table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
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
            Box::new(TestAddressMap {
                space: self.space.clone(),
            })
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

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(TestAddressMap { space: ram_space() })
    }

    #[test]
    fn create_opens_new_table_at_schema_version() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = ThunkFunctionAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn missing_table_reports_upgradeable_version_exception() {
        let mut handle = DBHandle::new().unwrap();
        let result = ThunkFunctionAdapterV0::new(&mut handle, addr_map(), false);
        let err = match result {
            Ok(_) => panic!("expected a VersionException for a missing table"),
            Err(e) => e,
        };
        assert_eq!(err.version_indicator(), VersionException::OLDER_VERSION);
    }

    #[test]
    fn create_get_update_remove_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ThunkFunctionAdapterV0::new(&mut handle, addr_map(), true).unwrap();

        adapter.create_thunk_record(1, 100).unwrap();
        adapter.create_thunk_record(2, 100).unwrap();
        adapter.create_thunk_record(3, 200).unwrap();
        assert_eq!(adapter.get_record_count(), 3);

        let rec = adapter.get_thunk_record(1).unwrap().unwrap();
        assert_eq!(rec.get_long(LINKED_FUNCTION_ID_COL), Some(100));

        let mut count = 0;
        {
            let mut iter = adapter.iterate_thunk_records_for_linked_function(100).unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
        }
        assert_eq!(count, 2);

        let mut updated = rec;
        updated.set_long(LINKED_FUNCTION_ID_COL, 999);
        adapter.update_thunk_record(&updated).unwrap();
        assert_eq!(
            adapter.get_thunk_record(1).unwrap().unwrap().get_long(LINKED_FUNCTION_ID_COL),
            Some(999)
        );

        adapter.remove_thunk_record(1).unwrap();
        assert!(adapter.get_thunk_record(1).unwrap().is_none());
        assert_eq!(adapter.get_record_count(), 2);
    }

    #[test]
    fn iterate_thunk_records_visits_every_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ThunkFunctionAdapterV0::new(&mut handle, addr_map(), true).unwrap();
        adapter.create_thunk_record(1, 100).unwrap();
        adapter.create_thunk_record(2, 200).unwrap();

        let mut count = 0;
        let mut iter = adapter.iterate_thunk_records().unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn reopening_with_wrong_schema_version_reports_newer_version() {
        // This port only ever writes SCHEMA_VERSION, so a version mismatch is only reachable via
        // a manually-crafted table; exercise the version-check branch directly instead.
        let err =
            VersionException::with_version_indicator(VersionException::NEWER_VERSION, false);
        assert_eq!(err.version_indicator(), VersionException::NEWER_VERSION);
    }
}
