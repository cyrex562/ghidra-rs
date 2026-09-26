//! Port of `ghidra.program.database.function.ThunkFunctionAdapter`.
//!
//! The Java type is an abstract, package-private class whose static factory method (`getAdapter`,
//! plus the private `findReadOnlyAdapter` helper and the `upgrade` migration helper it delegates
//! to) selects and migrates between concrete version-specific implementations (currently just
//! `ThunkFunctionAdapterV0`). That concrete adapter has not been ported yet, so this port only
//! models the abstract instance API it implements, as an object-safe trait; the
//! version-selection/upgrade logic belongs with whichever type ends up owning the concrete
//! adapter. This follows the same convention already used for
//! [`FunctionAdapter`](crate::program::database::function::FunctionAdapter) and
//! [`FunctionTagMappingAdapter`](crate::program::database::function::FunctionTagMappingAdapter).
//! This trait was itself selected as a dependency-cycle cut-point.
//!
//! Likewise left out: the `THUNK_FUNCTIONS_TABLE_NAME`/`THUNK_FUNCTION_SCHEMA`/`CURRENT_VERSION`
//! constants, since they describe a concrete table layout used only by the not-yet-ported
//! `ThunkFunctionAdapterV0` class itself, rather than this trait's dynamic-dispatch surface --
//! left for whichever concrete subclass is ported first.
//!
//! Kept, unlike those table-layout constants: [`LINKED_FUNCTION_ID_COL`], the same reasoning that
//! kept `FunctionAdapter`'s `RETURN_DATA_TYPE_ID_COL`..`RETURN_STORAGE_COL` and
//! `FunctionTagMappingAdapter`'s `FUNCTION_ID_COL`/`TAG_ID_COL` -- it is read directly by
//! `ghidra.program.database.function.FunctionManagerDB` (a real caller outside the
//! `ThunkFunctionAdapter*` hierarchy, not yet ported) to resolve a thunked function's linked
//! function ID.
//!
//! The protected `addrMap` field (set once via the constructor and read by subclasses) is exposed
//! as [`ThunkFunctionAdapter::get_address_map`], mirroring
//! [`FunctionAdapter::get_address_map`](crate::program::database::function::FunctionAdapter::get_address_map).
//!
//! Java's overloaded `iterateThunkRecords` (one overload taking no arguments, the other taking a
//! linked-function key) is split into two distinctly-named methods, since Rust traits do not
//! support overloading by argument arity:
//! [`ThunkFunctionAdapter::iterate_thunk_records`] and
//! [`ThunkFunctionAdapter::iterate_thunk_records_for_linked_function`].

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::map::AddressMap;

/// Column index into the thunk functions table for a thunk's linked (referenced) function ID.
/// Stands in for `ThunkFunctionAdapter.LINKED_FUNCTION_ID_COL`.
pub const LINKED_FUNCTION_ID_COL: usize = 0;

/// Database adapter for thunk functions, which map a thunk function record to the function it
/// refers to.
///
/// Port of `ghidra.program.database.function.ThunkFunctionAdapter`. See the module docs for what
/// was intentionally left out (the static factory/version-upgrade logic and the concrete
/// table-layout constants) and how the overloaded `iterateThunkRecords` was split.
pub trait ThunkFunctionAdapter {
    /// Returns a count of thunk function records.
    ///
    /// Stands in for the package-private `ThunkFunctionAdapter.getRecordCount()`.
    fn get_record_count(&self) -> i32;

    /// Gets an iterator over all thunk function records.
    ///
    /// Stands in for the package-private `ThunkFunctionAdapter.iterateThunkRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn iterate_thunk_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Gets an iterator over all thunk function records whose linked function ID matches
    /// `linked_function_key`.
    ///
    /// Stands in for the single-argument overload of
    /// `ThunkFunctionAdapter.iterateThunkRecords(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn iterate_thunk_records_for_linked_function(
        &self,
        linked_function_key: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Gets a thunk function record, or `None` if there is no record for `function_key`.
    ///
    /// Stands in for the package-private `ThunkFunctionAdapter.getThunkRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_thunk_record(&self, function_key: i64) -> io::Result<Option<DBRecord>>;

    /// Removes a thunk function record.
    ///
    /// Stands in for the package-private `ThunkFunctionAdapter.removeThunkRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_thunk_record(&mut self, function_key: i64) -> io::Result<()>;

    /// Update/insert the specified thunk function record.
    ///
    /// Stands in for the package-private `ThunkFunctionAdapter.updateThunkRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_thunk_record(&mut self, rec: &DBRecord) -> io::Result<()>;

    /// Creates a new thunk function record linking `thunk_function_id` to
    /// `referenced_function_id`.
    ///
    /// Stands in for the package-private
    /// `ThunkFunctionAdapter.createThunkRecord(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn create_thunk_record(
        &mut self,
        thunk_function_id: i64,
        referenced_function_id: i64,
    ) -> io::Result<DBRecord>;

    /// Gets the map used to convert addresses to longs and longs to addresses.
    ///
    /// Stands in for the protected `ThunkFunctionAdapter.addrMap` field.
    fn get_address_map(&self) -> &dyn AddressMap;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::address::{
        Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
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

    /// Minimal stub `AddressMap`, since [`ThunkFunctionAdapter`] only ever returns this type
    /// opaquely via [`ThunkFunctionAdapter::get_address_map`].
    struct StubAddressMap {
        base: Address,
    }

    impl AddressMap for StubAddressMap {
        fn get_key(&self, _addr: &Address, _create: bool) -> i64 {
            0
        }

        fn get_absolute_encoding(&self, _addr: &Address, _create: bool) -> i64 {
            0
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, _value: i64) -> Address {
            self.base.clone()
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
            Box::new(StubAddressMap {
                base: self.base.clone(),
            })
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.base.clone()
        }
    }

    /// A minimal in-memory `ThunkFunctionAdapter`, exercising object-safety and the
    /// create/get/update/remove/query-by-linked-function contract described by the Java class.
    struct MockThunkFunctionAdapter {
        records: BTreeMap<i64, DBRecord>,
        addr_map: StubAddressMap,
    }

    impl MockThunkFunctionAdapter {
        fn new() -> Self {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            MockThunkFunctionAdapter {
                records: BTreeMap::new(),
                addr_map: StubAddressMap {
                    base: space.address(0),
                },
            }
        }
    }

    impl ThunkFunctionAdapter for MockThunkFunctionAdapter {
        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn iterate_thunk_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(VecRecordIterator {
                records: self.records.values().cloned().collect::<Vec<_>>().into_iter(),
            }))
        }

        fn iterate_thunk_records_for_linked_function(
            &self,
            linked_function_key: i64,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|record| record.get_long(LINKED_FUNCTION_ID_COL) == Some(linked_function_key))
                .cloned()
                .collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_thunk_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&function_key).cloned())
        }

        fn remove_thunk_record(&mut self, function_key: i64) -> io::Result<()> {
            self.records.remove(&function_key);
            Ok(())
        }

        fn update_thunk_record(&mut self, rec: &DBRecord) -> io::Result<()> {
            let key = rec.get_key().get_long_value();
            self.records.insert(key, rec.clone());
            Ok(())
        }

        fn create_thunk_record(
            &mut self,
            thunk_function_id: i64,
            referenced_function_id: i64,
        ) -> io::Result<DBRecord> {
            let mut record = DBRecord::new(test_schema(), Field::Long(Some(thunk_function_id)));
            record.set_long(LINKED_FUNCTION_ID_COL, referenced_function_id);
            self.records.insert(thunk_function_id, record.clone());
            Ok(record)
        }

        fn get_address_map(&self) -> &dyn AddressMap {
            &self.addr_map
        }
    }

    #[test]
    fn object_safe_and_tracks_thunk_records() {
        let mut adapter: Box<dyn ThunkFunctionAdapter> = Box::new(MockThunkFunctionAdapter::new());

        assert_eq!(adapter.get_record_count(), 0);
        assert!(adapter.get_thunk_record(1).unwrap().is_none());

        adapter.create_thunk_record(1, 100).unwrap();
        adapter.create_thunk_record(2, 100).unwrap();
        adapter.create_thunk_record(3, 200).unwrap();

        assert_eq!(adapter.get_record_count(), 3);
        assert!(adapter.get_thunk_record(1).unwrap().is_some());

        {
            let mut count = 0;
            let mut iter = adapter.iterate_thunk_records_for_linked_function(100).unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 2);
        }

        {
            let mut count = 0;
            let mut iter = adapter.iterate_thunk_records().unwrap();
            while iter.next().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 3);
        }

        let mut rec = adapter.get_thunk_record(1).unwrap().unwrap();
        rec.set_long(LINKED_FUNCTION_ID_COL, 999);
        adapter.update_thunk_record(&rec).unwrap();
        assert_eq!(
            adapter.get_thunk_record(1).unwrap().unwrap().get_long(LINKED_FUNCTION_ID_COL),
            Some(999)
        );

        adapter.remove_thunk_record(1).unwrap();
        assert!(adapter.get_thunk_record(1).unwrap().is_none());
        assert_eq!(adapter.get_record_count(), 2);

        let _ = adapter.get_address_map();
    }
}
