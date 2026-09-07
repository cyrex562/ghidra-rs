//! Port of `ghidra.program.database.code.CommentHistoryAdapterV0`.
//!
//! Where Java uses an indexed lookup (`Table.indexIterator`) and `AddressKeyRecordIterator` to
//! walk records in address order, this port's [`Table`] has no secondary-index support, so both
//! `get_records_by_address` and `get_all_records` scan linearly instead -- decoding each
//! candidate record's address through the real `AddressMap` and filtering/sorting in memory. Same
//! observable result, just O(n) rather than indexed (matching the convention already established
//! by `CompositeDBAdapterV5V6`/`SymbolDatabaseAdapterV5` and others in this DB-adapter family).
//!
//! Java stamps each created record's `HISTORY_USER_COL` with `SystemUtilities.getUserName()` at
//! construction time; this port takes that user name as an explicit constructor argument instead
//! of reaching into the environment, keeping the adapter free of ambient global state.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::comment_history_adapter::{
    self, CommentHistoryAdapter, COMMENT_HISTORY_TABLE_NAME, HISTORY_ADDRESS_COL, HISTORY_DATE_COL,
    HISTORY_POS1_COL, HISTORY_POS2_COL, HISTORY_STRING_COL, HISTORY_TYPE_COL, HISTORY_USER_COL,
};
use crate::program::database::map::AddressMap;
use crate::program::model::address::Address;
use crate::util::exception::VersionException;

/// A `RecordIterator` over an eagerly-collected set of records.
struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// Version 0 implementation for accessing the Comment History table.
///
/// Port of `ghidra.program.database.code.CommentHistoryAdapterV0`. See the module docs for the
/// indexed-lookup and user-name deviations.
pub struct CommentHistoryAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
    user_name: String,
}

impl CommentHistoryAdapterV0 {
    /// Constructs a new Version 0 comment history adapter. `addr_map` is used to generate keys
    /// for addresses; `create` is `true` to create a new table, `false` to load an existing one;
    /// `user_name` stands in for Java's `SystemUtilities.getUserName()` (see the module docs).
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table was not found (when `create` is `false`) or has
    /// an unexpected schema version.
    pub fn new(
        handle: &mut crate::framework::db::DBHandle,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
        user_name: String,
    ) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(COMMENT_HISTORY_TABLE_NAME.to_string(), comment_history_adapter::schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(COMMENT_HISTORY_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {COMMENT_HISTORY_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != 0 {
                return Err(VersionException::with_version_indicator(
                    VersionException::NEWER_VERSION,
                    false,
                ));
            }
            table
        };
        Ok(CommentHistoryAdapterV0 {
            table,
            addr_map,
            user_name,
        })
    }
}

impl CommentHistoryAdapter for CommentHistoryAdapterV0 {
    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn create_record(
        &mut self,
        addr: i64,
        comment_type: i8,
        pos1: i32,
        pos2: i32,
        data: &str,
        date: i64,
    ) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(table.get_schema(), Field::Long(Some(key)));
        record.set_field(HISTORY_ADDRESS_COL, Field::Long(Some(addr)));
        record.set_field(HISTORY_TYPE_COL, Field::Byte(Some(comment_type)));
        record.set_field(HISTORY_POS1_COL, Field::Int(Some(pos1)));
        record.set_field(HISTORY_POS2_COL, Field::Int(Some(pos2)));
        record.set_field(HISTORY_STRING_COL, Field::String(Some(data.to_string())));
        record.set_field(
            HISTORY_USER_COL,
            Field::String(Some(self.user_name.clone())),
        );
        record.set_field(HISTORY_DATE_COL, Field::Long(Some(date)));
        table.put_record(record)
    }

    fn update_record(&mut self, rec: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(rec.clone())
    }

    fn delete_records(&mut self, start: &Address, end: &Address) -> io::Result<bool> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_delete = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(key)) = rec.get_field(HISTORY_ADDRESS_COL) {
                let addr = self.addr_map.decode_address(*key);
                if &addr >= start && &addr <= end {
                    to_delete.push(rec.get_key().clone());
                }
            }
        }
        drop(iter);
        let mut removed_any = false;
        for key in to_delete {
            if table.delete_record(&key)? {
                removed_any = true;
            }
        }
        Ok(removed_any)
    }

    fn get_records_by_address(&self, address: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        let target_key = self.addr_map.get_key(address, false);
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut matches = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(HISTORY_ADDRESS_COL), Field::Long(Some(v)) if *v == target_key)
            {
                matches.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: matches.into_iter(),
        }))
    }

    fn get_all_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(key)) = rec.get_field(HISTORY_ADDRESS_COL) {
                let addr = self.addr_map.decode_address(*key);
                entries.push((addr, rec));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBHandle;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType, KeyRange};

    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for IdentityAddressMap {
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
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
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
            Box::new(IdentityAddressMap {
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

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap {
            space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
        })
    }

    #[test]
    fn create_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CommentHistoryAdapterV0::new(&mut handle, addr_map(), true, "alice".to_string()).unwrap();
        assert_eq!(adapter.get_record_count(), 0);

        adapter.create_record(0x1000, 3, 0, 5, "hello", 111).unwrap();
        assert_eq!(adapter.get_record_count(), 1);

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut iter = adapter.get_records_by_address(&space.address(0x1000)).unwrap();
        let rec = iter.next().unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(HISTORY_STRING_COL),
            &Field::String(Some("hello".to_string()))
        );
        assert_eq!(
            rec.get_field(HISTORY_USER_COL),
            &Field::String(Some("alice".to_string()))
        );
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn get_all_records_is_sorted_by_address() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CommentHistoryAdapterV0::new(&mut handle, addr_map(), true, "bob".to_string()).unwrap();
        adapter.create_record(0x3000, 0, 0, 0, "c", 3).unwrap();
        adapter.create_record(0x1000, 0, 0, 0, "a", 1).unwrap();
        adapter.create_record(0x2000, 0, 0, 0, "b", 2).unwrap();

        let mut iter = adapter.get_all_records().unwrap();
        let mut strings = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            if let Field::String(Some(s)) = rec.get_field(HISTORY_STRING_COL) {
                strings.push(s.clone());
            }
        }
        assert_eq!(strings, vec!["a", "b", "c"]);
    }

    #[test]
    fn delete_records_removes_only_in_range() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter =
            CommentHistoryAdapterV0::new(&mut handle, addr_map(), true, "carol".to_string()).unwrap();
        adapter.create_record(0x1000, 0, 0, 0, "a", 1).unwrap();
        adapter.create_record(0x2000, 0, 0, 0, "b", 2).unwrap();
        adapter.create_record(0x3000, 0, 0, 0, "c", 3).unwrap();

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let deleted = adapter
            .delete_records(&space.address(0x1500), &space.address(0x2500))
            .unwrap();
        assert!(deleted);
        assert_eq!(adapter.get_record_count(), 2);

        let deleted_again = adapter
            .delete_records(&space.address(0x1500), &space.address(0x2500))
            .unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(CommentHistoryAdapterV0::new(&mut handle, addr_map(), false, "x".to_string()).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn CommentHistoryAdapter> = Box::new(
            CommentHistoryAdapterV0::new(&mut handle, addr_map(), true, "x".to_string()).unwrap(),
        );
        assert_eq!(adapter.get_record_count(), 0);
    }
}
