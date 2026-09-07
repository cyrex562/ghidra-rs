//! Port of `ghidra.program.database.references.FromAdapterSharedTable`.
//!
//! Read-only legacy adapter for the oldest reference storage format -- the same "Memory
//! References" table [`ToAdapterSharedTable`](crate::program::database::references::ToAdapterSharedTable)
//! reads, just scanned by `From Address` instead of `To Address`. Every read reconstructs a
//! temporary [`RefListV0Impl`] on the fly by scanning for matching rows; every mutation is
//! rejected. See `ToAdapterSharedTable`'s own module docs for the shared rationale (no
//! secondary-index support, the `SendSyncAddressMap` reuse, eager iteration) -- not repeated here.
//!
//! Unlike `ToAdapterSharedTable::get_to_iterator_in_set` (which scans the *other* column, `OLD_FROM_ADDR_COL`,
//! from what every sibling overload uses -- ported bug-for-bug), every one of
//! `FromAdapterSharedTable`'s `getFromIterator` overloads consistently scans `OLD_FROM_ADDR_COL`,
//! matching this class's own name. There is no analogous inconsistency to preserve here.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord, Field, Table};
use crate::program::database::map::{AddressIndexKeyIterator, AddressMap};
use crate::program::database::references::ref_list_v0::RefListV0Impl;
use crate::program::database::references::to_adapter_v0::SendSyncAddressMap;
use crate::program::database::references::{FromAdapter, RecordAdapter, RefList};
use crate::program::database::ProgramDB;
use crate::program::model::address::{Address, AddressSetView, BoxedAddressIterator};
use crate::program::model::symbol::{RefTypeFactory, SourceType};
use crate::util::exception::VersionException;

/// Table name for the oldest, one-row-per-reference "Memory References" table.
pub const OLD_REFS_TABLE_NAME: &str = "Memory References";

const OLD_FROM_ADDR_COL: usize = 0; // Indexed Column
const OLD_TO_ADDR_COL: usize = 1; // Indexed Column
const OLD_OP_INDEX_COL: usize = 2;
const OLD_USER_DEFINED_COL: usize = 3;
const OLD_REF_TYPE_COL: usize = 4;
const OLD_SYMBOL_ID_COL: usize = 5;
#[allow(dead_code)] // Mirrors Java: declared, never read by any method this class implements.
const OLD_BASE_ADDR_COL: usize = 6;
#[allow(dead_code)] // Mirrors Java: declared, never read by any method this class implements.
const OLD_IS_OFFSET_COL: usize = 7;
const OLD_IS_PRIMARY_COL: usize = 8;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "UnsupportedOperationException: FromAdapterSharedTable is a read-only legacy adapter",
    )
}

/// Read-only legacy adapter for the one-row-per-reference "Memory References" table, scanned by
/// `From Address`.
///
/// Port of `ghidra.program.database.references.FromAdapterSharedTable`.
pub struct FromAdapterSharedTable {
    table: Arc<std::sync::RwLock<Table>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
}

impl FromAdapterSharedTable {
    /// Opens the existing "Memory References" table from `handle`, verifying it is schema
    /// version 0. `addr_map` mirrors Java's constructor parameter (the *current*, post-upgrade
    /// map); this constructor takes its [`AddressMap::get_old_address_map`] internally.
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table does not exist or is not schema version 0.
    pub fn new(handle: &DBHandle, addr_map: &dyn AddressMap) -> Result<Self, VersionException> {
        let table = handle.get_table(OLD_REFS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {OLD_REFS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(VersionException::with_upgradeable(false));
        }
        Ok(FromAdapterSharedTable {
            table,
            addr_map: Arc::new(SendSyncAddressMap(addr_map.get_old_address_map())),
        })
    }

    /// Scans every row of the "Memory References" table whose `From Address` column matches
    /// `from_addr`, appending each as a reference into a fresh, temporary "from" list. Stands in
    /// for `FromAdapterSharedTable.getRefList`'s `table.indexIterator(OLD_FROM_ADDR_COL, ...)`
    /// loop.
    fn scan_refs_from(&self, from: &Address, from_addr: i64) -> io::Result<RefListV0Impl> {
        let mut from_refs = RefListV0Impl::create_temporary(from_addr, self.addr_map.clone(), true);
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(OLD_FROM_ADDR_COL) != Some(from_addr) {
                continue;
            }
            let is_user = rec.get_bool(OLD_USER_DEFINED_COL).unwrap_or(false);
            let source = if is_user { SourceType::UserDefined } else { SourceType::Default };
            let ref_type_short = match rec.get_field(OLD_REF_TYPE_COL) {
                Field::Short(Some(v)) => *v,
                _ => 0,
            };
            let ref_type = RefTypeFactory::get(ref_type_short as i8)
                .expect("FromAdapterSharedTable-stored RefType bytes are always valid");
            let op_index_short = match rec.get_field(OLD_OP_INDEX_COL) {
                Field::Short(Some(v)) => *v,
                _ => 0,
            };
            let to_addr_key = rec.get_long(OLD_TO_ADDR_COL).unwrap_or(0);
            let to = self.addr_map.decode_address(to_addr_key);
            let symbol_id = rec.get_long(OLD_SYMBOL_ID_COL).unwrap_or(-1);
            let is_primary = rec.get_bool(OLD_IS_PRIMARY_COL).unwrap_or(false);

            from_refs.add_ref(
                from,
                &to,
                ref_type,
                op_index_short as i32,
                symbol_id,
                is_primary,
                source,
                false,
                false,
                0,
            )?;
        }
        Ok(from_refs)
    }

    fn collect_from_addresses(
        &self,
        set: Option<&dyn AddressSetView>,
        start_addr: Option<&Address>,
        forward: bool,
    ) -> io::Result<BoxedAddressIterator> {
        use crate::framework::db::DBLongIterator;

        let mut key_iter = if let Some(set) = set {
            AddressIndexKeyIterator::new_over_set(
                &self.table,
                OLD_FROM_ADDR_COL,
                self.addr_map.as_ref(),
                Some(set),
                forward,
            )?
        } else if let Some(start) = start_addr {
            AddressIndexKeyIterator::new_at(&self.table, OLD_FROM_ADDR_COL, self.addr_map.as_ref(), start, forward)?
        } else {
            AddressIndexKeyIterator::new(&self.table, OLD_FROM_ADDR_COL, self.addr_map.as_ref(), forward)?
        };

        let mut addrs = Vec::new();
        loop {
            let has = if forward { key_iter.has_next()? } else { key_iter.has_previous()? };
            if !has {
                break;
            }
            let k = if forward { key_iter.next()? } else { key_iter.previous()? };
            addrs.push(self.addr_map.decode_address(k));
        }
        Ok(Box::new(addrs.into_iter()))
    }
}

impl RecordAdapter for FromAdapterSharedTable {
    /// Always fails. Stands in for `FromAdapterSharedTable.createRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn create_record(
        &mut self,
        _key: i64,
        _num_refs: i32,
        _ref_level: u8,
        _ref_data: Option<&[u8]>,
    ) -> io::Result<DBRecord> {
        Err(unsupported())
    }

    /// Returns the raw "Memory References" row for `key`, unlike `FromAdapterV0::get_record`:
    /// Java never translates this legacy schema's shape into the current one for this class.
    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such Memory References record"))
    }

    /// Always fails. Stands in for `FromAdapterSharedTable.putRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn put_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    /// Always fails. Stands in for `FromAdapterSharedTable.removeRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn remove_record(&mut self, _key: i64) -> io::Result<()> {
        Err(unsupported())
    }
}

impl FromAdapter for FromAdapterSharedTable {
    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    /// Always fails. Stands in for `FromAdapterSharedTable.createRefList`, which always throws
    /// `UnsupportedOperationException`.
    fn create_ref_list(
        &mut self,
        _program: Option<&ProgramDB>,
        _from_addr: &Address,
    ) -> io::Result<Box<dyn RefList>> {
        Err(unsupported())
    }

    fn get_ref_list(
        &self,
        _program: Option<&ProgramDB>,
        from: &Address,
        from_addr: i64,
    ) -> io::Result<Option<Box<dyn RefList>>> {
        let from_refs = self.scan_refs_from(from, from_addr)?;
        if from_refs.is_empty() {
            return Ok(None);
        }
        Ok(Some(Box::new(from_refs)))
    }

    fn has_ref_from(&self, from_addr: i64) -> io::Result<bool> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(OLD_FROM_ADDR_COL) == Some(from_addr) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_from_iterator(&self, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_from_addresses(None, None, forward)
    }

    fn get_from_iterator_from(&self, start_addr: &Address, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_from_addresses(None, Some(start_addr), forward)
    }

    fn get_from_iterator_in_set(&self, set: &dyn AddressSetView, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_from_addresses(Some(set), None, forward)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSpace, AddressSpaceType, KeyRange};
    use crate::program::model::symbol::RefType;

    #[derive(Clone)]
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
            Address::new(self.space.clone(), value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            start: &Address,
            end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            vec![KeyRange::new(start.offset(), end.offset())]
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            match set {
                None => vec![KeyRange::new(i64::MIN, i64::MAX)],
                Some(set) => {
                    let mut ranges = Vec::new();
                    let mut it = set.address_ranges();
                    while let Some(range) = it.next() {
                        ranges.push(KeyRange::new(range.min_address().offset(), range.max_address().offset()));
                    }
                    ranges
                }
            }
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(self.clone())
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(self.space.clone(), 0)
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr_map() -> IdentityAddressMap {
        IdentityAddressMap { space: space() }
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn old_refs_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::Long,
                FieldType::Long,
                FieldType::Short,
                FieldType::Boolean,
                FieldType::Short,
                FieldType::Long,
                FieldType::Long,
                FieldType::Boolean,
                FieldType::Boolean,
            ],
            vec![
                "From Address".to_string(),
                "To Address".to_string(),
                "Op Index".to_string(),
                "User Defined".to_string(),
                "Ref Type".to_string(),
                "Symbol ID".to_string(),
                "Base Address".to_string(),
                "Is Offset".to_string(),
                "Is Primary".to_string(),
            ],
            vec![],
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn old_ref_record(
        key: i64,
        from: i64,
        to: i64,
        op_index: i16,
        is_user: bool,
        ref_type: RefType,
        symbol_id: i64,
        is_primary: bool,
    ) -> DBRecord {
        let mut rec = DBRecord::new(old_refs_schema(), Field::Long(Some(key)));
        rec.set_field(OLD_FROM_ADDR_COL, Field::Long(Some(from)));
        rec.set_field(OLD_TO_ADDR_COL, Field::Long(Some(to)));
        rec.set_field(OLD_OP_INDEX_COL, Field::Short(Some(op_index)));
        rec.set_field(OLD_USER_DEFINED_COL, Field::Boolean(Some(is_user)));
        rec.set_field(OLD_REF_TYPE_COL, Field::Short(Some(ref_type.value() as i16)));
        rec.set_field(OLD_SYMBOL_ID_COL, Field::Long(Some(symbol_id)));
        rec.set_field(OLD_BASE_ADDR_COL, Field::Long(Some(0)));
        rec.set_field(OLD_IS_OFFSET_COL, Field::Boolean(Some(false)));
        rec.set_field(OLD_IS_PRIMARY_COL, Field::Boolean(Some(is_primary)));
        rec
    }

    fn setup_table(handle: &mut DBHandle, records: &[DBRecord]) {
        let table = handle.create_table(OLD_REFS_TABLE_NAME.to_string(), old_refs_schema()).unwrap();
        let mut t = table.write().unwrap();
        for rec in records {
            t.put_record(rec.clone()).unwrap();
        }
    }

    #[test]
    fn opening_missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        let map = addr_map();
        assert!(FromAdapterSharedTable::new(&handle, &map).is_err());
    }

    #[test]
    fn get_ref_list_aggregates_every_matching_row_into_one_from_list() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x1000, 0x2010, 1, true, RefType::UnconditionalCall, 7, true),
                old_ref_record(2, 0x9999, 0x2020, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        let from = addr(0x1000);
        let list = adapter.get_ref_list(None, &from, 0x1000).unwrap().expect("should exist");
        assert_eq!(list.get_num_refs(), 2);

        let r0 = list.get_ref(&addr(0x2000), 0).unwrap();
        assert_eq!(r0.source(), SourceType::Default);
        assert!(!r0.is_primary());

        let r1 = list.get_ref(&addr(0x2010), 1).unwrap();
        assert_eq!(r1.source(), SourceType::UserDefined);
        assert_eq!(r1.symbol_id(), 7);
        assert!(r1.is_primary());
        assert_eq!(r1.reference_type(), RefType::UnconditionalCall);
    }

    #[test]
    fn get_ref_list_returns_none_when_no_rows_match() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();
        assert!(adapter.get_ref_list(None, &addr(0x9000), 0x9000).unwrap().is_none());
    }

    #[test]
    fn has_ref_from_and_record_count_reflect_the_table() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x1010, 0x3000, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        assert!(adapter.has_ref_from(0x1000).unwrap());
        assert!(adapter.has_ref_from(0x1010).unwrap());
        assert!(!adapter.has_ref_from(0x4000).unwrap());
        assert_eq!(adapter.get_record_count(), 2);
    }

    #[test]
    fn get_record_returns_the_raw_untranslated_row() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(7, 0x1000, 0x2000, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        let rec = RecordAdapter::get_record(&adapter, 7).unwrap();
        assert_eq!(rec.get_long(OLD_FROM_ADDR_COL), Some(0x1000));
        assert_eq!(rec.get_long(OLD_TO_ADDR_COL), Some(0x2000));
        assert!(RecordAdapter::get_record(&adapter, 999).is_err());
    }

    #[test]
    fn from_iterator_visits_distinct_from_addresses_in_order() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x300, 0x1, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x100, 0x2, 0, false, RefType::Data, -1, false),
                old_ref_record(2, 0x200, 0x3, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        let forward: Vec<i64> = adapter.get_from_iterator(true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(forward, vec![0x100, 0x200, 0x300]);
        let backward: Vec<i64> = adapter.get_from_iterator(false).unwrap().map(|a| a.offset()).collect();
        assert_eq!(backward, vec![0x300, 0x200, 0x100]);
    }

    #[test]
    fn from_iterator_from_start_address_is_restricted() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x100, 0x1, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x200, 0x2, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        let from: Vec<i64> =
            adapter.get_from_iterator_from(&addr(0x150), true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(from, vec![0x200]);
    }

    #[test]
    fn from_iterator_in_set_scans_the_from_column() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x50, 0x9000, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x9000, 0x50, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        let set = AddressSet::from_start_end(addr(0x0), addr(0x100));
        let in_set: Vec<i64> = adapter.get_from_iterator_in_set(&set, true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(in_set, vec![0x50]);
    }

    #[test]
    fn mutating_methods_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(0, 0x1, 0x100, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let mut adapter = FromAdapterSharedTable::new(&handle, &map).unwrap();

        match adapter.create_ref_list(None, &addr(0x999)) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected an Unsupported error"),
        }
        assert_eq!(
            RecordAdapter::create_record(&mut adapter, 1, 0, 0, Some(&[])).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let rec = old_ref_record(1, 0x1, 0x100, 0, false, RefType::Data, -1, false);
        assert_eq!(RecordAdapter::put_record(&mut adapter, &rec).unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(RecordAdapter::remove_record(&mut adapter, 1).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter: Box<dyn FromAdapter> = Box::new(FromAdapterSharedTable::new(&handle, &map).unwrap());
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.has_ref_from(0x1000).unwrap());
    }
}
