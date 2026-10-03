//! Port of `ghidra.program.database.references.ToAdapterSharedTable`.
//!
//! Read-only legacy adapter for the oldest reference storage format: a single, un-versioned
//! "Memory References" table with one row *per reference* (not per address), each row's `From
//! Address`/`To Address` columns holding both endpoints directly rather than being split across
//! separate "to"/"from" per-address tables. Every read reconstructs a temporary
//! [`RefListV0Impl`] on the fly by scanning for matching rows; every mutation is rejected,
//! matching Java's `UnsupportedOperationException`s.
//!
//! **No secondary-index support.** Java opens `table.indexIterator`/`AddressIndexKeyIterator`
//! against `OLD_TO_ADDR_COL`/`OLD_FROM_ADDR_COL`, both declared `// Indexed Column`. This port's
//! [`Table`] has no secondary-index support at all (matching `InstDBAdapterV0`/`ToAdapterV0`'s own
//! established convention), but [`AddressIndexKeyIterator`] already emulates one via an eager
//! linear scan (see that module's own docs), so it's reused here unchanged -- no bespoke
//! iterator/table walk is needed for this class specifically.
//!
//! **`getToIterator(AddressSetView, boolean)` really does scan `OLD_FROM_ADDR_COL`, not
//! `OLD_TO_ADDR_COL`.** This looks like it could be a stray copy-paste in the original Java (every
//! other `getToIterator` overload here, and every overload in `ToAdapterV0`/`ToAdapterV1`, scans
//! the "to" column), but a faithful port preserves Java's actual behavior rather than "fixing" a
//! legacy, already-dead code path no test in this port can validate against real Ghidra --
//! ported bug-for-bug, see [`Self::get_to_iterator_in_set`].
//!
//! **Address-map thread-safety.** Same [`SendSyncAddressMap`] wrapper `ToAdapterV0` already
//! defines and documents, reused here rather than duplicated.
//!
//! **Iteration.** Same eager-`Vec`-collection convention as `ToAdapterV0`/`ToAdapterV1` -- see
//! either module's docs for the full rationale.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord, Field, Table};
use crate::program::database::map::{AddressIndexKeyIterator, AddressMap};
use crate::program::database::references::ref_list_v0::RefListV0Impl;
use crate::program::database::references::to_adapter_v0::SendSyncAddressMap;
use crate::program::database::references::{RecordAdapter, RefList, ToAdapter};
use crate::program::database::ProgramDB;
use crate::program::model::address::{Address, AddressSetView, AddressSpace, BoxedAddressIterator};
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
        "UnsupportedOperationException: ToAdapterSharedTable is a read-only legacy adapter",
    )
}

/// Read-only legacy adapter for the one-row-per-reference "Memory References" table.
///
/// Port of `ghidra.program.database.references.ToAdapterSharedTable`. See the module docs for the
/// linear-scan and read-only deviations.
pub struct ToAdapterSharedTable {
    table: Arc<std::sync::RwLock<Table>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
}

impl ToAdapterSharedTable {
    /// Opens the existing "Memory References" table from `handle`, verifying it is schema
    /// version 0. `addr_map` mirrors Java's constructor parameter (the *current*, post-upgrade
    /// map); this constructor takes its [`AddressMap::get_old_address_map`] internally, mirroring
    /// `addrMap.getOldAddressMap()`.
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
        Ok(ToAdapterSharedTable {
            table,
            addr_map: Arc::new(SendSyncAddressMap(addr_map.get_old_address_map())),
        })
    }

    /// Scans every row of the "Memory References" table whose `To Address` column matches
    /// `to_addr`, appending each as a reference into a fresh, temporary "to" list. Stands in for
    /// `ToAdapterSharedTable.getRefList`'s `table.indexIterator(OLD_TO_ADDR_COL, ...)` loop.
    fn scan_refs_to(&self, to: &Address, to_addr: i64) -> io::Result<RefListV0Impl> {
        let mut to_refs = RefListV0Impl::create_temporary(to_addr, self.addr_map.clone(), false);
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(OLD_TO_ADDR_COL) != Some(to_addr) {
                continue;
            }
            let is_user = rec.get_bool(OLD_USER_DEFINED_COL).unwrap_or(false);
            let source = if is_user { SourceType::UserDefined } else { SourceType::Default };
            let ref_type_short = match rec.get_field(OLD_REF_TYPE_COL) {
                Field::Short(Some(v)) => *v,
                _ => 0,
            };
            let ref_type = RefTypeFactory::get(ref_type_short as i8)
                .expect("ToAdapterSharedTable-stored RefType bytes are always valid");
            let op_index_short = match rec.get_field(OLD_OP_INDEX_COL) {
                Field::Short(Some(v)) => *v,
                _ => 0,
            };
            let from_addr_key = rec.get_long(OLD_FROM_ADDR_COL).unwrap_or(0);
            let from = self.addr_map.decode_address(from_addr_key);
            let symbol_id = rec.get_long(OLD_SYMBOL_ID_COL).unwrap_or(-1);
            let is_primary = rec.get_bool(OLD_IS_PRIMARY_COL).unwrap_or(false);

            to_refs.add_ref(
                &from,
                to,
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
        Ok(to_refs)
    }

    fn collect_to_addresses(
        &self,
        index_col: usize,
        set: Option<&dyn AddressSetView>,
        start_addr: Option<&Address>,
        forward: bool,
    ) -> io::Result<BoxedAddressIterator> {
        use crate::framework::db::DBLongIterator;

        let mut key_iter = if let Some(set) = set {
            AddressIndexKeyIterator::new_over_set(&self.table, index_col, self.addr_map.as_ref(), Some(set), forward)?
        } else if let Some(start) = start_addr {
            AddressIndexKeyIterator::new_at(&self.table, index_col, self.addr_map.as_ref(), start, forward)?
        } else {
            AddressIndexKeyIterator::new(&self.table, index_col, self.addr_map.as_ref(), forward)?
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

impl RecordAdapter for ToAdapterSharedTable {
    /// Always fails. Stands in for `ToAdapterSharedTable.createRecord`, which always throws
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

    /// Returns the raw "Memory References" row for `key`, unlike `ToAdapterV0::get_record`: Java
    /// never translates this legacy schema's shape into the current one for this class.
    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such Memory References record"))
    }

    /// Always fails. Stands in for `ToAdapterSharedTable.putRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn put_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    /// Always fails. Stands in for `ToAdapterSharedTable.removeRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn remove_record(&mut self, _key: i64) -> io::Result<()> {
        Err(unsupported())
    }
}

impl ToAdapter for ToAdapterSharedTable {
    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    /// Always fails. Stands in for `ToAdapterSharedTable.createRefList`, which always throws
    /// `UnsupportedOperationException`.
    fn create_ref_list(
        &mut self,
        _program: Option<&ProgramDB>,
        _to_addr: &Address,
    ) -> io::Result<Box<dyn RefList>> {
        Err(unsupported())
    }

    fn get_ref_list(
        &self,
        _program: Option<&ProgramDB>,
        to: &Address,
        to_addr: i64,
    ) -> io::Result<Option<Box<dyn RefList>>> {
        let to_refs = self.scan_refs_to(to, to_addr)?;
        if to_refs.is_empty() {
            return Ok(None);
        }
        Ok(Some(Box::new(to_refs)))
    }

    fn has_ref_to(&self, to_addr: i64) -> io::Result<bool> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(OLD_TO_ADDR_COL) == Some(to_addr) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_to_iterator(&self, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(OLD_TO_ADDR_COL, None, None, forward)
    }

    fn get_to_iterator_from(&self, start_addr: &Address, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(OLD_TO_ADDR_COL, None, Some(start_addr), forward)
    }

    /// Scans `OLD_FROM_ADDR_COL`, not `OLD_TO_ADDR_COL` -- see the module docs for why this is a
    /// faithful (not "fixed") port of Java's actual behavior.
    fn get_to_iterator_in_set(&self, set: &dyn AddressSetView, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(OLD_FROM_ADDR_COL, Some(set), None, forward)
    }

    /// Always fails. Stands in for `ToAdapterSharedTable.getOldNamespaceAddresses`, which always
    /// throws `UnsupportedOperationException`.
    fn get_old_namespace_addresses(&self, _addr_space: &AddressSpace) -> io::Result<BoxedAddressIterator> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSpaceType, KeyRange};
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
        assert!(ToAdapterSharedTable::new(&handle, &map).is_err());
    }

    #[test]
    fn opening_wrong_version_table_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        let mut v1_schema_fields = old_refs_schema();
        // Reuse the same field shape but bump the version to prove version-checking works
        // regardless of column layout.
        v1_schema_fields = Arc::new(Schema::new(
            1,
            v1_schema_fields.get_key_type(),
            v1_schema_fields.get_key_name().to_string(),
            (0..v1_schema_fields.get_field_count()).map(|i| v1_schema_fields.get_field_type(i)).collect(),
            (0..v1_schema_fields.get_field_count()).map(|i| v1_schema_fields.get_field_name(i).to_string()).collect(),
            vec![],
        ));
        handle.create_table(OLD_REFS_TABLE_NAME.to_string(), v1_schema_fields).unwrap();
        let map = addr_map();
        assert!(ToAdapterSharedTable::new(&handle, &map).is_err());
    }

    #[test]
    fn get_ref_list_aggregates_every_matching_row_into_one_to_list() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x1010, 0x2000, 1, true, RefType::UnconditionalCall, 7, true),
                old_ref_record(2, 0x1020, 0x9999, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

        let to = addr(0x2000);
        let list = adapter.get_ref_list(None, &to, 0x2000).unwrap().expect("should exist");
        assert_eq!(list.get_num_refs(), 2);

        let r0 = list.get_ref(&addr(0x1000), 0).unwrap();
        assert_eq!(r0.source(), SourceType::Default);
        assert!(!r0.is_primary());

        let r1 = list.get_ref(&addr(0x1010), 1).unwrap();
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
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();
        assert!(adapter.get_ref_list(None, &addr(0x9000), 0x9000).unwrap().is_none());
    }

    #[test]
    fn has_ref_to_and_record_count_reflect_the_table() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x1010, 0x3000, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

        assert!(adapter.has_ref_to(0x2000).unwrap());
        assert!(adapter.has_ref_to(0x3000).unwrap());
        assert!(!adapter.has_ref_to(0x4000).unwrap());
        assert_eq!(adapter.get_record_count(), 2);
    }

    #[test]
    fn get_record_returns_the_raw_untranslated_row() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(7, 0x1000, 0x2000, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

        let rec = RecordAdapter::get_record(&adapter, 7).unwrap();
        assert_eq!(rec.get_long(OLD_FROM_ADDR_COL), Some(0x1000));
        assert_eq!(rec.get_long(OLD_TO_ADDR_COL), Some(0x2000));
        assert!(RecordAdapter::get_record(&adapter, 999).is_err());
    }

    #[test]
    fn to_iterator_visits_distinct_to_addresses_in_order() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x1, 0x300, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x2, 0x100, 0, false, RefType::Data, -1, false),
                old_ref_record(2, 0x3, 0x200, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

        let forward: Vec<i64> = adapter.get_to_iterator(true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(forward, vec![0x100, 0x200, 0x300]);
        let backward: Vec<i64> = adapter.get_to_iterator(false).unwrap().map(|a| a.offset()).collect();
        assert_eq!(backward, vec![0x300, 0x200, 0x100]);
    }

    #[test]
    fn to_iterator_from_start_address_is_restricted() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                old_ref_record(0, 0x1, 0x100, 0, false, RefType::Data, -1, false),
                old_ref_record(1, 0x2, 0x200, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

        let from: Vec<i64> =
            adapter.get_to_iterator_from(&addr(0x150), true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(from, vec![0x200]);
    }

    #[test]
    fn to_iterator_in_set_scans_the_from_column_matching_java() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(
            &mut handle,
            &[
                // from=0x50 (in set), to=0x9000 (out of the queried set) -- if this adapter
                // scanned OLD_TO_ADDR_COL like every other overload, this row would be excluded;
                // since Java's actual implementation scans OLD_FROM_ADDR_COL, it's included.
                old_ref_record(0, 0x50, 0x9000, 0, false, RefType::Data, -1, false),
            ],
        );
        let map = addr_map();
        let adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

        let set = AddressSet::from_start_end(addr(0x0), addr(0x100));
        let in_set: Vec<i64> = adapter.get_to_iterator_in_set(&set, true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(in_set, vec![0x50]);
    }

    #[test]
    fn mutating_methods_and_get_old_namespace_addresses_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(0, 0x1, 0x100, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let mut adapter = ToAdapterSharedTable::new(&handle, &map).unwrap();

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
        match adapter.get_old_namespace_addresses(&space()) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected an Unsupported error"),
        }
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, &[old_ref_record(0, 0x1000, 0x2000, 0, false, RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter: Box<dyn ToAdapter> = Box::new(ToAdapterSharedTable::new(&handle, &map).unwrap());
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.has_ref_to(0x2000).unwrap());
    }
}
