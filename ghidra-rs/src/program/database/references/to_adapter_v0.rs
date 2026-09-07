//! Port of `ghidra.program.database.references.ToAdapterV0`.
//!
//! Read-only legacy (schema version 0) adapter for the "TO REFS" table -- one of the handful of
//! read-only adapters `ToAdapter.findReadOnlyAdapter`/`upgrade` (both static factory methods, not
//! yet ported -- see `to_adapter.rs`'s module docs) probe when the live [`ToAdapterV1`] (not yet
//! ported) schema doesn't open. Version 0's on-disk schema has just two columns -- `[Number of
//! Refs, Ref Data]` (no `Ref Level`) -- so every read translates the stored record into the
//! current (version 1) three-column shape on the fly, computing the missing `Ref Level` byte by
//! decoding the reference list and taking the maximum [`ref_level_for`] over every reference,
//! exactly like Java's private `getRefLevel(DBRecord)`. Every mutating method
//! (`createRefList`/`createRecord`/`putRecord`/`removeRecord`/`getOldNamespaceAddresses`) is
//! rejected, matching Java's `UnsupportedOperationException`s.
//!
//! This module also hosts the "current" (version 1) `TO_REFS_TABLE_NAME`/schema/column constants
//! that `ghidra.program.database.references.ToAdapter` declares as shared statics --
//! `to_adapter.rs`'s module docs left them for "whichever concrete subclass is ported first" (this
//! one, since it's the first of `ToAdapterV0`/`ToAdapterV1`/`ToAdapterSharedTable` to land).
//! `ToAdapterV1` (not yet ported) should import [`to_refs_schema`]/[`TO_REFS_TABLE_NAME`]/the
//! column constants from here rather than duplicating them, since V1's on-disk schema *is* the
//! current schema (no translation needed).
//!
//! Not ported: the private nested `TranslatedRecordIterator` class -- it has no call site
//! anywhere in `ToAdapterV0.java` itself (dead code even in the original), so there is nothing to
//! preserve parity with.
//!
//! **Iteration.** Java threads a `db.util.ErrorHandler` through `AddressKeyAddressIterator` so
//! per-item I/O failures during lazy iteration can be reported without a checked-exception-free
//! `Iterator`. This port's [`AddressKeyIterator`] already snapshots every matching key eagerly
//! (see that module's docs), so `get_to_iterator`/`get_to_iterator_from`/`get_to_iterator_in_set`
//! just walk the (already fully-materialized) key snapshot into a `Vec<Address>` up front and
//! propagate any I/O error through the outer `io::Result` instead -- no error handler needed.
//!
//! **Address-map thread-safety.**
//! [`RefListV0Impl`](crate::program::database::references::ref_list_v0::RefListV0Impl) (this
//! adapter's [`RefList`] factory) requires an `Arc<dyn AddressMap + Send + Sync>`, but
//! [`AddressMap::get_old_address_map`] only returns a plain `Box<dyn AddressMap>` (the trait
//! itself declares no `Send`/`Sync` bound). Every real [`AddressMap`] implementor in this port is
//! plain data or `Arc<RwLock<..>>`-backed (no `Rc`/`RefCell`), so [`SendSyncAddressMap`] below is
//! a thin, zero-behavior newtype that asserts what is already true of the wrapped map, rather than
//! widening the shared trait (and its ~20 mock implementors across the codebase) just for this one
//! adapter.

use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::map::{AddressKeyIterator, AddressMap};
use crate::program::database::references::ref_list_v0::{ref_level_for, RefListV0Impl};
use crate::program::database::references::{RecordAdapter, RefList, ToAdapter};
use crate::program::database::ProgramDB;
use crate::program::model::address::{
    Address, AddressFactory, AddressSetView, AddressSpace, BoxedAddressIterator, KeyRange,
};
use crate::util::exception::VersionException;

/// Table name shared by every schema version of the "to address" reference list table.
pub const TO_REFS_TABLE_NAME: &str = "TO REFS";

/// Current (version 1) schema version. Version 0 predates the `Ref Level` column.
pub const CURRENT_VERSION: i32 = 1;

/// Column index of the reference count, in both the legacy (V0) and current schema.
pub const REF_COUNT_COL: usize = 0;
/// Column index of the packed reference-data blob, in both the legacy (V0) and current schema.
pub const REF_DATA_COL: usize = 1;
/// Column index of the cached reference level. Only present in the current schema -- version 0's
/// on-disk records don't have this column at all, so [`ToAdapterV0`] computes it on every read.
pub const REF_LEVEL_COL: usize = 2;

/// Returns the current (version 1) schema for the "TO REFS" table. Stands in for
/// `ToAdapter.TO_REFS_SCHEMA`.
pub fn to_refs_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "To Address".to_string(),
        vec![FieldType::Int, FieldType::Binary, FieldType::Byte],
        vec![
            "Number of Refs".to_string(),
            "Ref Data".to_string(),
            "Ref Level".to_string(),
        ],
        vec![],
    ))
}

/// Legacy (version 0) on-disk schema: no `Ref Level` column.
fn to_refs_schema_v0() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "To Address".to_string(),
        vec![FieldType::Int, FieldType::Binary],
        vec!["Number of Refs".to_string(), "Ref Data".to_string()],
        vec![],
    ))
}

/// See the module docs for why this exists.
struct SendSyncAddressMap(Box<dyn AddressMap>);

// SAFETY: every real `AddressMap` implementor in this port is plain data or
// `Arc<RwLock<..>>`-backed, with no `Rc`/`RefCell`/thread-local state, so a boxed `AddressMap`
// trait object is safe to hand across threads even though the trait itself declares no
// `Send`/`Sync` bound. See the module docs.
unsafe impl Send for SendSyncAddressMap {}
unsafe impl Sync for SendSyncAddressMap {}

impl AddressMap for SendSyncAddressMap {
    fn get_key(&self, addr: &Address, create: bool) -> i64 {
        self.0.get_key(addr, create)
    }

    fn get_absolute_encoding(&self, addr: &Address, create: bool) -> i64 {
        self.0.get_absolute_encoding(addr, create)
    }

    fn find_key_range(&self, key_range_list: &[KeyRange], addr: Option<&Address>) -> i32 {
        self.0.find_key_range(key_range_list, addr)
    }

    fn decode_address(&self, value: i64) -> Address {
        self.0.decode_address(value)
    }

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        self.0.get_address_factory()
    }

    fn get_key_ranges_absolute(
        &self,
        start: &Address,
        end: &Address,
        absolute: bool,
        create: bool,
    ) -> Vec<KeyRange> {
        self.0.get_key_ranges_absolute(start, end, absolute, create)
    }

    fn get_key_ranges_for_set_absolute(
        &self,
        set: Option<&dyn AddressSetView>,
        absolute: bool,
        create: bool,
    ) -> Vec<KeyRange> {
        self.0.get_key_ranges_for_set_absolute(set, absolute, create)
    }

    fn get_old_address_map(&self) -> Box<dyn AddressMap> {
        self.0.get_old_address_map()
    }

    fn is_upgraded(&self) -> bool {
        self.0.is_upgraded()
    }

    fn get_image_base(&self) -> Address {
        self.0.get_image_base()
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "UnsupportedOperationException: ToAdapterV0 is a read-only legacy adapter",
    )
}

/// A [`RecordAdapter`] that rejects every mutation. Handed to [`RefListV0Impl`] as the "backing
/// adapter" for lists read out of [`ToAdapterV0`], mirroring how Java passes `this` (a `ToAdapterV0`
/// whose own `createRecord`/`putRecord`/`removeRecord` all throw) to `RefListV0.instantiateExisting`
/// -- any attempted mutation of a list read from this legacy adapter fails loudly rather than
/// silently no-op'ing.
struct UnsupportedRecordAdapter;

impl RecordAdapter for UnsupportedRecordAdapter {
    fn create_record(
        &mut self,
        _key: i64,
        _num_refs: i32,
        _ref_level: u8,
        _ref_data: &[u8],
    ) -> io::Result<DBRecord> {
        Err(unsupported())
    }

    fn get_record(&self, _key: i64) -> io::Result<DBRecord> {
        Err(unsupported())
    }

    fn put_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    fn remove_record(&mut self, _key: i64) -> io::Result<()> {
        Err(unsupported())
    }
}

/// Read-only legacy (schema version 0) adapter for the "TO REFS" table.
///
/// Port of `ghidra.program.database.references.ToAdapterV0`. See the module docs for the
/// record-translation and read-only deviations.
pub struct ToAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
}

impl ToAdapterV0 {
    /// Opens the existing "TO REFS" table from `handle`, verifying it is schema version 0.
    /// `addr_map` mirrors Java's constructor parameter (the *current*, post-upgrade map); this
    /// constructor takes its [`AddressMap::get_old_address_map`] internally, mirroring
    /// `addrMap.getOldAddressMap()`.
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table does not exist or is not schema version 0.
    pub fn new(handle: &DBHandle, addr_map: &dyn AddressMap) -> Result<Self, VersionException> {
        let table = handle.get_table(TO_REFS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {TO_REFS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(VersionException::with_upgradeable(false));
        }
        Ok(ToAdapterV0 {
            table,
            addr_map: Arc::new(SendSyncAddressMap(addr_map.get_old_address_map())),
        })
    }

    /// Converts a legacy (version 0) record -- `[Number of Refs, Ref Data]` -- into the current
    /// (version 1) record shape, computing `Ref Level` by decoding the reference data. Stands in
    /// for `ToAdapterV0.translateRecord(DBRecord)`.
    fn translate_record(&self, old_rec: Option<DBRecord>) -> io::Result<Option<DBRecord>> {
        let Some(old_rec) = old_rec else {
            return Ok(None);
        };
        let key = match old_rec.get_key() {
            Field::Long(Some(k)) => *k,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TO REFS record must have a Long key",
                ))
            }
        };
        let num_refs = old_rec.get_int(REF_COUNT_COL).unwrap_or(0);
        let ref_data = match old_rec.get_field(REF_DATA_COL) {
            Field::Binary(Some(data)) => data.clone(),
            _ => Vec::new(),
        };
        let ref_level = self.compute_ref_level(key, &ref_data, num_refs);

        let mut rec = DBRecord::new(to_refs_schema(), Field::Long(Some(key)));
        rec.set_int(REF_COUNT_COL, num_refs);
        rec.set_field(REF_DATA_COL, Field::Binary(Some(ref_data)));
        rec.set_byte(REF_LEVEL_COL, ref_level);
        Ok(Some(rec))
    }

    /// Decodes `ref_data` and returns the highest [`ref_level_for`] across every reference.
    /// Stands in for `ToAdapterV0.getRefLevel(DBRecord)`.
    fn compute_ref_level(&self, key: i64, ref_data: &[u8], num_refs: i32) -> i8 {
        let list = RefListV0Impl::instantiate_existing(
            key,
            ref_data.to_vec(),
            num_refs,
            -1,
            None,
            self.addr_map.clone(),
            false,
        );
        let mut ref_level: i8 = -1;
        for r in list.get_all_refs() {
            let level = ref_level_for(r.reference_type());
            if level > ref_level {
                ref_level = level;
            }
        }
        ref_level
    }

    fn get_ref_list_impl(&self, to_addr: i64) -> io::Result<Option<Box<dyn RefList>>> {
        let raw = self.table.read().unwrap().get_record(&Field::Long(Some(to_addr)))?;
        let Some(translated) = self.translate_record(raw)? else {
            return Ok(None);
        };
        let key = match translated.get_key() {
            Field::Long(Some(k)) => *k,
            _ => to_addr,
        };
        let num_refs = translated.get_int(REF_COUNT_COL).unwrap_or(0);
        let ref_level = translated.get_byte(REF_LEVEL_COL).unwrap_or(-1);
        let ref_data = match translated.get_field(REF_DATA_COL) {
            Field::Binary(Some(data)) => data.clone(),
            _ => Vec::new(),
        };
        let adapter: Arc<Mutex<dyn RecordAdapter + Send>> =
            Arc::new(Mutex::new(UnsupportedRecordAdapter));
        let list = RefListV0Impl::instantiate_existing(
            key,
            ref_data,
            num_refs,
            ref_level,
            Some(adapter),
            self.addr_map.clone(),
            false,
        );
        Ok(Some(Box::new(list)))
    }

    /// Shared implementation of the three `getToIterator` overloads: eagerly snapshots every
    /// matching address key via [`AddressKeyIterator`] and decodes them into a `Vec<Address>`.
    /// See the module docs for why this is eager rather than lazy.
    fn collect_to_addresses(
        &self,
        set: Option<&dyn AddressSetView>,
        start_addr: Option<&Address>,
        forward: bool,
    ) -> io::Result<BoxedAddressIterator> {
        use crate::framework::db::DBLongIterator;

        let mut key_iter = if let Some(set) = set {
            AddressKeyIterator::new_over_set(
                &self.table,
                self.addr_map.as_ref(),
                Some(set),
                set.min_address().as_ref(),
                forward,
            )?
        } else if let Some(start) = start_addr {
            AddressKeyIterator::new_at(&self.table, self.addr_map.as_ref(), start, forward)?
        } else {
            AddressKeyIterator::new(&self.table, self.addr_map.as_ref(), forward)?
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

impl RecordAdapter for ToAdapterV0 {
    /// Always fails. Stands in for `ToAdapterV0.createRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn create_record(
        &mut self,
        _key: i64,
        _num_refs: i32,
        _ref_level: u8,
        _ref_data: &[u8],
    ) -> io::Result<DBRecord> {
        Err(unsupported())
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        let raw = self.table.read().unwrap().get_record(&Field::Long(Some(key)))?;
        self.translate_record(raw)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such TO REFS record"))
    }

    /// Always fails. Stands in for `ToAdapterV0.putRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn put_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    /// Always fails. Stands in for `ToAdapterV0.removeRecord`, which always throws
    /// `UnsupportedOperationException`.
    fn remove_record(&mut self, _key: i64) -> io::Result<()> {
        Err(unsupported())
    }
}

impl ToAdapter for ToAdapterV0 {
    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    /// Always fails. Stands in for `ToAdapterV0.createRefList`, which always throws
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
        _to: &Address,
        to_addr: i64,
    ) -> io::Result<Option<Box<dyn RefList>>> {
        self.get_ref_list_impl(to_addr)
    }

    fn has_ref_to(&self, to_addr: i64) -> io::Result<bool> {
        Ok(self.table.read().unwrap().has_record(&Field::Long(Some(to_addr))))
    }

    fn get_to_iterator(&self, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(None, None, forward)
    }

    fn get_to_iterator_from(
        &self,
        start_addr: &Address,
        forward: bool,
    ) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(None, Some(start_addr), forward)
    }

    fn get_to_iterator_in_set(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(Some(set), None, forward)
    }

    /// Always fails. Stands in for `ToAdapterV0.getOldNamespaceAddresses`, which always throws
    /// `UnsupportedOperationException`.
    fn get_old_namespace_addresses(&self, _addr_space: &AddressSpace) -> io::Result<BoxedAddressIterator> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpaceType, KeyRange as ArKeyRange};
    use crate::program::model::symbol::{RefType, SourceType};
    use std::sync::Arc as StdArc;

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
        fn find_key_range(&self, _key_range_list: &[ArKeyRange], _addr: Option<&Address>) -> i32 {
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
        ) -> Vec<ArKeyRange> {
            vec![ArKeyRange::new(start.offset(), end.offset())]
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<ArKeyRange> {
            match set {
                None => vec![ArKeyRange::new(i64::MIN, i64::MAX)],
                Some(set) => {
                    let mut ranges = Vec::new();
                    let mut it = set.address_ranges();
                    while let Some(range) = it.next() {
                        ranges.push(ArKeyRange::new(
                            range.min_address().offset(),
                            range.max_address().offset(),
                        ));
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

    /// Builds a "to" list with `RefListV0Impl` (the just-landed concrete `RefList`), then writes
    /// its raw encoded bytes into a legacy (version 0, two-column) "TO REFS" table record --
    /// exactly the on-disk shape `ToAdapterV0` reads.
    fn setup_v0_table(handle: &mut DBHandle, to: &Address, refs: &[(Address, RefType, i64, bool)]) {
        let map: Arc<dyn AddressMap + Send + Sync> = StdArc::new(addr_map());
        let mut list = RefListV0Impl::create_temporary(map.get_key(to, true), map.clone(), false);
        for (from, ref_type, symbol_id, is_primary) in refs {
            list.add_ref(
                from,
                to,
                *ref_type,
                0,
                *symbol_id,
                *is_primary,
                SourceType::Analysis,
                false,
                false,
                0,
            )
            .unwrap();
        }

        let table = handle
            .create_table(TO_REFS_TABLE_NAME.to_string(), to_refs_schema_v0())
            .unwrap();
        let mut rec = DBRecord::new(to_refs_schema_v0(), Field::Long(Some(map.get_key(to, true))));
        rec.set_int(REF_COUNT_COL, list.get_num_refs());
        rec.set_field(REF_DATA_COL, Field::Binary(Some(list.raw_ref_data().to_vec())));
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn opening_wrong_version_table_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(TO_REFS_TABLE_NAME.to_string(), to_refs_schema())
            .unwrap();
        let map = addr_map();
        assert!(ToAdapterV0::new(&handle, &map).is_err());
    }

    #[test]
    fn opening_missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        let map = addr_map();
        assert!(ToAdapterV0::new(&handle, &map).is_err());
    }

    #[test]
    fn get_ref_list_translates_a_legacy_record_and_computes_ref_level() {
        let mut handle = DBHandle::new().unwrap();
        let to = addr(0x2000);
        setup_v0_table(
            &mut handle,
            &to,
            &[
                (addr(0x1000), RefType::Data, -1, false),
                (addr(0x1010), RefType::UnconditionalCall, 7, true),
            ],
        );
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        let list = adapter
            .get_ref_list(None, &to, to.offset())
            .unwrap()
            .expect("record should exist");
        assert_eq!(list.get_num_refs(), 2);
        // A call reference should have raised the level to SUB_LEVEL.
        assert_eq!(
            list.get_reference_level(),
            crate::program::model::symbol::SUB_LEVEL as i8
        );
        let refs = list.get_all_refs();
        assert!(refs.iter().any(|r| r.from_address() == addr(0x1010) && r.symbol_id() == 7));
    }

    #[test]
    fn get_ref_list_returns_none_for_missing_address() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x2000), &[(addr(0x1000), RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        assert!(adapter.get_ref_list(None, &addr(0x9000), 0x9000).unwrap().is_none());
    }

    #[test]
    fn has_ref_to_and_record_count_reflect_the_table() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x2000), &[(addr(0x1000), RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        assert!(adapter.has_ref_to(0x2000).unwrap());
        assert!(!adapter.has_ref_to(0x3000).unwrap());
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn get_record_returns_translated_record_with_ref_level_populated() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(
            &mut handle,
            &addr(0x2000),
            &[(addr(0x1000), RefType::UnconditionalJump, -1, false)],
        );
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        let rec = RecordAdapter::get_record(&adapter, 0x2000).unwrap();
        assert_eq!(rec.get_int(REF_COUNT_COL), Some(1));
        assert!(rec.get_byte(REF_LEVEL_COL).is_some());

        assert!(RecordAdapter::get_record(&adapter, 0x9999).is_err());
    }

    #[test]
    fn to_iterator_visits_addresses_in_order_both_directions() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x300), &[(addr(0x1), RefType::Data, -1, false)]);
        {
            let table = handle.get_table(TO_REFS_TABLE_NAME).unwrap();
            let mut rec = DBRecord::new(to_refs_schema_v0(), Field::Long(Some(0x100)));
            rec.set_int(REF_COUNT_COL, 0);
            rec.set_field(REF_DATA_COL, Field::Binary(Some(Vec::new())));
            table.write().unwrap().put_record(rec).unwrap();
            let mut rec2 = DBRecord::new(to_refs_schema_v0(), Field::Long(Some(0x200)));
            rec2.set_int(REF_COUNT_COL, 0);
            rec2.set_field(REF_DATA_COL, Field::Binary(Some(Vec::new())));
            table.write().unwrap().put_record(rec2).unwrap();
        }
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        let forward: Vec<i64> = adapter.get_to_iterator(true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(forward, vec![0x100, 0x200, 0x300]);

        let backward: Vec<i64> = adapter.get_to_iterator(false).unwrap().map(|a| a.offset()).collect();
        assert_eq!(backward, vec![0x300, 0x200, 0x100]);
    }

    #[test]
    fn to_iterator_from_start_address_is_restricted() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x100), &[(addr(0x1), RefType::Data, -1, false)]);
        {
            let table = handle.get_table(TO_REFS_TABLE_NAME).unwrap();
            let mut rec = DBRecord::new(to_refs_schema_v0(), Field::Long(Some(0x200)));
            rec.set_int(REF_COUNT_COL, 0);
            rec.set_field(REF_DATA_COL, Field::Binary(Some(Vec::new())));
            table.write().unwrap().put_record(rec).unwrap();
        }
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        let from: Vec<i64> = adapter
            .get_to_iterator_from(&addr(0x150), true)
            .unwrap()
            .map(|a| a.offset())
            .collect();
        assert_eq!(from, vec![0x200]);
    }

    #[test]
    fn to_iterator_in_set_is_restricted() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x100), &[(addr(0x1), RefType::Data, -1, false)]);
        {
            let table = handle.get_table(TO_REFS_TABLE_NAME).unwrap();
            let mut rec = DBRecord::new(to_refs_schema_v0(), Field::Long(Some(0x500)));
            rec.set_int(REF_COUNT_COL, 0);
            rec.set_field(REF_DATA_COL, Field::Binary(Some(Vec::new())));
            table.write().unwrap().put_record(rec).unwrap();
        }
        let map = addr_map();
        let adapter = ToAdapterV0::new(&handle, &map).unwrap();

        let set = AddressSet::from_start_end(addr(0x0), addr(0x200));
        let in_set: Vec<i64> = adapter
            .get_to_iterator_in_set(&set, true)
            .unwrap()
            .map(|a| a.offset())
            .collect();
        assert_eq!(in_set, vec![0x100]);
    }

    #[test]
    fn mutating_methods_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x100), &[(addr(0x1), RefType::Data, -1, false)]);
        let map = addr_map();
        let mut adapter = ToAdapterV0::new(&handle, &map).unwrap();

        match adapter.create_ref_list(None, &addr(0x999)) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected an Unsupported error"),
        }
        assert_eq!(
            RecordAdapter::create_record(&mut adapter, 1, 0, 0, &[]).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let rec = DBRecord::new(to_refs_schema(), Field::Long(Some(1)));
        assert_eq!(
            RecordAdapter::put_record(&mut adapter, &rec).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            RecordAdapter::remove_record(&mut adapter, 1).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        match adapter.get_old_namespace_addresses(&space()) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected an Unsupported error"),
        }
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        setup_v0_table(&mut handle, &addr(0x2000), &[(addr(0x1000), RefType::Data, -1, false)]);
        let map = addr_map();
        let adapter: Box<dyn ToAdapter> = Box::new(ToAdapterV0::new(&handle, &map).unwrap());
        assert_eq!(adapter.get_record_count(), 1);
        assert!(adapter.has_ref_to(0x2000).unwrap());
    }
}
