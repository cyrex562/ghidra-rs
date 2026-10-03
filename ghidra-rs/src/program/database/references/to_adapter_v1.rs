//! Port of `ghidra.program.database.references.ToAdapterV1`.
//!
//! The live (current, schema version 1), read-write adapter for the "TO REFS" table. Unlike
//! [`ToAdapterV0`] (a read-only legacy translation layer), this adapter is the real
//! [`RecordAdapter`] handed to [`RefListV0Impl`]/[`BigRefListV0Impl`] so their mutations actually
//! persist: a "to" address's stored pointer record's `Ref Data` column being `None` (vs
//! `Some(bytes)`) is the sentinel distinguishing "this address's references live in a
//! [`BigRefListV0Impl`] side table" from "this address's references are packed inline in a
//! [`RefListV0Impl`]" -- see [`RecordAdapter::create_record`]'s own doc comment for the same
//! sentinel from the writer's side.
//!
//! **Self-referential adapter handle.** Java passes `this` (the `ToAdapterV1` instance itself,
//! which implements `RecordAdapter`) to `RefListV0.createNew`/`instantiateExisting` and
//! `BigRefListV0.createExisting`, so lists it hands out can call back into its `putRecord`/
//! `createRecord` on every mutation. A Rust `&self`/`&mut self` reference can't be captured inside
//! a `Box<dyn RefList>` returned by value the way Java's object reference can, so the table this
//! adapter wraps instead lives inside a small private [`ToAdapterV1Core`], shared via
//! `Arc<Mutex<ToAdapterV1Core>>` -- `create_ref_list`/`get_ref_list` clone that `Arc` (coerced to
//! `Arc<Mutex<dyn RecordAdapter + Send>>`) to hand out a live, independently-lockable handle back
//! to the same table, and `ToAdapterV1`'s own [`RecordAdapter`] impl (required by the
//! `ToAdapter: RecordAdapter` supertrait bound) just delegates to the same core.
//!
//! **No stored `Program`.** Same rationale as `RefListV0Impl`/`BigRefListV0Impl`: Java's
//! constructor takes no `Program` itself (curiously -- `ToAdapterV1` predates `BigRefListV0`
//! needing one), but `getRefList`'s `BigRefListV0.createExisting(..., program, ...)` call does
//! pass one through, used only to reach `program.getDBHandle()`. This port stores the `DBHandle`
//! it needs directly (`Arc<Mutex<DBHandle>>`, threaded straight into any `BigRefListV0Impl` it
//! constructs) instead.
//!
//! **`getOldNamespaceAddresses` is not supported by this port.** Java's version converts an
//! `AddressSpace` into a `[minKey, maxKey]` range via
//! `OldGenericNamespaceAddress.getMinAddress/getMaxAddress(addrSpace, id).getKey(...)`. This
//! port's [`OldGenericNamespaceAddress`] is a deliberately distinct value type from [`Address`]
//! (see that module's own doc comment: "It intentionally remains a distinct value type instead of
//! changing the modern `Address` identity model"), so it cannot be passed to
//! [`AddressMap::get_key`], which only accepts a real `Address`. Reconciling that would mean
//! growing `AddressMap` a namespace-aware key encoding this port doesn't have anywhere else, which
//! is out of scope for porting this one (legacy-namespace-upgrade-only) method. This is an honest,
//! tested gap, not a silent one: the method returns a clear, documented [`io::Error`] rather than
//! wrong or empty data -- see [`Self::get_old_namespace_addresses`]'s own doc comment and the
//! `get_old_namespace_addresses_is_not_supported` test.
//!
//! **Iteration.** Same convention as [`ToAdapterV0`]: `AddressKeyIterator`'s snapshot is walked
//! eagerly into a `Vec<Address>` rather than threading Java's `ErrorHandler` through a lazy
//! iterator -- see that module's docs for the full rationale.

use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, Table};
use crate::program::database::map::{AddressKeyIterator, AddressMap};
use crate::program::database::references::big_ref_list_v0::BigRefListV0Impl;
use crate::program::database::references::ref_list_v0::RefListV0Impl;
use crate::program::database::references::to_adapter_v0::{
    to_refs_schema, CURRENT_VERSION, REF_COUNT_COL, REF_DATA_COL, REF_LEVEL_COL, TO_REFS_TABLE_NAME,
};
use crate::program::database::references::{RecordAdapter, RefList, ToAdapter};
use crate::program::database::ProgramDB;
use crate::program::model::address::{Address, AddressSetView, AddressSpace, BoxedAddressIterator};
use crate::util::exception::VersionException;

/// The shared, lockable table handle every [`RefListV0Impl`]/[`BigRefListV0Impl`] this adapter
/// hands out calls back into. See the module docs for why this indirection exists.
struct ToAdapterV1Core {
    table: Arc<RwLock<Table>>,
}

impl RecordAdapter for ToAdapterV1Core {
    fn create_record(
        &mut self,
        key: i64,
        num_refs: i32,
        ref_level: u8,
        ref_data: Option<&[u8]>,
    ) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(to_refs_schema(), Field::Long(Some(key)));
        rec.set_int(REF_COUNT_COL, num_refs);
        rec.set_field(REF_DATA_COL, Field::Binary(ref_data.map(|d| d.to_vec())));
        rec.set_byte(REF_LEVEL_COL, ref_level as i8);
        self.table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such TO REFS record"))
    }

    fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_record(&mut self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key))).map(|_| ())
    }
}

/// Live (current, schema version 1), read-write adapter for the "TO REFS" table.
///
/// Port of `ghidra.program.database.references.ToAdapterV1`. See the module docs for the
/// self-referential-adapter and dropped-`Program` deviations, and the one deliberately unsupported
/// method (`getOldNamespaceAddresses`).
pub struct ToAdapterV1 {
    core: Arc<Mutex<ToAdapterV1Core>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    db_handle: Arc<Mutex<DBHandle>>,
}

impl ToAdapterV1 {
    /// Opens (or, if `create`, creates) the "TO REFS" table from `db_handle`.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if `create` is `false` and the table is missing, is an
    /// older (upgradable) version, is a newer version, or (collapsing Java's separate
    /// `IOException` for this one case, matching this codebase's established convention for
    /// version-checking constructors -- see e.g. `FunctionAdapterV0`'s own module docs for the
    /// same collapse) table creation itself fails.
    pub fn new(
        create: bool,
        db_handle: Arc<Mutex<DBHandle>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
    ) -> Result<Self, VersionException> {
        let table = {
            let mut handle = db_handle
                .lock()
                .expect("ToAdapterV1's db_handle mutex should never be poisoned");
            if create {
                handle
                    .create_table(TO_REFS_TABLE_NAME.to_string(), to_refs_schema())
                    .map_err(|e| VersionException::with_message(format!("{e}")))?
            } else {
                let table = handle.get_table(TO_REFS_TABLE_NAME).ok_or_else(|| {
                    VersionException::with_message(format!("Missing Table: {TO_REFS_TABLE_NAME}"))
                })?;
                let version = table.read().unwrap().get_schema().get_version();
                if version != CURRENT_VERSION {
                    if version < CURRENT_VERSION {
                        return Err(VersionException::with_upgradeable(true));
                    }
                    return Err(VersionException::with_version_indicator(
                        VersionException::NEWER_VERSION,
                        false,
                    ));
                }
                table
            }
        };
        Ok(ToAdapterV1 {
            core: Arc::new(Mutex::new(ToAdapterV1Core { table })),
            addr_map,
            db_handle,
        })
    }

    fn table(&self) -> Arc<RwLock<Table>> {
        self.core.lock().expect("ToAdapterV1's core mutex should never be poisoned").table.clone()
    }

    fn adapter_handle(&self) -> Arc<Mutex<dyn RecordAdapter + Send>> {
        self.core.clone()
    }

    fn collect_to_addresses(
        &self,
        set: Option<&dyn AddressSetView>,
        start_addr: Option<&Address>,
        forward: bool,
    ) -> io::Result<BoxedAddressIterator> {
        use crate::framework::db::DBLongIterator;

        let table = self.table();
        let mut key_iter = if let Some(set) = set {
            AddressKeyIterator::new_over_set(
                &table,
                self.addr_map.as_ref(),
                Some(set),
                set.min_address().as_ref(),
                forward,
            )?
        } else if let Some(start) = start_addr {
            AddressKeyIterator::new_at(&table, self.addr_map.as_ref(), start, forward)?
        } else {
            AddressKeyIterator::new(&table, self.addr_map.as_ref(), forward)?
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

impl RecordAdapter for ToAdapterV1 {
    fn create_record(
        &mut self,
        key: i64,
        num_refs: i32,
        ref_level: u8,
        ref_data: Option<&[u8]>,
    ) -> io::Result<DBRecord> {
        self.core.lock().unwrap().create_record(key, num_refs, ref_level, ref_data)
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.core.lock().unwrap().get_record(key)
    }

    fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.core.lock().unwrap().put_record(record)
    }

    fn remove_record(&mut self, key: i64) -> io::Result<()> {
        self.core.lock().unwrap().remove_record(key)
    }
}

impl ToAdapter for ToAdapterV1 {
    fn get_record_count(&self) -> i32 {
        self.table().read().unwrap().get_record_count() as i32
    }

    fn create_ref_list(
        &mut self,
        _program: Option<&ProgramDB>,
        to_addr: &Address,
    ) -> io::Result<Box<dyn RefList>> {
        let list = RefListV0Impl::create_new(
            to_addr.clone(),
            Some(self.adapter_handle()),
            self.addr_map.clone(),
            false,
        );
        Ok(Box::new(list))
    }

    fn get_ref_list(
        &self,
        _program: Option<&ProgramDB>,
        _to: &Address,
        to_addr: i64,
    ) -> io::Result<Option<Box<dyn RefList>>> {
        let table = self.table();
        let rec = table.read().unwrap().get_record(&Field::Long(Some(to_addr)))?;
        let Some(rec) = rec else {
            return Ok(None);
        };
        let num_refs = rec.get_int(REF_COUNT_COL).unwrap_or(0);
        let ref_level = rec.get_byte(REF_LEVEL_COL).unwrap_or(-1);
        match rec.get_field(REF_DATA_COL) {
            Field::Binary(None) => {
                let list = BigRefListV0Impl::create_existing(
                    to_addr,
                    ref_level,
                    Some(self.adapter_handle()),
                    self.addr_map.clone(),
                    self.db_handle.clone(),
                    false,
                )?;
                Ok(Some(Box::new(list)))
            }
            Field::Binary(Some(data)) => {
                let list = RefListV0Impl::instantiate_existing(
                    to_addr,
                    data.clone(),
                    num_refs,
                    ref_level,
                    Some(self.adapter_handle()),
                    self.addr_map.clone(),
                    false,
                );
                Ok(Some(Box::new(list)))
            }
            _ => Ok(None),
        }
    }

    fn has_ref_to(&self, to_addr: i64) -> io::Result<bool> {
        Ok(self.table().read().unwrap().has_record(&Field::Long(Some(to_addr))))
    }

    fn get_to_iterator(&self, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(None, None, forward)
    }

    fn get_to_iterator_from(&self, start_addr: &Address, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(None, Some(start_addr), forward)
    }

    fn get_to_iterator_in_set(&self, set: &dyn AddressSetView, forward: bool) -> io::Result<BoxedAddressIterator> {
        self.collect_to_addresses(Some(set), None, forward)
    }

    /// Not supported by this port -- see the module docs for why.
    ///
    /// # Errors
    ///
    /// Always returns an [`io::ErrorKind::Unsupported`] error.
    fn get_old_namespace_addresses(&self, _addr_space: &AddressSpace) -> io::Result<BoxedAddressIterator> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ToAdapterV1::get_old_namespace_addresses: OldGenericNamespaceAddress is not an \
             Address in this port, so it cannot be encoded via AddressMap::get_key -- see the \
             module docs",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSpaceType, KeyRange};
    use crate::program::model::symbol::{RefType, SourceType, SUB_LEVEL};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    #[derive(Clone)]
    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
        special: Arc<StdMutex<HashMap<i64, Address>>>,
        next_special_key: Arc<StdMutex<i64>>,
    }

    impl IdentityAddressMap {
        fn new(space: Arc<AddressSpace>) -> Self {
            IdentityAddressMap {
                space,
                special: Arc::new(StdMutex::new(HashMap::new())),
                next_special_key: Arc::new(StdMutex::new(-1000)),
            }
        }
    }

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            if addr.space().space_type() == AddressSpaceType::Ram {
                return addr.offset();
            }
            let mut special = self.special.lock().unwrap();
            if let Some((k, _)) = special.iter().find(|(_, v)| *v == addr) {
                return *k;
            }
            let mut next = self.next_special_key.lock().unwrap();
            let key = *next;
            *next -= 1;
            special.insert(key, addr.clone());
            key
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            if value >= 0 {
                Address::new(self.space.clone(), value)
            } else {
                self.special.lock().unwrap().get(&value).cloned().expect("unknown key")
            }
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

    fn addr_map() -> Arc<dyn AddressMap + Send + Sync> {
        Arc::new(IdentityAddressMap::new(space()))
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn handle() -> Arc<Mutex<DBHandle>> {
        Arc::new(Mutex::new(DBHandle::new().unwrap()))
    }

    #[test]
    fn create_true_creates_a_fresh_table() {
        let h = handle();
        let adapter = ToAdapterV1::new(true, h.clone(), addr_map()).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
        assert!(h.lock().unwrap().get_table(TO_REFS_TABLE_NAME).is_some());
    }

    #[test]
    fn create_false_on_missing_table_is_an_error() {
        let h = handle();
        assert!(ToAdapterV1::new(false, h, addr_map()).is_err());
    }

    #[test]
    fn create_false_on_wrong_version_table_is_an_error() {
        let h = handle();
        {
            let mut guard = h.lock().unwrap();
            // Version 0 schema shape (two columns, no Ref Level) -- same on-disk layout
            // `ToAdapterV0` opens, but here used just to prove `ToAdapterV1::new` rejects it.
            let v0_schema = Arc::new(crate::framework::db::Schema::new(
                0,
                crate::framework::db::FieldType::Long,
                "To Address".to_string(),
                vec![crate::framework::db::FieldType::Int, crate::framework::db::FieldType::Binary],
                vec!["Number of Refs".to_string(), "Ref Data".to_string()],
                vec![],
            ));
            guard.create_table(TO_REFS_TABLE_NAME.to_string(), v0_schema).unwrap();
        }
        assert!(ToAdapterV1::new(false, h, addr_map()).is_err());
    }

    #[test]
    fn create_ref_list_then_get_ref_list_round_trips_a_small_list() {
        let h = handle();
        let mut adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        let to = addr(0x2000);

        let mut list = adapter.create_ref_list(None, &to).unwrap();
        let from = addr(0x1000);
        list.add_ref(&from, &to, RefType::UnconditionalCall, 0, 42, true, SourceType::Imported, false, false, 0)
            .unwrap();
        drop(list);

        assert!(adapter.has_ref_to(0x2000).unwrap());
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter.get_ref_list(None, &to, 0x2000).unwrap().expect("should exist");
        assert_eq!(fetched.get_num_refs(), 1);
        assert_eq!(fetched.get_reference_level(), SUB_LEVEL as i8);
        let r = fetched.get_ref(&from, 0).unwrap();
        assert_eq!(r.symbol_id(), 42);
        assert!(r.is_primary());
    }

    #[test]
    fn get_ref_list_promotes_to_big_ref_list_when_ref_data_is_none() {
        let h = handle();
        let adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        let to = addr(0x3000);
        let key = addr_map().get_key(&to, true);

        // Simulate an address whose references already live in a BigRefListV0 side table by
        // writing a pointer record with a None Ref Data column directly, mirroring what
        // BigRefListV0Impl::update_record itself would have done.
        {
            let rec = record(key, 0, (-1i8) as u8, None);
            adapter.table().write().unwrap().put_record(rec).unwrap();
        }

        let err = adapter.get_ref_list(None, &to, key);
        // BigRefListV0Impl::create_existing will fail to find its own per-address table (since
        // none was ever created for this synthetic record), proving get_ref_list really did take
        // the BigRefListV0 branch instead of silently treating it as an empty inline list.
        assert!(err.is_err());
    }

    fn record(key: i64, num_refs: i32, ref_level: u8, ref_data: Option<Vec<u8>>) -> DBRecord {
        let mut rec = DBRecord::new(to_refs_schema(), Field::Long(Some(key)));
        rec.set_int(REF_COUNT_COL, num_refs);
        rec.set_field(REF_DATA_COL, Field::Binary(ref_data));
        rec.set_byte(REF_LEVEL_COL, ref_level as i8);
        rec
    }

    #[test]
    fn get_ref_list_returns_none_for_missing_address() {
        let h = handle();
        let adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        assert!(adapter.get_ref_list(None, &addr(0x9000), 0x9000).unwrap().is_none());
    }

    #[test]
    fn record_adapter_methods_write_through_the_real_table() {
        let h = handle();
        let mut adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        let rec = RecordAdapter::create_record(&mut adapter, 5, 3, 1, Some(&[1, 2, 3])).unwrap();
        assert_eq!(rec.get_int(REF_COUNT_COL), Some(3));

        let fetched = RecordAdapter::get_record(&adapter, 5).unwrap();
        assert_eq!(fetched.get_int(REF_COUNT_COL), Some(3));

        RecordAdapter::remove_record(&mut adapter, 5).unwrap();
        assert!(RecordAdapter::get_record(&adapter, 5).is_err());
    }

    #[test]
    fn to_iterator_visits_addresses_in_order_both_directions() {
        let h = handle();
        let mut adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        for offset in [0x300, 0x100, 0x200] {
            adapter.create_ref_list(None, &addr(offset)).unwrap();
            RecordAdapter::create_record(&mut adapter, offset, 0, 0, Some(&[])).unwrap();
        }

        let forward: Vec<i64> = adapter.get_to_iterator(true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(forward, vec![0x100, 0x200, 0x300]);
        let backward: Vec<i64> = adapter.get_to_iterator(false).unwrap().map(|a| a.offset()).collect();
        assert_eq!(backward, vec![0x300, 0x200, 0x100]);
    }

    #[test]
    fn to_iterator_from_and_in_set_are_restricted() {
        let h = handle();
        let mut adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        for offset in [0x100, 0x200, 0x500] {
            RecordAdapter::create_record(&mut adapter, offset, 0, 0, Some(&[])).unwrap();
        }

        let from: Vec<i64> =
            adapter.get_to_iterator_from(&addr(0x150), true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(from, vec![0x200, 0x500]);

        let set = AddressSet::from_start_end(addr(0x0), addr(0x200));
        let in_set: Vec<i64> = adapter.get_to_iterator_in_set(&set, true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(in_set, vec![0x100, 0x200]);
    }

    #[test]
    fn get_old_namespace_addresses_is_not_supported() {
        let h = handle();
        let adapter = ToAdapterV1::new(true, h, addr_map()).unwrap();
        match adapter.get_old_namespace_addresses(&space()) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected an Unsupported error"),
        }
    }

    #[test]
    fn behaves_as_trait_object() {
        let h = handle();
        let mut adapter: Box<dyn ToAdapter> = Box::new(ToAdapterV1::new(true, h, addr_map()).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
        adapter.create_ref_list(None, &addr(0x42)).unwrap();
        RecordAdapter::create_record(adapter.as_mut(), 0x42, 0, 0, Some(&[])).unwrap();
        assert!(adapter.has_ref_to(0x42).unwrap());
    }
}
