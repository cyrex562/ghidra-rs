//! Port of `ghidra.program.database.references.FromAdapterV0`.
//!
//! The live (and, unlike `ToAdapter`'s family, *only* -- there is no `FromAdapterV1`), read-write
//! adapter for the "FROM REFS" table: the real [`RecordAdapter`] handed to
//! [`RefListV0Impl`]/[`BigRefListV0Impl`] so their mutations actually persist. Structurally this
//! mirrors [`ToAdapterV1`](crate::program::database::references::ToAdapterV1) closely (same
//! self-referential-adapter-handle and dropped-`Program` deviations -- see that module's docs for
//! the full rationale, not repeated here), with two differences that fall directly out of Java's
//! own schema:
//! - **`FROM_REFS_SCHEMA` has no `Ref Level` column at all** (`[Number of Refs, Ref Data]`, not
//!   `ToAdapter`'s three-column `[Number of Refs, Ref Data, Ref Level]`) -- "from" lists never
//!   read or write a cached reference level (`RefListV0Impl`/`BigRefListV0Impl` both leave
//!   `ref_level` at its constructor-default `-1` whenever `is_from` is `true`), so there's nothing
//!   to store. [`FromAdapterV0Core::create_record`] simply never touches a `Ref Level` field.
//! - **The version check never branches into an "older, upgradable" case.** Version `0` is
//!   already `FROM_REFS_SCHEMA`'s only version, so any mismatch is unconditionally treated as
//!   "newer" (mirrors Java's `throw new VersionException(VersionException.NEWER_VERSION, false)`,
//!   with no `version < CURRENT_VERSION` branch to speak of).
//!
//! Every `RefList` this adapter hands out is created with `is_from = true`.

use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::map::{AddressKeyIterator, AddressMap};
use crate::program::database::references::big_ref_list_v0::BigRefListV0Impl;
use crate::program::database::references::ref_list_v0::RefListV0Impl;
use crate::program::database::references::{FromAdapter, RecordAdapter, RefList};
use crate::program::database::ProgramDB;
use crate::program::model::address::{Address, AddressSetView, BoxedAddressIterator};
use crate::util::exception::VersionException;

/// Table name for the "from address" reference list table.
pub const FROM_REFS_TABLE_NAME: &str = "FROM REFS";

/// `FROM_REFS_SCHEMA`'s only version. Stands in for the schema-version literal Java's
/// `new Schema(0, ...)` and version check both hard-code.
pub const CURRENT_VERSION: i32 = 0;

/// Column index of the reference count.
pub const REF_COUNT_COL: usize = 0;
/// Column index of the packed reference-data blob.
pub const REF_DATA_COL: usize = 1;

/// Returns the "FROM REFS" table's schema. Stands in for `FromAdapter.FROM_REFS_SCHEMA`.
pub fn from_refs_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "From Address".to_string(),
        vec![FieldType::Int, FieldType::Binary],
        vec!["Number of Refs".to_string(), "Ref Data".to_string()],
        vec![],
    ))
}

/// The shared, lockable table handle every [`RefListV0Impl`]/[`BigRefListV0Impl`] this adapter
/// hands out calls back into. See [`ToAdapterV1Core`](crate::program::database::references::to_adapter_v1)'s
/// module docs for why this indirection exists (identical rationale, mirrored here).
struct FromAdapterV0Core {
    table: Arc<RwLock<Table>>,
}

impl RecordAdapter for FromAdapterV0Core {
    fn create_record(
        &mut self,
        key: i64,
        num_refs: i32,
        _ref_level: u8,
        ref_data: Option<&[u8]>,
    ) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(from_refs_schema(), Field::Long(Some(key)));
        rec.set_int(REF_COUNT_COL, num_refs);
        rec.set_field(REF_DATA_COL, Field::Binary(ref_data.map(|d| d.to_vec())));
        self.table.write().unwrap().put_record(rec.clone())?;
        Ok(rec)
    }

    fn get_record(&self, key: i64) -> io::Result<DBRecord> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such FROM REFS record"))
    }

    fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_record(&mut self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key))).map(|_| ())
    }
}

/// Live, read-write adapter for the "FROM REFS" table.
///
/// Port of `ghidra.program.database.references.FromAdapterV0`. See the module docs for the
/// schema/version-check deviations from `ToAdapterV1`.
pub struct FromAdapterV0 {
    core: Arc<Mutex<FromAdapterV0Core>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    db_handle: Arc<Mutex<DBHandle>>,
}

impl FromAdapterV0 {
    /// Opens (or, if `create`, creates) the "FROM REFS" table from `db_handle`.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if `create` is `false` and the table is missing, is not
    /// schema version 0, or (collapsing Java's separate `IOException` for this one case, matching
    /// this codebase's established convention -- see `ToAdapterV1::new`'s own doc comment) table
    /// creation itself fails.
    pub fn new(
        create: bool,
        db_handle: Arc<Mutex<DBHandle>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
    ) -> Result<Self, VersionException> {
        let table = {
            let mut handle = db_handle
                .lock()
                .expect("FromAdapterV0's db_handle mutex should never be poisoned");
            if create {
                handle
                    .create_table(FROM_REFS_TABLE_NAME.to_string(), from_refs_schema())
                    .map_err(|e| VersionException::with_message(format!("{e}")))?
            } else {
                let table = handle.get_table(FROM_REFS_TABLE_NAME).ok_or_else(|| {
                    VersionException::with_message(format!("Missing Table: {FROM_REFS_TABLE_NAME}"))
                })?;
                let version = table.read().unwrap().get_schema().get_version();
                if version != CURRENT_VERSION {
                    return Err(VersionException::with_version_indicator(
                        VersionException::NEWER_VERSION,
                        false,
                    ));
                }
                table
            }
        };
        Ok(FromAdapterV0 {
            core: Arc::new(Mutex::new(FromAdapterV0Core { table })),
            addr_map,
            db_handle,
        })
    }

    fn table(&self) -> Arc<RwLock<Table>> {
        self.core.lock().expect("FromAdapterV0's core mutex should never be poisoned").table.clone()
    }

    fn adapter_handle(&self) -> Arc<Mutex<dyn RecordAdapter + Send>> {
        self.core.clone()
    }

    fn collect_from_addresses(
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

impl RecordAdapter for FromAdapterV0 {
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

impl FromAdapter for FromAdapterV0 {
    fn get_record_count(&self) -> i32 {
        self.table().read().unwrap().get_record_count() as i32
    }

    fn create_ref_list(
        &mut self,
        _program: Option<&ProgramDB>,
        from_addr: &Address,
    ) -> io::Result<Box<dyn RefList>> {
        let list = RefListV0Impl::create_new(
            from_addr.clone(),
            Some(self.adapter_handle()),
            self.addr_map.clone(),
            true,
        );
        Ok(Box::new(list))
    }

    fn get_ref_list(
        &self,
        _program: Option<&ProgramDB>,
        _from: &Address,
        from_addr: i64,
    ) -> io::Result<Option<Box<dyn RefList>>> {
        let table = self.table();
        let rec = table.read().unwrap().get_record(&Field::Long(Some(from_addr)))?;
        let Some(rec) = rec else {
            return Ok(None);
        };
        let num_refs = rec.get_int(REF_COUNT_COL).unwrap_or(0);
        match rec.get_field(REF_DATA_COL) {
            Field::Binary(None) => {
                let list = BigRefListV0Impl::create_existing(
                    from_addr,
                    -1,
                    Some(self.adapter_handle()),
                    self.addr_map.clone(),
                    self.db_handle.clone(),
                    true,
                )?;
                Ok(Some(Box::new(list)))
            }
            Field::Binary(Some(data)) => {
                let list = RefListV0Impl::instantiate_existing(
                    from_addr,
                    data.clone(),
                    num_refs,
                    -1,
                    Some(self.adapter_handle()),
                    self.addr_map.clone(),
                    true,
                );
                Ok(Some(Box::new(list)))
            }
            _ => Ok(None),
        }
    }

    fn has_ref_from(&self, from_addr: i64) -> io::Result<bool> {
        Ok(self.table().read().unwrap().has_record(&Field::Long(Some(from_addr))))
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
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSpace, AddressSpaceType, KeyRange};
    use crate::program::model::symbol::{RefType, SourceType};
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
        let adapter = FromAdapterV0::new(true, h.clone(), addr_map()).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
        assert!(h.lock().unwrap().get_table(FROM_REFS_TABLE_NAME).is_some());
    }

    #[test]
    fn create_false_on_missing_table_is_an_error() {
        let h = handle();
        assert!(FromAdapterV0::new(false, h, addr_map()).is_err());
    }

    #[test]
    fn create_false_on_wrong_version_table_is_an_error() {
        let h = handle();
        {
            let mut guard = h.lock().unwrap();
            let v1_schema = Arc::new(Schema::new(
                1,
                FieldType::Long,
                "From Address".to_string(),
                vec![FieldType::Int, FieldType::Binary],
                vec!["Number of Refs".to_string(), "Ref Data".to_string()],
                vec![],
            ));
            guard.create_table(FROM_REFS_TABLE_NAME.to_string(), v1_schema).unwrap();
        }
        assert!(FromAdapterV0::new(false, h, addr_map()).is_err());
    }

    #[test]
    fn create_ref_list_then_get_ref_list_round_trips_a_small_list() {
        let h = handle();
        let mut adapter = FromAdapterV0::new(true, h, addr_map()).unwrap();
        let from = addr(0x1000);

        let mut list = adapter.create_ref_list(None, &from).unwrap();
        let to = addr(0x2000);
        list.add_ref(&from, &to, RefType::UnconditionalCall, 0, 42, true, SourceType::Imported, false, false, 0)
            .unwrap();
        drop(list);

        assert!(adapter.has_ref_from(0x1000).unwrap());
        assert_eq!(adapter.get_record_count(), 1);

        let fetched = adapter.get_ref_list(None, &from, 0x1000).unwrap().expect("should exist");
        assert_eq!(fetched.get_num_refs(), 1);
        // "from" lists never track a reference level.
        assert_eq!(fetched.get_reference_level(), -1);
        let r = fetched.get_ref(&to, 0).unwrap();
        assert_eq!(r.symbol_id(), 42);
        assert!(r.is_primary());
    }

    #[test]
    fn get_ref_list_promotes_to_big_ref_list_when_ref_data_is_none() {
        let h = handle();
        let adapter = FromAdapterV0::new(true, h, addr_map()).unwrap();
        let from = addr(0x3000);
        let key = addr_map().get_key(&from, true);

        let mut rec = DBRecord::new(from_refs_schema(), Field::Long(Some(key)));
        rec.set_int(REF_COUNT_COL, 0);
        rec.set_field(REF_DATA_COL, Field::Binary(None));
        adapter.table().write().unwrap().put_record(rec).unwrap();

        // BigRefListV0Impl::create_existing will fail to find its own per-address table (since
        // none was ever created for this synthetic record), proving get_ref_list really did take
        // the BigRefListV0 branch instead of silently treating it as an empty inline list.
        assert!(adapter.get_ref_list(None, &from, key).is_err());
    }

    #[test]
    fn get_ref_list_returns_none_for_missing_address() {
        let h = handle();
        let adapter = FromAdapterV0::new(true, h, addr_map()).unwrap();
        assert!(adapter.get_ref_list(None, &addr(0x9000), 0x9000).unwrap().is_none());
    }

    #[test]
    fn record_adapter_methods_write_through_the_real_table() {
        let h = handle();
        let mut adapter = FromAdapterV0::new(true, h, addr_map()).unwrap();
        let rec = RecordAdapter::create_record(&mut adapter, 5, 3, 0, Some(&[1, 2, 3])).unwrap();
        assert_eq!(rec.get_int(REF_COUNT_COL), Some(3));

        let fetched = RecordAdapter::get_record(&adapter, 5).unwrap();
        assert_eq!(fetched.get_int(REF_COUNT_COL), Some(3));

        RecordAdapter::remove_record(&mut adapter, 5).unwrap();
        assert!(RecordAdapter::get_record(&adapter, 5).is_err());
    }

    #[test]
    fn from_iterator_visits_addresses_in_order_both_directions() {
        let h = handle();
        let mut adapter = FromAdapterV0::new(true, h, addr_map()).unwrap();
        for offset in [0x300, 0x100, 0x200] {
            RecordAdapter::create_record(&mut adapter, offset, 0, 0, Some(&[])).unwrap();
        }

        let forward: Vec<i64> = adapter.get_from_iterator(true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(forward, vec![0x100, 0x200, 0x300]);
        let backward: Vec<i64> = adapter.get_from_iterator(false).unwrap().map(|a| a.offset()).collect();
        assert_eq!(backward, vec![0x300, 0x200, 0x100]);
    }

    #[test]
    fn from_iterator_from_and_in_set_are_restricted() {
        let h = handle();
        let mut adapter = FromAdapterV0::new(true, h, addr_map()).unwrap();
        for offset in [0x100, 0x200, 0x500] {
            RecordAdapter::create_record(&mut adapter, offset, 0, 0, Some(&[])).unwrap();
        }

        let from: Vec<i64> =
            adapter.get_from_iterator_from(&addr(0x150), true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(from, vec![0x200, 0x500]);

        let set = AddressSet::from_start_end(addr(0x0), addr(0x200));
        let in_set: Vec<i64> = adapter.get_from_iterator_in_set(&set, true).unwrap().map(|a| a.offset()).collect();
        assert_eq!(in_set, vec![0x100, 0x200]);
    }

    #[test]
    fn behaves_as_trait_object() {
        let h = handle();
        let mut adapter: Box<dyn FromAdapter> = Box::new(FromAdapterV0::new(true, h, addr_map()).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
        adapter.create_ref_list(None, &addr(0x42)).unwrap();
        RecordAdapter::create_record(adapter.as_mut(), 0x42, 0, 0, Some(&[])).unwrap();
        assert!(adapter.has_ref_from(0x42).unwrap());
    }
}
