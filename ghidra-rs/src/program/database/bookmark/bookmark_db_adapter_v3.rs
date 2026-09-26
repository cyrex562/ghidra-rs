//! Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV3`.
//!
//! The live, current-schema implementation: one [`Table`] per bookmark type, named
//! `"{BOOKMARK_TABLE_NAME}{typeId}"`, each record's key packing its owning type ID into the high
//! 16 bits (`typeId << TYPE_ID_OFFSET | localId`) so [`BookmarkDBAdapterV3::table_for_key`] can
//! recover the right table from a bare bookmark ID alone (mirrors `BookmarkDBAdapter.getTypeId`).
//!
//! **Indexing.** Java's `V3_SCHEMA` is created with `INDEXED_COLUMNS = {V3_ADDRESS_COL,
//! V3_CATEGORY_COL}` and `getRecordsByType*` methods lean on `Table.indexIterator`/
//! `indexIteratorBefore`/`indexIteratorAfter` for fast lookups. This port's [`Table`] has no
//! secondary-index support at all (same gap already documented by
//! `CompositeDBAdapterV0::get_record_ids_in_category`'s module doc), so every by-address/
//! by-category query here does a linear scan of the type's table instead, sorting/filtering in
//! memory. Same observable results, just O(n) instead of O(log n).
//!
//! **`create_bookmark`'s ID allocation quirk.** Java: `long nextId = table.getKey() + 1; long id
//! = ((long) typeID << TYPE_ID_OFFSET) | nextId;` where `Table.getKey()` itself already returns
//! `getMaxKey() + 1` (or `0` on an empty table). That means `nextId` is `getMaxKey() + 2`, so the
//! low 48 bits of consecutively created bookmark IDs within one type advance by *two* each time
//! (1, 3, 5, ...) rather than one -- values are still always unique, just not contiguous. This
//! looks like a real quirk/bug in the original, but this port mirrors it faithfully rather than
//! "fixing" it (same policy `CompositeDBAdapterV0`'s module docs describe). This port's [`Table`]
//! only updates its own max-key tracking via `get_next_key`/`ensure_next_key_at_least`, not on
//! arbitrary `put_record` calls (unlike Java's B-tree, which derives `getMaxKey()` from whatever
//! keys are actually present) -- so [`BookmarkDBAdapterV3::create_bookmark`] calls
//! `ensure_next_key_at_least` explicitly after each insert to reproduce the same
//! `table.getKey()`-reflects-prior-inserts behavior.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::bookmark::bookmark_db_adapter::{
    BookmarkDbAdapter, BOOKMARK_TABLE_NAME,
};
use crate::program::database::bookmark::bookmark_type_db_adapter::BOOKMARK_TYPE_TABLE_NAME;
use crate::program::database::map::AddressMap;
use crate::program::model::address::AddressSet;
use crate::util::exception::VersionException;

/// Bit offset at which a bookmark's owning type ID is packed into its record key. Port of
/// `BookmarkDBAdapterV3.TYPE_ID_OFFSET`.
pub const TYPE_ID_OFFSET: i32 = 48;

/// Column index of a V3 bookmark's address. Port of `BookmarkDBAdapterV3.V3_ADDRESS_COL`.
pub const V3_ADDRESS_COL: usize = 0;
/// Column index of a V3 bookmark's category. Port of `BookmarkDBAdapterV3.V3_CATEGORY_COL`.
pub const V3_CATEGORY_COL: usize = 1;
/// Column index of a V3 bookmark's comment. Port of `BookmarkDBAdapterV3.V3_COMMENT_COL`.
pub const V3_COMMENT_COL: usize = 2;

/// Schema version implemented by this adapter. Port of `BookmarkDBAdapterV3.VERSION`.
pub const VERSION: i32 = 3;

/// Builds the V3 bookmark table schema, as defined by `BookmarkDBAdapterV3.V3_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::Long, FieldType::String, FieldType::String],
        vec!["Address".to_string(), "Category".to_string(), "Comment".to_string()],
        vec![],
    ))
}

/// The live, table-backed implementation of the Bookmarks database adapter (one table per
/// bookmark type).
///
/// Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV3`.
pub struct BookmarkDbAdapterV3 {
    tables: Vec<Option<Arc<std::sync::RwLock<Table>>>>,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
}

impl BookmarkDbAdapterV3 {
    fn table_name(type_id: i32) -> String {
        format!("{BOOKMARK_TABLE_NAME}{type_id}")
    }

    /// Creates (`create = true`) or opens (`create = false`) the per-type bookmark tables for
    /// `type_ids`. Port of `BookmarkDBAdapterV3(DBHandle, boolean, int[], AddressMap)`.
    ///
    /// # Errors
    /// Returns a [`VersionException`] if a stale, empty legacy `"Bookmarks"` table is found (Java:
    /// "Previous version improperly upgraded and left this empty table behind" -- upgradeable), if
    /// the Bookmark Types table is missing (upgradeable -- "Indicates use of Bookmark
    /// Properties"), if per-type table schema versions are inconsistent (an I/O error, matching
    /// Java's plain `IOException`, wrapped as a non-upgradeable `VersionException` here since this
    /// port's single `Result` error type must be a `VersionException`), or if any per-type table
    /// exists at a schema version other than [`VERSION`] (non-upgradeable).
    pub fn new(
        handle: &mut DBHandle,
        create: bool,
        type_ids: &[i32],
        addr_map: Arc<dyn AddressMap + Send + Sync>,
    ) -> Result<Self, VersionException> {
        let table_count = type_ids.iter().copied().max().map(|m| m + 1).unwrap_or(0) as usize;
        let mut tables: Vec<Option<Arc<std::sync::RwLock<Table>>>> = vec![None; table_count];

        if create {
            for &id in type_ids {
                let table = handle
                    .create_table(Self::table_name(id), schema())
                    .map_err(|e| VersionException::with_message(e.to_string()))?;
                tables[id as usize] = Some(table);
            }
        } else {
            if let Some(legacy) = handle.get_table(BOOKMARK_TABLE_NAME) {
                if legacy.read().unwrap().get_record_count() != 0 {
                    return Err(VersionException::with_upgradeable(true));
                }
            }
            if handle.get_table(BOOKMARK_TYPE_TABLE_NAME).is_none() {
                return Err(VersionException::with_upgradeable(true));
            }
            if !type_ids.is_empty() {
                let mut version: i32 = -1;
                for &id in type_ids {
                    if let Some(table) = handle.get_table(&Self::table_name(id)) {
                        let schema_version = table.read().unwrap().get_schema().get_version();
                        if version >= 0 && schema_version != version {
                            return Err(VersionException::with_message(
                                "Inconsistent bookmark table versions",
                            ));
                        }
                        version = schema_version;
                        tables[id as usize] = Some(table);
                    }
                }
                if version >= 0 && version != VERSION {
                    return Err(VersionException::with_upgradeable(false));
                }
            }
        }

        Ok(BookmarkDbAdapterV3 { tables, addr_map })
    }

    /// Recovers the table owning the given bookmark record key, by decoding its packed type ID.
    /// Port of the private `BookmarkDBAdapterV3.getTable(long)`.
    fn table_for_key(&self, id: i64) -> Option<Arc<std::sync::RwLock<Table>>> {
        let table_id = (id >> TYPE_ID_OFFSET) as usize;
        self.tables.get(table_id).cloned().flatten()
    }

    /// Returns the table for the given bookmark type ID, or `None` if it doesn't exist. Port of
    /// the package-private `BookmarkDBAdapterV3.getTable(int)`. `pub(crate)` (rather than part of
    /// the object-safe [`BookmarkDbAdapter`] trait): Java's own base class stubs this out as
    /// `UnsupportedOperationException` for every other version, and exposing a live `Table`
    /// handle through the trait would leak this adapter's internal storage type into a contract
    /// meant to be implementable by non-table-backed adapters too (see
    /// [`BookmarkTypeDbAdapterNoTable`](crate::program::database::bookmark::bookmark_type_db_adapter_no_table::BookmarkTypeDbAdapterNoTable)
    /// for the same reasoning applied to the sibling type-adapter family). No current caller in
    /// this port needs it outside the `bookmark` module (the intended caller,
    /// `BookmarkDBManager`, is not yet ported), so `pub(crate)` is deliberately narrower than
    /// Java's package-private.
    pub(crate) fn get_table(&self, type_id: i32) -> Option<Arc<std::sync::RwLock<Table>>> {
        if type_id < 0 {
            return None;
        }
        self.tables.get(type_id as usize).cloned().flatten()
    }

    /// Re-fetches every per-type table handle from the database. Port of the package-private
    /// `BookmarkDBAdapterV3.reloadTables()`. `pub(crate)` for the same reason as
    /// [`BookmarkDbAdapterV3::get_table`]; takes `handle` as an explicit parameter rather than a
    /// stored field (see the module docs / [`BookmarkDbAdapter::add_type`]'s doc comment).
    pub(crate) fn reload_tables(&mut self, handle: &DBHandle) {
        for (id, slot) in self.tables.iter_mut().enumerate() {
            *slot = handle.get_table(&Self::table_name(id as i32));
        }
    }

    fn records_for_type(&self, type_id: i32) -> io::Result<Vec<DBRecord>> {
        let Some(table) = self.tables.get(type_id as usize).cloned().flatten() else {
            return Ok(Vec::new());
        };
        let table = table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(records)
    }
}

impl BookmarkDbAdapter for BookmarkDbAdapterV3 {
    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
        match self.table_for_key(id) {
            Some(table) => table.read().unwrap().get_record(&Field::Long(Some(id))),
            None => Ok(None),
        }
    }

    fn get_records_by_type_at_address(&self, type_id: i32, address: i64) -> io::Result<Vec<DBRecord>> {
        let mut records = self.records_for_type(type_id)?;
        records.retain(|r| matches!(r.get_field(V3_ADDRESS_COL), Field::Long(Some(a)) if *a == address));
        Ok(records)
    }

    fn get_records_by_type_starting_at_address(
        &self,
        type_id: i32,
        start_address: i64,
        forward: bool,
    ) -> io::Result<Vec<DBRecord>> {
        let mut records = self.records_for_type(type_id)?;
        records.sort_by_key(|r| r.get_field(V3_ADDRESS_COL).get_long_value());
        if forward {
            records.retain(|r| r.get_field(V3_ADDRESS_COL).get_long_value() >= start_address);
        } else {
            records.retain(|r| r.get_field(V3_ADDRESS_COL).get_long_value() <= start_address);
            records.reverse();
        }
        Ok(records)
    }

    fn get_records_by_type_for_address_range(
        &self,
        type_id: i32,
        start_addr: i64,
        end_addr: i64,
    ) -> io::Result<Vec<DBRecord>> {
        let mut records = self.records_for_type(type_id)?;
        records.retain(|r| {
            let a = r.get_field(V3_ADDRESS_COL).get_long_value();
            a >= start_addr && a <= end_addr
        });
        records.sort_by_key(|r| r.get_field(V3_ADDRESS_COL).get_long_value());
        Ok(records)
    }

    fn get_records_by_type_and_category(
        &self,
        type_id: i32,
        category: Option<&str>,
    ) -> io::Result<Vec<DBRecord>> {
        let mut records = self.records_for_type(type_id)?;
        if let Some(cat) = category {
            records.retain(|r| r.get_string(V3_CATEGORY_COL) == Some(cat));
        }
        Ok(records)
    }

    fn get_records_by_type(&self, type_id: i32) -> io::Result<Vec<DBRecord>> {
        self.records_for_type(type_id)
    }

    fn get_categories(&self, type_id: i32) -> io::Result<Vec<String>> {
        let records = self.records_for_type(type_id)?;
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for rec in &records {
            if let Some(cat) = rec.get_string(V3_CATEGORY_COL) {
                if !cat.is_empty() {
                    set.insert(cat.to_string());
                }
            }
        }
        Ok(set.into_iter().collect())
    }

    fn get_bookmark_addresses(&self, type_id: i32) -> io::Result<AddressSet> {
        let records = self.records_for_type(type_id)?;
        let mut set = AddressSet::new();
        for rec in &records {
            let key = rec.get_field(V3_ADDRESS_COL).get_long_value();
            let addr = self.addr_map.decode_address(key);
            set.add_address(&addr);
        }
        Ok(set)
    }

    fn get_bookmark_count_for_type(&self, type_id: i32) -> i32 {
        match self.tables.get(type_id as usize).cloned().flatten() {
            Some(table) => table.read().unwrap().get_record_count() as i32,
            None => 0,
        }
    }

    fn get_bookmark_count(&self) -> i32 {
        (0..self.tables.len() as i32)
            .map(|id| self.get_bookmark_count_for_type(id))
            .sum()
    }

    fn create_bookmark(
        &mut self,
        type_id: i32,
        category: Option<&str>,
        index: i64,
        comment: Option<&str>,
    ) -> io::Result<Option<DBRecord>> {
        if !self.has_table(type_id) {
            return Ok(None);
        }
        let table = self.tables[type_id as usize].clone().unwrap();
        let mut table = table.write().unwrap();

        // Mirrors Java's `table.getKey() + 1` double-increment quirk -- see the module docs.
        let next_id = table.peek_next_key() + 1;
        let id = ((type_id as i64) << TYPE_ID_OFFSET) | next_id;

        let mut rec = DBRecord::new(schema(), Field::Long(Some(id)));
        rec.set_field(V3_ADDRESS_COL, Field::Long(Some(index)));
        rec.set_field(
            V3_CATEGORY_COL,
            Field::String(Some(category.unwrap_or("").to_string())),
        );
        rec.set_field(
            V3_COMMENT_COL,
            Field::String(Some(comment.unwrap_or("").to_string())),
        );
        table.put_record(rec.clone())?;
        table.ensure_next_key_at_least(id);
        Ok(Some(rec))
    }

    fn delete_record(&mut self, id: i64) -> io::Result<()> {
        if let Some(table) = self.table_for_key(id) {
            table.write().unwrap().delete_record(&Field::Long(Some(id)))?;
        }
        Ok(())
    }

    fn update_record(&mut self, rec: &DBRecord) -> io::Result<()> {
        if let Some(table) = self.table_for_key(rec.get_key().get_long_value()) {
            table.write().unwrap().put_record(rec.clone())?;
        }
        Ok(())
    }

    fn add_type(&mut self, handle: &mut DBHandle, type_id: i32) -> io::Result<()> {
        if type_id as usize >= self.tables.len() {
            self.tables.resize(type_id as usize + 1, None);
        }
        if self.tables[type_id as usize].is_none() {
            let table = match handle.get_table(&Self::table_name(type_id)) {
                Some(t) => t,
                None => handle.create_table(Self::table_name(type_id), schema())?,
            };
            self.tables[type_id as usize] = Some(table);
        }
        Ok(())
    }

    fn delete_type(&mut self, handle: &mut DBHandle, type_id: i32) -> io::Result<()> {
        if let Some(slot) = self.tables.get_mut(type_id as usize) {
            if slot.is_some() {
                handle.delete_table(&Self::table_name(type_id));
                *slot = None;
            }
        }
        Ok(())
    }

    fn has_table(&self, type_id: i32) -> bool {
        if type_id < 0 {
            return false;
        }
        self.tables
            .get(type_id as usize)
            .map(|t| t.is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, AddressFactory, AddressSetView, KeyRange};

    /// Identity `AddressMap`: keys equal ram-space offsets directly. Enough to exercise
    /// `get_bookmark_addresses` without a real `AddressMapDB`.
    struct IdentityAddressMap {
        ram: Arc<AddressSpace>,
    }

    impl IdentityAddressMap {
        fn new() -> Self {
            IdentityAddressMap {
                ram: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            }
        }
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
            Address::new(self.ram.clone(), value)
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
            Box::new(IdentityAddressMap::new())
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(self.ram.clone(), 0)
        }
    }

    fn addr_map() -> Arc<dyn AddressMap + Send + Sync> {
        Arc::new(IdentityAddressMap::new())
    }

    fn create_adapter(handle: &mut DBHandle, type_ids: &[i32]) -> BookmarkDbAdapterV3 {
        BookmarkDbAdapterV3::new(handle, true, type_ids, addr_map()).unwrap()
    }

    #[test]
    fn create_bookmark_allocates_unique_ids_and_reports_the_double_increment_quirk() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);

        let r1 = adapter
            .create_bookmark(0, Some("cat"), 0x1000, Some("first"))
            .unwrap()
            .unwrap();
        let r2 = adapter
            .create_bookmark(0, Some("cat"), 0x2000, Some("second"))
            .unwrap()
            .unwrap();

        let id1 = r1.get_key().get_long_value() & ((1i64 << TYPE_ID_OFFSET) - 1);
        let id2 = r2.get_key().get_long_value() & ((1i64 << TYPE_ID_OFFSET) - 1);
        // See the module docs: consecutive local IDs advance by 2, not 1 (1, 3, 5, ...).
        assert_eq!(id1, 1);
        assert_eq!(id2, 3);
        assert_ne!(r1.get_key(), r2.get_key());
    }

    #[test]
    fn create_bookmark_without_a_table_returns_none() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        assert!(adapter.create_bookmark(5, None, 0, None).unwrap().is_none());
    }

    #[test]
    fn get_record_round_trips_through_the_owning_type_table() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0, 1]);
        let rec = adapter
            .create_bookmark(1, Some("cat"), 0x500, Some("hi"))
            .unwrap()
            .unwrap();
        let id = rec.get_key().get_long_value();

        let fetched = adapter.get_record(id).unwrap().unwrap();
        assert_eq!(fetched.get_string(V3_COMMENT_COL), Some("hi"));
        assert!(adapter.get_record(id + 1000).unwrap().is_none());
    }

    #[test]
    fn get_records_by_type_at_address_filters_correctly() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        adapter.create_bookmark(0, None, 0x100, None).unwrap();
        adapter.create_bookmark(0, None, 0x200, None).unwrap();

        let at_100 = adapter.get_records_by_type_at_address(0, 0x100).unwrap();
        assert_eq!(at_100.len(), 1);
        assert!(adapter.get_records_by_type_at_address(0, 0x999).unwrap().is_empty());
    }

    #[test]
    fn get_records_by_type_starting_at_address_orders_forward_and_backward() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        adapter.create_bookmark(0, None, 0x100, None).unwrap();
        adapter.create_bookmark(0, None, 0x200, None).unwrap();
        adapter.create_bookmark(0, None, 0x300, None).unwrap();

        let forward = adapter
            .get_records_by_type_starting_at_address(0, 0x200, true)
            .unwrap();
        let forward_addrs: Vec<i64> = forward
            .iter()
            .map(|r| r.get_field(V3_ADDRESS_COL).get_long_value())
            .collect();
        assert_eq!(forward_addrs, vec![0x200, 0x300]);

        let backward = adapter
            .get_records_by_type_starting_at_address(0, 0x200, false)
            .unwrap();
        let backward_addrs: Vec<i64> = backward
            .iter()
            .map(|r| r.get_field(V3_ADDRESS_COL).get_long_value())
            .collect();
        assert_eq!(backward_addrs, vec![0x200, 0x100]);
    }

    #[test]
    fn get_records_by_type_for_address_range_is_inclusive_and_sorted() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        adapter.create_bookmark(0, None, 0x100, None).unwrap();
        adapter.create_bookmark(0, None, 0x200, None).unwrap();
        adapter.create_bookmark(0, None, 0x300, None).unwrap();

        let in_range = adapter
            .get_records_by_type_for_address_range(0, 0x100, 0x200)
            .unwrap();
        let addrs: Vec<i64> = in_range
            .iter()
            .map(|r| r.get_field(V3_ADDRESS_COL).get_long_value())
            .collect();
        assert_eq!(addrs, vec![0x100, 0x200]);
    }

    #[test]
    fn get_records_by_type_and_category_filters_and_none_returns_all() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        adapter.create_bookmark(0, Some("a"), 0x10, None).unwrap();
        adapter.create_bookmark(0, Some("b"), 0x20, None).unwrap();

        assert_eq!(
            adapter.get_records_by_type_and_category(0, Some("a")).unwrap().len(),
            1
        );
        assert_eq!(adapter.get_records_by_type_and_category(0, None).unwrap().len(), 2);
    }

    #[test]
    fn get_categories_returns_sorted_non_empty_categories() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        adapter.create_bookmark(0, Some("zeta"), 0x10, None).unwrap();
        adapter.create_bookmark(0, Some("alpha"), 0x20, None).unwrap();
        adapter.create_bookmark(0, None, 0x30, None).unwrap(); // empty category

        assert_eq!(
            adapter.get_categories(0).unwrap(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
    }

    #[test]
    fn get_bookmark_addresses_decodes_through_the_address_map() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        adapter.create_bookmark(0, None, 0x10, None).unwrap();
        adapter.create_bookmark(0, None, 0x20, None).unwrap();

        let set = adapter.get_bookmark_addresses(0).unwrap();
        assert_eq!(set.num_addresses(), 2);
    }

    #[test]
    fn bookmark_counts_are_per_type_and_total() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0, 1]);
        adapter.create_bookmark(0, None, 0x10, None).unwrap();
        adapter.create_bookmark(0, None, 0x20, None).unwrap();
        adapter.create_bookmark(1, None, 0x30, None).unwrap();

        assert_eq!(adapter.get_bookmark_count_for_type(0), 2);
        assert_eq!(adapter.get_bookmark_count_for_type(1), 1);
        assert_eq!(adapter.get_bookmark_count(), 3);
    }

    #[test]
    fn delete_record_and_update_record_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        let mut rec = adapter
            .create_bookmark(0, Some("cat"), 0x10, Some("orig"))
            .unwrap()
            .unwrap();
        let id = rec.get_key().get_long_value();

        rec.set_field(V3_COMMENT_COL, Field::String(Some("updated".to_string())));
        adapter.update_record(&rec).unwrap();
        assert_eq!(
            adapter.get_record(id).unwrap().unwrap().get_string(V3_COMMENT_COL),
            Some("updated")
        );

        adapter.delete_record(id).unwrap();
        assert!(adapter.get_record(id).unwrap().is_none());
    }

    #[test]
    fn add_type_and_delete_type_manage_tables_dynamically() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        assert!(!adapter.has_table(5));

        adapter.add_type(&mut handle, 5).unwrap();
        assert!(adapter.has_table(5));
        adapter.create_bookmark(5, None, 0x1, None).unwrap();
        assert_eq!(adapter.get_bookmark_count_for_type(5), 1);

        adapter.delete_type(&mut handle, 5).unwrap();
        assert!(!adapter.has_table(5));
        assert_eq!(adapter.get_bookmark_count_for_type(5), 0);
    }

    #[test]
    fn open_mode_rejects_a_program_with_no_bookmark_type_table() {
        let mut handle = DBHandle::new().unwrap();
        match BookmarkDbAdapterV3::new(&mut handle, false, &[0], addr_map()) {
            Err(e) => assert!(e.is_upgradable()),
            Ok(_) => panic!("expected a VersionException"),
        }
    }

    #[test]
    fn open_mode_reopens_previously_created_tables() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = create_adapter(&mut handle, &[0]);
            adapter.create_bookmark(0, Some("cat"), 0x10, Some("hi")).unwrap();
            // Java's V3 open-mode check requires the Bookmark Types table to exist too.
            handle
                .create_table(
                    BOOKMARK_TYPE_TABLE_NAME.to_string(),
                    crate::program::database::bookmark::bookmark_type_db_adapter::schema(),
                )
                .unwrap();
        }
        let reopened = BookmarkDbAdapterV3::new(&mut handle, false, &[0], addr_map()).unwrap();
        assert_eq!(reopened.get_bookmark_count_for_type(0), 1);
    }

    #[test]
    fn get_table_and_reload_tables_reflect_current_state() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle, &[0]);
        assert!(adapter.get_table(0).is_some());
        assert!(adapter.get_table(9).is_none());
        assert!(adapter.get_table(-1).is_none());

        adapter.add_type(&mut handle, 2).unwrap();
        // Simulate a fresh view of the database picking up the table `add_type` just created.
        adapter.reload_tables(&handle);
        assert!(adapter.get_table(2).is_some());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter: Box<dyn BookmarkDbAdapter> = Box::new(create_adapter(&mut handle, &[0]));
        adapter.create_bookmark(0, None, 0x1, None).unwrap();
        assert_eq!(adapter.get_bookmark_count(), 1);
    }
}
