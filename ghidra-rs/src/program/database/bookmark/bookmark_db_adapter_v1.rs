//! Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV1`.
//!
//! `V1` is the historical single-table schema that predates `V3`'s one-table-per-type layout: all
//! bookmarks, of every type, live in one `"Bookmarks"` table with columns `[Address, Type ID, Type
//! ID/Category (mangled), Comment]`. Every read converts a raw `V1` row into the current (`V3`)
//! three-column record shape on the fly via [`convert_v1_record`], packing the row's `Type ID`
//! column into the high bits of a synthetic key exactly like `BookmarkDbAdapterV3` does for its own
//! records (`(type_id << TYPE_ID_OFFSET) | (local_key & 0xFFFF_FFFF)`).
//!
//! **Faithfully-mirrored Java quirks -- not fixed here, per this port's established policy (see
//! `BookmarkDbAdapterV3`'s module docs) of preserving originally-observed behavior rather than
//! silently correcting it:**
//! - [`convert_v1_record`] masks the raw local key with `0xFFFF_FFFF` (32 bits), even though 48
//!   bits are available before colliding with the packed type ID -- copied verbatim from Java's
//!   `record.getKey() & 0xffffffffL`.
//! - [`BookmarkDbAdapterV1::get_record`] looks up the *packed* id directly against the raw V1
//!   table (whose real primary key is the *unpacked* local id), exactly like Java's `getRecord(long
//!   id) { return convertV1Record(table.getRecord(id)); }`. This only actually finds the right row
//!   when `type_id == 0` (since `0 << 48 == 0`, so the packed and raw keys coincide) -- for any
//!   other type, this call looks up the wrong row (or none). This is a real latent bug in the
//!   original; mirrored rather than fixed.
//! - [`BookmarkDbAdapterV1::get_records_by_type`] and
//!   [`BookmarkDbAdapterV1::get_records_by_type_for_address_range`] (and therefore
//!   [`BookmarkDbAdapterV1::get_bookmark_addresses`], which is built on the former) both silently
//!   *ignore* their `type_id` parameter and operate over every record in the shared table,
//!   regardless of type -- exactly matching Java's `getRecordsByType(int typeId) { return new
//!   V1ConvertedRecordIterator(table.iterator()); }` (parameter unused) and the private
//!   `BatchRecordIterator(int typeId, long start, long end)` (constructor parameter also unused).
//!   [`BookmarkDbAdapterV1::get_categories`] and [`BookmarkDbAdapterV1::get_bookmark_count_for_type`],
//!   by contrast, *do* filter correctly by `type_id` in Java, and do here too.
//! - [`BookmarkDbAdapterV1::get_records_by_type_starting_at_address`] is unconditionally
//!   unsupported, matching Java's own `throw new UnsupportedOperationException(); // they tell me
//!   that this class is too old to care`.
//!
//! **No secondary-index support**, same as `BookmarkDbAdapterV3`: every query here does a linear
//! scan of the shared table and filters in memory, since this port's `Table` has no
//! `indexIterator` equivalent.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, Table};
use crate::program::database::bookmark::bookmark_db_adapter::{
    demangle_type_category, mangle_type_category, schema as v3_schema, BookmarkDbAdapter, BOOKMARK_TABLE_NAME,
};
use crate::program::database::bookmark::bookmark_db_adapter_v3::{TYPE_ID_OFFSET, V3_ADDRESS_COL, V3_CATEGORY_COL, V3_COMMENT_COL};
use crate::program::database::map::AddressMap;
use crate::program::database::references::to_adapter_v0::SendSyncAddressMap;
use crate::program::model::address::AddressSet;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `BookmarkDBAdapterV1.VERSION`.
pub const VERSION: i32 = 1;

/// Column index of a `V1` bookmark's address. Port of `BookmarkDBAdapterV1.V1_ADDRESS_COL`.
pub const V1_ADDRESS_COL: usize = 0;
/// Column index of a `V1` bookmark's type ID. Port of `BookmarkDBAdapterV1.V1_TYPE_ID_COL`.
pub const V1_TYPE_ID_COL: usize = 1;
/// Column index of a `V1` bookmark's mangled `"typeId/category"` string, used for indexing. Port
/// of `BookmarkDBAdapterV1.V1_TYPE_CATEGORY_COL`.
pub const V1_TYPE_CATEGORY_COL: usize = 2;
/// Column index of a `V1` bookmark's comment. Port of `BookmarkDBAdapterV1.V1_COMMENT_COL`.
pub const V1_COMMENT_COL: usize = 3;

/// Builds the `V1` bookmark table schema. Reconstructed directly from Java's own commented-out
/// `SCHEMA` field declaration (`BookmarkDBAdapterV1` never creates this table itself -- only reads
/// one created by a much older release -- so Java leaves the constant commented out; this port
/// still needs it to build fixture tables for tests).
pub fn v1_schema() -> Arc<crate::framework::db::Schema> {
    use crate::framework::db::{FieldType, Schema};
    Arc::new(Schema::new(
        VERSION,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::Long, FieldType::Long, FieldType::String, FieldType::String],
        vec![
            "Address".to_string(),
            "Type ID".to_string(),
            "Type ID/Category".to_string(),
            "Comment".to_string(),
        ],
        vec![],
    ))
}

/// Converts a raw `V1` record into the current (`V3`) record shape. Port of the private static
/// `BookmarkDBAdapterV1.convertV1Record(DBRecord)`. See the module docs for the faithfully-mirrored
/// key-masking quirk.
pub(super) fn convert_v1_record(record: &DBRecord) -> DBRecord {
    let type_id = record.get_field(V1_TYPE_ID_COL).get_long_value();
    let local_key = record.get_key().get_long_value() & 0xFFFF_FFFFi64;
    let key = (type_id << TYPE_ID_OFFSET) | local_key;

    let mut rec = DBRecord::new(v3_schema(), Field::Long(Some(key)));
    rec.set_field(V3_ADDRESS_COL, record.get_field(V1_ADDRESS_COL).clone());
    let category = demangle_type_category(record.get_string(V1_TYPE_CATEGORY_COL).unwrap_or(""));
    rec.set_field(V3_CATEGORY_COL, Field::String(Some(category.to_string())));
    rec.set_field(V3_COMMENT_COL, record.get_field(V1_COMMENT_COL).clone());
    rec
}

/// Read-only adapter for the historical single-table (`V1`) bookmark schema. See the module docs
/// for the faithfully-mirrored quirks.
///
/// Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV1`.
pub struct BookmarkDbAdapterV1 {
    pub(super) table: Arc<RwLock<Table>>,
    pub(super) addr_map: Arc<dyn AddressMap + Send + Sync>,
}

impl BookmarkDbAdapterV1 {
    /// Opens the existing `"Bookmarks"` table from `handle`, verifying it is schema version
    /// [`VERSION`]. `addr_map` mirrors Java's constructor parameter (the *current* map); this
    /// constructor takes its [`AddressMap::get_old_address_map`] internally, mirroring
    /// `addrMap.getOldAddressMap()` -- wrapped in [`SendSyncAddressMap`] for the same
    /// thread-safety reason `ToAdapterV0` already documents.
    ///
    /// Port of `BookmarkDBAdapterV1(DBHandle, AddressMap)`.
    ///
    /// # Errors
    /// Returns [`VersionException`] if the table is missing or not schema version [`VERSION`].
    pub fn new(handle: &DBHandle, addr_map: &dyn AddressMap) -> Result<Self, VersionException> {
        let table = handle
            .get_table(BOOKMARK_TABLE_NAME)
            .ok_or_else(|| VersionException::with_message(format!("Missing Table: {BOOKMARK_TABLE_NAME}")))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != VERSION {
            return Err(VersionException::with_message(format!(
                "Expected version {VERSION} for table {BOOKMARK_TABLE_NAME} but got {version}"
            )));
        }
        Ok(BookmarkDbAdapterV1 {
            table,
            addr_map: Arc::new(SendSyncAddressMap(addr_map.get_old_address_map())),
        })
    }

    fn all_converted_records(&self) -> io::Result<Vec<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(convert_v1_record(&rec));
        }
        Ok(records)
    }
}

impl BookmarkDbAdapter for BookmarkDbAdapterV1 {
    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
        // See the module docs: this only actually resolves the right row when `type_id == 0`,
        // faithfully mirroring Java's own latent bug.
        let raw = self.table.read().unwrap().get_record(&Field::Long(Some(id)))?;
        Ok(raw.map(|r| convert_v1_record(&r)))
    }

    fn get_records_by_type_at_address(&self, _type_id: i32, address: i64) -> io::Result<Vec<DBRecord>> {
        self.get_records_by_type_for_address_range(_type_id, address, address)
    }

    fn get_records_by_type_starting_at_address(
        &self,
        _type_id: i32,
        _start_address: i64,
        _forward: bool,
    ) -> io::Result<Vec<DBRecord>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "they tell me that this class is too old to care",
        ))
    }

    fn get_records_by_type_for_address_range(
        &self,
        _type_id: i32,
        start_addr: i64,
        end_addr: i64,
    ) -> io::Result<Vec<DBRecord>> {
        // Mirrors Java's `BatchRecordIterator`: `type_id` is unused -- see the module docs.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            let a = rec.get_field(V1_ADDRESS_COL).get_long_value();
            if a >= start_addr && a <= end_addr {
                records.push(convert_v1_record(&rec));
            }
        }
        records.sort_by_key(|r| r.get_field(V3_ADDRESS_COL).get_long_value());
        Ok(records)
    }

    fn get_records_by_type_and_category(&self, type_id: i32, category: Option<&str>) -> io::Result<Vec<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            let matches = match category {
                None => rec.get_field(V1_TYPE_ID_COL).get_long_value() == type_id as i64,
                Some(cat) => {
                    rec.get_string(V1_TYPE_CATEGORY_COL) == Some(mangle_type_category(type_id as i64, Some(cat)).as_str())
                }
            };
            if matches {
                records.push(convert_v1_record(&rec));
            }
        }
        Ok(records)
    }

    fn get_records_by_type(&self, _type_id: i32) -> io::Result<Vec<DBRecord>> {
        // Mirrors Java's `getRecordsByType`: `type_id` is unused -- see the module docs.
        self.all_converted_records()
    }

    fn get_categories(&self, type_id: i32) -> io::Result<Vec<String>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut set = std::collections::BTreeSet::new();
        while let Some(rec) = iter.next()? {
            if rec.get_field(V1_TYPE_ID_COL).get_long_value() == type_id as i64 {
                let cat = demangle_type_category(rec.get_string(V1_TYPE_CATEGORY_COL).unwrap_or(""));
                set.insert(cat.to_string());
            }
        }
        Ok(set.into_iter().collect())
    }

    fn get_bookmark_addresses(&self, type_id: i32) -> io::Result<AddressSet> {
        // Mirrors Java: built on `getRecordsByType`, which ignores `type_id` -- see the module
        // docs.
        let records = self.get_records_by_type(type_id)?;
        let mut set = AddressSet::new();
        for rec in &records {
            let addr = self.addr_map.decode_address(rec.get_field(V3_ADDRESS_COL).get_long_value());
            set.add_address(&addr);
        }
        Ok(set)
    }

    fn get_bookmark_count_for_type(&self, type_id: i32) -> i32 {
        let table = self.table.read().unwrap();
        let Ok(mut iter) = table.get_record_iterator() else {
            return 0;
        };
        let mut count = 0;
        while let Ok(Some(rec)) = iter.next() {
            if rec.get_field(V1_TYPE_ID_COL).get_long_value() == type_id as i64 {
                count += 1;
            }
        }
        count
    }

    fn get_bookmark_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};

    struct IdentityAddressMap;
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
            Address::new(ram(), value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(&self, _s: &Address, _e: &Address, _a: bool, _c: bool) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(&self, _s: Option<&dyn AddressSetView>, _a: bool, _c: bool) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap)
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(ram(), 0)
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn v1_record(id: i64, type_id: i64, addr: i64, category: &str, comment: &str) -> DBRecord {
        let mut rec = DBRecord::new(v1_schema(), Field::Long(Some(id)));
        rec.set_field(V1_ADDRESS_COL, Field::Long(Some(addr)));
        rec.set_field(V1_TYPE_ID_COL, Field::Long(Some(type_id)));
        rec.set_field(
            V1_TYPE_CATEGORY_COL,
            Field::String(Some(mangle_type_category(type_id, Some(category)))),
        );
        rec.set_field(V1_COMMENT_COL, Field::String(Some(comment.to_string())));
        rec
    }

    fn build_table(records: &[DBRecord]) -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle.create_table(BOOKMARK_TABLE_NAME.to_string(), v1_schema()).unwrap();
        {
            let mut t = table.write().unwrap();
            for rec in records {
                t.put_record(rec.clone()).unwrap();
            }
        }
        handle
    }

    #[test]
    fn new_rejects_missing_table_and_wrong_version() {
        let mut empty = DBHandle::new().unwrap();
        assert!(BookmarkDbAdapterV1::new(&empty, &IdentityAddressMap).is_err());

        empty
            .create_table(BOOKMARK_TABLE_NAME.to_string(), crate::program::database::bookmark::bookmark_db_adapter_v3::schema())
            .unwrap();
        assert!(BookmarkDbAdapterV1::new(&empty, &IdentityAddressMap).is_err());
    }

    #[test]
    fn new_opens_a_valid_v1_table() {
        let handle = build_table(&[v1_record(1, 0, 0x100, "general", "hi")]);
        assert!(BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).is_ok());
    }

    #[test]
    fn get_record_resolves_correctly_only_for_type_zero() {
        let handle = build_table(&[
            v1_record(1, 0, 0x100, "cat", "type0"),
            v1_record(2, 5, 0x200, "cat", "type5"),
        ]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();

        // Packed key for type 0, local id 1 == 1 (0 << 48 | 1), so this resolves correctly.
        let rec = adapter.get_record(1).unwrap().unwrap();
        assert_eq!(rec.get_string(V3_COMMENT_COL), Some("type0"));

        // Packed key for type 5, local id 2 is `(5 << 48) | 2`, which does NOT exist as a raw
        // local key in the table (the type-5 row's real raw key is just `2`) -- demonstrating the
        // documented quirk: looking a bookmark up by its own packed id fails for any type != 0.
        let packed_type5 = (5i64 << TYPE_ID_OFFSET) | 2;
        assert!(adapter.get_record(packed_type5).unwrap().is_none());
    }

    #[test]
    fn get_records_by_type_ignores_its_type_id_argument() {
        let handle = build_table(&[
            v1_record(1, 0, 0x100, "cat", "a"),
            v1_record(2, 7, 0x200, "cat", "b"),
        ]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();

        // Asking for type 0 returns records of every type -- see the module docs.
        let all = adapter.get_records_by_type(0).unwrap();
        assert_eq!(all.len(), 2);
        let all_other = adapter.get_records_by_type(999).unwrap();
        assert_eq!(all_other.len(), 2);
    }

    #[test]
    fn get_records_by_type_for_address_range_also_ignores_type_id_but_filters_by_address() {
        let handle = build_table(&[
            v1_record(1, 0, 0x100, "cat", "a"),
            v1_record(2, 7, 0x200, "cat", "b"),
            v1_record(3, 7, 0x300, "cat", "c"),
        ]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();

        let in_range = adapter.get_records_by_type_for_address_range(0, 0x100, 0x200).unwrap();
        assert_eq!(in_range.len(), 2);
        let addrs: Vec<i64> = in_range.iter().map(|r| r.get_field(V3_ADDRESS_COL).get_long_value()).collect();
        assert_eq!(addrs, vec![0x100, 0x200]);
    }

    #[test]
    fn get_categories_and_bookmark_count_for_type_correctly_filter_by_type() {
        let handle = build_table(&[
            v1_record(1, 0, 0x100, "alpha", "a"),
            v1_record(2, 0, 0x200, "beta", "b"),
            v1_record(3, 7, 0x300, "gamma", "c"),
        ]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();

        assert_eq!(adapter.get_categories(0).unwrap(), vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(adapter.get_categories(7).unwrap(), vec!["gamma".to_string()]);
        assert_eq!(adapter.get_bookmark_count_for_type(0), 2);
        assert_eq!(adapter.get_bookmark_count_for_type(7), 1);
        assert_eq!(adapter.get_bookmark_count_for_type(99), 0);
        assert_eq!(adapter.get_bookmark_count(), 3);
    }

    #[test]
    fn get_records_by_type_and_category_filters_by_mangled_type_and_category() {
        let handle = build_table(&[
            v1_record(1, 0, 0x100, "alpha", "a"),
            v1_record(2, 7, 0x200, "alpha", "b"),
        ]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();

        let matched = adapter.get_records_by_type_and_category(0, Some("alpha")).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].get_string(V3_COMMENT_COL), Some("a"));

        let by_type_only = adapter.get_records_by_type_and_category(7, None).unwrap();
        assert_eq!(by_type_only.len(), 1);
        assert_eq!(by_type_only[0].get_string(V3_COMMENT_COL), Some("b"));
    }

    #[test]
    fn get_records_by_type_starting_at_address_is_unsupported() {
        let handle = build_table(&[v1_record(1, 0, 0x100, "cat", "a")]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();
        assert_eq!(
            adapter.get_records_by_type_starting_at_address(0, 0, true).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn get_bookmark_addresses_decodes_every_type_regardless_of_argument() {
        let handle = build_table(&[
            v1_record(1, 0, 0x100, "cat", "a"),
            v1_record(2, 7, 0x200, "cat", "b"),
        ]);
        let adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();
        let set = adapter.get_bookmark_addresses(0).unwrap();
        assert_eq!(set.num_addresses(), 2);
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = build_table(&[v1_record(1, 0, 0x100, "cat", "a")]);
        let adapter: Box<dyn BookmarkDbAdapter> = Box::new(BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap());
        assert_eq!(adapter.get_bookmark_count(), 1);
    }

    #[test]
    fn default_mutating_methods_remain_unsupported() {
        let handle = build_table(&[v1_record(1, 0, 0x100, "cat", "a")]);
        let mut adapter = BookmarkDbAdapterV1::new(&handle, &IdentityAddressMap).unwrap();
        assert_eq!(
            adapter.create_bookmark(0, None, 0, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(adapter.update_record(&v1_record(1, 0, 0, "", "")).unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(adapter.delete_record(0).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
