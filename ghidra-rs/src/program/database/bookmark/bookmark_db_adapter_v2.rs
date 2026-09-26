//! Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV2`.
//!
//! `V2`'s on-disk schema and every read algorithm are identical to `V1` -- Java's
//! `BookmarkDBAdapterV2 extends BookmarkDBAdapterV1` and overrides only the constructor's version
//! check (`V2_VERSION = 2` instead of `VERSION = 1`). Rust has no implementation inheritance, so
//! this port models the same relationship via composition: [`BookmarkDbAdapterV2`] wraps a fully
//! constructed [`BookmarkDbAdapterV1`] and delegates every [`BookmarkDbAdapter`] method to it
//! verbatim, including every quirk that module's docs describe.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord};
use crate::program::database::bookmark::bookmark_db_adapter::{BookmarkDbAdapter, BOOKMARK_TABLE_NAME};
use crate::program::database::bookmark::bookmark_db_adapter_v1::BookmarkDbAdapterV1;
use crate::program::database::map::AddressMap;
use crate::program::database::references::to_adapter_v0::SendSyncAddressMap;
use crate::program::model::address::AddressSet;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `BookmarkDBAdapterV2.V2_VERSION`.
pub const V2_VERSION: i32 = 2;

/// Read-only adapter for schema version 2 of the historical single-table bookmark schema. See the
/// module docs: this is a thin, version-check-only variant of [`BookmarkDbAdapterV1`].
///
/// Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV2`.
pub struct BookmarkDbAdapterV2(BookmarkDbAdapterV1);

impl BookmarkDbAdapterV2 {
    /// Opens the existing `"Bookmarks"` table from `handle`, verifying it is schema version
    /// [`V2_VERSION`]. Port of `BookmarkDBAdapterV2(DBHandle, AddressMap)`.
    ///
    /// # Errors
    /// Returns [`VersionException`] if the table is missing (upgradeable) or is not schema version
    /// [`V2_VERSION`] (upgradeable if the stored version is older, non-upgradeable if newer --
    /// mirroring Java's `new VersionException(ver < V2_VERSION)`).
    pub fn new(handle: &DBHandle, addr_map: &dyn AddressMap) -> Result<Self, VersionException> {
        let table = handle
            .get_table(BOOKMARK_TABLE_NAME)
            .ok_or_else(|| VersionException::with_upgradeable(true))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != V2_VERSION {
            return Err(VersionException::with_upgradeable(version < V2_VERSION));
        }
        Ok(BookmarkDbAdapterV2(BookmarkDbAdapterV1 {
            table,
            addr_map: Arc::new(SendSyncAddressMap(addr_map.get_old_address_map())),
        }))
    }
}

impl BookmarkDbAdapter for BookmarkDbAdapterV2 {
    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
        self.0.get_record(id)
    }

    fn get_records_by_type_at_address(&self, type_id: i32, address: i64) -> io::Result<Vec<DBRecord>> {
        self.0.get_records_by_type_at_address(type_id, address)
    }

    fn get_records_by_type_starting_at_address(
        &self,
        type_id: i32,
        start_address: i64,
        forward: bool,
    ) -> io::Result<Vec<DBRecord>> {
        self.0.get_records_by_type_starting_at_address(type_id, start_address, forward)
    }

    fn get_records_by_type_for_address_range(
        &self,
        type_id: i32,
        start_addr: i64,
        end_addr: i64,
    ) -> io::Result<Vec<DBRecord>> {
        self.0.get_records_by_type_for_address_range(type_id, start_addr, end_addr)
    }

    fn get_records_by_type_and_category(&self, type_id: i32, category: Option<&str>) -> io::Result<Vec<DBRecord>> {
        self.0.get_records_by_type_and_category(type_id, category)
    }

    fn get_records_by_type(&self, type_id: i32) -> io::Result<Vec<DBRecord>> {
        self.0.get_records_by_type(type_id)
    }

    fn get_categories(&self, type_id: i32) -> io::Result<Vec<String>> {
        self.0.get_categories(type_id)
    }

    fn get_bookmark_addresses(&self, type_id: i32) -> io::Result<AddressSet> {
        self.0.get_bookmark_addresses(type_id)
    }

    fn get_bookmark_count_for_type(&self, type_id: i32) -> i32 {
        self.0.get_bookmark_count_for_type(type_id)
    }

    fn get_bookmark_count(&self) -> i32 {
        self.0.get_bookmark_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use crate::program::database::bookmark::bookmark_db_adapter::mangle_type_category;
    use crate::program::database::bookmark::bookmark_db_adapter_v1::{v1_schema, V1_ADDRESS_COL, V1_COMMENT_COL, V1_TYPE_CATEGORY_COL, V1_TYPE_ID_COL};
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

    fn v2_schema() -> Arc<crate::framework::db::Schema> {
        use crate::framework::db::{FieldType, Schema};
        Arc::new(Schema::new(
            V2_VERSION,
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

    fn v2_record(id: i64, type_id: i64, addr: i64, category: &str, comment: &str) -> DBRecord {
        let mut rec = DBRecord::new(v2_schema(), Field::Long(Some(id)));
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
        let table = handle.create_table(BOOKMARK_TABLE_NAME.to_string(), v2_schema()).unwrap();
        {
            let mut t = table.write().unwrap();
            for rec in records {
                t.put_record(rec.clone()).unwrap();
            }
        }
        handle
    }

    #[test]
    fn new_rejects_missing_table() {
        let empty = DBHandle::new().unwrap();
        match BookmarkDbAdapterV2::new(&empty, &IdentityAddressMap) {
            Err(e) => assert!(e.is_upgradable()),
            Ok(_) => panic!("expected VersionException"),
        }
    }

    #[test]
    fn new_rejects_a_v1_table_as_upgradeable() {
        let mut handle = DBHandle::new().unwrap();
        handle.create_table(BOOKMARK_TABLE_NAME.to_string(), v1_schema()).unwrap();
        match BookmarkDbAdapterV2::new(&handle, &IdentityAddressMap) {
            Err(e) => assert!(e.is_upgradable()),
            Ok(_) => panic!("expected VersionException"),
        }
    }

    #[test]
    fn new_opens_a_valid_v2_table() {
        let handle = build_table(&[v2_record(1, 0, 0x100, "general", "hi")]);
        assert!(BookmarkDbAdapterV2::new(&handle, &IdentityAddressMap).is_ok());
    }

    #[test]
    fn delegates_reads_to_the_wrapped_v1_logic() {
        let handle = build_table(&[
            v2_record(1, 0, 0x100, "alpha", "a"),
            v2_record(2, 7, 0x200, "beta", "b"),
        ]);
        let adapter = BookmarkDbAdapterV2::new(&handle, &IdentityAddressMap).unwrap();

        assert_eq!(adapter.get_bookmark_count(), 2);
        assert_eq!(adapter.get_bookmark_count_for_type(0), 1);
        assert_eq!(adapter.get_categories(7).unwrap(), vec!["beta".to_string()]);
        // `get_records_by_type` ignores its argument, same as V1 -- see V1's module docs.
        assert_eq!(adapter.get_records_by_type(0).unwrap().len(), 2);
        assert_eq!(
            adapter.get_records_by_type_starting_at_address(0, 0, true).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = build_table(&[v2_record(1, 0, 0x100, "cat", "a")]);
        let adapter: Box<dyn BookmarkDbAdapter> = Box::new(BookmarkDbAdapterV2::new(&handle, &IdentityAddressMap).unwrap());
        assert_eq!(adapter.get_bookmark_count(), 1);
    }
}
