//! Port of `ghidra.program.database.bookmark.BookmarkDBAdapter`.
//!
//! The Java type is a package-private abstract class whose `getAdapter` static factory (plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects between four schema versions
//! (`V0`/`V1`/`V2`/`V3`). Only `BookmarkDBAdapterV3` (the live, current schema) is ported so far
//! -- `V0`/`V1`/`V2` are historical migration-only adapters for programs saved by releases old
//! enough that this port's `TODO` backlog has not reached them yet (each would need its own
//! per-type-table-vs-single-table layout ported faithfully; left honestly `TODO` in
//! `PORT_MANIFEST.tsv` rather than stubbed). Consequently `get_adapter`/`upgrade`'s Java bodies,
//! which route between all four, are not ported here either: a real multi-version factory
//! function would need every version present to be meaningful, and stubbing it now would just be
//! dead code until `V0`-`V2` land. What *is* ported: the abstract instance API (as the
//! object-safe [`BookmarkDbAdapter`] trait, with the same "Bookmarks are read-only" default
//! errors Java's base class throws for the mutating methods) and the three package-private
//! static helpers every version (and `BookmarkDBManager`, not yet ported) shares: [`get_type_id`],
//! [`mangle_type_category`], [`demangle_type_category`].

use std::io;

use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};
use crate::program::database::bookmark::bookmark_db_adapter_v3;
use crate::program::model::address::AddressSet;

/// Name of the database table used to store bookmarks, as defined by
/// `BookmarkDBAdapter.BOOKMARK_TABLE_NAME`.
pub const BOOKMARK_TABLE_NAME: &str = "Bookmarks";

/// Column index of a bookmark's address, as defined by `BookmarkDBAdapter.ADDRESS_COL` (aliased
/// from `BookmarkDBAdapterV3.V3_ADDRESS_COL`, the only version this port implements).
pub const ADDRESS_COL: usize = bookmark_db_adapter_v3::V3_ADDRESS_COL;

/// Column index of a bookmark's category, as defined by `BookmarkDBAdapter.CATEGORY_COL`.
pub const CATEGORY_COL: usize = bookmark_db_adapter_v3::V3_CATEGORY_COL;

/// Column index of a bookmark's comment, as defined by `BookmarkDBAdapter.COMMENT_COL`.
pub const COMMENT_COL: usize = bookmark_db_adapter_v3::V3_COMMENT_COL;

/// The current bookmark table schema, aliased from `BookmarkDBAdapterV3.V3_SCHEMA` (Java:
/// `static final Schema SCHEMA = BookmarkDBAdapterV3.V3_SCHEMA;`).
pub fn schema() -> std::sync::Arc<Schema> {
    bookmark_db_adapter_v3::schema()
}

/// Extracts the bookmark type ID encoded in the high 16 bits of a bookmark record's key. Port of
/// the package-private `BookmarkDBAdapter.getTypeId(DBRecord)`.
pub fn get_type_id(rec: &DBRecord) -> i32 {
    let key = rec.get_key().get_long_value();
    (key >> bookmark_db_adapter_v3::TYPE_ID_OFFSET) as i32
}

/// Combines a bookmark type ID and category into the single mangled string legacy (`V0`-era)
/// storage used as a lookup key. Port of the package-private
/// `BookmarkDBAdapter.mangleTypeCategory(long, String)`.
pub fn mangle_type_category(type_id: i64, category: Option<&str>) -> String {
    format!("{type_id}/{}", category.unwrap_or(""))
}

/// Extracts the category portion of a mangled type/category string produced by
/// [`mangle_type_category`]. Port of the package-private
/// `BookmarkDBAdapter.demangleTypeCategory(String)`.
///
/// Mirrors Java exactly: if no `/` separator is found (which "should not happen" per Java's own
/// comment -- bad data), the whole input is returned unchanged rather than panicking.
pub fn demangle_type_category(type_category: &str) -> &str {
    match type_category.find('/') {
        Some(ix) => &type_category[ix + 1..],
        None => type_category,
    }
}

/// Adapter to access the Bookmarks database tables (one table per bookmark type).
///
/// Port of `ghidra.program.database.bookmark.BookmarkDBAdapter`.
pub trait BookmarkDbAdapter {
    /// Creates a new bookmark record. Port of `BookmarkDBAdapter.createBookmark(int, String,
    /// long, String)`.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`, mirroring
    /// Java's default `UnsupportedOperationException("Bookmarks are read-only and may not be
    /// created")`.
    fn create_bookmark(
        &mut self,
        _type_id: i32,
        _category: Option<&str>,
        _index: i64,
        _comment: Option<&str>,
    ) -> io::Result<Option<DBRecord>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bookmarks are read-only and may not be created",
        ))
    }

    /// Updates the database with the specified bookmark record. Port of
    /// `BookmarkDBAdapter.updateRecord(DBRecord)`.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`, mirroring
    /// Java's default `UnsupportedOperationException("Bookmarks are read-only and may not be
    /// modified")`.
    fn update_record(&mut self, _rec: &DBRecord) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bookmarks are read-only and may not be modified",
        ))
    }

    /// Deletes a specific bookmark. Port of `BookmarkDBAdapter.deleteRecord(long)`.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`, mirroring
    /// Java's default `UnsupportedOperationException("Bookmarks are read-only and may not be
    /// deleted")`.
    fn delete_record(&mut self, _id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bookmarks are read-only and may not be deleted",
        ))
    }

    /// Gets the bookmark record corresponding to the specified bookmark ID, or `None` if not
    /// found. Port of the abstract `BookmarkDBAdapter.getRecord(long)`.
    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>>;

    /// Gets all bookmark records associated with a specific type and address. Port of the
    /// abstract `BookmarkDBAdapter.getRecordsByTypeAtAddress(int, long)`.
    fn get_records_by_type_at_address(&self, type_id: i32, address: i64) -> io::Result<Vec<DBRecord>>;

    /// Gets bookmark records of the given type ordered by address, starting at (and including)
    /// `start_address`, walking forward (ascending) or backward (descending). Port of the
    /// abstract `BookmarkDBAdapter.getRecordsByTypeStartingAtAddress(int, long, boolean)`.
    fn get_records_by_type_starting_at_address(
        &self,
        type_id: i32,
        start_address: i64,
        forward: bool,
    ) -> io::Result<Vec<DBRecord>>;

    /// Gets bookmark records of the given type whose address falls within `[start_addr,
    /// end_addr]`, ordered by address ascending. Port of the abstract
    /// `BookmarkDBAdapter.getRecordsByTypeForAddressRange(int, long, long)`.
    fn get_records_by_type_for_address_range(
        &self,
        type_id: i32,
        start_addr: i64,
        end_addr: i64,
    ) -> io::Result<Vec<DBRecord>>;

    /// Gets all bookmark records with a specific type ID and category (`None` for all
    /// categories). Port of the abstract `BookmarkDBAdapter.getRecordsByTypeAndCategory(int,
    /// String)`.
    fn get_records_by_type_and_category(
        &self,
        type_id: i32,
        category: Option<&str>,
    ) -> io::Result<Vec<DBRecord>>;

    /// Returns all bookmark records with the given type. Port of the abstract
    /// `BookmarkDBAdapter.getRecordsByType(int)`.
    fn get_records_by_type(&self, type_id: i32) -> io::Result<Vec<DBRecord>>;

    /// Gets the list of all known (non-empty) categories for the specified bookmark type, sorted
    /// in ascending order. Port of the abstract `BookmarkDBAdapter.getCategories(int)`.
    fn get_categories(&self, type_id: i32) -> io::Result<Vec<String>>;

    /// Gets the set of addresses where bookmarks of the specified type exist. Port of the
    /// abstract `BookmarkDBAdapter.getBookmarkAddresses(int)`.
    fn get_bookmark_addresses(&self, type_id: i32) -> io::Result<AddressSet>;

    /// Returns the number of bookmarks of the given type. Port of the abstract
    /// `BookmarkDBAdapter.getBookmarkCount(int)`.
    fn get_bookmark_count_for_type(&self, type_id: i32) -> i32;

    /// Returns the total number of bookmarks across all types. Port of the abstract
    /// `BookmarkDBAdapter.getBookmarkCount()`.
    fn get_bookmark_count(&self) -> i32;

    //==============================================================================================
    // V3 and Newer Methods
    //
    // Java stubs these out on the abstract base with `UnsupportedOperationException` so V0-V2
    // don't each need a copy; only V3 overrides them for real. Mirrored the same way here.
    //==============================================================================================

    /// Creates a new bookmark type's table. Port of `BookmarkDBAdapter.addType(int)`.
    ///
    /// Java reaches the database via a `dbHandle` field stashed in the constructor; this port
    /// takes `handle` as an explicit parameter instead (same simplification
    /// [`CompositeDBAdapter::delete_table`](crate::program::database::data::CompositeDBAdapter::delete_table)
    /// already uses), so no adapter needs to store its own `DBHandle`.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`.
    fn add_type(&mut self, _handle: &mut DBHandle, _type_id: i32) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "addType"))
    }

    /// Deletes the table associated with the given bookmark type. Port of
    /// `BookmarkDBAdapter.deleteType(int)`. See [`BookmarkDbAdapter::add_type`] for why `handle`
    /// is an explicit parameter here.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`.
    fn delete_type(&mut self, _handle: &mut DBHandle, _type_id: i32) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "deleteType"))
    }

    /// Returns true if a table exists for the given bookmark type ID. Port of
    /// `BookmarkDBAdapter.hasTable(int)`. The default implementation always returns `false`
    /// (Java's default throws `UnsupportedOperationException`, but a boolean-returning method
    /// can't propagate that without changing the signature to `io::Result`; `false` is the
    /// closest honest default -- "no such table" -- for any adapter that never overrides this).
    fn has_table(&self, _type_id: i32) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_type_id_extracts_high_bits() {
        let rec = DBRecord::new(schema(), crate::framework::db::Field::Long(Some((7i64 << 48) | 3)));
        assert_eq!(get_type_id(&rec), 7);
    }

    #[test]
    fn mangle_and_demangle_round_trip() {
        let mangled = mangle_type_category(3, Some("general"));
        assert_eq!(mangled, "3/general");
        assert_eq!(demangle_type_category(&mangled), "general");
    }

    #[test]
    fn mangle_with_no_category_uses_empty_string() {
        let mangled = mangle_type_category(0, None);
        assert_eq!(mangled, "0/");
        assert_eq!(demangle_type_category(&mangled), "");
    }

    #[test]
    fn demangle_without_separator_returns_input_unchanged() {
        assert_eq!(demangle_type_category("bad-data"), "bad-data");
    }

    #[test]
    fn default_mutating_methods_are_unsupported() {
        struct Stub;
        impl BookmarkDbAdapter for Stub {
            fn get_record(&self, _id: i64) -> io::Result<Option<DBRecord>> {
                Ok(None)
            }
            fn get_records_by_type_at_address(&self, _t: i32, _a: i64) -> io::Result<Vec<DBRecord>> {
                Ok(Vec::new())
            }
            fn get_records_by_type_starting_at_address(
                &self,
                _t: i32,
                _a: i64,
                _f: bool,
            ) -> io::Result<Vec<DBRecord>> {
                Ok(Vec::new())
            }
            fn get_records_by_type_for_address_range(
                &self,
                _t: i32,
                _s: i64,
                _e: i64,
            ) -> io::Result<Vec<DBRecord>> {
                Ok(Vec::new())
            }
            fn get_records_by_type_and_category(
                &self,
                _t: i32,
                _c: Option<&str>,
            ) -> io::Result<Vec<DBRecord>> {
                Ok(Vec::new())
            }
            fn get_records_by_type(&self, _t: i32) -> io::Result<Vec<DBRecord>> {
                Ok(Vec::new())
            }
            fn get_categories(&self, _t: i32) -> io::Result<Vec<String>> {
                Ok(Vec::new())
            }
            fn get_bookmark_addresses(&self, _t: i32) -> io::Result<AddressSet> {
                Ok(AddressSet::new())
            }
            fn get_bookmark_count_for_type(&self, _t: i32) -> i32 {
                0
            }
            fn get_bookmark_count(&self) -> i32 {
                0
            }
        }

        let mut stub = Stub;
        assert_eq!(
            stub.create_bookmark(0, None, 0, None).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let rec = DBRecord::new(schema(), crate::framework::db::Field::Long(Some(1)));
        assert_eq!(
            stub.update_record(&rec).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            stub.delete_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let mut handle = DBHandle::new().unwrap();
        assert_eq!(
            stub.add_type(&mut handle, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            stub.delete_type(&mut handle, 0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!stub.has_table(0));
    }

    #[test]
    fn schema_matches_v3() {
        let s = schema();
        assert_eq!(s.get_key_type(), FieldType::Long);
        assert_eq!(s.get_field_count(), 3);
    }
}
