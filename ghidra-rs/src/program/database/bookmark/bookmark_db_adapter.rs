//! Port of `ghidra.program.database.bookmark.BookmarkDBAdapter`.
//!
//! The Java type is a package-private abstract class whose `getAdapter` static factory (plus the
//! private `findReadOnlyAdapter`/`upgrade` helpers) selects between four schema versions
//! (`V0`/`V1`/`V2`/`V3`). What's ported: the abstract instance API (as the object-safe
//! [`BookmarkDbAdapter`] trait, with the same "Bookmarks are read-only" default errors Java's base
//! class throws for the mutating methods); the three package-private static helpers every version
//! (and [`BookmarkDBManager`](crate::program::database::bookmark::BookmarkDBManager)) shares --
//! [`get_type_id`], [`mangle_type_category`], [`demangle_type_category`]; and, now that all four
//! concrete versions exist, the real version-selection/upgrade logic itself: [`get_adapter`] (with
//! `findReadOnlyAdapter`/`upgrade` inlined as private helpers, mirroring how
//! [`bookmark_type_db_adapter::get_adapter`](crate::program::database::bookmark::bookmark_type_db_adapter::get_adapter)
//! already handles the identical situation for the sibling type-adapter family) and the
//! [`BookmarkAdapterKind`] enum it returns.
//!
//! **Why an enum, not `Box<dyn BookmarkDbAdapter>`.** `BookmarkDbAdapter` itself declares no
//! `Send`/`Sync` bound (not every hypothetical implementor needs one), but
//! [`BookmarkDBManager`](crate::program::database::bookmark::BookmarkDBManager) does need whatever
//! it stores to be `Send` so the manager itself can satisfy
//! [`BookmarkManagerDb`](crate::program::database::bookmark::BookmarkManagerDb)'s `Send + Sync`
//! supertrait bound. A `Box<dyn BookmarkDbAdapter + Send>` would work too, but every one of the
//! four concrete adapters is already `Send` on its own (see each one's own module for why --
//! `V1`/`V2` in particular rely on
//! [`SendSyncAddressMap`](crate::program::database::references::to_adapter_v0::SendSyncAddressMap)
//! for exactly this), so a closed `enum` avoids the trait-object bound question entirely: it is
//! `Send`/`Sync` automatically whenever all four variants are.

use std::io;
use std::sync::Arc;

use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};
use crate::program::database::bookmark::bookmark_db_adapter_v0::BookmarkDbAdapterV0;
use crate::program::database::bookmark::bookmark_db_adapter_v1::BookmarkDbAdapterV1;
use crate::program::database::bookmark::bookmark_db_adapter_v2::BookmarkDbAdapterV2;
use crate::program::database::bookmark::bookmark_db_adapter_v3::{self, BookmarkDbAdapterV3};
use crate::program::database::map::AddressMap;
use crate::program::database::references::to_adapter_v0::SendSyncAddressMap;
use crate::program::model::address::AddressSet;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

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

/// Whichever concrete bookmark table schema is actually in play. See the module docs for why this
/// is an enum rather than a trait object.
pub enum BookmarkAdapterKind {
    V0(BookmarkDbAdapterV0),
    V1(BookmarkDbAdapterV1),
    V2(BookmarkDbAdapterV2),
    V3(BookmarkDbAdapterV3),
}

impl BookmarkDbAdapter for BookmarkAdapterKind {
    fn create_bookmark(
        &mut self,
        type_id: i32,
        category: Option<&str>,
        index: i64,
        comment: Option<&str>,
    ) -> io::Result<Option<DBRecord>> {
        match self {
            Self::V0(a) => a.create_bookmark(type_id, category, index, comment),
            Self::V1(a) => a.create_bookmark(type_id, category, index, comment),
            Self::V2(a) => a.create_bookmark(type_id, category, index, comment),
            Self::V3(a) => a.create_bookmark(type_id, category, index, comment),
        }
    }

    fn update_record(&mut self, rec: &DBRecord) -> io::Result<()> {
        match self {
            Self::V0(a) => a.update_record(rec),
            Self::V1(a) => a.update_record(rec),
            Self::V2(a) => a.update_record(rec),
            Self::V3(a) => a.update_record(rec),
        }
    }

    fn delete_record(&mut self, id: i64) -> io::Result<()> {
        match self {
            Self::V0(a) => a.delete_record(id),
            Self::V1(a) => a.delete_record(id),
            Self::V2(a) => a.delete_record(id),
            Self::V3(a) => a.delete_record(id),
        }
    }

    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
        match self {
            Self::V0(a) => a.get_record(id),
            Self::V1(a) => a.get_record(id),
            Self::V2(a) => a.get_record(id),
            Self::V3(a) => a.get_record(id),
        }
    }

    fn get_records_by_type_at_address(&self, type_id: i32, address: i64) -> io::Result<Vec<DBRecord>> {
        match self {
            Self::V0(a) => a.get_records_by_type_at_address(type_id, address),
            Self::V1(a) => a.get_records_by_type_at_address(type_id, address),
            Self::V2(a) => a.get_records_by_type_at_address(type_id, address),
            Self::V3(a) => a.get_records_by_type_at_address(type_id, address),
        }
    }

    fn get_records_by_type_starting_at_address(
        &self,
        type_id: i32,
        start_address: i64,
        forward: bool,
    ) -> io::Result<Vec<DBRecord>> {
        match self {
            Self::V0(a) => a.get_records_by_type_starting_at_address(type_id, start_address, forward),
            Self::V1(a) => a.get_records_by_type_starting_at_address(type_id, start_address, forward),
            Self::V2(a) => a.get_records_by_type_starting_at_address(type_id, start_address, forward),
            Self::V3(a) => a.get_records_by_type_starting_at_address(type_id, start_address, forward),
        }
    }

    fn get_records_by_type_for_address_range(
        &self,
        type_id: i32,
        start_addr: i64,
        end_addr: i64,
    ) -> io::Result<Vec<DBRecord>> {
        match self {
            Self::V0(a) => a.get_records_by_type_for_address_range(type_id, start_addr, end_addr),
            Self::V1(a) => a.get_records_by_type_for_address_range(type_id, start_addr, end_addr),
            Self::V2(a) => a.get_records_by_type_for_address_range(type_id, start_addr, end_addr),
            Self::V3(a) => a.get_records_by_type_for_address_range(type_id, start_addr, end_addr),
        }
    }

    fn get_records_by_type_and_category(&self, type_id: i32, category: Option<&str>) -> io::Result<Vec<DBRecord>> {
        match self {
            Self::V0(a) => a.get_records_by_type_and_category(type_id, category),
            Self::V1(a) => a.get_records_by_type_and_category(type_id, category),
            Self::V2(a) => a.get_records_by_type_and_category(type_id, category),
            Self::V3(a) => a.get_records_by_type_and_category(type_id, category),
        }
    }

    fn get_records_by_type(&self, type_id: i32) -> io::Result<Vec<DBRecord>> {
        match self {
            Self::V0(a) => a.get_records_by_type(type_id),
            Self::V1(a) => a.get_records_by_type(type_id),
            Self::V2(a) => a.get_records_by_type(type_id),
            Self::V3(a) => a.get_records_by_type(type_id),
        }
    }

    fn get_categories(&self, type_id: i32) -> io::Result<Vec<String>> {
        match self {
            Self::V0(a) => a.get_categories(type_id),
            Self::V1(a) => a.get_categories(type_id),
            Self::V2(a) => a.get_categories(type_id),
            Self::V3(a) => a.get_categories(type_id),
        }
    }

    fn get_bookmark_addresses(&self, type_id: i32) -> io::Result<AddressSet> {
        match self {
            Self::V0(a) => a.get_bookmark_addresses(type_id),
            Self::V1(a) => a.get_bookmark_addresses(type_id),
            Self::V2(a) => a.get_bookmark_addresses(type_id),
            Self::V3(a) => a.get_bookmark_addresses(type_id),
        }
    }

    fn get_bookmark_count_for_type(&self, type_id: i32) -> i32 {
        match self {
            Self::V0(a) => a.get_bookmark_count_for_type(type_id),
            Self::V1(a) => a.get_bookmark_count_for_type(type_id),
            Self::V2(a) => a.get_bookmark_count_for_type(type_id),
            Self::V3(a) => a.get_bookmark_count_for_type(type_id),
        }
    }

    fn get_bookmark_count(&self) -> i32 {
        match self {
            Self::V0(a) => a.get_bookmark_count(),
            Self::V1(a) => a.get_bookmark_count(),
            Self::V2(a) => a.get_bookmark_count(),
            Self::V3(a) => a.get_bookmark_count(),
        }
    }

    fn add_type(&mut self, handle: &mut DBHandle, type_id: i32) -> io::Result<()> {
        match self {
            Self::V0(a) => a.add_type(handle, type_id),
            Self::V1(a) => a.add_type(handle, type_id),
            Self::V2(a) => a.add_type(handle, type_id),
            Self::V3(a) => a.add_type(handle, type_id),
        }
    }

    fn delete_type(&mut self, handle: &mut DBHandle, type_id: i32) -> io::Result<()> {
        match self {
            Self::V0(a) => a.delete_type(handle, type_id),
            Self::V1(a) => a.delete_type(handle, type_id),
            Self::V2(a) => a.delete_type(handle, type_id),
            Self::V3(a) => a.delete_type(handle, type_id),
        }
    }

    fn has_table(&self, type_id: i32) -> bool {
        match self {
            Self::V0(a) => a.has_table(type_id),
            Self::V1(a) => a.has_table(type_id),
            Self::V2(a) => a.has_table(type_id),
            Self::V3(a) => a.has_table(type_id),
        }
    }
}

/// Selects (and upgrades, if needed) the appropriate bookmark table schema for the given database
/// handle and open mode.
///
/// Port of `BookmarkDBAdapter.getAdapter(DBHandle, OpenMode, int[], AddressMap, TaskMonitor)`.
///
/// # Errors
/// Returns a [`VersionException`] if the stored schema version is incompatible with `open_mode`.
pub fn get_adapter(
    handle: &mut DBHandle,
    open_mode: OpenMode,
    type_ids: &[i32],
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    monitor: &dyn TaskMonitor,
) -> Result<BookmarkAdapterKind, VersionException> {
    if open_mode == OpenMode::Create {
        return Ok(BookmarkAdapterKind::V3(BookmarkDbAdapterV3::new(
            handle, true, type_ids, addr_map,
        )?));
    }

    match BookmarkDbAdapterV3::new(handle, false, type_ids, addr_map.clone()) {
        Ok(adapter) => {
            if addr_map.is_upgraded() {
                return Err(VersionException::with_upgradeable(true));
            }
            Ok(BookmarkAdapterKind::V3(adapter))
        }
        Err(e) => {
            if !e.is_upgradable() || open_mode == OpenMode::Update {
                return Err(e);
            }
            let old_adapter = find_read_only_adapter(handle, addr_map.as_ref(), type_ids)?;
            if open_mode == OpenMode::Upgrade {
                return upgrade(handle, old_adapter, type_ids, addr_map, monitor);
            }
            Ok(old_adapter)
        }
    }
}

/// Probes each historical schema version, newest first, returning the first one that opens
/// successfully (or [`BookmarkAdapterKind::V0`] if none do). Port of the private
/// `BookmarkDBAdapter.findReadOnlyAdapter(DBHandle, AddressMap, int[])`.
fn find_read_only_adapter(
    handle: &mut DBHandle,
    addr_map: &dyn AddressMap,
    type_ids: &[i32],
) -> Result<BookmarkAdapterKind, VersionException> {
    let old_map: Arc<dyn AddressMap + Send + Sync> = Arc::new(SendSyncAddressMap(addr_map.get_old_address_map()));
    if let Ok(v3) = BookmarkDbAdapterV3::new(handle, false, type_ids, old_map) {
        return Ok(BookmarkAdapterKind::V3(v3));
    }
    if let Ok(v2) = BookmarkDbAdapterV2::new(handle, addr_map) {
        return Ok(BookmarkAdapterKind::V2(v2));
    }
    if let Ok(v1) = BookmarkDbAdapterV1::new(handle, addr_map) {
        return Ok(BookmarkAdapterKind::V1(v1));
    }
    Ok(BookmarkAdapterKind::V0(BookmarkDbAdapterV0::new()))
}

/// Upgrades an older bookmark schema to the current ([`BookmarkDbAdapterV3`]) one in place. Port
/// of the private `BookmarkDBAdapter.upgrade(DBHandle, BookmarkDBAdapter, int[], AddressMap,
/// TaskMonitor)`.
///
/// **Faithfully-mirrored quirk.** Because [`BookmarkDbAdapterV1::get_records_by_type`] (which
/// `V2` also uses) ignores its `type_id` argument and always returns *every* record in the shared
/// legacy table (see that module's docs), the `for type_id in type_ids { ... get_records_by_type
/// (type_id) ... }` loop below re-processes the *entire* legacy table once per known type -- for a
/// `V1`/`V2` source database with more than one bookmark type, this means every bookmark is
/// converted (and thus duplicated) once per type. This is a real latent bug in the original Java
/// (the same method, calling the same buggy `getRecordsByType`), mirrored rather than fixed, per
/// this port's established policy of preserving originally-observed behavior.
///
/// # Errors
/// Returns a [`VersionException`] if building the replacement `V3` tables fails.
fn upgrade(
    handle: &mut DBHandle,
    old_adapter: BookmarkAdapterKind,
    type_ids: &[i32],
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    monitor: &dyn TaskMonitor,
) -> Result<BookmarkAdapterKind, VersionException> {
    if matches!(old_adapter, BookmarkAdapterKind::V0(_)) {
        // Actual upgrade from Version 0 is delayed until BookmarkDBManager wires an
        // OldBookmarkManager in -- mirrors Java's own comment on this branch.
        return Ok(BookmarkAdapterKind::V3(BookmarkDbAdapterV3::new(
            handle, true, type_ids, addr_map,
        )?));
    }

    if !matches!(old_adapter, BookmarkAdapterKind::V1(_)) {
        handle.delete_table(BOOKMARK_TABLE_NAME);
    }

    monitor.set_message("Upgrading Bookmarks...");
    monitor.initialize(2 * old_adapter.get_bookmark_count() as i64);
    let mut cnt: i64 = 0;

    let old_addr_map: Arc<dyn AddressMap + Send + Sync> = Arc::new(SendSyncAddressMap(addr_map.get_old_address_map()));

    let map_io_err = |e: io::Error| VersionException::with_message(e.to_string());

    let mut tmp_handle = DBHandle::new().map_err(map_io_err)?;
    let mut tmp_adapter = BookmarkDbAdapterV3::new(&mut tmp_handle, true, type_ids, addr_map.clone())?;

    for &type_id2 in type_ids {
        let records = old_adapter.get_records_by_type(type_id2).map_err(map_io_err)?;
        for rec in records {
            let type_id = get_type_id(&rec);
            tmp_adapter.add_type(&mut tmp_handle, type_id).map_err(map_io_err)?;
            let addr = old_addr_map.decode_address(rec.get_field(ADDRESS_COL).get_long_value());
            tmp_adapter
                .create_bookmark(
                    type_id,
                    rec.get_string(CATEGORY_COL),
                    addr_map.get_key(&addr, true),
                    rec.get_string(COMMENT_COL),
                )
                .map_err(map_io_err)?;
            cnt += 1;
            monitor.set_progress(cnt);
        }
    }

    handle.delete_table(BOOKMARK_TABLE_NAME);
    for &type_id in type_ids {
        handle.delete_table(&format!("{BOOKMARK_TABLE_NAME}{type_id}"));
    }

    let mut new_adapter = BookmarkDbAdapterV3::new(handle, true, type_ids, addr_map)?;
    for &type_id in type_ids {
        let records = tmp_adapter.get_records_by_type(type_id).map_err(map_io_err)?;
        for rec in records {
            new_adapter.update_record(&rec).map_err(map_io_err)?;
            cnt += 1;
            monitor.set_progress(cnt);
        }
    }
    Ok(BookmarkAdapterKind::V3(new_adapter))
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
