//! Port of `ghidra.program.database.bookmark.BookmarkTypeDBAdapter`.
//!
//! The Java type is a package-private abstract class whose static factory method (`getAdapter`,
//! plus the private `findReadOnlyAdapter`/`upgrade` helpers) selects between the concrete
//! `BookmarkTypeDBAdapterV0` (live, table-backed) and `BookmarkTypeDBAdapterNoTable`
//! (property-map-derived, read-only) implementations. This port models the abstract instance API
//! as an object-safe trait ([`BookmarkTypeDbAdapter`]) plus a free [`get_adapter`] function that
//! reproduces the same selection/upgrade logic, since Rust traits cannot host a `Self`-returning
//! static factory without losing object safety.
//!
//! `addType`/`deleteRecord` default to `UnsupportedOperationException("Bookmarks are read-only
//! and may not be added/deleted")` in Java; the equivalent default trait methods here return an
//! `io::ErrorKind::Unsupported` error with the same message. `getTypeIds()` is a concrete method
//! in Java (`derived from getRecords()`), ported as a default trait method built on the required
//! [`BookmarkTypeDbAdapter::get_records`].

use std::io;
use std::sync::Arc;

use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, FieldType, Schema};
use crate::program::database::bookmark::bookmark_type_db_adapter_no_table::BookmarkTypeDbAdapterNoTable;
use crate::program::database::bookmark::bookmark_type_db_adapter_v0::BookmarkTypeDbAdapterV0;
use crate::util::exception::VersionException;

/// Name of the database table used to store bookmark types, as defined by
/// `BookmarkTypeDBAdapter.TABLE_NAME`.
pub const BOOKMARK_TYPE_TABLE_NAME: &str = "Bookmark Types";

/// Column index of a bookmark type's name, as defined by `BookmarkTypeDBAdapter.TYPE_NAME_COL`.
pub const TYPE_NAME_COL: usize = 0;

/// Builds the bookmark type table schema, as defined by `BookmarkTypeDBAdapter.SCHEMA`. Exposed
/// as a function (rather than a `Schema` constant) since `Schema` construction is not `const`.
///
/// Java's `new Schema(0, "ID", new Field[] { StringField.INSTANCE }, new String[] { "Name" })`
/// uses the 4-arg `Schema` constructor, which defaults the key field type to `LongField`
/// (`db.Schema`'s javadoc: "Construct a new Schema which uses a long key") -- the key is the
/// bookmark type's integer ID, not a string.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "ID".to_string(),
        vec![FieldType::String],
        vec!["Name".to_string()],
        vec![],
    ))
}

/// Adapter to access the Bookmark Types database table.
///
/// Port of `ghidra.program.database.bookmark.BookmarkTypeDBAdapter`.
pub trait BookmarkTypeDbAdapter {
    /// Allocates a new bookmark type. Port of `BookmarkTypeDBAdapter.addType(int, String)`.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`, mirroring
    /// Java's default `UnsupportedOperationException("Bookmarks are read-only and may not be
    /// added")`.
    fn add_type(&mut self, _type_id: i32, _type_name: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bookmarks are read-only and may not be added",
        ))
    }

    /// Deletes a bookmark type. Port of `BookmarkTypeDBAdapter.deleteRecord(long)`.
    ///
    /// # Errors
    /// The default implementation always fails with `io::ErrorKind::Unsupported`, mirroring
    /// Java's default `UnsupportedOperationException("Bookmarks are read-only and may not be
    /// deleted")`.
    fn delete_record(&mut self, _type_id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bookmarks are read-only and may not be deleted",
        ))
    }

    /// Gets all bookmark type records. Port of the abstract `BookmarkTypeDBAdapter.getRecords()`.
    ///
    /// # Errors
    /// Returns an error if there was a problem accessing the database.
    fn get_records(&self) -> io::Result<Vec<DBRecord>>;

    /// Gets the type IDs of all bookmark type records. Port of
    /// `BookmarkTypeDBAdapter.getTypeIds()`.
    ///
    /// # Errors
    /// Returns an error if there was a problem accessing the database.
    fn get_type_ids(&self) -> io::Result<Vec<i32>> {
        Ok(self
            .get_records()?
            .iter()
            .map(|rec| rec.get_key().get_long_value() as i32)
            .collect())
    }
}

/// Selects (and upgrades, if needed) the appropriate concrete [`BookmarkTypeDbAdapter`] for the
/// given database handle and open mode.
///
/// Port of `BookmarkTypeDBAdapter.getAdapter(DBHandle, OpenMode)`, including the private
/// `findReadOnlyAdapter`/`upgrade` helpers inlined (both only ever produce a
/// [`BookmarkTypeDbAdapterNoTable`]/[`BookmarkTypeDbAdapterV0`] respectively, so there is no
/// separate helper worth keeping).
///
/// Note: Java's `findReadOnlyAdapter` returns a `BookmarkTypeDBAdapterNoTable` whose javadoc
/// states "The old bookmark manager must be set prior to invoking any other method" via
/// `setOldBookmarkManager`; since `OldBookmarkManager` is not yet ported, the caller of this
/// function is responsible for populating the returned adapter's records (see
/// [`BookmarkTypeDbAdapterNoTable::set_records`]) before using it, exactly mirroring the ordering
/// Java's callers must already observe.
///
/// # Errors
/// Returns a [`VersionException`] if the stored schema version is incompatible with `open_mode`.
pub fn get_adapter(
    handle: &mut DBHandle,
    open_mode: OpenMode,
) -> Result<Box<dyn BookmarkTypeDbAdapter>, VersionException> {
    if open_mode == OpenMode::Create {
        return Ok(Box::new(BookmarkTypeDbAdapterV0::new(handle, true)?));
    }

    match BookmarkTypeDbAdapterV0::new(handle, false) {
        Ok(adapter) => Ok(Box::new(adapter)),
        Err(e) => {
            if open_mode == OpenMode::Update {
                return Err(e);
            }
            let mut adapter: Box<dyn BookmarkTypeDbAdapter> =
                Box::new(BookmarkTypeDbAdapterNoTable::new());
            if open_mode == OpenMode::Upgrade {
                adapter = Box::new(BookmarkTypeDbAdapterV0::new(handle, true)?);
            }
            Ok(adapter)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::DBHandle;

    #[test]
    fn schema_matches_java() {
        let s = schema();
        assert_eq!(s.get_version(), 0);
        assert_eq!(s.get_key_type(), FieldType::Long);
        assert_eq!(s.get_field_count(), 1);
        assert_eq!(s.get_field_name(TYPE_NAME_COL), "Name");
    }

    #[test]
    fn get_adapter_create_mode_produces_a_v0_adapter() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = get_adapter(&mut handle, OpenMode::Create).unwrap();
        adapter.add_type(0, "Note").unwrap();
        assert_eq!(adapter.get_type_ids().unwrap(), vec![0]);
    }

    #[test]
    fn get_adapter_update_mode_without_a_table_fails() {
        let mut handle = DBHandle::new().unwrap();
        assert!(get_adapter(&mut handle, OpenMode::Update).is_err());
    }

    #[test]
    fn get_adapter_upgrade_mode_without_a_table_creates_one() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = get_adapter(&mut handle, OpenMode::Upgrade).unwrap();
        assert_eq!(adapter.get_type_ids().unwrap(), Vec::<i32>::new());
    }

    #[test]
    fn get_adapter_immutable_mode_without_a_table_falls_back_to_no_table() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = get_adapter(&mut handle, OpenMode::Immutable).unwrap();
        // NoTable starts empty until records are injected by the caller.
        assert_eq!(adapter.get_type_ids().unwrap(), Vec::<i32>::new());
    }

    #[test]
    fn default_add_type_and_delete_record_are_unsupported() {
        struct Stub;
        impl BookmarkTypeDbAdapter for Stub {
            fn get_records(&self) -> io::Result<Vec<DBRecord>> {
                Ok(Vec::new())
            }
        }
        let mut stub = Stub;
        assert_eq!(
            stub.add_type(0, "x").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            stub.delete_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
