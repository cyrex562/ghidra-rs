//! Port of `ghidra.program.database.properties.PropertiesDBAdapterV0`.
//!
//! Version 0 (and, so far, only version) implementation of [`PropertiesDBAdapter`], backed by a
//! `Properties` [`Table`] whose key is the property name and whose columns are the property's
//! type byte and (for `OBJECT_PROPERTY_TYPE` properties) the `Saveable` implementation's class
//! name.
//!
//! Java's version reads `DBPropertyMapManager.PROPERTIES_TABLE_NAME`/`PROPERTIES_SCHEMA`/
//! `PROPERTY_TYPE_COL`/`OBJECT_CLASS_COL`/`OBJECT_PROPERTY_TYPE` off the package-private
//! `DBPropertyMapManager` class. `DBPropertyMapManager` is ported in this crate only as a trait
//! (`db_property_map_manager.rs`, selected as a dependency-cycle cut-point) with no concrete type
//! that owns this schema, so those constants -- and the `Properties` table schema itself -- are
//! declared here instead, where they are actually used. A future concrete `DBPropertyMapManager`
//! implementation should construct its adapters against these same constants rather than
//! redeclaring them again.
//!
//! Not ported here: `testVersion`'s Java exception type is `VersionException`, which this crate
//! does not yet have wired into this module's error surface; `PropertiesDBAdapter::get_records`/
//! `put_record`/`remove_record` return `io::Result`, so the version check in [`PropertiesDBAdapterV0::new`]
//! is surfaced as an `io::Error` with `InvalidData` kind instead.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::properties::PropertiesDBAdapter;

/// Name of the shared table holding one record per defined property map. Stands in for
/// `DBPropertyMapManager.PROPERTIES_TABLE_NAME`.
pub const PROPERTIES_TABLE_NAME: &str = "Properties";

/// Column holding the property's type byte. Stands in for `DBPropertyMapManager.PROPERTY_TYPE_COL`.
pub const PROPERTY_TYPE_COL: usize = 0;
/// Column holding the `Saveable` class name for `OBJECT_PROPERTY_TYPE` properties, `None`
/// otherwise. Stands in for `DBPropertyMapManager.OBJECT_CLASS_COL`.
pub const OBJECT_CLASS_COL: usize = 1;
/// Unused by this adapter (Java never writes it either) but present in the schema for layout
/// parity with `DBPropertyMapManager.PROPERTIES_SCHEMA`'s third `Version` column.
#[allow(dead_code)]
const VERSION_COL: usize = 2;

/// Property map value-type tag: integer-valued map. Stands in for
/// `DBPropertyMapManager.INT_PROPERTY_TYPE`.
pub const INT_PROPERTY_TYPE: u8 = 0;
/// Property map value-type tag: long-valued map. Stands in for
/// `DBPropertyMapManager.LONG_PROPERTY_TYPE`.
pub const LONG_PROPERTY_TYPE: u8 = 1;
/// Property map value-type tag: string-valued map. Stands in for
/// `DBPropertyMapManager.STRING_PROPERTY_TYPE`.
pub const STRING_PROPERTY_TYPE: u8 = 2;
/// Property map value-type tag: void (marker) map. Stands in for
/// `DBPropertyMapManager.VOID_PROPERTY_TYPE`.
pub const VOID_PROPERTY_TYPE: u8 = 3;
/// Property map value-type tag: `Saveable`-object-valued map. Stands in for
/// `DBPropertyMapManager.OBJECT_PROPERTY_TYPE`.
pub const OBJECT_PROPERTY_TYPE: u8 = 4;

/// Builds the `Properties` table schema. Stands in for `DBPropertyMapManager.PROPERTIES_SCHEMA`.
pub fn properties_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::String,
        "Name".to_string(),
        vec![FieldType::Byte, FieldType::String, FieldType::Int],
        vec![
            "Type".to_string(),
            "Object Class".to_string(),
            "Version".to_string(),
        ],
        vec![],
    ))
}

/// Version 0 adapter for accessing property definitions in the database.
///
/// Port of `ghidra.program.database.properties.PropertiesDBAdapterV0`.
pub struct PropertiesDBAdapterV0 {
    properties_table: Arc<RwLock<Table>>,
}

impl PropertiesDBAdapterV0 {
    /// Construct a property map DB adapter, creating the `Properties` table if it does not yet
    /// exist in `db_handle`. Stands in for `PropertiesDBAdapterV0(DBHandle)`.
    ///
    /// # Errors
    /// Returns an error if the table's schema version is not 0 (stands in for `VersionException`),
    /// or if an I/O error occurs.
    pub fn new(db_handle: &mut DBHandle) -> io::Result<Self> {
        let table = match db_handle.get_table(PROPERTIES_TABLE_NAME) {
            Some(t) => t,
            None => db_handle.create_table(PROPERTIES_TABLE_NAME.to_string(), properties_schema())?,
        };

        {
            let guard = table.read().unwrap();
            let version = guard.get_schema().get_version();
            if version != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Properties table: Expected Version 0, got {version}"),
                ));
            }
        }

        Ok(Self {
            properties_table: table,
        })
    }
}

impl PropertiesDBAdapter for PropertiesDBAdapterV0 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let guard = self.properties_table.read().unwrap();
        let mut it = guard.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = it.next()? {
            records.push(rec);
        }
        Ok(Box::new(OwnedRecordIterator { records, pos: 0 }))
    }

    fn put_record(
        &mut self,
        property_name: &str,
        type_byte: u8,
        obj_class_name: Option<&str>,
    ) -> io::Result<()> {
        let mut guard = self.properties_table.write().unwrap();
        let schema = guard.get_schema();
        let mut rec = DBRecord::new(schema, Field::String(Some(property_name.to_string())));
        rec.set_byte(PROPERTY_TYPE_COL, type_byte as i8);
        if type_byte == OBJECT_PROPERTY_TYPE {
            rec.set_string(OBJECT_CLASS_COL, obj_class_name.map(|s| s.to_string()));
        }
        guard.put_record(rec)
    }

    fn remove_record(&mut self, property_name: &str) -> io::Result<()> {
        let mut guard = self.properties_table.write().unwrap();
        guard
            .delete_record(&Field::String(Some(property_name.to_string())))
            .map(|_| ())
    }
}

/// Owned snapshot iterator: collects every matching record up front so this adapter's
/// `get_records` doesn't need to hand back something borrowing the `RwLockReadGuard` it took
/// (which would not outlive the method call).
struct OwnedRecordIterator {
    records: Vec<DBRecord>,
    pos: usize,
}

impl RecordIterator for OwnedRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        if self.pos >= self.records.len() {
            return Ok(None);
        }
        let rec = self.records[self.pos].clone();
        self.pos += 1;
        Ok(Some(rec))
    }

    fn has_next(&self) -> bool {
        self.pos < self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> PropertiesDBAdapterV0 {
        let mut handle = DBHandle::new().unwrap();
        PropertiesDBAdapterV0::new(&mut handle).unwrap()
    }

    #[test]
    fn new_creates_table_and_reuses_it_on_reopen() {
        let mut handle = DBHandle::new().unwrap();
        let a1 = PropertiesDBAdapterV0::new(&mut handle).unwrap();
        drop(a1);
        // Reopening against the same handle should find the existing table rather than erroring.
        let _a2 = PropertiesDBAdapterV0::new(&mut handle).unwrap();
    }

    #[test]
    fn put_and_get_records_round_trips() {
        let mut adapter = adapter();
        adapter.put_record("intProp", INT_PROPERTY_TYPE, None).unwrap();
        adapter
            .put_record("objProp", OBJECT_PROPERTY_TYPE, Some("com.example.MyClass"))
            .unwrap();

        let mut it = adapter.get_records().unwrap();
        let mut seen = Vec::new();
        while let Some(rec) = it.next().unwrap() {
            let name = rec.get_key().get_string_value().unwrap().to_string();
            let type_byte = rec.get_byte(PROPERTY_TYPE_COL).unwrap() as u8;
            let class_name = rec.get_string(OBJECT_CLASS_COL).map(|s| s.to_string());
            seen.push((name, type_byte, class_name));
        }
        seen.sort();

        assert_eq!(
            seen,
            vec![
                ("intProp".to_string(), INT_PROPERTY_TYPE, None),
                (
                    "objProp".to_string(),
                    OBJECT_PROPERTY_TYPE,
                    Some("com.example.MyClass".to_string())
                ),
            ]
        );
    }

    #[test]
    fn remove_record_deletes_it() {
        let mut adapter = adapter();
        adapter.put_record("temp", VOID_PROPERTY_TYPE, None).unwrap();

        {
            let mut it = adapter.get_records().unwrap();
            assert!(it.next().unwrap().is_some());
        }

        adapter.remove_record("temp").unwrap();

        let mut it = adapter.get_records().unwrap();
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn put_record_without_object_class_leaves_column_unset() {
        let mut adapter = adapter();
        adapter.put_record("simple", STRING_PROPERTY_TYPE, Some("ignored")).unwrap();

        let mut it = adapter.get_records().unwrap();
        let rec = it.next().unwrap().unwrap();
        // Only OBJECT_PROPERTY_TYPE records get their object-class column populated; anything
        // else leaves it at the schema's default (null string).
        assert_eq!(rec.get_string(OBJECT_CLASS_COL), None);
    }
}
