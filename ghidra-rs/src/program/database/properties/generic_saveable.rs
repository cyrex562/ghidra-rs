//! Port of `ghidra.program.database.properties.GenericSaveable`.
//!
//! `GenericSaveable` is used by `DBPropertyMapManager` when the class named by a stored
//! `ObjectPropertyMap`'s `Saveable` class-path can no longer be found/loaded. It lets the manager
//! keep treating that property generically -- copying or removing it at a particular address, for
//! Diff/Merge -- without being able to actually interpret its bytes. `save`/`restore` are
//! deliberately unsupported: this type is a read-only, opaque handle onto the raw stored record.

use std::sync::Arc;

use crate::framework::db::{DBRecord, Schema};
use crate::util::{ObjectStorage, ObjectStorageFieldType, Saveable};

/// Opaque handle onto a property record whose `Saveable` value type could not be resolved.
///
/// Port of `ghidra.program.database.properties.GenericSaveable`. Java's constructor is
/// package-private (only `DBPropertyMapManager` is meant to construct one); [`GenericSaveable::new`]
/// is `pub(crate)` here for the same reason.
#[derive(Clone, Debug)]
pub struct GenericSaveable {
    record: DBRecord,
    schema: Arc<Schema>,
}

impl GenericSaveable {
    /// Creates a generic saveable wrapping `record` (read using `schema`).
    pub(crate) fn new(record: DBRecord, schema: Arc<Schema>) -> Self {
        GenericSaveable { record, schema }
    }

    /// The wrapped record, exposed so `DBPropertyMapManager`-style callers can copy/remove the
    /// underlying property without interpreting its value.
    pub fn record(&self) -> &DBRecord {
        &self.record
    }
}

impl Saveable for GenericSaveable {
    // Stands in for `GenericSaveable.getObjectStorageFields()`, which always returns an empty
    // `Class<?>[]`.
    fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
        Vec::new()
    }

    // Stands in for `GenericSaveable.save(ObjectStorage)`, which always throws
    // `UnsupportedOperationException("not supported by GenericSaveable")`.
    fn save(&self, _obj_storage: &mut dyn ObjectStorage) {
        panic!("UnsupportedOperationException: not supported by GenericSaveable");
    }

    // Stands in for `GenericSaveable.restore(ObjectStorage)`, which always throws
    // `UnsupportedOperationException("not supported by GenericSaveable")`.
    fn restore(&mut self, _obj_storage: &mut dyn ObjectStorage) {
        panic!("UnsupportedOperationException: not supported by GenericSaveable");
    }

    fn get_schema_version(&self) -> i32 {
        0
    }

    fn is_upgradeable(&self, _old_schema_version: i32) -> bool {
        false
    }

    fn upgrade(
        &mut self,
        _old_obj_storage: &mut dyn ObjectStorage,
        _old_schema_version: i32,
        _current_obj_storage: &mut dyn ObjectStorage,
    ) -> bool {
        false
    }

    fn is_private(&self) -> bool {
        false
    }
}

impl PartialEq for GenericSaveable {
    // Stands in for `GenericSaveable.equals(Object)`, which compares only `record`.
    fn eq(&self, other: &Self) -> bool {
        self.record.get_key() == other.record.get_key()
            && (0..self.record.get_field_count())
                .all(|i| self.record.get_field(i) == other.record.get_field(i))
    }
}

impl std::fmt::Display for GenericSaveable {
    // Stands in for `GenericSaveable.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = String::new();
        for i in 0..self.schema.get_field_count() {
            let field = self.record.get_field(i);
            buf.push_str(&format!("\n{}={:?} ", self.schema.get_field_name(i), field));
        }
        buf.push('\n');
        write!(f, "{buf}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType};

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        ))
    }

    fn record(key: i64, value: i32) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_int(0, value);
        rec
    }

    /// Minimal no-op [`ObjectStorage`], used only to prove `save`/`restore` panic before ever
    /// reading or writing through it, and that `upgrade` short-circuits without touching it.
    struct NoopStorage;
    impl ObjectStorage for NoopStorage {
        fn put_int(&mut self, _v: i32) {}
        fn put_byte(&mut self, _v: i8) {}
        fn put_short(&mut self, _v: i16) {}
        fn put_long(&mut self, _v: i64) {}
        fn put_string(&mut self, _v: &str) {}
        fn put_boolean(&mut self, _v: bool) {}
        fn put_float(&mut self, _v: f32) {}
        fn put_double(&mut self, _v: f64) {}
        fn put_ints(&mut self, _v: &[i32]) {}
        fn put_bytes(&mut self, _v: &[i8]) {}
        fn put_shorts(&mut self, _v: &[i16]) {}
        fn put_longs(&mut self, _v: &[i64]) {}
        fn put_floats(&mut self, _v: &[f32]) {}
        fn put_doubles(&mut self, _v: &[f64]) {}
        fn put_strings(&mut self, _v: &[&str]) {}
        fn get_int(&mut self) -> i32 {
            0
        }
        fn get_byte(&mut self) -> i8 {
            0
        }
        fn get_short(&mut self) -> i16 {
            0
        }
        fn get_long(&mut self) -> i64 {
            0
        }
        fn get_boolean(&mut self) -> bool {
            false
        }
        fn get_string(&mut self) -> String {
            String::new()
        }
        fn get_float(&mut self) -> f32 {
            0.0
        }
        fn get_double(&mut self) -> f64 {
            0.0
        }
        fn get_ints(&mut self) -> Vec<i32> {
            Vec::new()
        }
        fn get_bytes(&mut self) -> Vec<i8> {
            Vec::new()
        }
        fn get_shorts(&mut self) -> Vec<i16> {
            Vec::new()
        }
        fn get_longs(&mut self) -> Vec<i64> {
            Vec::new()
        }
        fn get_floats(&mut self) -> Vec<f32> {
            Vec::new()
        }
        fn get_doubles(&mut self) -> Vec<f64> {
            Vec::new()
        }
        fn get_strings(&mut self) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn get_object_storage_fields_is_empty() {
        let gs = GenericSaveable::new(record(1, 1), schema());
        assert!(gs.get_object_storage_fields().is_empty());
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn save_panics() {
        let gs = GenericSaveable::new(record(1, 1), schema());
        let mut dummy = NoopStorage;
        gs.save(&mut dummy);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn restore_panics() {
        let mut gs = GenericSaveable::new(record(1, 1), schema());
        let mut dummy = NoopStorage;
        gs.restore(&mut dummy);
    }

    #[test]
    fn schema_version_and_upgrade_are_fixed() {
        let mut gs = GenericSaveable::new(record(1, 1), schema());
        assert_eq!(gs.get_schema_version(), 0);
        assert!(!gs.is_upgradeable(0));
        assert!(!gs.is_upgradeable(-1));
        assert!(!gs.is_private());

        let mut a = NoopStorage;
        let mut b = NoopStorage;
        assert!(!gs.upgrade(&mut a, 0, &mut b));
    }

    #[test]
    fn equals_compares_record_contents() {
        let a = GenericSaveable::new(record(1, 42), schema());
        let b = GenericSaveable::new(record(1, 42), schema());
        let c = GenericSaveable::new(record(1, 43), schema());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn to_string_includes_field_names() {
        let gs = GenericSaveable::new(record(1, 42), schema());
        let s = gs.to_string();
        assert!(s.contains("Value"));
    }
}
