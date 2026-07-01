use crate::util::ObjectStorage;

/// Describes the type of a field stored in ObjectStorage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStorageFieldType {
    Int,
    Byte,
    Short,
    Long,
    String,
    Bool,
    Float,
    Double,
    Ints,
    Bytes,
    Shorts,
    Longs,
    Floats,
    Doubles,
    Strings,
}

/// Save and restore elements that are compatible with ObjectStorage objects.
///
/// **Important**: Any class implementing this trait that may have its class path saved to the
/// data base (i.e. user defined properties) should register a mapping in a class translator
/// when it is moved or renamed between versions of Ghidra.
///
/// For example, any type that implements the `Saveable` trait can potentially be saved as a
/// property in the program. If used as a program property, the class name gets saved to a
/// database field in the property manager. If the class gets moved or renamed, the property
/// manager won't be able to instantiate it. A class translator allows the saveable type to
/// indicate its old path name (that was stored in the database) and its current path name
/// (the actual location of the type it needs to instantiate for the property).
///
/// Port of `ghidra.util.Saveable`.
pub trait Saveable {
    /// Returns the field types, in the same order as used in [`save`](Self::save) and
    /// [`restore`](Self::restore).
    ///
    /// For example, if the save method calls `obj_storage.put_int()` and then
    /// `obj_storage.put_float()`, then this method must return
    /// `vec![ObjectStorageFieldType::Int, ObjectStorageFieldType::Float]`.
    fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType>;

    /// Save to the given ObjectStorage.
    ///
    /// # Arguments
    /// * `obj_storage` - Object that can handle primitives, strings, and arrays of primitives and strings.
    fn save(&self, obj_storage: &mut dyn ObjectStorage);

    /// Restore from the given ObjectStorage.
    ///
    /// # Arguments
    /// * `obj_storage` - Object that can handle primitives, strings, and arrays of primitives and strings.
    fn restore(&mut self, obj_storage: &mut dyn ObjectStorage);

    /// Get the storage schema version.
    ///
    /// Any time there is a software release in which the implementing type has changed the
    /// data structure used for the save and restore methods, the schema version must be incremented.
    fn get_schema_version(&self) -> i32;

    /// Determine if the implementation supports a storage upgrade from the specified older schema version
    /// to the current schema version.
    ///
    /// # Arguments
    /// * `old_schema_version` - The older schema version to check compatibility for.
    ///
    /// # Returns
    /// `true` if upgrading is supported for the older schema version, `false` otherwise.
    fn is_upgradeable(&self, old_schema_version: i32) -> bool;

    /// Upgrade an older stored object to the current storage schema.
    ///
    /// # Arguments
    /// * `old_obj_storage` - The old stored object.
    /// * `old_schema_version` - Storage schema version number for the old object.
    /// * `current_obj_storage` - New object for storage in the current schema.
    ///
    /// # Returns
    /// `true` if data was upgraded to the `current_obj_storage` successfully, `false` otherwise.
    fn upgrade(
        &mut self,
        old_obj_storage: &mut dyn ObjectStorage,
        old_schema_version: i32,
        current_obj_storage: &mut dyn ObjectStorage,
    ) -> bool;

    /// Returns true if this saveable should not have its changes broadcast.
    fn is_private(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct TestEntry {
        int_val: i32,
        float_val: f32,
    }

    impl TestEntry {
        fn new(int_val: i32, float_val: f32) -> Self {
            TestEntry { int_val, float_val }
        }
    }

    struct TestStorage {
        data: Vec<String>,
        index: usize,
    }

    impl TestStorage {
        fn new() -> Self {
            TestStorage {
                data: Vec::new(),
                index: 0,
            }
        }

        fn from_data(data: Vec<String>) -> Self {
            TestStorage { data, index: 0 }
        }
    }

    impl ObjectStorage for TestStorage {
        fn put_int(&mut self, value: i32) {
            self.data.push(format!("int:{}", value));
        }

        fn put_byte(&mut self, value: i8) {
            self.data.push(format!("byte:{}", value));
        }

        fn put_short(&mut self, value: i16) {
            self.data.push(format!("short:{}", value));
        }

        fn put_long(&mut self, value: i64) {
            self.data.push(format!("long:{}", value));
        }

        fn put_string(&mut self, value: &str) {
            self.data.push(format!("string:{}", value));
        }

        fn put_boolean(&mut self, value: bool) {
            self.data.push(format!("bool:{}", value));
        }

        fn put_float(&mut self, value: f32) {
            self.data.push(format!("float:{}", value));
        }

        fn put_double(&mut self, value: f64) {
            self.data.push(format!("double:{}", value));
        }

        fn put_ints(&mut self, value: &[i32]) {
            self.data
                .push(format!("ints:{}", value.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
        }

        fn put_bytes(&mut self, value: &[i8]) {
            self.data
                .push(format!("bytes:{}", value.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
        }

        fn put_shorts(&mut self, value: &[i16]) {
            self.data
                .push(format!("shorts:{}", value.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
        }

        fn put_longs(&mut self, value: &[i64]) {
            self.data
                .push(format!("longs:{}", value.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
        }

        fn put_floats(&mut self, value: &[f32]) {
            self.data
                .push(format!("floats:{}", value.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
        }

        fn put_doubles(&mut self, value: &[f64]) {
            self.data
                .push(format!("doubles:{}", value.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
        }

        fn put_strings(&mut self, value: &[&str]) {
            self.data.push(format!("strings:{}", value.join(",")));
        }

        fn get_int(&mut self) -> i32 {
            self.index += 1;
            self.data[self.index - 1].parse().unwrap_or(0)
        }

        fn get_byte(&mut self) -> i8 {
            self.index += 1;
            self.data[self.index - 1].parse().unwrap_or(0)
        }

        fn get_short(&mut self) -> i16 {
            self.index += 1;
            self.data[self.index - 1].parse().unwrap_or(0)
        }

        fn get_long(&mut self) -> i64 {
            self.index += 1;
            self.data[self.index - 1].parse().unwrap_or(0)
        }

        fn get_boolean(&mut self) -> bool {
            self.index += 1;
            self.data[self.index - 1].contains("true")
        }

        fn get_string(&mut self) -> String {
            self.index += 1;
            String::new()
        }

        fn get_float(&mut self) -> f32 {
            self.index += 1;
            0.0
        }

        fn get_double(&mut self) -> f64 {
            self.index += 1;
            0.0
        }

        fn get_ints(&mut self) -> Vec<i32> {
            self.index += 1;
            Vec::new()
        }

        fn get_bytes(&mut self) -> Vec<i8> {
            self.index += 1;
            Vec::new()
        }

        fn get_shorts(&mut self) -> Vec<i16> {
            self.index += 1;
            Vec::new()
        }

        fn get_longs(&mut self) -> Vec<i64> {
            self.index += 1;
            Vec::new()
        }

        fn get_floats(&mut self) -> Vec<f32> {
            self.index += 1;
            Vec::new()
        }

        fn get_doubles(&mut self) -> Vec<f64> {
            self.index += 1;
            Vec::new()
        }

        fn get_strings(&mut self) -> Vec<String> {
            self.index += 1;
            Vec::new()
        }
    }

    struct SimpleSaveable {
        int_field: i32,
        float_field: f32,
        schema_version: i32,
    }

    impl SimpleSaveable {
        fn new(int_field: i32, float_field: f32) -> Self {
            SimpleSaveable {
                int_field,
                float_field,
                schema_version: 1,
            }
        }
    }

    impl Saveable for SimpleSaveable {
        fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
            vec![ObjectStorageFieldType::Int, ObjectStorageFieldType::Float]
        }

        fn save(&self, obj_storage: &mut dyn ObjectStorage) {
            obj_storage.put_int(self.int_field);
            obj_storage.put_float(self.float_field);
        }

        fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
            self.int_field = obj_storage.get_int();
            self.float_field = obj_storage.get_float();
        }

        fn get_schema_version(&self) -> i32 {
            self.schema_version
        }

        fn is_upgradeable(&self, old_schema_version: i32) -> bool {
            old_schema_version <= self.schema_version
        }

        fn upgrade(
            &mut self,
            old_obj_storage: &mut dyn ObjectStorage,
            old_schema_version: i32,
            current_obj_storage: &mut dyn ObjectStorage,
        ) -> bool {
            if !self.is_upgradeable(old_schema_version) {
                return false;
            }
            self.restore(old_obj_storage);
            self.save(current_obj_storage);
            true
        }

        fn is_private(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_get_object_storage_fields() {
        let obj = SimpleSaveable::new(42, 3.14);
        let fields = obj.get_object_storage_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], ObjectStorageFieldType::Int);
        assert_eq!(fields[1], ObjectStorageFieldType::Float);
    }

    #[test]
    fn test_schema_version() {
        let obj = SimpleSaveable::new(42, 3.14);
        assert_eq!(obj.get_schema_version(), 1);
    }

    #[test]
    fn test_is_upgradeable() {
        let obj = SimpleSaveable::new(42, 3.14);
        assert!(obj.is_upgradeable(1));
        assert!(obj.is_upgradeable(0));
        assert!(!obj.is_upgradeable(2));
    }

    #[test]
    fn test_save_and_restore() {
        let mut original = SimpleSaveable::new(42, 3.14);
        let mut storage = TestStorage::new();
        original.save(&mut storage);

        let mut restored = SimpleSaveable::new(0, 0.0);
        let mut restore_storage = TestStorage::from_data(vec!["int:42".to_string(), "float:3.14".to_string()]);
        restored.restore(&mut restore_storage);

        assert_eq!(restored.int_field, 42);
        assert_eq!(restored.float_field, 3.14);
    }

    #[test]
    fn test_is_private() {
        let obj = SimpleSaveable::new(42, 3.14);
        assert!(!obj.is_private());
    }

    #[test]
    fn test_upgrade_from_older_version() {
        let mut obj = SimpleSaveable::new(0, 0.0);
        let mut old_storage = TestStorage::from_data(vec!["int:10".to_string(), "float:2.5".to_string()]);
        let mut new_storage = TestStorage::new();

        let success = obj.upgrade(&mut old_storage, 1, &mut new_storage);
        assert!(success);
        assert_eq!(obj.int_field, 10);
        assert_eq!(obj.float_field, 2.5);
    }

    #[test]
    fn test_upgrade_from_unsupported_version() {
        let mut obj = SimpleSaveable::new(0, 0.0);
        let mut old_storage = TestStorage::new();
        let mut new_storage = TestStorage::new();

        let success = obj.upgrade(&mut old_storage, 5, &mut new_storage);
        assert!(!success);
    }

    #[test]
    fn test_object_storage_field_type_equality() {
        assert_eq!(ObjectStorageFieldType::Int, ObjectStorageFieldType::Int);
        assert_ne!(ObjectStorageFieldType::Int, ObjectStorageFieldType::Float);
    }
}
