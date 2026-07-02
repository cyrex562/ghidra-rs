use crate::util::Saveable;

/// A trait for objects that signal their changes should not be broadcast.
///
/// Types implementing this trait indicate they are not meant to broadcast their changes
/// to change listeners. This is useful for internal or temporary saveables that shouldn't
/// trigger UI updates or external notifications.
///
/// Port of `ghidra.util.PrivateSaveable`.
pub trait PrivateSaveable: Saveable {
    fn is_private(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{ObjectStorage, ObjectStorageFieldType};

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

        /// Returns the portion of a stored `"type:value"` entry after the `:`.
        fn suffix(entry: &str) -> &str {
            entry.split_once(':').map(|(_, v)| v).unwrap_or(entry)
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
            Self::suffix(&self.data[self.index - 1]).parse().unwrap_or(0)
        }

        fn get_byte(&mut self) -> i8 {
            self.index += 1;
            Self::suffix(&self.data[self.index - 1]).parse().unwrap_or(0)
        }

        fn get_short(&mut self) -> i16 {
            self.index += 1;
            Self::suffix(&self.data[self.index - 1]).parse().unwrap_or(0)
        }

        fn get_long(&mut self) -> i64 {
            self.index += 1;
            Self::suffix(&self.data[self.index - 1]).parse().unwrap_or(0)
        }

        fn get_boolean(&mut self) -> bool {
            self.index += 1;
            self.data[self.index - 1].contains("true")
        }

        fn get_string(&mut self) -> String {
            self.index += 1;
            Self::suffix(&self.data[self.index - 1]).to_string()
        }

        fn get_float(&mut self) -> f32 {
            self.index += 1;
            Self::suffix(&self.data[self.index - 1]).parse().unwrap_or(0.0)
        }

        fn get_double(&mut self) -> f64 {
            self.index += 1;
            Self::suffix(&self.data[self.index - 1]).parse().unwrap_or(0.0)
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

    struct SimplePrivateSaveable {
        data: String,
        schema_version: i32,
    }

    impl SimplePrivateSaveable {
        fn new(data: String) -> Self {
            SimplePrivateSaveable {
                data,
                schema_version: 1,
            }
        }
    }

    impl Saveable for SimplePrivateSaveable {
        fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
            vec![ObjectStorageFieldType::String]
        }

        fn save(&self, obj_storage: &mut dyn ObjectStorage) {
            obj_storage.put_string(&self.data);
        }

        fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
            self.data = obj_storage.get_string();
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

    impl PrivateSaveable for SimplePrivateSaveable {}

    #[test]
    fn private_saveable_is_private() {
        let obj = SimplePrivateSaveable::new("test".to_string());
        assert!(PrivateSaveable::is_private(&obj));
    }

    #[test]
    fn private_saveable_maintains_saveable_behavior() {
        let mut original = SimplePrivateSaveable::new("hello".to_string());
        let mut storage = TestStorage::new();
        original.save(&mut storage);

        let mut restored = SimplePrivateSaveable::new(String::new());
        let mut restore_storage = TestStorage::from_data(vec!["string:hello".to_string()]);
        restored.restore(&mut restore_storage);

        assert_eq!(restored.data, "hello");
        assert!(PrivateSaveable::is_private(&restored));
    }

    #[test]
    fn multiple_private_saveables_all_private() {
        let obj1 = SimplePrivateSaveable::new("obj1".to_string());
        let obj2 = SimplePrivateSaveable::new("obj2".to_string());

        assert!(PrivateSaveable::is_private(&obj1));
        assert!(PrivateSaveable::is_private(&obj2));
    }
}
