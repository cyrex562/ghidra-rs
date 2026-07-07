use crate::util::{ObjectStorage, ObjectStorageFieldType, Saveable};

/// A simple [`Saveable`] implementation exercising every primitive and array type supported by
/// [`ObjectStorage`], used to test property map round-tripping.
///
/// Port of `ghidra.program.database.properties.TestSaveable`.
#[derive(Debug, Clone, Default)]
pub struct TestSaveable {
    pub boolean_value: bool,
    pub byte_value: i8,
    pub short_value: i16,
    pub int_value: i32,
    pub long_value: i64,
    pub float_value: f32,
    pub double_value: f64,
    pub str_value: String,
    pub byte_values: Vec<i8>,
    pub short_values: Vec<i16>,
    pub int_values: Vec<i32>,
    pub long_values: Vec<i64>,
    pub float_values: Vec<f32>,
    pub double_values: Vec<f64>,
    pub str_values: Vec<String>,
}

impl TestSaveable {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Saveable for TestSaveable {
    fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
        // Mirrors the Java implementation's empty `fields` array; not used by the tests.
        Vec::new()
    }

    fn save(&self, obj_storage: &mut dyn ObjectStorage) {
        obj_storage.put_boolean(self.boolean_value);
        obj_storage.put_byte(self.byte_value);
        obj_storage.put_short(self.short_value);
        obj_storage.put_int(self.int_value);
        obj_storage.put_long(self.long_value);
        obj_storage.put_float(self.float_value);
        obj_storage.put_double(self.double_value);
        obj_storage.put_string(&self.str_value);
        obj_storage.put_bytes(&self.byte_values);
        obj_storage.put_shorts(&self.short_values);
        obj_storage.put_ints(&self.int_values);
        obj_storage.put_longs(&self.long_values);
        obj_storage.put_floats(&self.float_values);
        obj_storage.put_doubles(&self.double_values);
        let str_refs: Vec<&str> = self.str_values.iter().map(String::as_str).collect();
        obj_storage.put_strings(&str_refs);
    }

    fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
        self.boolean_value = obj_storage.get_boolean();
        self.byte_value = obj_storage.get_byte();
        self.short_value = obj_storage.get_short();
        self.int_value = obj_storage.get_int();
        self.long_value = obj_storage.get_long();
        self.float_value = obj_storage.get_float();
        self.double_value = obj_storage.get_double();
        self.str_value = obj_storage.get_string();
        self.byte_values = obj_storage.get_bytes();
        self.short_values = obj_storage.get_shorts();
        self.int_values = obj_storage.get_ints();
        self.long_values = obj_storage.get_longs();
        self.float_values = obj_storage.get_floats();
        self.double_values = obj_storage.get_doubles();
        self.str_values = obj_storage.get_strings();
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

impl PartialEq for TestSaveable {
    fn eq(&self, other: &Self) -> bool {
        self.boolean_value == other.boolean_value
            && self.byte_value == other.byte_value
            && self.byte_values == other.byte_values
            && self.double_value.to_bits() == other.double_value.to_bits()
            && self.double_values == other.double_values
            && self.float_value.to_bits() == other.float_value.to_bits()
            && self.float_values == other.float_values
            && self.int_value == other.int_value
            && self.int_values == other.int_values
            && self.long_value == other.long_value
            && self.long_values == other.long_values
            && self.short_value == other.short_value
            && self.short_values == other.short_values
            && self.str_value == other.str_value
            && self.str_values == other.str_values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    enum Entry {
        Bool(bool),
        Byte(i8),
        Short(i16),
        Int(i32),
        Long(i64),
        Float(f32),
        Double(f64),
        Str(String),
        Bytes(Vec<i8>),
        Shorts(Vec<i16>),
        Ints(Vec<i32>),
        Longs(Vec<i64>),
        Floats(Vec<f32>),
        Doubles(Vec<f64>),
        Strings(Vec<String>),
    }

    struct QueueStorage {
        queue: VecDeque<Entry>,
    }

    impl QueueStorage {
        fn new() -> Self {
            Self { queue: VecDeque::new() }
        }

        fn pop(&mut self) -> Entry {
            self.queue.pop_front().expect("storage underflow")
        }
    }

    impl ObjectStorage for QueueStorage {
        fn put_int(&mut self, value: i32) {
            self.queue.push_back(Entry::Int(value));
        }
        fn put_byte(&mut self, value: i8) {
            self.queue.push_back(Entry::Byte(value));
        }
        fn put_short(&mut self, value: i16) {
            self.queue.push_back(Entry::Short(value));
        }
        fn put_long(&mut self, value: i64) {
            self.queue.push_back(Entry::Long(value));
        }
        fn put_string(&mut self, value: &str) {
            self.queue.push_back(Entry::Str(value.to_owned()));
        }
        fn put_boolean(&mut self, value: bool) {
            self.queue.push_back(Entry::Bool(value));
        }
        fn put_float(&mut self, value: f32) {
            self.queue.push_back(Entry::Float(value));
        }
        fn put_double(&mut self, value: f64) {
            self.queue.push_back(Entry::Double(value));
        }

        fn get_int(&mut self) -> i32 {
            if let Entry::Int(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_byte(&mut self) -> i8 {
            if let Entry::Byte(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_short(&mut self) -> i16 {
            if let Entry::Short(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_long(&mut self) -> i64 {
            if let Entry::Long(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_boolean(&mut self) -> bool {
            if let Entry::Bool(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_string(&mut self) -> String {
            if let Entry::Str(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_float(&mut self) -> f32 {
            if let Entry::Float(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_double(&mut self) -> f64 {
            if let Entry::Double(v) = self.pop() { v } else { panic!("type mismatch") }
        }

        fn put_ints(&mut self, value: &[i32]) {
            self.queue.push_back(Entry::Ints(value.to_vec()));
        }
        fn put_bytes(&mut self, value: &[i8]) {
            self.queue.push_back(Entry::Bytes(value.to_vec()));
        }
        fn put_shorts(&mut self, value: &[i16]) {
            self.queue.push_back(Entry::Shorts(value.to_vec()));
        }
        fn put_longs(&mut self, value: &[i64]) {
            self.queue.push_back(Entry::Longs(value.to_vec()));
        }
        fn put_floats(&mut self, value: &[f32]) {
            self.queue.push_back(Entry::Floats(value.to_vec()));
        }
        fn put_doubles(&mut self, value: &[f64]) {
            self.queue.push_back(Entry::Doubles(value.to_vec()));
        }
        fn put_strings(&mut self, value: &[&str]) {
            self.queue
                .push_back(Entry::Strings(value.iter().map(|s| s.to_string()).collect()));
        }

        fn get_ints(&mut self) -> Vec<i32> {
            if let Entry::Ints(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_bytes(&mut self) -> Vec<i8> {
            if let Entry::Bytes(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_shorts(&mut self) -> Vec<i16> {
            if let Entry::Shorts(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_longs(&mut self) -> Vec<i64> {
            if let Entry::Longs(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_floats(&mut self) -> Vec<f32> {
            if let Entry::Floats(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_doubles(&mut self) -> Vec<f64> {
            if let Entry::Doubles(v) = self.pop() { v } else { panic!("type mismatch") }
        }
        fn get_strings(&mut self) -> Vec<String> {
            if let Entry::Strings(v) = self.pop() { v } else { panic!("type mismatch") }
        }
    }

    fn sample() -> TestSaveable {
        TestSaveable {
            boolean_value: true,
            byte_value: -5,
            short_value: 1000,
            int_value: 42,
            long_value: i64::MAX,
            float_value: 1.5,
            double_value: 3.14,
            str_value: "hello".to_string(),
            byte_values: vec![1, -2, 3],
            short_values: vec![10, 20],
            int_values: vec![100, 200, 300],
            long_values: vec![i64::MIN, i64::MAX],
            float_values: vec![0.1, 0.2],
            double_values: vec![1.1, 2.2],
            str_values: vec!["a".to_string(), "b".to_string()],
        }
    }

    #[test]
    fn default_is_zeroed() {
        let obj = TestSaveable::new();
        assert!(!obj.boolean_value);
        assert_eq!(obj.int_value, 0);
        assert_eq!(obj.str_value, "");
        assert!(obj.byte_values.is_empty());
    }

    #[test]
    fn get_object_storage_fields_is_empty() {
        let obj = TestSaveable::new();
        assert!(obj.get_object_storage_fields().is_empty());
    }

    #[test]
    fn save_and_restore_round_trips_all_fields() {
        let original = sample();
        let mut storage = QueueStorage::new();
        original.save(&mut storage);

        let mut restored = TestSaveable::new();
        restored.restore(&mut storage);

        assert_eq!(original, restored);
    }

    #[test]
    fn equals_and_not_equals() {
        let a = sample();
        let mut b = sample();
        assert_eq!(a, b);

        b.int_value += 1;
        assert_ne!(a, b);
    }

    #[test]
    fn schema_version_and_upgrade() {
        let mut obj = TestSaveable::new();
        assert_eq!(obj.get_schema_version(), 0);
        assert!(!obj.is_upgradeable(0));
        assert!(!obj.is_upgradeable(-1));

        let mut old_storage = QueueStorage::new();
        let mut new_storage = QueueStorage::new();
        assert!(!obj.upgrade(&mut old_storage, 0, &mut new_storage));
    }

    #[test]
    fn is_not_private() {
        let obj = TestSaveable::new();
        assert!(!obj.is_private());
    }
}
