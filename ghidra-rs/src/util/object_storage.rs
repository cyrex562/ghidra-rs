/// Interface for sequentially saving and restoring primitives, strings, and their arrays.
///
/// Put operations must be called in the same order as the corresponding get operations.
///
/// Port of `ghidra.util.ObjectStorage`.
pub trait ObjectStorage {
    /// Store an `i32` value.
    fn put_int(&mut self, value: i32);
    /// Store an `i8` (Java `byte`) value.
    fn put_byte(&mut self, value: i8);
    /// Store an `i16` value.
    fn put_short(&mut self, value: i16);
    /// Store an `i64` value.
    fn put_long(&mut self, value: i64);
    /// Store a string value.
    fn put_string(&mut self, value: &str);
    /// Store a `bool` value.
    fn put_boolean(&mut self, value: bool);
    /// Store an `f32` value.
    fn put_float(&mut self, value: f32);
    /// Store an `f64` value.
    fn put_double(&mut self, value: f64);

    /// Retrieve an `i32` value.
    fn get_int(&mut self) -> i32;
    /// Retrieve an `i8` value.
    fn get_byte(&mut self) -> i8;
    /// Retrieve an `i16` value.
    fn get_short(&mut self) -> i16;
    /// Retrieve an `i64` value.
    fn get_long(&mut self) -> i64;
    /// Retrieve a `bool` value.
    fn get_boolean(&mut self) -> bool;
    /// Retrieve a string value.
    fn get_string(&mut self) -> String;
    /// Retrieve an `f32` value.
    fn get_float(&mut self) -> f32;
    /// Retrieve an `f64` value.
    fn get_double(&mut self) -> f64;

    /// Store a slice of `i32` values.
    fn put_ints(&mut self, value: &[i32]);
    /// Store a slice of `i8` values.
    fn put_bytes(&mut self, value: &[i8]);
    /// Store a slice of `i16` values.
    fn put_shorts(&mut self, value: &[i16]);
    /// Store a slice of `i64` values.
    fn put_longs(&mut self, value: &[i64]);
    /// Store a slice of `f32` values.
    fn put_floats(&mut self, value: &[f32]);
    /// Store a slice of `f64` values.
    fn put_doubles(&mut self, value: &[f64]);
    /// Store a slice of string values.
    fn put_strings(&mut self, value: &[&str]);

    /// Retrieve a `Vec<i32>`.
    fn get_ints(&mut self) -> Vec<i32>;
    /// Retrieve a `Vec<i8>`.
    fn get_bytes(&mut self) -> Vec<i8>;
    /// Retrieve a `Vec<i16>`.
    fn get_shorts(&mut self) -> Vec<i16>;
    /// Retrieve a `Vec<i64>`.
    fn get_longs(&mut self) -> Vec<i64>;
    /// Retrieve a `Vec<f32>`.
    fn get_floats(&mut self) -> Vec<f32>;
    /// Retrieve a `Vec<f64>`.
    fn get_doubles(&mut self) -> Vec<f64>;
    /// Retrieve a `Vec<String>`.
    fn get_strings(&mut self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    enum Entry {
        Int(i32),
        Byte(i8),
        Short(i16),
        Long(i64),
        Str(String),
        Bool(bool),
        Float(f32),
        Double(f64),
        Ints(Vec<i32>),
        Bytes(Vec<i8>),
        Shorts(Vec<i16>),
        Longs(Vec<i64>),
        Floats(Vec<f32>),
        Doubles(Vec<f64>),
        Strings(Vec<String>),
    }

    struct SimpleStorage {
        queue: VecDeque<Entry>,
    }

    impl SimpleStorage {
        fn new() -> Self {
            Self { queue: VecDeque::new() }
        }

        fn pop(&mut self) -> Entry {
            self.queue.pop_front().expect("storage underflow")
        }
    }

    impl ObjectStorage for SimpleStorage {
        fn put_int(&mut self, v: i32) { self.queue.push_back(Entry::Int(v)); }
        fn put_byte(&mut self, v: i8) { self.queue.push_back(Entry::Byte(v)); }
        fn put_short(&mut self, v: i16) { self.queue.push_back(Entry::Short(v)); }
        fn put_long(&mut self, v: i64) { self.queue.push_back(Entry::Long(v)); }
        fn put_string(&mut self, v: &str) { self.queue.push_back(Entry::Str(v.to_owned())); }
        fn put_boolean(&mut self, v: bool) { self.queue.push_back(Entry::Bool(v)); }
        fn put_float(&mut self, v: f32) { self.queue.push_back(Entry::Float(v)); }
        fn put_double(&mut self, v: f64) { self.queue.push_back(Entry::Double(v)); }

        fn get_int(&mut self) -> i32 { if let Entry::Int(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_byte(&mut self) -> i8 { if let Entry::Byte(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_short(&mut self) -> i16 { if let Entry::Short(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_long(&mut self) -> i64 { if let Entry::Long(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_boolean(&mut self) -> bool { if let Entry::Bool(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_string(&mut self) -> String { if let Entry::Str(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_float(&mut self) -> f32 { if let Entry::Float(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_double(&mut self) -> f64 { if let Entry::Double(v) = self.pop() { v } else { panic!("type mismatch") } }

        fn put_ints(&mut self, v: &[i32]) { self.queue.push_back(Entry::Ints(v.to_vec())); }
        fn put_bytes(&mut self, v: &[i8]) { self.queue.push_back(Entry::Bytes(v.to_vec())); }
        fn put_shorts(&mut self, v: &[i16]) { self.queue.push_back(Entry::Shorts(v.to_vec())); }
        fn put_longs(&mut self, v: &[i64]) { self.queue.push_back(Entry::Longs(v.to_vec())); }
        fn put_floats(&mut self, v: &[f32]) { self.queue.push_back(Entry::Floats(v.to_vec())); }
        fn put_doubles(&mut self, v: &[f64]) { self.queue.push_back(Entry::Doubles(v.to_vec())); }
        fn put_strings(&mut self, v: &[&str]) {
            self.queue.push_back(Entry::Strings(v.iter().map(|s| s.to_string()).collect()));
        }

        fn get_ints(&mut self) -> Vec<i32> { if let Entry::Ints(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_bytes(&mut self) -> Vec<i8> { if let Entry::Bytes(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_shorts(&mut self) -> Vec<i16> { if let Entry::Shorts(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_longs(&mut self) -> Vec<i64> { if let Entry::Longs(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_floats(&mut self) -> Vec<f32> { if let Entry::Floats(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_doubles(&mut self) -> Vec<f64> { if let Entry::Doubles(v) = self.pop() { v } else { panic!("type mismatch") } }
        fn get_strings(&mut self) -> Vec<String> { if let Entry::Strings(v) = self.pop() { v } else { panic!("type mismatch") } }
    }

    #[test]
    fn roundtrip_scalars() {
        let mut s = SimpleStorage::new();
        s.put_int(42);
        s.put_byte(-1);
        s.put_short(1000);
        s.put_long(i64::MAX);
        s.put_string("hello");
        s.put_boolean(true);
        s.put_float(1.5);
        s.put_double(3.14);

        assert_eq!(s.get_int(), 42);
        assert_eq!(s.get_byte(), -1);
        assert_eq!(s.get_short(), 1000);
        assert_eq!(s.get_long(), i64::MAX);
        assert_eq!(s.get_string(), "hello");
        assert!(s.get_boolean());
        assert_eq!(s.get_float(), 1.5_f32);
        assert_eq!(s.get_double(), 3.14_f64);
    }

    #[test]
    fn roundtrip_arrays() {
        let mut s = SimpleStorage::new();
        s.put_ints(&[1, 2, 3]);
        s.put_bytes(&[-128, 0, 127]);
        s.put_shorts(&[100, 200]);
        s.put_longs(&[i64::MIN, i64::MAX]);
        s.put_floats(&[0.1, 0.2]);
        s.put_doubles(&[1.1, 2.2]);
        s.put_strings(&["foo", "bar"]);

        assert_eq!(s.get_ints(), vec![1, 2, 3]);
        assert_eq!(s.get_bytes(), vec![-128_i8, 0, 127]);
        assert_eq!(s.get_shorts(), vec![100_i16, 200]);
        assert_eq!(s.get_longs(), vec![i64::MIN, i64::MAX]);
        assert_eq!(s.get_floats(), vec![0.1_f32, 0.2]);
        assert_eq!(s.get_doubles(), vec![1.1_f64, 2.2]);
        assert_eq!(s.get_strings(), vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn empty_arrays() {
        let mut s = SimpleStorage::new();
        s.put_ints(&[]);
        s.put_strings(&[]);
        assert_eq!(s.get_ints(), Vec::<i32>::new());
        assert_eq!(s.get_strings(), Vec::<String>::new());
    }

    #[test]
    fn ordering_preserved() {
        let mut s = SimpleStorage::new();
        s.put_int(1);
        s.put_int(2);
        s.put_int(3);
        assert_eq!(s.get_int(), 1);
        assert_eq!(s.get_int(), 2);
        assert_eq!(s.get_int(), 3);
    }

    #[test]
    #[should_panic(expected = "storage underflow")]
    fn get_from_empty_panics() {
        let mut s = SimpleStorage::new();
        s.get_int();
    }

    #[test]
    fn trait_object_usage() {
        let mut s: Box<dyn ObjectStorage> = Box::new(SimpleStorage::new());
        s.put_boolean(false);
        assert!(!s.get_boolean());
    }
}
