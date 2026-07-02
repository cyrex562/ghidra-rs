use crate::util::{ObjectStorage, ObjectStorageFieldType, Saveable};

/// Minimum capacity used by the Java class's zero-size-aware constructor.
///
/// Preserved for parity with the original API; has no observable effect since
/// the backing storage grows on demand.
pub const MIN_SIZE: usize = 4;

/// An ArrayList type object for `i32` values.
///
/// Port of `ghidra.util.datastruct.IntArrayList`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntArrayList {
    ints: Vec<i32>,
}

impl IntArrayList {
    /// Creates a new, empty `IntArrayList`.
    pub fn new() -> Self {
        Self { ints: Vec::with_capacity(MIN_SIZE) }
    }

    /// Creates a new, empty `IntArrayList`, optionally starting with zero capacity.
    pub fn with_zero_size(use_zero_size: bool) -> Self {
        if use_zero_size {
            Self { ints: Vec::new() }
        } else {
            Self::new()
        }
    }

    /// Creates a new `IntArrayList` using the values in `arr` as its initial contents.
    pub fn from_array(arr: Vec<i32>) -> Self {
        Self { ints: arr }
    }

    /// Adds `value` at the end of the list.
    pub fn add(&mut self, value: i32) {
        self.ints.push(value);
    }

    /// Inserts `value` at `index`, shifting subsequent elements to the right.
    ///
    /// # Panics
    /// Panics if `index > size()`.
    pub fn insert(&mut self, index: usize, value: i32) {
        assert!(index <= self.ints.len(), "index out of bounds");
        self.ints.insert(index, value);
    }

    /// Removes the value at `index`, decreasing the list size by 1.
    ///
    /// # Panics
    /// Panics if `index >= size()`.
    pub fn remove_value_at(&mut self, index: usize) {
        assert!(index < self.ints.len(), "index out of bounds");
        self.ints.remove(index);
    }

    /// Removes the first occurrence of `value`, if present.
    pub fn remove_value(&mut self, value: i32) {
        if let Some(pos) = self.ints.iter().position(|&v| v == value) {
            self.ints.remove(pos);
        }
    }

    /// Returns the value at `index`.
    ///
    /// # Panics
    /// Panics if `index >= size()`.
    pub fn get(&self, index: usize) -> i32 {
        self.ints[index]
    }

    /// Sets the value at `index` to `value`.
    ///
    /// # Panics
    /// Panics if `index >= size()`.
    pub fn set(&mut self, index: usize, value: i32) {
        assert!(index < self.ints.len(), "index out of bounds");
        self.ints[index] = value;
    }

    /// Clears all values from the list.
    pub fn clear(&mut self) {
        self.ints.clear();
    }

    /// Returns the number of values in the list.
    pub fn size(&self) -> usize {
        self.ints.len()
    }

    /// Returns `true` if the list contains no values.
    pub fn is_empty(&self) -> bool {
        self.ints.is_empty()
    }

    /// Returns a copy of the list's contents as a `Vec<i32>`.
    pub fn to_array(&self) -> Vec<i32> {
        self.ints.clone()
    }
}

impl Saveable for IntArrayList {
    fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
        vec![ObjectStorageFieldType::Ints]
    }

    fn save(&self, obj_storage: &mut dyn ObjectStorage) {
        obj_storage.put_ints(&self.ints);
    }

    fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
        self.ints = obj_storage.get_ints();
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

#[cfg(test)]
mod tests {
    use super::*;

    struct IntsOnlyStorage {
        ints: Vec<i32>,
    }

    impl ObjectStorage for IntsOnlyStorage {
        fn put_int(&mut self, _value: i32) {
            unreachable!("not used by IntArrayList")
        }
        fn put_byte(&mut self, _value: i8) {
            unreachable!("not used by IntArrayList")
        }
        fn put_short(&mut self, _value: i16) {
            unreachable!("not used by IntArrayList")
        }
        fn put_long(&mut self, _value: i64) {
            unreachable!("not used by IntArrayList")
        }
        fn put_string(&mut self, _value: &str) {
            unreachable!("not used by IntArrayList")
        }
        fn put_boolean(&mut self, _value: bool) {
            unreachable!("not used by IntArrayList")
        }
        fn put_float(&mut self, _value: f32) {
            unreachable!("not used by IntArrayList")
        }
        fn put_double(&mut self, _value: f64) {
            unreachable!("not used by IntArrayList")
        }
        fn get_int(&mut self) -> i32 {
            unreachable!("not used by IntArrayList")
        }
        fn get_byte(&mut self) -> i8 {
            unreachable!("not used by IntArrayList")
        }
        fn get_short(&mut self) -> i16 {
            unreachable!("not used by IntArrayList")
        }
        fn get_long(&mut self) -> i64 {
            unreachable!("not used by IntArrayList")
        }
        fn get_boolean(&mut self) -> bool {
            unreachable!("not used by IntArrayList")
        }
        fn get_string(&mut self) -> String {
            unreachable!("not used by IntArrayList")
        }
        fn get_float(&mut self) -> f32 {
            unreachable!("not used by IntArrayList")
        }
        fn get_double(&mut self) -> f64 {
            unreachable!("not used by IntArrayList")
        }
        fn put_ints(&mut self, value: &[i32]) {
            self.ints = value.to_vec();
        }
        fn put_bytes(&mut self, _value: &[i8]) {
            unreachable!("not used by IntArrayList")
        }
        fn put_shorts(&mut self, _value: &[i16]) {
            unreachable!("not used by IntArrayList")
        }
        fn put_longs(&mut self, _value: &[i64]) {
            unreachable!("not used by IntArrayList")
        }
        fn put_floats(&mut self, _value: &[f32]) {
            unreachable!("not used by IntArrayList")
        }
        fn put_doubles(&mut self, _value: &[f64]) {
            unreachable!("not used by IntArrayList")
        }
        fn put_strings(&mut self, _value: &[&str]) {
            unreachable!("not used by IntArrayList")
        }
        fn get_ints(&mut self) -> Vec<i32> {
            self.ints.clone()
        }
        fn get_bytes(&mut self) -> Vec<i8> {
            unreachable!("not used by IntArrayList")
        }
        fn get_shorts(&mut self) -> Vec<i16> {
            unreachable!("not used by IntArrayList")
        }
        fn get_longs(&mut self) -> Vec<i64> {
            unreachable!("not used by IntArrayList")
        }
        fn get_floats(&mut self) -> Vec<f32> {
            unreachable!("not used by IntArrayList")
        }
        fn get_doubles(&mut self) -> Vec<f64> {
            unreachable!("not used by IntArrayList")
        }
        fn get_strings(&mut self) -> Vec<String> {
            unreachable!("not used by IntArrayList")
        }
    }

    #[test]
    fn new_is_empty() {
        let list = IntArrayList::new();
        assert!(list.is_empty());
        assert_eq!(list.size(), 0);
    }

    #[test]
    fn with_zero_size_starts_empty() {
        let list = IntArrayList::with_zero_size(true);
        assert!(list.is_empty());
        let list = IntArrayList::with_zero_size(false);
        assert!(list.is_empty());
    }

    #[test]
    fn from_array_uses_given_values() {
        let list = IntArrayList::from_array(vec![1, 2, 3]);
        assert_eq!(list.size(), 3);
        assert_eq!(list.to_array(), vec![1, 2, 3]);
    }

    #[test]
    fn add_appends_to_end() {
        let mut list = IntArrayList::new();
        list.add(1);
        list.add(2);
        list.add(3);
        assert_eq!(list.to_array(), vec![1, 2, 3]);
    }

    #[test]
    fn insert_shifts_elements() {
        let mut list = IntArrayList::from_array(vec![1, 2, 4]);
        list.insert(2, 3);
        assert_eq!(list.to_array(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn insert_at_end_is_add() {
        let mut list = IntArrayList::from_array(vec![1, 2]);
        list.insert(2, 3);
        assert_eq!(list.to_array(), vec![1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn insert_past_end_panics() {
        let mut list = IntArrayList::from_array(vec![1, 2]);
        list.insert(3, 99);
    }

    #[test]
    fn remove_value_at_removes_and_shifts() {
        let mut list = IntArrayList::from_array(vec![1, 2, 3, 4]);
        list.remove_value_at(1);
        assert_eq!(list.to_array(), vec![1, 3, 4]);
        assert_eq!(list.size(), 3);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn remove_value_at_out_of_bounds_panics() {
        let mut list = IntArrayList::from_array(vec![1, 2]);
        list.remove_value_at(2);
    }

    #[test]
    fn remove_value_removes_first_occurrence_only() {
        let mut list = IntArrayList::from_array(vec![5, 3, 5, 3]);
        list.remove_value(5);
        assert_eq!(list.to_array(), vec![3, 5, 3]);
    }

    #[test]
    fn remove_value_missing_is_noop() {
        let mut list = IntArrayList::from_array(vec![1, 2, 3]);
        list.remove_value(99);
        assert_eq!(list.to_array(), vec![1, 2, 3]);
    }

    #[test]
    fn get_returns_value_at_index() {
        let list = IntArrayList::from_array(vec![10, 20, 30]);
        assert_eq!(list.get(1), 20);
    }

    #[test]
    #[should_panic]
    fn get_out_of_bounds_panics() {
        let list = IntArrayList::from_array(vec![10, 20]);
        list.get(5);
    }

    #[test]
    fn set_overwrites_value() {
        let mut list = IntArrayList::from_array(vec![1, 2, 3]);
        list.set(1, 99);
        assert_eq!(list.to_array(), vec![1, 99, 3]);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn set_out_of_bounds_panics() {
        let mut list = IntArrayList::from_array(vec![1, 2]);
        list.set(2, 99);
    }

    #[test]
    fn clear_empties_list() {
        let mut list = IntArrayList::from_array(vec![1, 2, 3]);
        list.clear();
        assert!(list.is_empty());
        assert_eq!(list.size(), 0);
    }

    #[test]
    fn to_array_returns_copy() {
        let mut list = IntArrayList::from_array(vec![1, 2, 3]);
        let arr = list.to_array();
        list.add(4);
        assert_eq!(arr, vec![1, 2, 3]);
        assert_eq!(list.to_array(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn saveable_round_trips_values() {
        let original = IntArrayList::from_array(vec![7, 8, 9]);
        let mut storage = IntsOnlyStorage { ints: Vec::new() };
        original.save(&mut storage);

        let mut restored = IntArrayList::new();
        restored.restore(&mut storage);
        assert_eq!(restored.to_array(), vec![7, 8, 9]);
    }

    #[test]
    fn saveable_metadata() {
        let list = IntArrayList::new();
        assert_eq!(list.get_object_storage_fields(), vec![ObjectStorageFieldType::Ints]);
        assert_eq!(list.get_schema_version(), 0);
        assert!(!list.is_upgradeable(0));
        assert!(!list.is_private());
    }
}
