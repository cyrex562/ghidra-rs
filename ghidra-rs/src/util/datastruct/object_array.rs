use super::array::Array;
use super::data_table::DataTable;

/// Minimum backing-array capacity.
pub const MIN_SIZE: usize = 4;

/// An array of `Option<T>` that grows as needed.
///
/// Port of `ghidra.util.datastruct.ObjectArray`. An index that was never
/// written (or was most recently `remove`d, or had `None` `put` into it)
/// reads back as `None` -- mirroring Java's `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectArray<T> {
    objs: Vec<Option<T>>,
    last_non_zero_index: i32,
}

impl<T> ObjectArray<T> {
    /// Creates a new `ObjectArray` with the default minimum capacity.
    pub fn new() -> Self {
        Self::with_capacity(MIN_SIZE)
    }

    /// Creates a new `ObjectArray` with at least the given initial capacity.
    /// Capacities below [`MIN_SIZE`] are rounded up to `MIN_SIZE`.
    pub fn with_capacity(size: usize) -> Self {
        let size = std::cmp::max(size, MIN_SIZE);
        Self {
            objs: (0..size).map(|_| None).collect(),
            last_non_zero_index: -1,
        }
    }

    /// Puts `value` at `index`, growing the backing storage if necessary.
    ///
    /// Passing `None` is equivalent to calling [`Self::remove`].
    pub fn put(&mut self, index: usize, value: Option<T>) {
        let Some(value) = value else {
            self.remove(index);
            return;
        };

        if index >= self.objs.len() {
            self.adjust_array(std::cmp::max(index as i64 + 1, self.objs.len() as i64 * 2));
        }
        self.objs[index] = Some(value);
        if index as i32 > self.last_non_zero_index {
            self.last_non_zero_index = index as i32;
        }
    }

    /// Sets the value at `index` to `None`. A no-op if `index` is beyond the
    /// current backing storage.
    pub fn remove(&mut self, index: usize) {
        if index >= self.objs.len() {
            return;
        }
        self.objs[index] = None;
        if index as i32 == self.last_non_zero_index {
            self.last_non_zero_index = self.find_last_non_zero_index();
        }
        if self.last_non_zero_index < self.objs.len() as i32 / 4 {
            self.adjust_array(self.last_non_zero_index as i64 * 2);
        }
    }

    fn find_last_non_zero_index(&self) -> i32 {
        let mut i = self.last_non_zero_index;
        while i >= 0 {
            if self.objs[i as usize].is_some() {
                return i;
            }
            i -= 1;
        }
        -1
    }

    /// Returns a reference to the value at `index`, or `None` if not
    /// initialized to another value (including indexes past the end of the
    /// backing storage).
    pub fn get(&self, index: usize) -> Option<&T> {
        self.objs.get(index).and_then(|o| o.as_ref())
    }

    /// Adjusts the capacity of the backing storage to `size`, clamped to a
    /// minimum of [`MIN_SIZE`]. `size` may be negative (mirroring Java's
    /// `int` parameter, since callers compute it from signed arithmetic);
    /// negative values simply clamp to `MIN_SIZE`.
    fn adjust_array(&mut self, size: i64) {
        let size = if size < MIN_SIZE as i64 { MIN_SIZE } else { size as usize };
        self.objs.resize_with(size, || None);
    }
}

impl<T> Default for ObjectArray<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + 'static> Array for ObjectArray<T> {
    fn remove(&mut self, index: usize) {
        ObjectArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.last_non_zero_index
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        match self.get(index) {
            Some(value) => table.put_object(to_index, to_col, Box::new(value.clone())),
            None => table.put_object(to_index, to_col, Box::new(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockDataTable {
        objects: HashMap<(i32, i32), Box<dyn Any>>,
    }

    impl DataTable for MockDataTable {
        fn remove_row(&mut self, _row: i32) {}
        fn copy_row_to(&self, _row: i32, _table: &mut dyn DataTable, _to_row: i32) {}
        fn put_boolean(&mut self, _row: i32, _col: i32, _value: bool) {}
        fn get_boolean(&self, _row: i32, _col: i32) -> bool {
            false
        }
        fn put_byte(&mut self, _row: i32, _col: i32, _value: i8) {}
        fn get_byte(&self, _row: i32, _col: i32) -> i8 {
            0
        }
        fn put_short(&mut self, _row: i32, _col: i32, _value: i16) {}
        fn get_short(&self, _row: i32, _col: i32) -> i16 {
            0
        }
        fn put_int(&mut self, _row: i32, _col: i32, _value: i32) {}
        fn get_int(&self, _row: i32, _col: i32) -> i32 {
            0
        }
        fn put_long(&mut self, _row: i32, _col: i32, _value: i64) {}
        fn get_long(&self, _row: i32, _col: i32) -> i64 {
            0
        }
        fn put_double(&mut self, _row: i32, _col: i32, _value: f64) {}
        fn get_double(&self, _row: i32, _col: i32) -> f64 {
            0.0
        }
        fn put_float(&mut self, _row: i32, _col: i32, _value: f32) {}
        fn get_float(&self, _row: i32, _col: i32) -> f32 {
            0.0
        }
        fn put_string(&mut self, _row: i32, _col: i32, _value: String) {}
        fn get_string(&self, _row: i32, _col: i32) -> String {
            String::new()
        }
        fn put_object(&mut self, row: i32, col: i32, value: Box<dyn Any>) {
            self.objects.insert((row, col), value);
        }
        fn get_object(&self, row: i32, col: i32) -> &dyn Any {
            self.objects
                .get(&(row, col))
                .map(|b| b.as_ref())
                .unwrap_or(&())
        }
        fn put_byte_array(&mut self, _row: i32, _col: i32, _value: Vec<u8>) {}
        fn get_byte_array(&self, _row: i32, _col: i32) -> Vec<u8> {
            Vec::new()
        }
        fn put_short_array(&mut self, _row: i32, _col: i32, _value: Vec<i16>) {}
        fn get_short_array(&self, _row: i32, _col: i32) -> Vec<i16> {
            Vec::new()
        }
        fn put_int_array(&mut self, _row: i32, _col: i32, _value: Vec<i32>) {}
        fn get_int_array(&self, _row: i32, _col: i32) -> Vec<i32> {
            Vec::new()
        }
        fn put_long_array(&mut self, _row: i32, _col: i32, _value: Vec<i64>) {}
        fn get_long_array(&self, _row: i32, _col: i32) -> Vec<i64> {
            Vec::new()
        }
        fn put_float_array(&mut self, _row: i32, _col: i32, _value: Vec<f32>) {}
        fn get_float_array(&self, _row: i32, _col: i32) -> Vec<f32> {
            Vec::new()
        }
        fn put_double_array(&mut self, _row: i32, _col: i32, _value: Vec<f64>) {}
        fn get_double_array(&self, _row: i32, _col: i32) -> Vec<f64> {
            Vec::new()
        }
        fn put_string_array(&mut self, _row: i32, _col: i32, _value: Vec<String>) {}
        fn get_string_array(&self, _row: i32, _col: i32) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn new_array_reads_back_none() {
        let arr: ObjectArray<String> = ObjectArray::new();
        assert_eq!(arr.get(0), None);
        assert_eq!(arr.get(1000), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn with_capacity_rounds_up_to_min_size() {
        let arr: ObjectArray<i32> = ObjectArray::with_capacity(1);
        assert_eq!(arr.objs.len(), MIN_SIZE);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut arr = ObjectArray::new();
        arr.put(2, Some("hello".to_string()));
        assert_eq!(arr.get(2), Some(&"hello".to_string()));
        assert_eq!(arr.get_last_non_empty_index(), 2);
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = ObjectArray::new();
        arr.put(100, Some(7));
        assert_eq!(arr.get(100), Some(&7));
        assert_eq!(arr.get_last_non_empty_index(), 100);
        assert_eq!(arr.get(50), None);
    }

    #[test]
    fn put_none_is_equivalent_to_remove() {
        let mut arr = ObjectArray::new();
        arr.put(1, Some(5));
        arr.put(1, None);
        assert_eq!(arr.get(1), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_updates_last_non_zero_index_to_new_max() {
        let mut arr = ObjectArray::new();
        arr.put(1, Some("a"));
        arr.put(3, Some("b"));
        arr.remove(3);
        assert_eq!(arr.get_last_non_empty_index(), 1);
        assert_eq!(arr.get(3), None);
    }

    #[test]
    fn remove_past_end_is_noop() {
        let mut arr: ObjectArray<i32> = ObjectArray::new();
        arr.remove(1000);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_shrinks_backing_storage() {
        let mut arr = ObjectArray::new();
        arr.put(200, Some(1));
        arr.remove(200);
        arr.put(3, Some(9));
        assert_eq!(arr.get(3), Some(&9));
    }

    #[test]
    fn array_trait_copy_data_to_writes_object_column() {
        let mut arr: ObjectArray<i32> = ObjectArray::new();
        arr.put(0, Some(99));
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        let stored = table.get_object(5, 1).downcast_ref::<i32>();
        assert_eq!(stored, Some(&99));
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = ObjectArray::new();
        arr.put(0, Some(1));
        Array::remove(&mut arr, 0);
        assert_eq!(arr.get(0), None);
    }

    #[test]
    fn default_matches_new() {
        let a: ObjectArray<i32> = ObjectArray::default();
        let b: ObjectArray<i32> = ObjectArray::new();
        assert_eq!(a, b);
    }
}
