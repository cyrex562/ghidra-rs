use super::array::Array;
use super::data_table::DataTable;

/// Minimum backing-array capacity.
pub const MIN_SIZE: usize = 4;

/// An array of `i16` (Java `short`) that grows as needed.
///
/// Port of `ghidra.util.datastruct.ShortArray`. An index that was never
/// written (or was most recently `remove`d) reads back as `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortArray {
    shorts: Vec<i16>,
    last_non_zero_index: i32,
}

impl ShortArray {
    /// Creates a new, empty `ShortArray`.
    pub fn new() -> Self {
        Self {
            shorts: vec![0; MIN_SIZE],
            last_non_zero_index: -1,
        }
    }

    /// Puts `value` at `index`, growing the backing storage if necessary.
    ///
    /// Storing `0` is equivalent to calling [`Self::remove`].
    pub fn put(&mut self, index: usize, value: i16) {
        if value == 0 {
            self.remove(index);
            return;
        }

        if index >= self.shorts.len() {
            self.adjust_array(std::cmp::max(index as i64 + 1, self.shorts.len() as i64 * 2));
        }
        self.shorts[index] = value;
        if index as i32 > self.last_non_zero_index {
            self.last_non_zero_index = index as i32;
        }
    }

    /// Sets the value at `index` to `0`. A no-op if `index` is beyond the
    /// current backing storage.
    pub fn remove(&mut self, index: usize) {
        if index >= self.shorts.len() {
            return;
        }
        self.shorts[index] = 0;
        if index as i32 == self.last_non_zero_index {
            self.last_non_zero_index = self.find_last_non_zero_index();
        }
        if self.last_non_zero_index < self.shorts.len() as i32 / 4 {
            self.adjust_array(self.last_non_zero_index as i64 * 2);
        }
    }

    /// Finds the index of the last non-zero value, or `-1` if the array is empty.
    fn find_last_non_zero_index(&self) -> i32 {
        let mut i = self.last_non_zero_index;
        while i >= 0 {
            if self.shorts[i as usize] != 0 {
                return i;
            }
            i -= 1;
        }
        -1
    }

    /// Returns the value at `index`. Returns `0` for any index not
    /// initialized to another value (including indexes past the end of the
    /// backing storage).
    pub fn get(&self, index: usize) -> i16 {
        if index < self.shorts.len() {
            self.shorts[index]
        } else {
            0
        }
    }

    /// Adjusts the capacity of the backing storage to `size`, clamped to a
    /// minimum of [`MIN_SIZE`]. `size` may be negative (mirroring Java's
    /// `int` parameter, since callers compute it from signed arithmetic);
    /// negative values simply clamp to `MIN_SIZE`.
    fn adjust_array(&mut self, size: i64) {
        let size = if size < MIN_SIZE as i64 { MIN_SIZE } else { size as usize };
        self.shorts.resize(size, 0);
    }
}

impl Default for ShortArray {
    fn default() -> Self {
        Self::new()
    }
}

impl Array for ShortArray {
    fn remove(&mut self, index: usize) {
        ShortArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.last_non_zero_index
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        table.put_short(to_index, to_col, self.get(index));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockDataTable {
        shorts: HashMap<(i32, i32), i16>,
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
        fn put_short(&mut self, row: i32, col: i32, value: i16) {
            self.shorts.insert((row, col), value);
        }
        fn get_short(&self, row: i32, col: i32) -> i16 {
            *self.shorts.get(&(row, col)).unwrap_or(&0)
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
        fn put_object(&mut self, _row: i32, _col: i32, _value: Box<dyn Any>) {}
        fn get_object(&self, _row: i32, _col: i32) -> &dyn Any {
            &()
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
    fn new_array_reads_back_zero() {
        let arr = ShortArray::new();
        assert_eq!(arr.get(0), 0);
        assert_eq!(arr.get(1000), 0);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut arr = ShortArray::new();
        arr.put(2, 4242);
        assert_eq!(arr.get(2), 4242);
        assert_eq!(arr.get_last_non_empty_index(), 2);
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = ShortArray::new();
        arr.put(100, 7);
        assert_eq!(arr.get(100), 7);
        assert_eq!(arr.get_last_non_empty_index(), 100);
        assert_eq!(arr.get(50), 0);
    }

    #[test]
    fn put_zero_is_equivalent_to_remove() {
        let mut arr = ShortArray::new();
        arr.put(1, 5);
        arr.put(1, 0);
        assert_eq!(arr.get(1), 0);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_updates_last_non_zero_index_to_new_max() {
        let mut arr = ShortArray::new();
        arr.put(1, 1);
        arr.put(3, 3);
        arr.remove(3);
        assert_eq!(arr.get_last_non_empty_index(), 1);
        assert_eq!(arr.get(3), 0);
    }

    #[test]
    fn remove_past_end_is_noop() {
        let mut arr = ShortArray::new();
        arr.remove(1000);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_shrinks_backing_storage() {
        let mut arr = ShortArray::new();
        arr.put(200, 1);
        arr.remove(200);
        arr.put(3, 9);
        assert_eq!(arr.get(3), 9);
    }

    #[test]
    fn negative_values_supported() {
        let mut arr = ShortArray::new();
        arr.put(0, -500);
        assert_eq!(arr.get(0), -500);
    }

    #[test]
    fn array_trait_copy_data_to_writes_short_column() {
        let mut arr = ShortArray::new();
        arr.put(0, 99);
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert_eq!(table.get_short(5, 1), 99);
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = ShortArray::new();
        arr.put(0, 1);
        Array::remove(&mut arr, 0);
        assert_eq!(arr.get(0), 0);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(ShortArray::default(), ShortArray::new());
    }
}
