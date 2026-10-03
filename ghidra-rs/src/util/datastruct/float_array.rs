use super::array::Array;
use super::data_table::DataTable;

/// Minimum backing-array capacity.
pub const MIN_SIZE: usize = 4;

/// An array of `f32` (Java `float`) that grows as needed.
///
/// Port of `ghidra.util.datastruct.FloatArray`. An index that was never
/// written (or was most recently `remove`d) reads back as `0.0`.
///
/// `FloatArray.java` is a near-identical clone of `IntArray`/`LongArray`
/// with the element type swapped to `float`; this port follows the same
/// shape as [`super::int_array::IntArray`]/[`super::long_array::LongArray`].
/// Since `f32` has no total order/no `Eq`, this type derives `PartialEq`
/// only (not `Eq`), unlike its integer siblings.
#[derive(Debug, Clone, PartialEq)]
pub struct FloatArray {
    floats: Vec<f32>,
    last_non_zero_index: i32,
}

impl FloatArray {
    /// Creates a new, empty `FloatArray`.
    pub fn new() -> Self {
        Self {
            floats: vec![0.0; MIN_SIZE],
            last_non_zero_index: -1,
        }
    }

    /// Puts `value` at `index`, growing the backing storage if necessary.
    ///
    /// Storing `0.0` is equivalent to calling [`Self::remove`].
    pub fn put(&mut self, index: usize, value: f32) {
        if value == 0.0 {
            self.remove(index);
            return;
        }

        if index >= self.floats.len() {
            self.adjust_array(std::cmp::max(index as i64 + 1, self.floats.len() as i64 * 2));
        }
        self.floats[index] = value;
        if index as i32 > self.last_non_zero_index {
            self.last_non_zero_index = index as i32;
        }
    }

    /// Sets the value at `index` to `0.0`. A no-op if `index` is beyond the
    /// current backing storage.
    pub fn remove(&mut self, index: usize) {
        if index >= self.floats.len() {
            return;
        }
        self.floats[index] = 0.0;
        if index as i32 == self.last_non_zero_index {
            self.last_non_zero_index = self.find_last_non_zero_index();
        }
        if self.last_non_zero_index < self.floats.len() as i32 / 4 {
            self.adjust_array(self.last_non_zero_index as i64 * 2);
        }
    }

    /// Finds the index of the last non-zero value, or `-1` if the array is empty.
    fn find_last_non_zero_index(&self) -> i32 {
        let mut i = self.last_non_zero_index;
        while i >= 0 {
            if self.floats[i as usize] != 0.0 {
                return i;
            }
            i -= 1;
        }
        -1
    }

    /// Returns the value at `index`. Returns `0.0` for any index not
    /// initialized to another value (including indexes past the end of the
    /// backing storage).
    pub fn get(&self, index: usize) -> f32 {
        if index < self.floats.len() {
            self.floats[index]
        } else {
            0.0
        }
    }

    /// Adjusts the capacity of the backing storage to `size`, clamped to a
    /// minimum of [`MIN_SIZE`]. `size` may be negative (mirroring Java's
    /// `int` parameter, since callers compute it from signed arithmetic);
    /// negative values simply clamp to `MIN_SIZE`.
    fn adjust_array(&mut self, size: i64) {
        let size = if size < MIN_SIZE as i64 { MIN_SIZE } else { size as usize };
        self.floats.resize(size, 0.0);
    }
}

impl Default for FloatArray {
    fn default() -> Self {
        Self::new()
    }
}

impl Array for FloatArray {
    fn remove(&mut self, index: usize) {
        FloatArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.last_non_zero_index
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        table.put_float(to_index, to_col, self.get(index));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockDataTable {
        floats: HashMap<(i32, i32), f32>,
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
        fn put_float(&mut self, row: i32, col: i32, value: f32) {
            self.floats.insert((row, col), value);
        }
        fn get_float(&self, row: i32, col: i32) -> f32 {
            *self.floats.get(&(row, col)).unwrap_or(&0.0)
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
        let arr = FloatArray::new();
        assert_eq!(arr.get(0), 0.0);
        assert_eq!(arr.get(1000), 0.0);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut arr = FloatArray::new();
        arr.put(2, 42.5);
        assert_eq!(arr.get(2), 42.5);
        assert_eq!(arr.get_last_non_empty_index(), 2);
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = FloatArray::new();
        arr.put(100, 7.25);
        assert_eq!(arr.get(100), 7.25);
        assert_eq!(arr.get_last_non_empty_index(), 100);
        assert_eq!(arr.get(50), 0.0);
    }

    #[test]
    fn put_zero_is_equivalent_to_remove() {
        let mut arr = FloatArray::new();
        arr.put(1, 5.0);
        arr.put(1, 0.0);
        assert_eq!(arr.get(1), 0.0);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_updates_last_non_zero_index_to_new_max() {
        let mut arr = FloatArray::new();
        arr.put(1, 1.5);
        arr.put(3, 3.5);
        arr.remove(3);
        assert_eq!(arr.get_last_non_empty_index(), 1);
        assert_eq!(arr.get(3), 0.0);
    }

    #[test]
    fn remove_past_end_is_noop() {
        let mut arr = FloatArray::new();
        arr.remove(1000);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_shrinks_backing_storage() {
        let mut arr = FloatArray::new();
        arr.put(200, 1.0);
        arr.remove(200);
        arr.put(3, 9.0);
        assert_eq!(arr.get(3), 9.0);
    }

    #[test]
    fn negative_values_supported() {
        let mut arr = FloatArray::new();
        arr.put(0, -500.25);
        assert_eq!(arr.get(0), -500.25);
    }

    #[test]
    fn nan_is_never_treated_as_zero() {
        // Java: `value == 0` is false for NaN, so putting NaN stores it (does not remove).
        let mut arr = FloatArray::new();
        arr.put(0, f32::NAN);
        assert!(arr.get(0).is_nan());
        assert_eq!(arr.get_last_non_empty_index(), 0);
    }

    #[test]
    fn array_trait_copy_data_to_writes_float_column() {
        let mut arr = FloatArray::new();
        arr.put(0, 99.5);
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert_eq!(table.get_float(5, 1), 99.5);
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = FloatArray::new();
        arr.put(0, 1.0);
        Array::remove(&mut arr, 0);
        assert_eq!(arr.get(0), 0.0);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(FloatArray::default(), FloatArray::new());
    }
}
