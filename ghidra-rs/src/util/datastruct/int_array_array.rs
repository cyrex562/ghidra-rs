use super::array::Array;
use super::data_table::DataTable;
use super::packed_array::PackedArrayArray;

/// An array of `Vec<i32>` (Java `int[]`) that grows as needed.
///
/// Port of `ghidra.util.datastruct.IntArrayArray`. Backed by
/// [`PackedArrayArray`], which also backs the other `*ArrayArray` element
/// types; see that module's docs for the Java quirks reproduced here (an
/// off-by-one `get` bounds check, and a `short`-overflow bug for slices
/// longer than `i16::MAX` elements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntArrayArray {
    inner: PackedArrayArray<i32>,
}

impl IntArrayArray {
    /// Creates a new, empty `IntArrayArray`.
    pub fn new() -> Self {
        Self { inner: PackedArrayArray::new() }
    }

    /// Puts `value` at `index`, growing the backing storage if necessary.
    /// Passing `None` is equivalent to calling [`Self::remove`].
    pub fn put(&mut self, index: usize, value: Option<&[i32]>) {
        self.inner.put(index, value);
    }

    /// Returns a copy of the `i32` slice stored at `index`, or `None` if not
    /// initialized to another value.
    ///
    /// # Panics
    /// See [`PackedArrayArray::get`] for the two faithfully-reproduced Java
    /// bugs this can panic on.
    pub fn get(&self, index: usize) -> Option<Vec<i32>> {
        self.inner.get(index)
    }

    /// Removes the array at `index`.
    pub fn remove(&mut self, index: usize) {
        self.inner.remove(index);
    }
}

impl Default for IntArrayArray {
    fn default() -> Self {
        Self::new()
    }
}

impl Array for IntArrayArray {
    fn remove(&mut self, index: usize) {
        IntArrayArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.inner.last_non_empty_index()
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        table.put_int_array(to_index, to_col, self.get(index).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;
    use std::panic::{self, AssertUnwindSafe};

    #[derive(Default)]
    struct MockDataTable {
        int_arrays: HashMap<(i32, i32), Vec<i32>>,
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
        fn put_int_array(&mut self, row: i32, col: i32, value: Vec<i32>) {
            self.int_arrays.insert((row, col), value);
        }
        fn get_int_array(&self, row: i32, col: i32) -> Vec<i32> {
            self.int_arrays.get(&(row, col)).cloned().unwrap_or_default()
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
        let arr = IntArrayArray::new();
        assert_eq!(arr.get(0), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut arr = IntArrayArray::new();
        arr.put(1, Some(&[1, 2, 3]));
        assert_eq!(arr.get(1), Some(vec![1, 2, 3]));
        assert_eq!(arr.get_last_non_empty_index(), 1);
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = IntArrayArray::new();
        arr.put(50, Some(&[7, 8]));
        assert_eq!(arr.get(50), Some(vec![7, 8]));
        assert_eq!(arr.get_last_non_empty_index(), 50);
        assert_eq!(arr.get(25), None);
    }

    #[test]
    fn overwrite_with_shorter_array_reuses_space() {
        let mut arr = IntArrayArray::new();
        arr.put(0, Some(&[1, 2, 3, 4, 5]));
        arr.put(0, Some(&[9, 9]));
        assert_eq!(arr.get(0), Some(vec![9, 9]));
    }

    #[test]
    fn overwrite_with_longer_array_reallocates() {
        let mut arr = IntArrayArray::new();
        arr.put(0, Some(&[1]));
        arr.put(0, Some(&[1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(arr.get(0), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn put_empty_slice_stores_empty_array_not_none() {
        let mut arr = IntArrayArray::new();
        arr.put(0, Some(&[]));
        assert_eq!(arr.get(0), Some(vec![]));
    }

    #[test]
    fn put_none_is_equivalent_to_remove() {
        let mut arr = IntArrayArray::new();
        arr.put(1, Some(&[1, 2]));
        arr.put(1, None);
        assert_eq!(arr.get(1), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_updates_last_non_empty_index_to_new_max() {
        let mut arr = IntArrayArray::new();
        arr.put(1, Some(&[1]));
        arr.put(3, Some(&[2]));
        arr.remove(3);
        assert_eq!(arr.get_last_non_empty_index(), 1);
        assert_eq!(arr.get(3), None);
    }

    #[test]
    fn remove_past_end_is_noop() {
        let mut arr = IntArrayArray::new();
        arr.remove(1000);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_and_reinsert_many_entries() {
        let mut arr = IntArrayArray::new();
        for i in 0..50usize {
            arr.put(i, Some(&[i as i32, (i * 2) as i32]));
        }
        for i in (0..50usize).step_by(2) {
            arr.remove(i);
        }
        for i in 0..50usize {
            if i % 2 == 0 {
                assert_eq!(arr.get(i), None);
            } else {
                assert_eq!(arr.get(i), Some(vec![i as i32, (i * 2) as i32]));
            }
        }
    }

    /// Faithfully reproduces the off-by-one bounds check in
    /// `Xxx.get(int)` (see `packed_array` module docs): the check is
    /// `index <= starts.length`, so `get(starts.length)` slips past the
    /// guard and then indexes out of bounds, throwing
    /// `ArrayIndexOutOfBoundsException` in Java. We verify the panic occurs
    /// specifically inside `get`, not merely somewhere in the test.
    #[test]
    fn get_at_exact_capacity_panics_due_to_off_by_one_bug() {
        let arr = IntArrayArray::new(); // starts.len() == MIN_SIZE == 4
        let result = panic::catch_unwind(AssertUnwindSafe(|| arr.get(4)));
        assert!(result.is_err(), "expected get(4) to panic (Java AIOOBE parity)");
    }

    #[test]
    fn get_just_past_capacity_returns_none_without_panicking() {
        let arr = IntArrayArray::new();
        assert_eq!(arr.get(5), None);
    }

    #[test]
    fn array_trait_copy_data_to_writes_int_array_column() {
        let mut arr = IntArrayArray::new();
        arr.put(0, Some(&[1, 2, 3]));
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert_eq!(table.get_int_array(5, 1), vec![1, 2, 3]);
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = IntArrayArray::new();
        arr.put(0, Some(&[1]));
        Array::remove(&mut arr, 0);
        assert_eq!(arr.get(0), None);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(IntArrayArray::default(), IntArrayArray::new());
    }
}
