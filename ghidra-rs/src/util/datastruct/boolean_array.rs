use super::array::Array;
use super::data_table::DataTable;

/// Minimum backing-array capacity, in bytes (each byte packs 8 keys).
pub const MIN_SIZE: usize = 4;

/// A bit-packed array of `bool` that grows as needed.
///
/// Port of `ghidra.util.datastruct.BooleanArray`. An index that was never
/// written (or was most recently `remove`d / set `false`) reads back as
/// `false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BooleanArray {
    bytes: Vec<u8>,
    last_non_zero_index: i32,
}

impl BooleanArray {
    /// Creates a new, empty `BooleanArray`.
    pub fn new() -> Self {
        Self {
            bytes: vec![0; MIN_SIZE],
            last_non_zero_index: -1,
        }
    }

    /// Puts `value` at `index`, growing the backing storage if necessary.
    pub fn put(&mut self, index: usize, value: bool) {
        let byte_num = index / 8;
        let bit_num = index % 8;

        if byte_num >= self.bytes.len() {
            if !value {
                return;
            }
            self.adjust_array(std::cmp::max(byte_num as i64 + 1, self.bytes.len() as i64 * 2));
        }

        if value {
            self.bytes[byte_num] |= 1u8 << bit_num;
            if index as i32 > self.last_non_zero_index {
                self.last_non_zero_index = index as i32;
            }
        } else {
            self.bytes[byte_num] &= !(1u8 << bit_num);
            if index as i32 == self.last_non_zero_index {
                self.last_non_zero_index = self.find_last_non_zero_index();
            }
            // Faithful port of a genuine bug in BooleanArray.java (lines ~69-70): the shrink
            // check divides by 8 (bytes -> bits) but the resize call uses `lastNonZeroIndex/4`
            // where the comment `// lastNonZeroIndex/8 * 2` reveals the *intended* formula.
            // `x/4` and `(x/8)*2` are NOT equal under integer truncation whenever `x` is not a
            // multiple of 8 (e.g. x=44: 44/4=11 but (44/8)*2=10). We reproduce the actual
            // (buggy) division here rather than the intended one; see
            // `boolean_array_shrink_uses_buggy_divisor_not_intended_formula` below.
            if self.last_non_zero_index / 8 < self.bytes.len() as i32 / 4 {
                self.adjust_array(self.last_non_zero_index as i64 / 4);
            }
        }
    }

    /// Sets the value at `index` to `false`.
    pub fn remove(&mut self, index: usize) {
        self.put(index, false);
    }

    /// Returns the value at `index`. Returns `false` for any index not
    /// initialized to `true` (including indexes past the end of the backing
    /// storage).
    pub fn get(&self, index: usize) -> bool {
        let byte_num = index / 8;
        if byte_num < self.bytes.len() {
            (self.bytes[byte_num] & (1u8 << (index % 8))) != 0
        } else {
            false
        }
    }

    fn find_last_non_zero_index(&self) -> i32 {
        let mut i = self.last_non_zero_index / 8;
        while i >= 0 {
            if self.bytes[i as usize] != 0 {
                let mut j = 7i32;
                while j >= 0 {
                    if self.bytes[i as usize] & (1u8 << j) != 0 {
                        return i * 8 + j;
                    }
                    j -= 1;
                }
            }
            i -= 1;
        }
        -1
    }

    /// Adjusts the capacity of the backing storage (in bytes) to `size`,
    /// clamped to a minimum of [`MIN_SIZE`]. `size` may be negative
    /// (mirroring Java's `int` parameter); negative values simply clamp to
    /// `MIN_SIZE`.
    fn adjust_array(&mut self, size: i64) {
        let size = if size < MIN_SIZE as i64 { MIN_SIZE } else { size as usize };
        self.bytes.resize(size, 0);
    }
}

impl Default for BooleanArray {
    fn default() -> Self {
        Self::new()
    }
}

impl Array for BooleanArray {
    fn remove(&mut self, index: usize) {
        BooleanArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.last_non_zero_index
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        table.put_boolean(to_index, to_col, self.get(index));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockDataTable {
        bools: HashMap<(i32, i32), bool>,
    }

    impl DataTable for MockDataTable {
        fn remove_row(&mut self, _row: i32) {}
        fn copy_row_to(&self, _row: i32, _table: &mut dyn DataTable, _to_row: i32) {}
        fn put_boolean(&mut self, row: i32, col: i32, value: bool) {
            self.bools.insert((row, col), value);
        }
        fn get_boolean(&self, row: i32, col: i32) -> bool {
            *self.bools.get(&(row, col)).unwrap_or(&false)
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
    fn new_array_reads_back_false() {
        let arr = BooleanArray::new();
        assert!(!arr.get(0));
        assert!(!arr.get(1000));
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut arr = BooleanArray::new();
        arr.put(10, true);
        assert!(arr.get(10));
        assert!(!arr.get(9));
        assert!(!arr.get(11));
        assert_eq!(arr.get_last_non_empty_index(), 10);
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = BooleanArray::new();
        arr.put(300, true);
        assert!(arr.get(300));
        assert_eq!(arr.get_last_non_empty_index(), 300);
        assert!(!arr.get(150));
    }

    #[test]
    fn put_false_on_unset_index_beyond_capacity_is_noop() {
        let mut arr = BooleanArray::new();
        arr.put(1000, false);
        assert_eq!(arr.get_last_non_empty_index(), -1);
        assert!(!arr.get(1000));
    }

    #[test]
    fn put_false_is_equivalent_to_remove() {
        let mut arr = BooleanArray::new();
        arr.put(1, true);
        arr.put(1, false);
        assert!(!arr.get(1));
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_updates_last_non_zero_index_to_new_max() {
        let mut arr = BooleanArray::new();
        arr.put(1, true);
        arr.put(20, true);
        arr.remove(20);
        assert_eq!(arr.get_last_non_empty_index(), 1);
        assert!(!arr.get(20));
    }

    #[test]
    fn remove_past_end_is_noop() {
        let mut arr = BooleanArray::new();
        arr.remove(1000);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn multiple_bits_in_same_byte_are_independent() {
        let mut arr = BooleanArray::new();
        arr.put(0, true);
        arr.put(1, true);
        arr.put(2, false);
        assert!(arr.get(0));
        assert!(arr.get(1));
        assert!(!arr.get(2));
    }

    /// Faithfully reproduces a genuine bug in `BooleanArray.java`'s shrink-on-remove logic
    /// (lines ~69-70):
    /// ```java
    /// if (lastNonZeroIndex/8 < bytes.length / 4) {
    ///     adjustArray(lastNonZeroIndex/4); // lastNonZeroIndex/8 * 2
    /// }
    /// ```
    /// The trailing comment documents the *intended* new capacity as
    /// `(lastNonZeroIndex/8)*2`, but the actual code computes `lastNonZeroIndex/4`. These are
    /// not equal under integer truncation whenever `lastNonZeroIndex` is not a multiple of 8:
    /// for `lastNonZeroIndex=44`, the intended formula gives `(44/8)*2 = 10` but the real code
    /// gives `44/4 = 11`. We port the actual (buggy) division, not the comment's intent.
    #[test]
    fn boolean_array_shrink_uses_buggy_divisor_not_intended_formula() {
        let mut arr = BooleanArray::new();
        // Grow well past MIN_SIZE so the shrink-on-remove branch actually triggers.
        arr.put(300, true); // byte_num = 37, grows bytes to len 38
        assert_eq!(arr.bytes.len(), 38);
        arr.put(44, true); // byte_num = 5, no growth needed; last_non_zero_index stays 300

        // Removing index 300 forces last_non_zero_index to be recomputed to 44, and
        // 44/8=5 < 38/4=9, so the shrink branch fires.
        arr.remove(300);
        assert_eq!(arr.get_last_non_empty_index(), 44);

        // The buggy formula (44/4=11) is what the real Java code produces; the "intended"
        // formula per the source comment ((44/8)*2=10) would have produced a different,
        // smaller capacity.
        assert_eq!(arr.bytes.len(), 11);
        assert_ne!(arr.bytes.len(), (44 / 8) * 2);

        // The bit is still readable after the shrink.
        assert!(arr.get(44));
    }

    #[test]
    fn array_trait_copy_data_to_writes_boolean_column() {
        let mut arr = BooleanArray::new();
        arr.put(0, true);
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert!(table.get_boolean(5, 1));
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = BooleanArray::new();
        arr.put(0, true);
        Array::remove(&mut arr, 0);
        assert!(!arr.get(0));
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(BooleanArray::default(), BooleanArray::new());
    }
}
