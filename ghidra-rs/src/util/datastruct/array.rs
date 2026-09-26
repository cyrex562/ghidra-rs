use super::data_table::DataTable;

/// Base trait for a "virtual" growable array of some data type.
///
/// Any access of an implementor with an index that has never been set
/// returns a zero-like value (`0`, `false`, `None`, `""`, etc, depending on
/// the concrete data type).
///
/// Port of `ghidra.util.datastruct.Array`.
pub trait Array {
    /// Removes the value at `index`. If the array is of a primitive type
    /// (`int`, `short`, etc), then "removing" the value is equivalent to
    /// setting the value to `0`.
    fn remove(&mut self, index: usize);

    /// Returns the index of the last non-null or non-zero element in the
    /// array, or `-1` if the array is empty.
    fn get_last_non_empty_index(&self) -> i32;

    /// Copies the underlying value for this array at `index` to `table` at
    /// `to_index`/`to_col`. The data type at `to_col` in `table` must match
    /// the data in this array.
    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal mock proving `Array` is object-safe and usable behind `&mut dyn Array`.
    struct MockArray {
        values: Vec<i32>,
        last_non_zero_index: i32,
    }

    impl Array for MockArray {
        fn remove(&mut self, index: usize) {
            if index >= self.values.len() {
                return;
            }
            self.values[index] = 0;
            if index as i32 == self.last_non_zero_index {
                self.last_non_zero_index = self
                    .values
                    .iter()
                    .rposition(|&v| v != 0)
                    .map(|i| i as i32)
                    .unwrap_or(-1);
            }
        }

        fn get_last_non_empty_index(&self) -> i32 {
            self.last_non_zero_index
        }

        fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
            let value = self.values.get(index).copied().unwrap_or(0);
            table.put_int(to_index, to_col, value);
        }
    }

    #[test]
    fn object_safe_behind_trait_object() {
        let mut arr: Box<dyn Array> = Box::new(MockArray {
            values: vec![0, 5, 0, 9],
            last_non_zero_index: 3,
        });
        assert_eq!(arr.get_last_non_empty_index(), 3);
        arr.remove(3);
        assert_eq!(arr.get_last_non_empty_index(), 1);
    }
}
