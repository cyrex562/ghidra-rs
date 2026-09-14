//! Port of `ghidra.util.map.ObjectStorageAdapter`.

use crate::util::datastruct::data_table::DataTable;
use crate::util::object_storage::ObjectStorage;

/// Convenience adapter implementation for saving and restoring Strings and Java primitives or
/// arrays of Strings and primitives for a row of a data table. The order in which the puts are
/// done must be the same order in which the gets are done.
///
/// Port of `ghidra.util.map.ObjectStorageAdapter`.
///
/// # Differences from Java
///
/// - Java's `private DataTable table;` field is a plain reference to a `DataTable` owned
///   elsewhere; this port holds `&'t mut dyn DataTable` for the same reason (composition, not
///   ownership), which additionally requires the borrow to be exclusive (`&mut`) since every
///   `get_*`/`put_*` here mutates the table (`col` bookkeeping aside, [`DataTable`]'s own
///   accessor methods are declared `&mut self`/`&self` per-operation, and put/get are
///   interleaved by the same adapter over the table's lifetime).
/// - `byte`/`byte[]` values are Java's signed 8-bit type, matching
///   [`ObjectStorage`]'s own `i8`/`&[i8]`/`Vec<i8>` shapes; [`DataTable::put_byte_array`]/
///   [`DataTable::get_byte_array`] were ported using unsigned `u8`/`Vec<u8>` instead (raw bytes),
///   so this adapter converts between the two via `as` casts (a lossless bit-pattern
///   reinterpretation, not a value-changing conversion).
pub struct ObjectStorageAdapter<'t> {
    table: &'t mut dyn DataTable,
    row: i32,
    col: i32,
}

impl<'t> ObjectStorageAdapter<'t> {
    /// Constructor for `ObjectStorageAdapter`.
    pub fn new(table: &'t mut dyn DataTable, row: i32) -> Self {
        ObjectStorageAdapter { table, row, col: 0 }
    }

    /// Returns the next column index to use, then advances the cursor -- mirrors the Java
    /// idiom `col++` used at every `put_*`/`get_*` call site.
    fn next_col(&mut self) -> i32 {
        let col = self.col;
        self.col += 1;
        col
    }
}

impl<'t> ObjectStorage for ObjectStorageAdapter<'t> {
    /// See `ObjectStorage#putInt(int)`.
    fn put_int(&mut self, value: i32) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_int(row, col, value);
    }

    /// See `ObjectStorage#putByte(byte)`.
    fn put_byte(&mut self, value: i8) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_byte(row, col, value);
    }

    /// See `ObjectStorage#putShort(short)`.
    fn put_short(&mut self, value: i16) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_short(row, col, value);
    }

    /// See `ObjectStorage#putLong(long)`.
    fn put_long(&mut self, value: i64) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_long(row, col, value);
    }

    /// See `ObjectStorage#putString(String)`.
    fn put_string(&mut self, value: &str) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_string(row, col, value.to_string());
    }

    /// See `ObjectStorage#putBoolean(boolean)`.
    fn put_boolean(&mut self, value: bool) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_boolean(row, col, value);
    }

    /// See `ObjectStorage#putFloat(float)`.
    fn put_float(&mut self, value: f32) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_float(row, col, value);
    }

    /// See `ObjectStorage#putDouble(double)`.
    fn put_double(&mut self, value: f64) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_double(row, col, value);
    }

    /// See `ObjectStorage#getInt()`.
    fn get_int(&mut self) -> i32 {
        let (row, col) = (self.row, self.next_col());
        self.table.get_int(row, col)
    }

    /// See `ObjectStorage#getByte()`.
    fn get_byte(&mut self) -> i8 {
        let (row, col) = (self.row, self.next_col());
        self.table.get_byte(row, col)
    }

    /// See `ObjectStorage#getShort()`.
    fn get_short(&mut self) -> i16 {
        let (row, col) = (self.row, self.next_col());
        self.table.get_short(row, col)
    }

    /// See `ObjectStorage#getLong()`.
    fn get_long(&mut self) -> i64 {
        let (row, col) = (self.row, self.next_col());
        self.table.get_long(row, col)
    }

    /// See `ObjectStorage#getBoolean()`.
    fn get_boolean(&mut self) -> bool {
        let (row, col) = (self.row, self.next_col());
        self.table.get_boolean(row, col)
    }

    /// See `ObjectStorage#getString()`.
    fn get_string(&mut self) -> String {
        let (row, col) = (self.row, self.next_col());
        self.table.get_string(row, col)
    }

    /// See `ObjectStorage#getFloat()`.
    fn get_float(&mut self) -> f32 {
        let (row, col) = (self.row, self.next_col());
        self.table.get_float(row, col)
    }

    /// See `ObjectStorage#getDouble()`.
    fn get_double(&mut self) -> f64 {
        let (row, col) = (self.row, self.next_col());
        self.table.get_double(row, col)
    }

    /// See `ObjectStorage#putInts(int[])`.
    fn put_ints(&mut self, value: &[i32]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_int_array(row, col, value.to_vec());
    }

    /// See `ObjectStorage#putBytes(byte[])`.
    fn put_bytes(&mut self, value: &[i8]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_byte_array(row, col, value.iter().map(|&b| b as u8).collect());
    }

    /// See `ObjectStorage#putShorts(short[])`.
    fn put_shorts(&mut self, value: &[i16]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_short_array(row, col, value.to_vec());
    }

    /// See `ObjectStorage#putLongs(long[])`.
    fn put_longs(&mut self, value: &[i64]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_long_array(row, col, value.to_vec());
    }

    /// See `ObjectStorage#putFloats(float[])`.
    fn put_floats(&mut self, value: &[f32]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_float_array(row, col, value.to_vec());
    }

    /// See `ObjectStorage#putDoubles(double[])`.
    fn put_doubles(&mut self, value: &[f64]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_double_array(row, col, value.to_vec());
    }

    /// See `ObjectStorage#getInts()`.
    fn get_ints(&mut self) -> Vec<i32> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_int_array(row, col)
    }

    /// See `ObjectStorage#getBytes()`.
    fn get_bytes(&mut self) -> Vec<i8> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_byte_array(row, col).into_iter().map(|b| b as i8).collect()
    }

    /// See `ObjectStorage#getShorts()`.
    fn get_shorts(&mut self) -> Vec<i16> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_short_array(row, col)
    }

    /// See `ObjectStorage#getLongs()`.
    fn get_longs(&mut self) -> Vec<i64> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_long_array(row, col)
    }

    /// See `ObjectStorage#getFloats()`.
    fn get_floats(&mut self) -> Vec<f32> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_float_array(row, col)
    }

    /// See `ObjectStorage#getDoubles()`.
    fn get_doubles(&mut self) -> Vec<f64> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_double_array(row, col)
    }

    /// See `ObjectStorage#getStrings()`.
    fn get_strings(&mut self) -> Vec<String> {
        let (row, col) = (self.row, self.next_col());
        self.table.get_string_array(row, col)
    }

    /// See `ObjectStorage#putStrings(String[])`.
    fn put_strings(&mut self, value: &[&str]) {
        let (row, col) = (self.row, self.next_col());
        self.table.put_string_array(row, col, value.iter().map(|s| s.to_string()).collect());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    /// A minimal in-memory [`DataTable`], enough to exercise every scalar/array type this
    /// adapter forwards. Mirrors the storage shape of `data_table.rs`'s own `MockDataTable` test
    /// double, extended to cover every column type this adapter needs.
    #[derive(Default)]
    struct MockDataTable {
        ints: HashMap<(i32, i32), i32>,
        bytes: HashMap<(i32, i32), i8>,
        shorts: HashMap<(i32, i32), i16>,
        longs: HashMap<(i32, i32), i64>,
        floats: HashMap<(i32, i32), f32>,
        doubles: HashMap<(i32, i32), f64>,
        strings: HashMap<(i32, i32), String>,
        booleans: HashMap<(i32, i32), bool>,
        int_arrays: HashMap<(i32, i32), Vec<i32>>,
        byte_arrays: HashMap<(i32, i32), Vec<u8>>,
        short_arrays: HashMap<(i32, i32), Vec<i16>>,
        long_arrays: HashMap<(i32, i32), Vec<i64>>,
        float_arrays: HashMap<(i32, i32), Vec<f32>>,
        double_arrays: HashMap<(i32, i32), Vec<f64>>,
        string_arrays: HashMap<(i32, i32), Vec<String>>,
    }

    impl DataTable for MockDataTable {
        fn remove_row(&mut self, _row: i32) {}
        fn copy_row_to(&self, _row: i32, _table: &mut dyn DataTable, _to_row: i32) {}

        fn put_boolean(&mut self, row: i32, col: i32, value: bool) {
            self.booleans.insert((row, col), value);
        }
        fn get_boolean(&self, row: i32, col: i32) -> bool {
            *self.booleans.get(&(row, col)).unwrap()
        }

        fn put_byte(&mut self, row: i32, col: i32, value: i8) {
            self.bytes.insert((row, col), value);
        }
        fn get_byte(&self, row: i32, col: i32) -> i8 {
            *self.bytes.get(&(row, col)).unwrap()
        }

        fn put_short(&mut self, row: i32, col: i32, value: i16) {
            self.shorts.insert((row, col), value);
        }
        fn get_short(&self, row: i32, col: i32) -> i16 {
            *self.shorts.get(&(row, col)).unwrap()
        }

        fn put_int(&mut self, row: i32, col: i32, value: i32) {
            self.ints.insert((row, col), value);
        }
        fn get_int(&self, row: i32, col: i32) -> i32 {
            *self.ints.get(&(row, col)).unwrap()
        }

        fn put_long(&mut self, row: i32, col: i32, value: i64) {
            self.longs.insert((row, col), value);
        }
        fn get_long(&self, row: i32, col: i32) -> i64 {
            *self.longs.get(&(row, col)).unwrap()
        }

        fn put_double(&mut self, row: i32, col: i32, value: f64) {
            self.doubles.insert((row, col), value);
        }
        fn get_double(&self, row: i32, col: i32) -> f64 {
            *self.doubles.get(&(row, col)).unwrap()
        }

        fn put_float(&mut self, row: i32, col: i32, value: f32) {
            self.floats.insert((row, col), value);
        }
        fn get_float(&self, row: i32, col: i32) -> f32 {
            *self.floats.get(&(row, col)).unwrap()
        }

        fn put_string(&mut self, row: i32, col: i32, value: String) {
            self.strings.insert((row, col), value);
        }
        fn get_string(&self, row: i32, col: i32) -> String {
            self.strings.get(&(row, col)).cloned().unwrap()
        }

        fn put_object(&mut self, _row: i32, _col: i32, _value: Box<dyn Any>) {}
        fn get_object(&self, _row: i32, _col: i32) -> &dyn Any {
            &()
        }

        fn put_byte_array(&mut self, row: i32, col: i32, value: Vec<u8>) {
            self.byte_arrays.insert((row, col), value);
        }
        fn get_byte_array(&self, row: i32, col: i32) -> Vec<u8> {
            self.byte_arrays.get(&(row, col)).cloned().unwrap()
        }

        fn put_short_array(&mut self, row: i32, col: i32, value: Vec<i16>) {
            self.short_arrays.insert((row, col), value);
        }
        fn get_short_array(&self, row: i32, col: i32) -> Vec<i16> {
            self.short_arrays.get(&(row, col)).cloned().unwrap()
        }

        fn put_int_array(&mut self, row: i32, col: i32, value: Vec<i32>) {
            self.int_arrays.insert((row, col), value);
        }
        fn get_int_array(&self, row: i32, col: i32) -> Vec<i32> {
            self.int_arrays.get(&(row, col)).cloned().unwrap()
        }

        fn put_long_array(&mut self, row: i32, col: i32, value: Vec<i64>) {
            self.long_arrays.insert((row, col), value);
        }
        fn get_long_array(&self, row: i32, col: i32) -> Vec<i64> {
            self.long_arrays.get(&(row, col)).cloned().unwrap()
        }

        fn put_float_array(&mut self, row: i32, col: i32, value: Vec<f32>) {
            self.float_arrays.insert((row, col), value);
        }
        fn get_float_array(&self, row: i32, col: i32) -> Vec<f32> {
            self.float_arrays.get(&(row, col)).cloned().unwrap()
        }

        fn put_double_array(&mut self, row: i32, col: i32, value: Vec<f64>) {
            self.double_arrays.insert((row, col), value);
        }
        fn get_double_array(&self, row: i32, col: i32) -> Vec<f64> {
            self.double_arrays.get(&(row, col)).cloned().unwrap()
        }

        fn put_string_array(&mut self, row: i32, col: i32, value: Vec<String>) {
            self.string_arrays.insert((row, col), value);
        }
        fn get_string_array(&self, row: i32, col: i32) -> Vec<String> {
            self.string_arrays.get(&(row, col)).cloned().unwrap()
        }
    }

    #[test]
    fn scalars_roundtrip_in_put_order() {
        let mut table = MockDataTable::default();
        {
            let mut adapter = ObjectStorageAdapter::new(&mut table, 3);
            adapter.put_int(42);
            adapter.put_byte(-1);
            adapter.put_short(1000);
            adapter.put_long(i64::MAX);
            adapter.put_string("hello");
            adapter.put_boolean(true);
            adapter.put_float(1.5);
            adapter.put_double(3.14);
        }
        let mut adapter = ObjectStorageAdapter::new(&mut table, 3);
        assert_eq!(adapter.get_int(), 42);
        assert_eq!(adapter.get_byte(), -1);
        assert_eq!(adapter.get_short(), 1000);
        assert_eq!(adapter.get_long(), i64::MAX);
        assert_eq!(adapter.get_string(), "hello");
        assert!(adapter.get_boolean());
        assert_eq!(adapter.get_float(), 1.5_f32);
        assert_eq!(adapter.get_double(), 3.14_f64);
    }

    #[test]
    fn arrays_roundtrip_in_put_order() {
        let mut table = MockDataTable::default();
        {
            let mut adapter = ObjectStorageAdapter::new(&mut table, 0);
            adapter.put_ints(&[1, 2, 3]);
            adapter.put_bytes(&[-128, 0, 127]);
            adapter.put_shorts(&[100, 200]);
            adapter.put_longs(&[i64::MIN, i64::MAX]);
            adapter.put_floats(&[0.1, 0.2]);
            adapter.put_doubles(&[1.1, 2.2]);
            adapter.put_strings(&["foo", "bar"]);
        }
        let mut adapter = ObjectStorageAdapter::new(&mut table, 0);
        assert_eq!(adapter.get_ints(), vec![1, 2, 3]);
        assert_eq!(adapter.get_bytes(), vec![-128_i8, 0, 127]);
        assert_eq!(adapter.get_shorts(), vec![100_i16, 200]);
        assert_eq!(adapter.get_longs(), vec![i64::MIN, i64::MAX]);
        assert_eq!(adapter.get_floats(), vec![0.1_f32, 0.2]);
        assert_eq!(adapter.get_doubles(), vec![1.1_f64, 2.2]);
        assert_eq!(adapter.get_strings(), vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn byte_array_round_trips_full_i8_range_via_bit_pattern_cast() {
        let mut table = MockDataTable::default();
        {
            let mut adapter = ObjectStorageAdapter::new(&mut table, 0);
            adapter.put_bytes(&[i8::MIN, -1, 0, 1, i8::MAX]);
        }
        let mut adapter = ObjectStorageAdapter::new(&mut table, 0);
        assert_eq!(adapter.get_bytes(), vec![i8::MIN, -1, 0, 1, i8::MAX]);
    }

    #[test]
    fn different_rows_are_independent() {
        let mut table = MockDataTable::default();
        {
            let mut row0 = ObjectStorageAdapter::new(&mut table, 0);
            row0.put_int(1);
        }
        {
            let mut row1 = ObjectStorageAdapter::new(&mut table, 1);
            row1.put_int(2);
        }
        assert_eq!(ObjectStorageAdapter::new(&mut table, 0).get_int(), 1);
        assert_eq!(ObjectStorageAdapter::new(&mut table, 1).get_int(), 2);
    }

    #[test]
    fn columns_increment_starting_at_zero_for_a_fresh_adapter() {
        // Mirrors the Java constructor setting `col = 0`, then each put/get advancing it: mixing
        // put and get calls on separate adapter instances over the same row/columns must line up.
        let mut table = MockDataTable::default();
        {
            let mut adapter = ObjectStorageAdapter::new(&mut table, 7);
            adapter.put_string("first");
            adapter.put_string("second");
            adapter.put_string("third");
        }
        let mut adapter = ObjectStorageAdapter::new(&mut table, 7);
        assert_eq!(adapter.get_string(), "first");
        assert_eq!(adapter.get_string(), "second");
        assert_eq!(adapter.get_string(), "third");
    }

    #[test]
    fn usable_as_trait_object() {
        let mut table = MockDataTable::default();
        {
            let mut adapter = ObjectStorageAdapter::new(&mut table, 0);
            let storage: &mut dyn ObjectStorage = &mut adapter;
            storage.put_boolean(false);
        }
        let mut reader = ObjectStorageAdapter::new(&mut table, 0);
        assert!(!reader.get_boolean());
    }
}
