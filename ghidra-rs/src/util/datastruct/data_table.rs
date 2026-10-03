use std::any::Any;

/// Table for managing rows and columns of typed data, addressed by row and
/// column index.
///
/// Port of `ghidra.util.datastruct.DataTable`, cut to a trait to break a
/// dependency cycle: the original class stored a `private Array[] dataColumns`
/// and cross-referenced [`ghidra.util.datastruct.Array`], whose own
/// `copyDataTo` method takes a `DataTable` back. Concrete storage (e.g. the
/// per-type growable `Array` columns) is left to implementors; this trait
/// only fixes the public row/column access API. A column accessed with the
/// wrong type, or a row/column never written, behaves as in Java: it is up to
/// the implementor (panic or default value), not specified here.
pub trait DataTable {
    /// Removes the given row from the table.
    fn remove_row(&mut self, row: i32);

    /// Copies one row from `self` to a row in `table`.
    fn copy_row_to(&self, row: i32, table: &mut dyn DataTable, to_row: i32);

    /// Stores a `bool` at the given row and column.
    fn put_boolean(&mut self, row: i32, col: i32, value: bool);
    /// Returns the `bool` at the given row and column.
    fn get_boolean(&self, row: i32, col: i32) -> bool;

    /// Stores a `byte` at the given row and column.
    fn put_byte(&mut self, row: i32, col: i32, value: i8);
    /// Returns the `byte` at the given row and column.
    fn get_byte(&self, row: i32, col: i32) -> i8;

    /// Stores a `short` at the given row and column.
    fn put_short(&mut self, row: i32, col: i32, value: i16);
    /// Returns the `short` at the given row and column.
    fn get_short(&self, row: i32, col: i32) -> i16;

    /// Stores an `int` at the given row and column.
    fn put_int(&mut self, row: i32, col: i32, value: i32);
    /// Returns the `int` at the given row and column.
    fn get_int(&self, row: i32, col: i32) -> i32;

    /// Stores a `long` at the given row and column.
    fn put_long(&mut self, row: i32, col: i32, value: i64);
    /// Returns the `long` at the given row and column.
    fn get_long(&self, row: i32, col: i32) -> i64;

    /// Stores a `double` at the given row and column.
    fn put_double(&mut self, row: i32, col: i32, value: f64);
    /// Returns the `double` at the given row and column.
    fn get_double(&self, row: i32, col: i32) -> f64;

    /// Stores a `float` at the given row and column.
    fn put_float(&mut self, row: i32, col: i32, value: f32);
    /// Returns the `float` at the given row and column.
    fn get_float(&self, row: i32, col: i32) -> f32;

    /// Stores a `String` at the given row and column.
    fn put_string(&mut self, row: i32, col: i32, value: String);
    /// Returns the `String` at the given row and column.
    fn get_string(&self, row: i32, col: i32) -> String;

    /// Stores an arbitrary `Object` at the given row and column.
    fn put_object(&mut self, row: i32, col: i32, value: Box<dyn Any>);
    /// Returns the `Object` at the given row and column.
    fn get_object(&self, row: i32, col: i32) -> &dyn Any;

    /// Stores a byte array at the given row and column.
    fn put_byte_array(&mut self, row: i32, col: i32, value: Vec<u8>);
    /// Returns the byte array at the given row and column.
    fn get_byte_array(&self, row: i32, col: i32) -> Vec<u8>;

    /// Stores a short array at the given row and column.
    fn put_short_array(&mut self, row: i32, col: i32, value: Vec<i16>);
    /// Returns the short array at the given row and column.
    fn get_short_array(&self, row: i32, col: i32) -> Vec<i16>;

    /// Stores an int array at the given row and column.
    fn put_int_array(&mut self, row: i32, col: i32, value: Vec<i32>);
    /// Returns the int array at the given row and column.
    fn get_int_array(&self, row: i32, col: i32) -> Vec<i32>;

    /// Stores a long array at the given row and column.
    fn put_long_array(&mut self, row: i32, col: i32, value: Vec<i64>);
    /// Returns the long array at the given row and column.
    fn get_long_array(&self, row: i32, col: i32) -> Vec<i64>;

    /// Stores a float array at the given row and column.
    fn put_float_array(&mut self, row: i32, col: i32, value: Vec<f32>);
    /// Returns the float array at the given row and column.
    fn get_float_array(&self, row: i32, col: i32) -> Vec<f32>;

    /// Stores a double array at the given row and column.
    fn put_double_array(&mut self, row: i32, col: i32, value: Vec<f64>);
    /// Returns the double array at the given row and column.
    fn get_double_array(&self, row: i32, col: i32) -> Vec<f64>;

    /// Stores a String array at the given row and column.
    fn put_string_array(&mut self, row: i32, col: i32, value: Vec<String>);
    /// Returns the String array at the given row and column.
    fn get_string_array(&self, row: i32, col: i32) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Trivial mock proving `DataTable` is object-safe and usable behind
    /// `Box<dyn DataTable>` / `&mut dyn DataTable`. Only backs `int` and
    /// `String` columns, enough to exercise `copy_row_to`.
    #[derive(Default)]
    struct MockDataTable {
        ints: HashMap<(i32, i32), i32>,
        strings: HashMap<(i32, i32), String>,
    }

    impl DataTable for MockDataTable {
        fn remove_row(&mut self, row: i32) {
            self.ints.retain(|(r, _), _| *r != row);
            self.strings.retain(|(r, _), _| *r != row);
        }

        fn copy_row_to(&self, row: i32, table: &mut dyn DataTable, to_row: i32) {
            for col in 0..2 {
                table.put_int(to_row, col, self.get_int(row, col));
            }
            table.put_string(to_row, 2, self.get_string(row, 2));
        }

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
        fn put_int(&mut self, row: i32, col: i32, value: i32) {
            self.ints.insert((row, col), value);
        }
        fn get_int(&self, row: i32, col: i32) -> i32 {
            *self.ints.get(&(row, col)).unwrap_or(&0)
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
        fn put_string(&mut self, row: i32, col: i32, value: String) {
            self.strings.insert((row, col), value);
        }
        fn get_string(&self, row: i32, col: i32) -> String {
            self.strings.get(&(row, col)).cloned().unwrap_or_default()
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
    fn object_safe_copy_row_to() {
        let mut src = MockDataTable::default();
        src.put_int(0, 0, 42);
        src.put_int(0, 1, 7);
        src.put_string(0, 2, "hello".to_string());

        let mut dst: Box<dyn DataTable> = Box::new(MockDataTable::default());
        src.copy_row_to(0, dst.as_mut(), 3);

        assert_eq!(dst.get_int(3, 0), 42);
        assert_eq!(dst.get_int(3, 1), 7);
        assert_eq!(dst.get_string(3, 2), "hello");
    }

    #[test]
    fn remove_row_clears_values() {
        let mut table = MockDataTable::default();
        table.put_int(1, 0, 99);
        table.remove_row(1);
        assert_eq!(table.get_int(1, 0), 0);
    }
}
