use std::any::Any;
use std::rc::Rc;

use super::boolean_array::BooleanArray;
use super::byte_array::ByteArray;
use super::byte_array_array::ByteArrayArray;
use super::data_table::DataTable;
use super::double_array::DoubleArray;
use super::double_array_array::DoubleArrayArray;
use super::float_array::FloatArray;
use super::float_array_array::FloatArrayArray;
use super::int_array::IntArray;
use super::int_array_array::IntArrayArray;
use super::long_array::LongArray;
use super::long_array_array::LongArrayArray;
use super::object_array::ObjectArray;
use super::short_array::ShortArray;
use super::short_array_array::ShortArrayArray;
use super::string_array::StringArray;
use super::string_array_array::StringArrayArray;

/// One column's typed backing storage.
///
/// Java's concrete `ghidra.util.datastruct.DataTable` (the class
/// `ManagedDataTable` extends) keeps `private Array[] dataColumns` and
/// downcasts each slot to whichever concrete `Array` subtype the column's
/// first write established, throwing `ClassCastException` if a later write
/// uses a different type. [`super::data_table::DataTable`] (this crate's
/// trait) was deliberately cut down to just the row/column access API "to
/// break a dependency cycle", explicitly leaving concrete column storage to
/// implementors -- so `ManagedDataTable` (which both *is* that concrete
/// storage, via inheritance, and adds occupied-row tracking on top) has to
/// provide it here. This enum is that storage, one variant per Java `Array`
/// subtype the base class supports.
enum Column {
    Boolean(BooleanArray),
    Byte(ByteArray),
    Short(ShortArray),
    Int(IntArray),
    Long(LongArray),
    Double(DoubleArray),
    Float(FloatArray),
    String(StringArray),
    /// Java's `Object` is always reference-typed, so two `DataTable`s can
    /// trivially share the same instance (e.g. via `copyRowTo`). An owned
    /// `Box<dyn Any>` cannot be cheaply duplicated without knowing its
    /// concrete type, so cells are stored as `Rc<dyn Any>` internally --
    /// only the `put_object`/`get_object` boundary (fixed by the
    /// `DataTable` trait) deals in `Box<dyn Any>`. See [`ManagedDataTable::copy_row_to`].
    Object(ObjectArray<Rc<dyn Any>>),
    ByteArrayCol(ByteArrayArray),
    ShortArrayCol(ShortArrayArray),
    IntArrayCol(IntArrayArray),
    LongArrayCol(LongArrayArray),
    FloatArrayCol(FloatArrayArray),
    DoubleArrayCol(DoubleArrayArray),
    StringArrayCol(StringArrayArray),
}

impl Column {
    /// Mirrors the base `DataTable.removeRow`'s per-column
    /// `dataColumns[i].remove(row)` loop body.
    fn remove(&mut self, index: usize) {
        match self {
            Column::Boolean(a) => a.remove(index),
            Column::Byte(a) => a.remove(index),
            Column::Short(a) => a.remove(index),
            Column::Int(a) => a.remove(index),
            Column::Long(a) => a.remove(index),
            Column::Double(a) => a.remove(index),
            Column::Float(a) => a.remove(index),
            Column::String(a) => a.remove(index),
            Column::Object(a) => a.remove(index),
            Column::ByteArrayCol(a) => a.remove(index),
            Column::ShortArrayCol(a) => a.remove(index),
            Column::IntArrayCol(a) => a.remove(index),
            Column::LongArrayCol(a) => a.remove(index),
            Column::FloatArrayCol(a) => a.remove(index),
            Column::DoubleArrayCol(a) => a.remove(index),
            Column::StringArrayCol(a) => a.remove(index),
        }
    }
}

/// Generates a `put_*`/`get_*` pair for a scalar-valued column (`bool`,
/// `i8`, `i16`, `i32`, `i64`, `f64`, `f32`), mirroring the identical
/// grow/create-or-fetch/put-or-cast pattern the Java base class repeats once
/// per primitive type.
macro_rules! scalar_column {
    ($put_fn:ident, $get_fn:ident, $variant:ident, $arr_ty:ty, $val_ty:ty) => {
        fn $put_fn(&mut self, row: i32, col: i32, value: $val_ty) {
            self.touch_row(row);
            self.ensure_col(col as usize);
            let entry = &mut self.data_columns[col as usize];
            if entry.is_none() {
                *entry = Some(Column::$variant(<$arr_ty>::new()));
            }
            match entry {
                Some(Column::$variant(arr)) => arr.put(row as usize, value),
                Some(_) => panic!(
                    "ClassCastException (Java parity): column {col} already holds a \
                     different Array type, not a {}",
                    stringify!($arr_ty)
                ),
                None => unreachable!(),
            }
        }

        fn $get_fn(&self, row: i32, col: i32) -> $val_ty {
            match self.column_or_panic(col as usize) {
                Some(Column::$variant(arr)) => arr.get(row as usize),
                Some(_) => panic!(
                    "ClassCastException (Java parity): column {col} is not a {}",
                    stringify!($arr_ty)
                ),
                None => panic!(
                    "NullPointerException (Java parity): column {col} has no data \
                     (dataColumns[col] is null)"
                ),
            }
        }
    };
}

/// Same shape as [`scalar_column`], but for the `Vec<T>`-valued "array of
/// arrays" columns (`byte[]`, `short[]`, ...), whose underlying `*ArrayArray`
/// storage takes `Option<&[T]>`/returns `Option<Vec<T>>` rather than a bare
/// `T`.
macro_rules! vector_column {
    ($put_fn:ident, $get_fn:ident, $variant:ident, $arr_ty:ty, $elem_ty:ty) => {
        fn $put_fn(&mut self, row: i32, col: i32, value: Vec<$elem_ty>) {
            self.touch_row(row);
            self.ensure_col(col as usize);
            let entry = &mut self.data_columns[col as usize];
            if entry.is_none() {
                *entry = Some(Column::$variant(<$arr_ty>::new()));
            }
            match entry {
                Some(Column::$variant(arr)) => arr.put(row as usize, Some(&value)),
                Some(_) => panic!(
                    "ClassCastException (Java parity): column {col} already holds a \
                     different Array type, not a {}",
                    stringify!($arr_ty)
                ),
                None => unreachable!(),
            }
        }

        fn $get_fn(&self, row: i32, col: i32) -> Vec<$elem_ty> {
            match self.column_or_panic(col as usize) {
                Some(Column::$variant(arr)) => arr.get(row as usize).unwrap_or_default(),
                Some(_) => panic!(
                    "ClassCastException (Java parity): column {col} is not a {}",
                    stringify!($arr_ty)
                ),
                None => panic!(
                    "NullPointerException (Java parity): column {col} has no data \
                     (dataColumns[col] is null)"
                ),
            }
        }
    };
}

/// A [`DataTable`] that also tracks which rows are occupied.
///
/// Port of `ghidra.util.datastruct.ManagedDataTable`. Java's version
/// `extends DataTable`, overriding `removeRow` and every `putX` method to
/// maintain a `BooleanArray occupied` and an `int maxRow`; this port follows
/// the crate's composition-over-inheritance convention by holding that
/// concrete column storage directly (see [`Column`]) rather than a `base`
/// field, since there is no already-ported concrete `DataTable` struct to
/// compose (only the [`DataTable`] trait, deliberately left storage-free).
pub struct ManagedDataTable {
    data_columns: Vec<Option<Column>>,
    occupied: BooleanArray,
    max_row: i32,
}

impl ManagedDataTable {
    /// Creates a new, empty `ManagedDataTable`.
    pub fn new() -> Self {
        Self {
            data_columns: Vec::new(),
            occupied: BooleanArray::new(),
            max_row: 0,
        }
    }

    /// Returns `true` if the given row contains data.
    ///
    /// Mirrors `hasRow(int)`; negative rows always return `false`.
    pub fn has_row(&self, row: i32) -> bool {
        if row < 0 {
            return false;
        }
        self.occupied.get(row as usize)
    }

    /// Returns the maximum row that contains data.
    ///
    /// Mirrors `getMaxRow()`. Note the same quirk as Java: after the last
    /// occupied row is removed, this resets to `0` (not `-1`), even though
    /// row `0` itself may never have held data.
    pub fn get_max_row(&self) -> i32 {
        self.max_row
    }

    /// Mirrors the shared `maxRow = Math.max(maxRow, row); occupied.put(row,
    /// true);` prologue duplicated at the top of every Java `putX` override.
    fn touch_row(&mut self, row: i32) {
        self.max_row = self.max_row.max(row);
        self.occupied.put(row as usize, true);
    }

    /// Mirrors the base class's `growTable(col+1)` call (`if (col >=
    /// dataColumns.length) growTable(col+1)`), which grows to exactly
    /// `col+1` slots -- not doubled -- on every new out-of-range column.
    fn ensure_col(&mut self, col: usize) {
        if col >= self.data_columns.len() {
            self.data_columns.resize_with(col + 1, || None);
        }
    }

    /// Mirrors the base class's unchecked `dataColumns[col]` read used by
    /// every `getX` method: panics (matching Java's
    /// `ArrayIndexOutOfBoundsException`) if `col` was never grown into, and
    /// otherwise returns the (possibly still-`None`/Java-`null`) slot.
    fn column_or_panic(&self, col: usize) -> Option<&Column> {
        if col >= self.data_columns.len() {
            panic!(
                "ArrayIndexOutOfBoundsException (Java parity): Index {col} out of bounds for \
                 length {}",
                self.data_columns.len()
            );
        }
        self.data_columns[col].as_ref()
    }
}

impl Default for ManagedDataTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DataTable for ManagedDataTable {
    fn remove_row(&mut self, row: i32) {
        if row < 0 || !self.occupied.get(row as usize) {
            return;
        }

        // super.removeRow(row): remove this row from every populated column.
        for entry in self.data_columns.iter_mut().flatten() {
            entry.remove(row as usize);
        }

        self.occupied.remove(row as usize);
        if row == self.max_row {
            self.max_row = 0;
            let mut i = row;
            while i >= 0 {
                if self.occupied.get(i as usize) {
                    self.max_row = i;
                    break;
                }
                i -= 1;
            }
        }
    }

    fn copy_row_to(&self, row: i32, table: &mut dyn DataTable, to_row: i32) {
        for (col_idx, entry) in self.data_columns.iter().enumerate() {
            let Some(column) = entry else { continue };
            let col = col_idx as i32;
            let r = row as usize;
            match column {
                Column::Boolean(a) => table.put_boolean(to_row, col, a.get(r)),
                Column::Byte(a) => table.put_byte(to_row, col, a.get(r)),
                Column::Short(a) => table.put_short(to_row, col, a.get(r)),
                Column::Int(a) => table.put_int(to_row, col, a.get(r)),
                Column::Long(a) => table.put_long(to_row, col, a.get(r)),
                Column::Double(a) => table.put_double(to_row, col, a.get(r)),
                Column::Float(a) => table.put_float(to_row, col, a.get(r)),
                Column::String(a) => table.put_string(to_row, col, a.get(r).unwrap_or_default()),
                Column::Object(a) => match a.get(r) {
                    // See the `Column::Object` doc comment: re-boxing a clone of the `Rc`
                    // is the closest available analog to Java's reference copy through the
                    // `Box<dyn Any>`-typed trait boundary; the destination cell's `Any`
                    // payload is an `Rc<dyn Any>`, not the original concrete type.
                    Some(rc) => table.put_object(to_row, col, Box::new(Rc::clone(rc))),
                    None => table.put_object(to_row, col, Box::new(())),
                },
                Column::ByteArrayCol(a) => {
                    table.put_byte_array(to_row, col, a.get(r).unwrap_or_default())
                }
                Column::ShortArrayCol(a) => {
                    table.put_short_array(to_row, col, a.get(r).unwrap_or_default())
                }
                Column::IntArrayCol(a) => {
                    table.put_int_array(to_row, col, a.get(r).unwrap_or_default())
                }
                Column::LongArrayCol(a) => {
                    table.put_long_array(to_row, col, a.get(r).unwrap_or_default())
                }
                Column::FloatArrayCol(a) => {
                    table.put_float_array(to_row, col, a.get(r).unwrap_or_default())
                }
                Column::DoubleArrayCol(a) => {
                    table.put_double_array(to_row, col, a.get(r).unwrap_or_default())
                }
                Column::StringArrayCol(a) => {
                    let strings = a
                        .get(r)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| s.unwrap_or_default())
                        .collect();
                    table.put_string_array(to_row, col, strings);
                }
            }
        }
    }

    scalar_column!(put_boolean, get_boolean, Boolean, BooleanArray, bool);
    scalar_column!(put_byte, get_byte, Byte, ByteArray, i8);
    scalar_column!(put_short, get_short, Short, ShortArray, i16);
    scalar_column!(put_int, get_int, Int, IntArray, i32);
    scalar_column!(put_long, get_long, Long, LongArray, i64);
    scalar_column!(put_double, get_double, Double, DoubleArray, f64);
    scalar_column!(put_float, get_float, Float, FloatArray, f32);

    fn put_string(&mut self, row: i32, col: i32, value: String) {
        self.touch_row(row);
        self.ensure_col(col as usize);
        let entry = &mut self.data_columns[col as usize];
        if entry.is_none() {
            *entry = Some(Column::String(StringArray::new()));
        }
        match entry {
            Some(Column::String(arr)) => arr.put(row as usize, Some(value.as_str())),
            Some(_) => panic!(
                "ClassCastException (Java parity): column {col} already holds a different \
                 Array type, not a StringArray"
            ),
            None => unreachable!(),
        }
    }

    fn get_string(&self, row: i32, col: i32) -> String {
        match self.column_or_panic(col as usize) {
            Some(Column::String(arr)) => arr.get(row as usize).unwrap_or_default(),
            Some(_) => panic!("ClassCastException (Java parity): column {col} is not a StringArray"),
            None => panic!(
                "NullPointerException (Java parity): column {col} has no data (dataColumns[col] is null)"
            ),
        }
    }

    fn put_object(&mut self, row: i32, col: i32, value: Box<dyn Any>) {
        self.touch_row(row);
        self.ensure_col(col as usize);
        let entry = &mut self.data_columns[col as usize];
        if entry.is_none() {
            *entry = Some(Column::Object(ObjectArray::new()));
        }
        match entry {
            Some(Column::Object(arr)) => arr.put(row as usize, Some(Rc::from(value))),
            Some(_) => panic!(
                "ClassCastException (Java parity): column {col} already holds a different \
                 Array type, not an ObjectArray"
            ),
            None => unreachable!(),
        }
    }

    fn get_object(&self, row: i32, col: i32) -> &dyn Any {
        match self.column_or_panic(col as usize) {
            Some(Column::Object(arr)) => match arr.get(row as usize) {
                Some(rc) => rc.as_ref(),
                // Java would return `null` here; `&dyn Any` has no null representation,
                // so (matching this crate's `DataTable` mock convention) an empty `()`
                // stands in for "no value".
                None => &(),
            },
            Some(_) => panic!("ClassCastException (Java parity): column {col} is not an ObjectArray"),
            None => panic!(
                "NullPointerException (Java parity): column {col} has no data (dataColumns[col] is null)"
            ),
        }
    }

    vector_column!(put_byte_array, get_byte_array, ByteArrayCol, ByteArrayArray, u8);
    vector_column!(put_short_array, get_short_array, ShortArrayCol, ShortArrayArray, i16);
    vector_column!(put_int_array, get_int_array, IntArrayCol, IntArrayArray, i32);
    vector_column!(put_long_array, get_long_array, LongArrayCol, LongArrayArray, i64);
    vector_column!(put_float_array, get_float_array, FloatArrayCol, FloatArrayArray, f32);
    vector_column!(put_double_array, get_double_array, DoubleArrayCol, DoubleArrayArray, f64);

    fn put_string_array(&mut self, row: i32, col: i32, value: Vec<String>) {
        self.touch_row(row);
        self.ensure_col(col as usize);
        let entry = &mut self.data_columns[col as usize];
        if entry.is_none() {
            *entry = Some(Column::StringArrayCol(StringArrayArray::new()));
        }
        let wrapped: Vec<Option<String>> = value.into_iter().map(Some).collect();
        match entry {
            Some(Column::StringArrayCol(arr)) => arr.put(row as usize, Some(&wrapped)),
            Some(_) => panic!(
                "ClassCastException (Java parity): column {col} already holds a different \
                 Array type, not a StringArrayArray"
            ),
            None => unreachable!(),
        }
    }

    fn get_string_array(&self, row: i32, col: i32) -> Vec<String> {
        match self.column_or_panic(col as usize) {
            Some(Column::StringArrayCol(arr)) => arr
                .get(row as usize)
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.unwrap_or_default())
                .collect(),
            Some(_) => panic!(
                "ClassCastException (Java parity): column {col} is not a StringArrayArray"
            ),
            None => panic!(
                "NullPointerException (Java parity): column {col} has no data (dataColumns[col] is null)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_no_rows() {
        let table = ManagedDataTable::new();
        assert!(!table.has_row(0));
        assert_eq!(table.get_max_row(), 0);
    }

    #[test]
    fn has_row_false_for_negative_row() {
        let table = ManagedDataTable::new();
        assert!(!table.has_row(-1));
    }

    #[test]
    fn put_marks_row_occupied_and_updates_max_row() {
        let mut table = ManagedDataTable::new();
        table.put_int(3, 0, 42);
        assert!(table.has_row(3));
        assert!(!table.has_row(2));
        assert_eq!(table.get_max_row(), 3);

        table.put_int(1, 0, 7);
        assert_eq!(table.get_max_row(), 3, "max_row only ever increases on put");
    }

    #[test]
    fn scalar_columns_roundtrip() {
        let mut table = ManagedDataTable::new();
        table.put_boolean(0, 0, true);
        table.put_byte(0, 1, 5i8);
        table.put_short(0, 2, 500i16);
        table.put_int(0, 3, 70000i32);
        table.put_long(0, 4, 5_000_000_000i64);
        table.put_double(0, 5, 1.5f64);
        table.put_float(0, 6, 2.5f32);
        table.put_string(0, 7, "hello".to_string());

        assert!(table.get_boolean(0, 0));
        assert_eq!(table.get_byte(0, 1), 5);
        assert_eq!(table.get_short(0, 2), 500);
        assert_eq!(table.get_int(0, 3), 70000);
        assert_eq!(table.get_long(0, 4), 5_000_000_000);
        assert_eq!(table.get_double(0, 5), 1.5);
        assert_eq!(table.get_float(0, 6), 2.5);
        assert_eq!(table.get_string(0, 7), "hello");
    }

    #[test]
    fn array_columns_roundtrip() {
        let mut table = ManagedDataTable::new();
        table.put_byte_array(0, 0, vec![1, 2, 3]);
        table.put_short_array(0, 1, vec![10, 20]);
        table.put_int_array(0, 2, vec![100, 200]);
        table.put_long_array(0, 3, vec![1_000_000_000_000]);
        table.put_float_array(0, 4, vec![1.5, 2.5]);
        table.put_double_array(0, 5, vec![3.5, 4.5]);
        table.put_string_array(0, 6, vec!["a".to_string(), "b".to_string()]);

        assert_eq!(table.get_byte_array(0, 0), vec![1, 2, 3]);
        assert_eq!(table.get_short_array(0, 1), vec![10, 20]);
        assert_eq!(table.get_int_array(0, 2), vec![100, 200]);
        assert_eq!(table.get_long_array(0, 3), vec![1_000_000_000_000]);
        assert_eq!(table.get_float_array(0, 4), vec![1.5, 2.5]);
        assert_eq!(table.get_double_array(0, 5), vec![3.5, 4.5]);
        assert_eq!(
            table.get_string_array(0, 6),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn object_column_roundtrip_and_missing_row_yields_unit() {
        let mut table = ManagedDataTable::new();
        table.put_object(5, 0, Box::new(123i32));

        let value = table.get_object(5, 0);
        assert_eq!(value.downcast_ref::<i32>(), Some(&123));

        // Row 0 in the same (now-existing) Object column was never written.
        let empty = table.get_object(0, 0);
        assert_eq!(empty.downcast_ref::<()>(), Some(&()));
    }

    #[test]
    fn remove_row_clears_data_and_occupied() {
        let mut table = ManagedDataTable::new();
        table.put_int(2, 0, 42);
        table.remove_row(2);
        assert!(!table.has_row(2));
        assert_eq!(table.get_int(2, 0), 0);
    }

    #[test]
    fn remove_row_on_unoccupied_row_is_noop() {
        let mut table = ManagedDataTable::new();
        table.put_int(2, 0, 42);
        table.remove_row(99);
        assert!(table.has_row(2));
        assert_eq!(table.get_int(2, 0), 42);
    }

    #[test]
    fn remove_row_updates_max_row_to_next_occupied_row_below() {
        let mut table = ManagedDataTable::new();
        table.put_int(1, 0, 1);
        table.put_int(5, 0, 5);
        assert_eq!(table.get_max_row(), 5);

        table.remove_row(5);
        assert_eq!(table.get_max_row(), 1);
    }

    /// Faithful port of a real quirk: when the last occupied row is removed, `maxRow`
    /// resets to `0` (not `-1`), even though row `0` may never have held data.
    #[test]
    fn remove_row_resets_max_row_to_zero_when_no_rows_remain() {
        let mut table = ManagedDataTable::new();
        table.put_int(5, 0, 5);
        assert_eq!(table.get_max_row(), 5);

        table.remove_row(5);
        assert_eq!(table.get_max_row(), 0);
        assert!(!table.has_row(0));
    }

    #[test]
    #[should_panic(expected = "ClassCastException")]
    fn put_wrong_type_on_existing_column_panics() {
        let mut table = ManagedDataTable::new();
        table.put_int(0, 0, 1);
        table.put_string(0, 0, "oops".to_string());
    }

    #[test]
    #[should_panic(expected = "NullPointerException")]
    fn get_never_written_column_panics() {
        let mut table = ManagedDataTable::new();
        // Grows data_columns to length 4 (cols 0..=3), leaving col 1 unset (`None`).
        table.put_int(0, 3, 1);
        table.get_boolean(0, 1);
    }

    #[test]
    #[should_panic(expected = "ArrayIndexOutOfBoundsException")]
    fn get_out_of_range_column_panics() {
        let table = ManagedDataTable::new();
        table.get_int(0, 0);
    }

    #[test]
    fn copy_row_to_copies_populated_columns() {
        let mut src = ManagedDataTable::new();
        src.put_int(0, 0, 42);
        src.put_string(0, 1, "hi".to_string());
        src.put_byte_array(0, 2, vec![9, 8, 7]);

        let mut dst = ManagedDataTable::new();
        src.copy_row_to(0, &mut dst, 3);

        assert_eq!(dst.get_int(3, 0), 42);
        assert_eq!(dst.get_string(3, 1), "hi");
        assert_eq!(dst.get_byte_array(3, 2), vec![9, 8, 7]);
        assert!(dst.has_row(3));
    }

    #[test]
    fn default_matches_new() {
        let table = ManagedDataTable::default();
        assert!(!table.has_row(0));
        assert_eq!(table.get_max_row(), 0);
    }
}
