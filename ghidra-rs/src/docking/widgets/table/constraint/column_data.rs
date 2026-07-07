use std::any::Any;

/// Provides column data and a table's data source to a constraint editor.
///
/// Some editors require access to the table column data. For example, a "Starts With" string
/// column might pre-process the data to provide an autocompletion feature in the editor.
///
/// Corresponds to `docking.widgets.table.constraint.ColumnData` in the Java source.
pub trait ColumnData<T> {
    /// Returns the name of the column being filtered.
    fn column_name(&self) -> &str;

    /// Returns the number of column values (unfiltered table row count).
    fn count(&self) -> usize;

    /// Returns the column value for the given row.
    fn column_value(&self, row: usize) -> T;

    /// Returns the table's data source.
    fn table_data_source(&self) -> &dyn Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecColumnData<T: Clone> {
        name: String,
        values: Vec<T>,
        source: String,
    }

    impl<T: Clone + 'static> ColumnData<T> for VecColumnData<T> {
        fn column_name(&self) -> &str {
            &self.name
        }

        fn count(&self) -> usize {
            self.values.len()
        }

        fn column_value(&self, row: usize) -> T {
            self.values[row].clone()
        }

        fn table_data_source(&self) -> &dyn Any {
            &self.source
        }
    }

    #[test]
    fn column_name_returns_name() {
        let data = VecColumnData {
            name: "Score".to_string(),
            values: vec![1_i32, 2, 3],
            source: "src".to_string(),
        };
        assert_eq!(data.column_name(), "Score");
    }

    #[test]
    fn count_reflects_row_count() {
        let data = VecColumnData {
            name: "X".to_string(),
            values: vec![10_i32, 20, 30, 40],
            source: "s".to_string(),
        };
        assert_eq!(data.count(), 4);
    }

    #[test]
    fn count_is_zero_when_empty() {
        let data: VecColumnData<i32> = VecColumnData {
            name: "Empty".to_string(),
            values: vec![],
            source: "s".to_string(),
        };
        assert_eq!(data.count(), 0);
    }

    #[test]
    fn column_value_returns_correct_element() {
        let data = VecColumnData {
            name: "N".to_string(),
            values: vec!["alpha", "beta", "gamma"],
            source: "s".to_string(),
        };
        assert_eq!(data.column_value(0), "alpha");
        assert_eq!(data.column_value(2), "gamma");
    }

    #[test]
    fn table_data_source_downcasts_to_concrete_type() {
        let data = VecColumnData {
            name: "N".to_string(),
            values: vec![1_i32],
            source: "my_source".to_string(),
        };
        let src = data.table_data_source();
        let s = src.downcast_ref::<String>().expect("source should be String");
        assert_eq!(s, "my_source");
    }
}
