use std::any::Any;

/// A filter that determines which rows are accepted in a table widget.
///
/// Corresponds to `docking.widgets.table.TableFilter` in the Java source.
///
/// `Any` is a supertrait so that callers holding only a type-erased `&dyn TableFilter<R>`
/// (for example, elements of a boxed collection) can still upcast to `&dyn Any` and downcast
/// to a concrete filter type, matching the way [`is_sub_filter_of`](Self::is_sub_filter_of)
/// is used.
pub trait TableFilter<R>: Any {
    /// Returns true if this filter accepts the given row object.
    fn accepts_row(&self, row_object: &R) -> bool;

    /// Returns true if this filter is a more specific version of the given filter.
    ///
    /// For example, a 'starts with' text filter for `"bobo"` is a sub-filter of
    /// a 'starts with' filter for `"bob"`, because every row accepted by `"bobo"`
    /// is also accepted by `"bob"`.
    ///
    /// The parameter uses `dyn Any` to mirror Java's `TableFilter<?>` wildcard,
    /// allowing callers to pass any filter type; implementors downcast as needed.
    fn is_sub_filter_of(&self, table_filter: &dyn Any) -> bool;

    /// Returns true if there is a column filter on the column at the given model index.
    fn has_column_filter(&self, column_model_index: usize) -> bool {
        let _ = column_model_index;
        false
    }

    /// Returns true if this filter will not perform any actual filtering.
    ///
    /// Useful for representing empty or null filter states.
    fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts rows whose value is at least `min`.
    struct MinFilter(i32);

    impl TableFilter<i32> for MinFilter {
        fn accepts_row(&self, row_object: &i32) -> bool {
            *row_object >= self.0
        }

        fn is_sub_filter_of(&self, table_filter: &dyn Any) -> bool {
            match table_filter.downcast_ref::<MinFilter>() {
                Some(other) => self.0 >= other.0,
                None => false,
            }
        }
    }

    /// A no-op filter that explicitly reports itself as empty.
    struct EmptyFilter;

    impl TableFilter<i32> for EmptyFilter {
        fn accepts_row(&self, _row_object: &i32) -> bool {
            true
        }

        fn is_sub_filter_of(&self, _table_filter: &dyn Any) -> bool {
            false
        }

        fn is_empty(&self) -> bool {
            true
        }
    }

    /// A filter that tracks a specific column index.
    struct ColumnFilter(usize);

    impl TableFilter<i32> for ColumnFilter {
        fn accepts_row(&self, _row_object: &i32) -> bool {
            true
        }

        fn is_sub_filter_of(&self, _table_filter: &dyn Any) -> bool {
            false
        }

        fn has_column_filter(&self, column_model_index: usize) -> bool {
            column_model_index == self.0
        }
    }

    #[test]
    fn accepts_row_above_min() {
        let f = MinFilter(5);
        assert!(f.accepts_row(&5));
        assert!(f.accepts_row(&10));
    }

    #[test]
    fn rejects_row_below_min() {
        let f = MinFilter(5);
        assert!(!f.accepts_row(&4));
        assert!(!f.accepts_row(&0));
    }

    #[test]
    fn is_sub_filter_of_stricter_filter() {
        let broad = MinFilter(3);
        let narrow = MinFilter(7);
        assert!(narrow.is_sub_filter_of(&broad));
    }

    #[test]
    fn equal_filter_is_not_sub_filter() {
        let a = MinFilter(5);
        let b = MinFilter(5);
        assert!(!a.is_sub_filter_of(&b));
    }

    #[test]
    fn broader_filter_is_not_sub_filter() {
        let broad = MinFilter(3);
        let narrow = MinFilter(7);
        assert!(!broad.is_sub_filter_of(&narrow));
    }

    #[test]
    fn is_sub_filter_of_incompatible_type_returns_false() {
        let f = MinFilter(5);
        let other = EmptyFilter;
        assert!(!f.is_sub_filter_of(&other));
    }

    #[test]
    fn default_has_column_filter_is_false() {
        let f = MinFilter(0);
        assert!(!f.has_column_filter(0));
        assert!(!f.has_column_filter(99));
    }

    #[test]
    fn custom_has_column_filter() {
        let f = ColumnFilter(2);
        assert!(f.has_column_filter(2));
        assert!(!f.has_column_filter(1));
        assert!(!f.has_column_filter(3));
    }

    #[test]
    fn default_is_empty_is_false() {
        let f = MinFilter(0);
        assert!(!f.is_empty());
    }

    #[test]
    fn custom_is_empty() {
        let f = EmptyFilter;
        assert!(f.is_empty());
    }
}
