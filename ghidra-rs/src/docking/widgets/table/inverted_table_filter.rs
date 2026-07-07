use std::any::Any;

use crate::docking::widgets::table::TableFilter;

/// Inverts another [`TableFilter`], accepting rows that would have been rejected and vice versa.
///
/// Note that inverted filters cannot add back data that has already been filtered out by
/// a previous filter. Thus, an inverted filter is never a sub-filter of any other filter.
///
/// Corresponds to `docking.widgets.table.InvertedTableFilter` in the Java source.
pub struct InvertedTableFilter<T> {
    filter: Box<dyn TableFilter<T>>,
}

impl<T: 'static> InvertedTableFilter<T> {
    /// Creates a new inverted filter that wraps the given filter.
    pub fn new(filter: Box<dyn TableFilter<T>>) -> Self {
        InvertedTableFilter { filter }
    }
}

impl<T: 'static> TableFilter<T> for InvertedTableFilter<T> {
    fn accepts_row(&self, row_object: &T) -> bool {
        !self.filter.accepts_row(row_object)
    }

    fn is_sub_filter_of(&self, _table_filter: &dyn Any) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MinFilter(i32);

    impl TableFilter<i32> for MinFilter {
        fn accepts_row(&self, row_object: &i32) -> bool {
            *row_object >= self.0
        }

        fn is_sub_filter_of(&self, _table_filter: &dyn Any) -> bool {
            false
        }
    }

    #[test]
    fn inverts_accepts_row() {
        let min_filter = Box::new(MinFilter(5)) as Box<dyn TableFilter<i32>>;
        let inverted = InvertedTableFilter::new(min_filter);

        assert!(!inverted.accepts_row(&10));
        assert!(!inverted.accepts_row(&5));
        assert!(inverted.accepts_row(&4));
        assert!(inverted.accepts_row(&0));
    }

    #[test]
    fn rejects_row_accepted_by_wrapped_filter() {
        let min_filter = Box::new(MinFilter(7)) as Box<dyn TableFilter<i32>>;
        let inverted = InvertedTableFilter::new(min_filter);

        assert!(!inverted.accepts_row(&100));
        assert!(!inverted.accepts_row(&7));
    }

    #[test]
    fn accepts_row_rejected_by_wrapped_filter() {
        let min_filter = Box::new(MinFilter(7)) as Box<dyn TableFilter<i32>>;
        let inverted = InvertedTableFilter::new(min_filter);

        assert!(inverted.accepts_row(&6));
        assert!(inverted.accepts_row(&0));
    }

    #[test]
    fn is_sub_filter_of_always_false() {
        let min_filter = Box::new(MinFilter(5)) as Box<dyn TableFilter<i32>>;
        let inverted = InvertedTableFilter::new(min_filter);

        assert!(!inverted.is_sub_filter_of(&inverted as &dyn Any));
        assert!(!inverted.is_sub_filter_of(&MinFilter(3) as &dyn Any));
    }
}
