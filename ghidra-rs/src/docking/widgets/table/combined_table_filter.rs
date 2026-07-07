use std::any::Any;

use crate::docking::widgets::table::TableFilter;

/// Combines multiple table filters into a single [`TableFilter`] that can be applied. All
/// contained filters must pass for this combined filter to pass.
///
/// Corresponds to `docking.widgets.table.CombinedTableFilter` in the Java source.
pub struct CombinedTableFilter<T> {
    filters: Vec<Box<dyn TableFilter<T>>>,
}

impl<T: 'static> CombinedTableFilter<T> {
    /// Creates a combined filter from up to three sub-filters, skipping any that are `None`.
    pub fn new(
        filter1: Option<Box<dyn TableFilter<T>>>,
        filter2: Option<Box<dyn TableFilter<T>>>,
        filter3: Option<Box<dyn TableFilter<T>>>,
    ) -> Self {
        let mut filters: Vec<Box<dyn TableFilter<T>>> = Vec::new();
        Self::add_if_not_null(&mut filters, filter1);
        Self::add_if_not_null(&mut filters, filter2);
        Self::add_if_not_null(&mut filters, filter3);
        Self { filters }
    }

    fn add_if_not_null(
        filters: &mut Vec<Box<dyn TableFilter<T>>>,
        filter: Option<Box<dyn TableFilter<T>>>,
    ) {
        if let Some(filter) = filter {
            filters.push(filter);
        }
    }

    /// Returns the number of sub-filters in this combined filter.
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }

    /// Returns the filter at the given index into the list of sub filters.
    pub fn filter(&self, index: usize) -> &dyn TableFilter<T> {
        self.filters[index].as_ref()
    }
}

impl<T: 'static> TableFilter<T> for CombinedTableFilter<T> {
    fn accepts_row(&self, row_object: &T) -> bool {
        self.filters.iter().all(|filter| filter.accepts_row(row_object))
    }

    fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    fn is_sub_filter_of(&self, table_filter: &dyn Any) -> bool {
        let other = match table_filter.downcast_ref::<CombinedTableFilter<T>>() {
            Some(other) => other,
            None => return false,
        };

        if self.filter_count() != other.filter_count() {
            return false;
        }
        if self.filter_count() == 0 {
            // if we are both empty then not a sub filter
            return false;
        }
        for i in 0..self.filter_count() {
            // Mirror Java: getFilter(i).isSubFilterOf(other.getFilter(i)).
            let other_filter = other.filter(i) as &dyn Any;
            if !self.filter(i).is_sub_filter_of(other_filter) {
                return false;
            }
        }
        true
    }

    fn has_column_filter(&self, model_index: usize) -> bool {
        self.filters.iter().any(|filter| filter.has_column_filter(model_index))
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

        fn is_sub_filter_of(&self, table_filter: &dyn Any) -> bool {
            match table_filter.downcast_ref::<MinFilter>() {
                Some(other) => self.0 >= other.0,
                None => false,
            }
        }
    }

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
    fn empty_when_all_filters_null() {
        let combined: CombinedTableFilter<i32> = CombinedTableFilter::new(None, None, None);
        assert!(combined.is_empty());
        assert_eq!(combined.filter_count(), 0);
    }

    #[test]
    fn skips_null_filters() {
        let combined = CombinedTableFilter::new(
            Some(Box::new(MinFilter(1)) as Box<dyn TableFilter<i32>>),
            None,
            Some(Box::new(MinFilter(2)) as Box<dyn TableFilter<i32>>),
        );
        assert!(!combined.is_empty());
        assert_eq!(combined.filter_count(), 2);
    }

    #[test]
    fn accepts_row_requires_all_filters_to_pass() {
        let combined = CombinedTableFilter::new(
            Some(Box::new(MinFilter(1)) as Box<dyn TableFilter<i32>>),
            Some(Box::new(MinFilter(5)) as Box<dyn TableFilter<i32>>),
            None,
        );
        assert!(combined.accepts_row(&10));
        assert!(!combined.accepts_row(&3));
    }

    #[test]
    fn accepts_row_true_when_no_filters() {
        let combined: CombinedTableFilter<i32> = CombinedTableFilter::new(None, None, None);
        assert!(combined.accepts_row(&0));
    }

    #[test]
    fn has_column_filter_true_if_any_sub_filter_has_it() {
        let combined = CombinedTableFilter::new(
            Some(Box::new(MinFilter(1)) as Box<dyn TableFilter<i32>>),
            Some(Box::new(ColumnFilter(2)) as Box<dyn TableFilter<i32>>),
            None,
        );
        assert!(combined.has_column_filter(2));
        assert!(!combined.has_column_filter(3));
    }

    #[test]
    fn is_sub_filter_of_false_for_non_combined_filter() {
        let combined = CombinedTableFilter::new(
            Some(Box::new(MinFilter(1)) as Box<dyn TableFilter<i32>>),
            None,
            None,
        );
        let other = MinFilter(1);
        assert!(!combined.is_sub_filter_of(&other as &dyn Any));
    }

    #[test]
    fn is_sub_filter_of_false_when_counts_differ() {
        let narrow = CombinedTableFilter::new(
            Some(Box::new(MinFilter(1)) as Box<dyn TableFilter<i32>>),
            None,
            None,
        );
        let broad = CombinedTableFilter::new(
            Some(Box::new(MinFilter(1)) as Box<dyn TableFilter<i32>>),
            Some(Box::new(MinFilter(2)) as Box<dyn TableFilter<i32>>),
            None,
        );
        assert!(!narrow.is_sub_filter_of(&broad as &dyn Any));
    }

    #[test]
    fn is_sub_filter_of_false_when_both_empty() {
        let a: CombinedTableFilter<i32> = CombinedTableFilter::new(None, None, None);
        let b: CombinedTableFilter<i32> = CombinedTableFilter::new(None, None, None);
        assert!(!a.is_sub_filter_of(&b as &dyn Any));
    }

    #[test]
    fn is_sub_filter_of_true_when_each_sub_filter_is_stricter() {
        let narrow = CombinedTableFilter::new(
            Some(Box::new(MinFilter(7)) as Box<dyn TableFilter<i32>>),
            Some(Box::new(MinFilter(10)) as Box<dyn TableFilter<i32>>),
            None,
        );
        let broad = CombinedTableFilter::new(
            Some(Box::new(MinFilter(3)) as Box<dyn TableFilter<i32>>),
            Some(Box::new(MinFilter(5)) as Box<dyn TableFilter<i32>>),
            None,
        );
        assert!(narrow.is_sub_filter_of(&broad as &dyn Any));
        assert!(!broad.is_sub_filter_of(&narrow as &dyn Any));
    }
}
