use std::any::Any;

use crate::docking::widgets::table::TableFilter;

/// A table filter that represents the state of having no filter applied.
///
/// This allows representing the "no filter" state without using `null`. Returns `true` for
/// all rows (accepts everything) and is never a sub-filter of any other filter.
///
/// Corresponds to `docking.widgets.table.threaded.NullTableFilter` in the Java source.
#[derive(Debug)]
pub struct NullTableFilter<R> {
    _phantom: std::marker::PhantomData<R>,
}

impl<R: 'static> NullTableFilter<R> {
    /// Creates a new null filter that accepts all rows.
    pub fn new() -> Self {
        NullTableFilter {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R: 'static> Default for NullTableFilter<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: 'static> TableFilter<R> for NullTableFilter<R> {
    fn accepts_row(&self, _row_object: &R) -> bool {
        true
    }

    fn is_sub_filter_of(&self, _table_filter: &dyn Any) -> bool {
        false
    }

    fn is_empty(&self) -> bool {
        true
    }
}

impl<R> PartialEq for NullTableFilter<R> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<R> Eq for NullTableFilter<R> {}

impl<R> std::hash::Hash for NullTableFilter<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        "NullTableFilter".hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_rows() {
        let filter = NullTableFilter::<i32>::new();
        assert!(filter.accepts_row(&0));
        assert!(filter.accepts_row(&42));
        assert!(filter.accepts_row(&-100));
    }

    #[test]
    fn is_empty() {
        let filter = NullTableFilter::<i32>::new();
        assert!(filter.is_empty());
    }

    #[test]
    fn is_not_sub_filter() {
        let filter = NullTableFilter::<i32>::new();
        assert!(!filter.is_sub_filter_of(&filter as &dyn Any));
    }

    #[test]
    fn equality() {
        let filter1 = NullTableFilter::<i32>::new();
        let filter2 = NullTableFilter::<i32>::new();
        assert_eq!(filter1, filter2);
    }

    #[test]
    fn default_creates_filter() {
        let filter = NullTableFilter::<i32>::default();
        assert!(filter.accepts_row(&5));
        assert!(filter.is_empty());
    }

    #[test]
    fn hash_code_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let filter1 = NullTableFilter::<i32>::new();
        let filter2 = NullTableFilter::<i32>::new();

        let mut hasher1 = DefaultHasher::new();
        filter1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        filter2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn accepts_custom_objects() {
        #[derive(Clone)]
        struct CustomObject {
            value: String,
        }

        let filter = NullTableFilter::<CustomObject>::new();
        let obj = CustomObject {
            value: "test".to_string(),
        };
        assert!(filter.accepts_row(&obj));
    }
}
