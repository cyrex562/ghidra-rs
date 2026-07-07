use std::cmp::Ordering;

/// The result of testing a sub-tree for inclusion in a query.
///
/// Corresponds to `ghidra.util.database.spatial.Query.QueryInclusion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryInclusion {
    /// The query certainly includes all data in the sub-tree.
    All,
    /// The query may include some data in the sub-tree.
    Some,
    /// The query certainly excludes all data in the sub-tree.
    None,
}

/// A spatial query that tests data entries and node (bounding-box) entries for
/// inclusion, and optionally imposes an ordering over node bounds.
///
/// Corresponds to `ghidra.util.database.spatial.Query<DS, NS>`.
///
/// `DS` is the data-shape type; `NS` is the node (bounding) shape type.
pub trait Query<DS, NS> {
    /// Returns `true` if no data entry that follows the given `shape` in
    /// iteration order could possibly be included in the query, allowing
    /// early termination of data-entry iteration.
    fn terminate_early_data(&self, shape: &DS) -> bool;

    /// Returns `true` if the given data shape is included in the query.
    fn test_data(&self, shape: &DS) -> bool;

    /// Returns `true` if no node entry that follows the given `shape` in
    /// iteration order could possibly contain data entries included in the
    /// query, allowing early termination of node-entry iteration.
    fn terminate_early_node(&self, shape: &NS) -> bool;

    /// Tests whether the given node shape (bounds) has data entries included
    /// in the query.
    fn test_node(&self, shape: &NS) -> QueryInclusion;

    /// Returns a comparator over node bounds if the query defines an ordering,
    /// or `None` if the query imposes no ordering on elements.
    ///
    /// Corresponds to `getBoundsComparator()` in the Java source; the Java
    /// return type (`Comparator<NS>`) may be null, hence `Option` here.
    fn get_bounds_comparator(&self) -> Option<Box<dyn Fn(&NS, &NS) -> Ordering>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple 1-D interval used as both data shape and node shape in tests.
    #[derive(Debug, Clone, PartialEq)]
    struct Interval {
        lo: i64,
        hi: i64,
    }

    impl Interval {
        fn new(lo: i64, hi: i64) -> Self {
            Interval { lo, hi }
        }
    }

    /// A query that selects intervals overlapping `[query_lo, query_hi]`.
    struct OverlapQuery {
        lo: i64,
        hi: i64,
    }

    impl Query<Interval, Interval> for OverlapQuery {
        fn terminate_early_data(&self, shape: &Interval) -> bool {
            // If the interval starts beyond the query range, no later interval
            // (assuming sorted ascending by lo) can overlap.
            shape.lo > self.hi
        }

        fn test_data(&self, shape: &Interval) -> bool {
            shape.lo <= self.hi && shape.hi >= self.lo
        }

        fn terminate_early_node(&self, shape: &Interval) -> bool {
            shape.lo > self.hi
        }

        fn test_node(&self, shape: &Interval) -> QueryInclusion {
            if shape.hi < self.lo || shape.lo > self.hi {
                QueryInclusion::None
            } else if shape.lo >= self.lo && shape.hi <= self.hi {
                QueryInclusion::All
            } else {
                QueryInclusion::Some
            }
        }

        fn get_bounds_comparator(&self) -> Option<Box<dyn Fn(&Interval, &Interval) -> Ordering>> {
            Some(Box::new(|a: &Interval, b: &Interval| a.lo.cmp(&b.lo)))
        }
    }

    /// A query that accepts everything and imposes no ordering.
    struct AcceptAllQuery;

    impl Query<Interval, Interval> for AcceptAllQuery {
        fn terminate_early_data(&self, _shape: &Interval) -> bool {
            false
        }

        fn test_data(&self, _shape: &Interval) -> bool {
            true
        }

        fn terminate_early_node(&self, _shape: &Interval) -> bool {
            false
        }

        fn test_node(&self, _shape: &Interval) -> QueryInclusion {
            QueryInclusion::All
        }

        fn get_bounds_comparator(&self) -> Option<Box<dyn Fn(&Interval, &Interval) -> Ordering>> {
            None
        }
    }

    #[test]
    fn test_data_overlapping_interval_is_included() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        assert!(q.test_data(&Interval::new(3, 6)));
        assert!(q.test_data(&Interval::new(5, 10)));
        assert!(q.test_data(&Interval::new(9, 15)));
    }

    #[test]
    fn test_data_non_overlapping_interval_is_excluded() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        assert!(!q.test_data(&Interval::new(0, 4)));
        assert!(!q.test_data(&Interval::new(11, 20)));
    }

    #[test]
    fn terminate_early_data_triggers_past_range() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        assert!(!q.terminate_early_data(&Interval::new(8, 12)));
        assert!(q.terminate_early_data(&Interval::new(11, 15)));
    }

    #[test]
    fn test_node_returns_all_when_fully_contained() {
        let q = OverlapQuery { lo: 0, hi: 20 };
        assert_eq!(q.test_node(&Interval::new(5, 10)), QueryInclusion::All);
    }

    #[test]
    fn test_node_returns_some_when_partially_overlapping() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        assert_eq!(q.test_node(&Interval::new(0, 7)), QueryInclusion::Some);
    }

    #[test]
    fn test_node_returns_none_when_disjoint() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        assert_eq!(q.test_node(&Interval::new(15, 20)), QueryInclusion::None);
        assert_eq!(q.test_node(&Interval::new(0, 3)), QueryInclusion::None);
    }

    #[test]
    fn terminate_early_node_triggers_past_range() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        assert!(!q.terminate_early_node(&Interval::new(8, 12)));
        assert!(q.terminate_early_node(&Interval::new(11, 15)));
    }

    #[test]
    fn get_bounds_comparator_orders_by_lo() {
        let q = OverlapQuery { lo: 5, hi: 10 };
        let cmp = q.get_bounds_comparator().expect("comparator expected");
        let a = Interval::new(1, 5);
        let b = Interval::new(3, 8);
        assert_eq!(cmp(&a, &b), Ordering::Less);
        assert_eq!(cmp(&b, &a), Ordering::Greater);
        assert_eq!(cmp(&a, &a), Ordering::Equal);
    }

    #[test]
    fn accept_all_query_includes_everything() {
        let q = AcceptAllQuery;
        assert!(q.test_data(&Interval::new(0, 100)));
        assert_eq!(q.test_node(&Interval::new(0, 100)), QueryInclusion::All);
        assert!(!q.terminate_early_data(&Interval::new(999, 9999)));
        assert!(!q.terminate_early_node(&Interval::new(999, 9999)));
    }

    #[test]
    fn accept_all_query_has_no_comparator() {
        let q = AcceptAllQuery;
        assert!(q.get_bounds_comparator().is_none());
    }
}
