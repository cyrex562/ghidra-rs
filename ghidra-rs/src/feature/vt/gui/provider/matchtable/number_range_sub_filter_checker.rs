/// Checks to see if one number range is a subset of the other.
///
/// Mirrors `NumberRangeSubFilterChecker` from the Java source.
use super::number_range_producer::NumberRangeProducer;

/// Returns true if filter 'a' is a more specific version of filter 'b'.
///
/// For a range to be a sub-filter, its lower bound must be greater than or equal to the
/// other filter's lower bound, and its upper bound must be less than or equal to the other
/// filter's upper bound. In this way, the range is inside of the other range.
pub fn is_sub_filter_of(
    a: &dyn NumberRangeProducer,
    b: &dyn NumberRangeProducer,
) -> bool {
    let lower_a = a.lower_number();
    let lower_b = b.lower_number();
    if !is_greater_than_or_equal(lower_a, lower_b) {
        return false;
    }

    let upper_a = a.upper_number();
    let upper_b = b.upper_number();
    if !is_less_than_or_equal(upper_a, upper_b) {
        return false;
    }

    true
}

fn is_greater_than_or_equal(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(a_val), Some(b_val)) => a_val >= b_val,
        (None, None) => true,
        _ => false,
    }
}

fn is_less_than_or_equal(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(a_val), Some(b_val)) => a_val <= b_val,
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRange {
        lower: Option<f64>,
        upper: Option<f64>,
    }

    impl NumberRangeProducer for TestRange {
        fn lower_number(&self) -> Option<f64> {
            self.lower
        }

        fn upper_number(&self) -> Option<f64> {
            self.upper
        }
    }

    #[test]
    fn sub_filter_fully_contained() {
        let a = TestRange { lower: Some(3.0), upper: Some(7.0) };
        let b = TestRange { lower: Some(1.0), upper: Some(10.0) };
        assert!(is_sub_filter_of(&a, &b));
    }

    #[test]
    fn same_range_is_sub_filter() {
        let a = TestRange { lower: Some(1.0), upper: Some(10.0) };
        let b = TestRange { lower: Some(1.0), upper: Some(10.0) };
        assert!(is_sub_filter_of(&a, &b));
    }

    #[test]
    fn larger_range_not_sub_filter() {
        let a = TestRange { lower: Some(1.0), upper: Some(10.0) };
        let b = TestRange { lower: Some(3.0), upper: Some(7.0) };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn lower_bound_exceeds_parent() {
        let a = TestRange { lower: Some(11.0), upper: Some(15.0) };
        let b = TestRange { lower: Some(1.0), upper: Some(10.0) };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn upper_bound_exceeds_parent() {
        let a = TestRange { lower: Some(5.0), upper: Some(11.0) };
        let b = TestRange { lower: Some(1.0), upper: Some(10.0) };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn both_bounds_none_is_sub_filter() {
        let a = TestRange { lower: None, upper: None };
        let b = TestRange { lower: None, upper: None };
        assert!(is_sub_filter_of(&a, &b));
    }

    #[test]
    fn none_lower_bound_in_child_fails() {
        let a = TestRange { lower: None, upper: Some(7.0) };
        let b = TestRange { lower: Some(1.0), upper: Some(10.0) };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn none_upper_bound_in_child_fails() {
        let a = TestRange { lower: Some(3.0), upper: None };
        let b = TestRange { lower: Some(1.0), upper: Some(10.0) };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn none_lower_bound_in_parent_fails() {
        let a = TestRange { lower: Some(3.0), upper: Some(7.0) };
        let b = TestRange { lower: None, upper: Some(10.0) };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn none_upper_bound_in_parent_fails() {
        let a = TestRange { lower: Some(3.0), upper: Some(7.0) };
        let b = TestRange { lower: Some(1.0), upper: None };
        assert!(!is_sub_filter_of(&a, &b));
    }

    #[test]
    fn negative_numbers() {
        let a = TestRange { lower: Some(-8.0), upper: Some(-2.0) };
        let b = TestRange { lower: Some(-10.0), upper: Some(0.0) };
        assert!(is_sub_filter_of(&a, &b));
    }

    #[test]
    fn floating_point_precision() {
        let a = TestRange { lower: Some(1.5), upper: Some(2.5) };
        let b = TestRange { lower: Some(1.0), upper: Some(3.0) };
        assert!(is_sub_filter_of(&a, &b));
    }
}
