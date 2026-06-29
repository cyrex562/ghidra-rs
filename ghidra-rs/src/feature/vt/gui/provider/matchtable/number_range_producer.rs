/// Produces two numbers that define a numeric range.
///
/// Mirrors `NumberRangeProducer` from the Java source.
pub trait NumberRangeProducer {
    /// Returns the lower bound of the range, or `None` if not set.
    fn lower_number(&self) -> Option<f64>;

    /// Returns the upper bound of the range, or `None` if not set.
    fn upper_number(&self) -> Option<f64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRange {
        lower: Option<f64>,
        upper: Option<f64>,
    }

    impl NumberRangeProducer for FixedRange {
        fn lower_number(&self) -> Option<f64> {
            self.lower
        }

        fn upper_number(&self) -> Option<f64> {
            self.upper
        }
    }

    #[test]
    fn both_bounds_present() {
        let r = FixedRange { lower: Some(1.0), upper: Some(10.0) };
        assert_eq!(r.lower_number(), Some(1.0));
        assert_eq!(r.upper_number(), Some(10.0));
    }

    #[test]
    fn both_bounds_absent() {
        let r = FixedRange { lower: None, upper: None };
        assert!(r.lower_number().is_none());
        assert!(r.upper_number().is_none());
    }

    #[test]
    fn lower_only() {
        let r = FixedRange { lower: Some(5.0), upper: None };
        assert_eq!(r.lower_number(), Some(5.0));
        assert!(r.upper_number().is_none());
    }

    #[test]
    fn upper_only() {
        let r = FixedRange { lower: None, upper: Some(42.5) };
        assert!(r.lower_number().is_none());
        assert_eq!(r.upper_number(), Some(42.5));
    }

    #[test]
    fn negative_bounds() {
        let r = FixedRange { lower: Some(-100.0), upper: Some(-1.0) };
        assert_eq!(r.lower_number(), Some(-100.0));
        assert_eq!(r.upper_number(), Some(-1.0));
    }
}
