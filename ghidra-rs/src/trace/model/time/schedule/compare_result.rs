/// The result of a rich comparison of two schedules (or parts thereof).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareResult {
    UnrelLt,
    RelLt,
    Equals,
    RelGt,
    UnrelGt,
}

impl CompareResult {
    /// Returns the integer ordering value: -1, 0, or 1.
    pub fn compare_to(self) -> i32 {
        match self {
            CompareResult::UnrelLt | CompareResult::RelLt => -1,
            CompareResult::Equals => 0,
            CompareResult::RelGt | CompareResult::UnrelGt => 1,
        }
    }

    /// Returns whether the two compared items are related.
    pub fn related(self) -> bool {
        match self {
            CompareResult::RelLt | CompareResult::Equals | CompareResult::RelGt => true,
            CompareResult::UnrelLt | CompareResult::UnrelGt => false,
        }
    }

    /// Enrich a standard `cmp` result, given that the two items are related.
    pub fn from_related(compare_to: i32) -> Self {
        if compare_to < 0 {
            CompareResult::RelLt
        } else if compare_to > 0 {
            CompareResult::RelGt
        } else {
            CompareResult::Equals
        }
    }

    /// Enrich a standard `cmp` result, given that the two items are not related.
    pub fn from_unrelated(compare_to: i32) -> Self {
        if compare_to < 0 {
            CompareResult::UnrelLt
        } else if compare_to > 0 {
            CompareResult::UnrelGt
        } else {
            CompareResult::Equals
        }
    }

    /// Maintain sort order from another rich comparison result, but mark the two as unrelated.
    pub fn unrelated(result: CompareResult) -> Self {
        Self::from_unrelated(result.compare_to())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_related_negative() {
        assert_eq!(CompareResult::from_related(-5), CompareResult::RelLt);
    }

    #[test]
    fn test_from_related_positive() {
        assert_eq!(CompareResult::from_related(3), CompareResult::RelGt);
    }

    #[test]
    fn test_from_related_zero() {
        assert_eq!(CompareResult::from_related(0), CompareResult::Equals);
    }

    #[test]
    fn test_from_unrelated_negative() {
        assert_eq!(CompareResult::from_unrelated(-1), CompareResult::UnrelLt);
    }

    #[test]
    fn test_from_unrelated_positive() {
        assert_eq!(CompareResult::from_unrelated(1), CompareResult::UnrelGt);
    }

    #[test]
    fn test_from_unrelated_zero() {
        assert_eq!(CompareResult::from_unrelated(0), CompareResult::Equals);
    }

    #[test]
    fn test_unrelated_strips_relation() {
        assert_eq!(CompareResult::unrelated(CompareResult::RelLt), CompareResult::UnrelLt);
        assert_eq!(CompareResult::unrelated(CompareResult::RelGt), CompareResult::UnrelGt);
        assert_eq!(CompareResult::unrelated(CompareResult::Equals), CompareResult::Equals);
        assert_eq!(CompareResult::unrelated(CompareResult::UnrelLt), CompareResult::UnrelLt);
        assert_eq!(CompareResult::unrelated(CompareResult::UnrelGt), CompareResult::UnrelGt);
    }

    #[test]
    fn test_compare_to_values() {
        assert_eq!(CompareResult::UnrelLt.compare_to(), -1);
        assert_eq!(CompareResult::RelLt.compare_to(), -1);
        assert_eq!(CompareResult::Equals.compare_to(), 0);
        assert_eq!(CompareResult::RelGt.compare_to(), 1);
        assert_eq!(CompareResult::UnrelGt.compare_to(), 1);
    }

    #[test]
    fn test_related_flags() {
        assert!(!CompareResult::UnrelLt.related());
        assert!(CompareResult::RelLt.related());
        assert!(CompareResult::Equals.related());
        assert!(CompareResult::RelGt.related());
        assert!(!CompareResult::UnrelGt.related());
    }
}
