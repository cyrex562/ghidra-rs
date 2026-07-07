/// Null-safe equality check for two optional references.
///
/// Returns `true` if both are `None`, or if both are `Some` and the inner values compare equal.
///
/// Mirrors `GSystemUtilities.isEqual(Object, Object)`.
pub fn is_equal<T: PartialEq>(o1: Option<&T>, o2: Option<&T>) -> bool {
    o1 == o2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_none_returns_true() {
        assert!(is_equal::<i32>(None, None));
    }

    #[test]
    fn first_none_second_some_returns_false() {
        assert!(!is_equal(None, Some(&1)));
    }

    #[test]
    fn first_some_second_none_returns_false() {
        assert!(!is_equal(Some(&1), None));
    }

    #[test]
    fn both_some_equal_values_returns_true() {
        assert!(is_equal(Some(&42), Some(&42)));
    }

    #[test]
    fn both_some_unequal_values_returns_false() {
        assert!(!is_equal(Some(&42), Some(&99)));
    }

    #[test]
    fn string_equal() {
        assert!(is_equal(Some(&"hello"), Some(&"hello")));
    }

    #[test]
    fn string_unequal() {
        assert!(!is_equal(Some(&"foo"), Some(&"bar")));
    }
}
