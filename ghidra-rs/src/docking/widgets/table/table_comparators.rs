use std::cmp::Ordering;

/// Returns `Ordering::Equal` for any two values, effectively disabling sort order.
///
/// Use this as a sort comparator when you want to preserve insertion order.
pub fn no_sort_comparator<T>(_a: &T, _b: &T) -> Ordering {
    Ordering::Equal
}

/// Compares two optional values, treating `None` as less than any `Some` value.
///
/// Both-`None` → `Equal`; left-`None` → `Less`; right-`None` → `Greater`.
/// Callers invoke this only when at least one argument is `None`.
pub fn compare_with_null_values<T>(o1: Option<&T>, o2: Option<&T>) -> Ordering {
    if o1.is_none() && o2.is_none() {
        return Ordering::Equal;
    }
    if o1.is_none() {
        return Ordering::Less;
    }
    Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sort_always_equal() {
        assert_eq!(no_sort_comparator(&1, &2), Ordering::Equal);
        assert_eq!(no_sort_comparator(&"z", &"a"), Ordering::Equal);
        assert_eq!(no_sort_comparator(&42, &42), Ordering::Equal);
    }

    #[test]
    fn both_none_is_equal() {
        assert_eq!(compare_with_null_values::<i32>(None, None), Ordering::Equal);
    }

    #[test]
    fn left_none_is_less() {
        assert_eq!(compare_with_null_values(None, Some(&1)), Ordering::Less);
    }

    #[test]
    fn right_none_is_greater() {
        assert_eq!(compare_with_null_values(Some(&1), None), Ordering::Greater);
    }
}
