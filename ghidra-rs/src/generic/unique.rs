/// Utilities for when singleton collections are expected.
///
/// Mirrors `generic.Unique` from Ghidra.

/// Assert that at most one element is in a slice and return a reference to it, or `None` if empty.
///
/// # Panics
///
/// Panics if the slice contains more than one element.
pub fn assert_at_most_one_arr<T>(arr: &[T]) -> Option<&T> {
    match arr.len() {
        0 => None,
        1 => Some(&arr[0]),
        _ => panic!("Expected at most one. Got many: {} elements", arr.len()),
    }
}

/// Assert that exactly one element is produced by `col` and return it.
///
/// # Panics
///
/// Panics if `col` is empty or yields more than one element.
pub fn assert_one<T>(col: impl IntoIterator<Item = T>) -> T {
    let mut it = col.into_iter();
    let Some(result) = it.next() else {
        panic!("Expected exactly one. Got none.");
    };
    if it.next().is_some() {
        panic!("Expected exactly one. Got many.");
    }
    result
}

/// Assert that at most one element is produced by `col` and return it, or `None` if empty.
///
/// # Panics
///
/// Panics if `col` yields more than one element.
pub fn assert_at_most_one<T>(col: impl IntoIterator<Item = T>) -> Option<T> {
    let mut it = col.into_iter();
    let Some(result) = it.next() else {
        return None;
    };
    if it.next().is_some() {
        panic!("Expected at most one. Got many.");
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_at_most_one_arr_empty() {
        let arr: &[i32] = &[];
        assert_eq!(assert_at_most_one_arr(arr), None);
    }

    #[test]
    fn test_assert_at_most_one_arr_single() {
        let arr = &[42i32];
        assert_eq!(assert_at_most_one_arr(arr), Some(&42));
    }

    #[test]
    #[should_panic(expected = "Expected at most one. Got many")]
    fn test_assert_at_most_one_arr_many() {
        let arr = &[1i32, 2];
        assert_at_most_one_arr(arr);
    }

    #[test]
    fn test_assert_one_single() {
        assert_eq!(assert_one(vec![99i32]), 99);
    }

    #[test]
    #[should_panic(expected = "Expected exactly one. Got none.")]
    fn test_assert_one_empty() {
        assert_one(Vec::<i32>::new());
    }

    #[test]
    #[should_panic(expected = "Expected exactly one. Got many.")]
    fn test_assert_one_many() {
        assert_one(vec![1i32, 2, 3]);
    }

    #[test]
    fn test_assert_one_iterator() {
        let result = assert_one(std::iter::once("hello"));
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_assert_at_most_one_empty() {
        assert_eq!(assert_at_most_one(Vec::<i32>::new()), None);
    }

    #[test]
    fn test_assert_at_most_one_single() {
        assert_eq!(assert_at_most_one(vec![7i32]), Some(7));
    }

    #[test]
    #[should_panic(expected = "Expected at most one. Got many.")]
    fn test_assert_at_most_one_many() {
        assert_at_most_one(vec![1i32, 2]);
    }

    #[test]
    fn test_assert_at_most_one_iterator() {
        let result = assert_at_most_one(std::iter::once(42u64));
        assert_eq!(result, Some(42));
    }
}
