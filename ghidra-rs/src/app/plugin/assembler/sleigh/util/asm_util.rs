use std::cmp::Ordering;

/// Compare two slices by their corresponding elements in order.
///
/// If the slices have differing lengths, the shorter precedes the longer.
/// Otherwise each corresponding pair of elements is compared in sequence.
/// This is analogous to lexicographic (`String`) comparison.
///
/// Mirrors `AsmUtil.compareInOrder`.
pub fn compare_in_order<T: Ord>(a: &[T], b: &[T]) -> Ordering {
    let len_ord = a.len().cmp(&b.len());
    if len_ord != Ordering::Equal {
        return len_ord;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = x.cmp(y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Compare two signed-byte arrays by their corresponding entries.
///
/// If the arrays have differing lengths, the shorter precedes the longer.
/// Otherwise they are compared element-by-element using signed comparison,
/// matching Java's signed `byte` semantics.
///
/// Mirrors `AsmUtil.compareArrays`.
pub fn compare_arrays(a: &[i8], b: &[i8]) -> Ordering {
    let len_ord = a.len().cmp(&b.len());
    if len_ord != Ordering::Equal {
        return len_ord;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = x.cmp(y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Return a new `Vec` containing all elements of `list` followed by `ext`.
///
/// Mirrors `AsmUtil.extendList`, which returns an immutable copy of the list
/// with the given element appended.
pub fn extend_list<T: Clone>(list: &[T], ext: T) -> Vec<T> {
    let mut result = list.to_vec();
    result.push(ext);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- compare_in_order ---

    #[test]
    fn compare_in_order_equal_empty() {
        let a: &[i32] = &[];
        let b: &[i32] = &[];
        assert_eq!(compare_in_order(a, b), Ordering::Equal);
    }

    #[test]
    fn compare_in_order_shorter_precedes_longer() {
        let a = &[1, 2];
        let b = &[1, 2, 3];
        assert_eq!(compare_in_order(a, b), Ordering::Less);
    }

    #[test]
    fn compare_in_order_longer_after_shorter() {
        let a = &[1, 2, 3];
        let b = &[1, 2];
        assert_eq!(compare_in_order(a, b), Ordering::Greater);
    }

    #[test]
    fn compare_in_order_equal_elements() {
        let a = &[1, 2, 3];
        let b = &[1, 2, 3];
        assert_eq!(compare_in_order(a, b), Ordering::Equal);
    }

    #[test]
    fn compare_in_order_first_differing_element_decides() {
        let a = &[1, 2, 3];
        let b = &[1, 3, 3];
        assert_eq!(compare_in_order(a, b), Ordering::Less);
    }

    #[test]
    fn compare_in_order_later_elements_ignored_after_first_diff() {
        let a = &[1, 9, 9];
        let b = &[2, 1, 1];
        assert_eq!(compare_in_order(a, b), Ordering::Less);
    }

    // --- compare_arrays ---

    #[test]
    fn compare_arrays_equal_empty() {
        assert_eq!(compare_arrays(&[], &[]), Ordering::Equal);
    }

    #[test]
    fn compare_arrays_shorter_precedes_longer() {
        assert_eq!(compare_arrays(&[1i8, 2], &[1i8, 2, 3]), Ordering::Less);
    }

    #[test]
    fn compare_arrays_longer_after_shorter() {
        assert_eq!(compare_arrays(&[1i8, 2, 3], &[1i8, 2]), Ordering::Greater);
    }

    #[test]
    fn compare_arrays_equal() {
        assert_eq!(compare_arrays(&[1i8, 2, 3], &[1i8, 2, 3]), Ordering::Equal);
    }

    #[test]
    fn compare_arrays_signed_negative_less_than_positive() {
        assert_eq!(compare_arrays(&[-1i8], &[1i8]), Ordering::Less);
    }

    #[test]
    fn compare_arrays_signed_positive_greater_than_negative() {
        assert_eq!(compare_arrays(&[1i8], &[-1i8]), Ordering::Greater);
    }

    #[test]
    fn compare_arrays_first_differing_byte_decides() {
        assert_eq!(compare_arrays(&[0i8, 5], &[0i8, 3]), Ordering::Greater);
    }

    // --- extend_list ---

    #[test]
    fn extend_list_appends_element() {
        let v = extend_list(&[1, 2, 3], 4);
        assert_eq!(v, vec![1, 2, 3, 4]);
    }

    #[test]
    fn extend_list_from_empty() {
        let v = extend_list(&[], 42);
        assert_eq!(v, vec![42]);
    }

    #[test]
    fn extend_list_does_not_mutate_original() {
        let original = vec![1, 2, 3];
        let extended = extend_list(&original, 4);
        assert_eq!(original, vec![1, 2, 3]);
        assert_eq!(extended, vec![1, 2, 3, 4]);
    }

    #[test]
    fn extend_list_length_is_one_more() {
        let original = vec![10, 20];
        let extended = extend_list(&original, 30);
        assert_eq!(extended.len(), original.len() + 1);
    }

    #[test]
    fn extend_list_works_with_strings() {
        let v = extend_list(&["a", "b"], "c");
        assert_eq!(v, vec!["a", "b", "c"]);
    }
}
