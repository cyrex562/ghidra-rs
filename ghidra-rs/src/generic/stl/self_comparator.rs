/// A comparator that orders values using their natural [`Ord`] ordering.
///
/// Mirrors `generic.stl.SelfComparator<T extends Comparable<T>>` from Ghidra.
/// The Java class implements `Comparator<T>` by delegating to `T.compareTo()`; this
/// struct provides the same semantics via [`Ord::cmp`].
pub struct SelfComparator<T: Ord> {
    _marker: std::marker::PhantomData<T>,
}

impl<T: Ord> SelfComparator<T> {
    pub fn new() -> Self {
        Self { _marker: std::marker::PhantomData }
    }

    /// Compares `o1` and `o2` using their natural ordering.
    ///
    /// Returns [`std::cmp::Ordering`] consistent with `T.compareTo()` in Java.
    pub fn compare(&self, o1: &T, o2: &T) -> std::cmp::Ordering {
        o1.cmp(o2)
    }
}

impl<T: Ord> Default for SelfComparator<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn test_equal_values() {
        let cmp = SelfComparator::<i32>::new();
        assert_eq!(cmp.compare(&5, &5), Ordering::Equal);
    }

    #[test]
    fn test_less_than() {
        let cmp = SelfComparator::<i32>::new();
        assert_eq!(cmp.compare(&3, &7), Ordering::Less);
    }

    #[test]
    fn test_greater_than() {
        let cmp = SelfComparator::<i32>::new();
        assert_eq!(cmp.compare(&9, &2), Ordering::Greater);
    }

    #[test]
    fn test_string_ordering() {
        let cmp = SelfComparator::<String>::new();
        assert_eq!(cmp.compare(&"apple".to_string(), &"banana".to_string()), Ordering::Less);
        assert_eq!(cmp.compare(&"zebra".to_string(), &"ant".to_string()), Ordering::Greater);
        assert_eq!(cmp.compare(&"equal".to_string(), &"equal".to_string()), Ordering::Equal);
    }

    #[test]
    fn test_default_constructs() {
        let cmp = SelfComparator::<u64>::default();
        assert_eq!(cmp.compare(&0, &1), Ordering::Less);
    }
}
