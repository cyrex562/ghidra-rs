/// Holds a beginning and ending index defining a contiguous range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexRange {
    start: i64,
    end: i64,
}

impl IndexRange {
    /// Creates a new [`IndexRange`] spanning `[start, end]`.
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    /// Returns the starting index of the range.
    pub fn start(&self) -> i64 {
        self.start
    }

    /// Returns the ending index of the range.
    pub fn end(&self) -> i64 {
        self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_start_and_end() {
        let r = IndexRange::new(5, 20);
        assert_eq!(r.start(), 5);
        assert_eq!(r.end(), 20);
    }

    #[test]
    fn equality_requires_both_fields() {
        let a = IndexRange::new(1, 10);
        let b = IndexRange::new(1, 10);
        let c = IndexRange::new(1, 11);
        let d = IndexRange::new(2, 10);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn copy_semantics() {
        let a = IndexRange::new(3, 7);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn negative_indices() {
        let r = IndexRange::new(-100, -1);
        assert_eq!(r.start(), -100);
        assert_eq!(r.end(), -1);
    }

    #[test]
    fn zero_length_range() {
        let r = IndexRange::new(42, 42);
        assert_eq!(r.start(), 42);
        assert_eq!(r.end(), 42);
        assert_eq!(r.start(), r.end());
    }
}
