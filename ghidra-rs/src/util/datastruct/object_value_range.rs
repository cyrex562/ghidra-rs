/// Associates a value of type `T` with a numeric range `[start, end]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectValueRange<T> {
    start: i64,
    end: i64,
    value: T,
}

impl<T> ObjectValueRange<T> {
    /// Creates a new range spanning `[start, end]` with an associated `value`.
    pub fn new(start: i64, end: i64, value: T) -> Self {
        Self { start, end, value }
    }

    /// Returns the beginning of the range.
    pub fn start(&self) -> i64 {
        self.start
    }

    /// Returns the end of the range.
    pub fn end(&self) -> i64 {
        self.end
    }

    /// Returns a reference to the value associated with the range.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns `true` if `index` falls within `[start, end]`.
    pub fn contains(&self, index: i64) -> bool {
        index >= self.start && index <= self.end
    }
}

impl<T: Eq> PartialOrd for ObjectValueRange<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Eq> Ord for ObjectValueRange<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let r = ObjectValueRange::new(10, 20, "hello");
        assert_eq!(r.start(), 10);
        assert_eq!(r.end(), 20);
        assert_eq!(*r.value(), "hello");
    }

    #[test]
    fn contains_inclusive_bounds() {
        let r = ObjectValueRange::new(5, 15, 0u8);
        assert!(r.contains(5));
        assert!(r.contains(10));
        assert!(r.contains(15));
        assert!(!r.contains(4));
        assert!(!r.contains(16));
    }

    #[test]
    fn ordering_by_start() {
        let a = ObjectValueRange::new(1, 100, ());
        let b = ObjectValueRange::new(5, 10, ());
        let c = ObjectValueRange::new(1, 50, ());
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.cmp(&c), std::cmp::Ordering::Equal);
    }

    #[test]
    fn sort_by_start() {
        let mut ranges = vec![
            ObjectValueRange::new(30, 40, 'c'),
            ObjectValueRange::new(10, 20, 'a'),
            ObjectValueRange::new(20, 30, 'b'),
        ];
        ranges.sort();
        assert_eq!(ranges[0].start(), 10);
        assert_eq!(ranges[1].start(), 20);
        assert_eq!(ranges[2].start(), 30);
    }

    #[test]
    fn negative_range() {
        let r = ObjectValueRange::new(-50, -10, true);
        assert!(r.contains(-50));
        assert!(r.contains(-10));
        assert!(!r.contains(-51));
        assert!(!r.contains(-9));
    }

    #[test]
    fn point_range() {
        let r = ObjectValueRange::new(42, 42, 99u32);
        assert!(r.contains(42));
        assert!(!r.contains(41));
        assert!(!r.contains(43));
    }
}
