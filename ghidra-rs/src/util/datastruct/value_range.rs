/// Associates an integer value with a numeric range `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueRange {
    start: i64,
    end: i64,
    value: i32,
}

impl ValueRange {
    /// Creates a new range spanning `[start, end]` with an associated integer `value`.
    pub fn new(start: i64, end: i64, value: i32) -> Self {
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

    /// Returns the value associated with the range.
    pub fn value(&self) -> i32 {
        self.value
    }

    /// Returns `true` if `index` falls within `[start, end]`.
    pub fn contains(&self, index: i64) -> bool {
        index >= self.start && index <= self.end
    }
}

impl PartialOrd for ValueRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValueRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let r = ValueRange::new(10, 20, 42);
        assert_eq!(r.start(), 10);
        assert_eq!(r.end(), 20);
        assert_eq!(r.value(), 42);
    }

    #[test]
    fn contains_inclusive_bounds() {
        let r = ValueRange::new(5, 15, 0);
        assert!(r.contains(5));
        assert!(r.contains(10));
        assert!(r.contains(15));
        assert!(!r.contains(4));
        assert!(!r.contains(16));
    }

    #[test]
    fn ordering_by_start() {
        let a = ValueRange::new(1, 100, 0);
        let b = ValueRange::new(5, 10, 0);
        let c = ValueRange::new(1, 50, 0);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.cmp(&c), std::cmp::Ordering::Equal);
    }

    #[test]
    fn sort_by_start() {
        let mut ranges = vec![
            ValueRange::new(30, 40, 3),
            ValueRange::new(10, 20, 1),
            ValueRange::new(20, 30, 2),
        ];
        ranges.sort();
        assert_eq!(ranges[0].start(), 10);
        assert_eq!(ranges[1].start(), 20);
        assert_eq!(ranges[2].start(), 30);
    }

    #[test]
    fn negative_range() {
        let r = ValueRange::new(-50, -10, -1);
        assert!(r.contains(-50));
        assert!(r.contains(-10));
        assert!(!r.contains(-51));
        assert!(!r.contains(-9));
    }

    #[test]
    fn point_range() {
        let r = ValueRange::new(42, 42, 99);
        assert!(r.contains(42));
        assert!(!r.contains(41));
        assert!(!r.contains(43));
    }

    #[test]
    fn copy_semantics() {
        let a = ValueRange::new(3, 7, 5);
        let b = a;
        assert_eq!(a, b);
    }
}
