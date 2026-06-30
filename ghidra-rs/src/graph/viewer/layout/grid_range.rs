/// Reports the min/max columns in a row or the min/max rows in a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridRange {
    pub min: i32,
    pub max: i32,
}

impl GridRange {
    /// Creates an empty range (`min > max`).
    pub fn new() -> Self {
        Self { min: i32::MAX, max: i32::MIN }
    }

    /// Creates a range with explicit bounds.
    pub fn with_bounds(min: i32, max: i32) -> Self {
        Self { min, max }
    }

    /// Expands the range to include `value`.
    pub fn add(&mut self, value: i32) {
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    /// Returns `true` when the range contains no values (`min > max`).
    pub fn is_empty(&self) -> bool {
        self.min > self.max
    }

    /// Returns `true` if `value` falls within `[min, max]`.
    pub fn contains(&self, value: i32) -> bool {
        value >= self.min && value <= self.max
    }

    /// Returns the number of integers in the range, or `0` if empty.
    pub fn width(&self) -> i32 {
        if self.is_empty() {
            0
        } else {
            self.max - self.min + 1
        }
    }
}

impl Default for GridRange {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for GridRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} -> {}]", self.min, self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_empty() {
        let r = GridRange::new();
        assert!(r.is_empty());
    }

    #[test]
    fn test_default_width_is_zero() {
        let r = GridRange::new();
        assert_eq!(r.width(), 0);
    }

    #[test]
    fn test_with_bounds_not_empty() {
        let r = GridRange::with_bounds(2, 5);
        assert!(!r.is_empty());
    }

    #[test]
    fn test_width() {
        let r = GridRange::with_bounds(2, 5);
        assert_eq!(r.width(), 4);
    }

    #[test]
    fn test_width_single_element() {
        let r = GridRange::with_bounds(3, 3);
        assert_eq!(r.width(), 1);
    }

    #[test]
    fn test_add_expands_range() {
        let mut r = GridRange::new();
        r.add(5);
        assert_eq!(r.min, 5);
        assert_eq!(r.max, 5);
        r.add(2);
        assert_eq!(r.min, 2);
        assert_eq!(r.max, 5);
        r.add(9);
        assert_eq!(r.min, 2);
        assert_eq!(r.max, 9);
    }

    #[test]
    fn test_contains() {
        let r = GridRange::with_bounds(3, 7);
        assert!(r.contains(3));
        assert!(r.contains(5));
        assert!(r.contains(7));
        assert!(!r.contains(2));
        assert!(!r.contains(8));
    }

    #[test]
    fn test_equality() {
        let a = GridRange::with_bounds(1, 10);
        let b = GridRange::with_bounds(1, 10);
        let c = GridRange::with_bounds(1, 11);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_display() {
        let r = GridRange::with_bounds(3, 7);
        assert_eq!(r.to_string(), "[3 -> 7]");
    }

    #[test]
    fn test_inverted_bounds_is_empty() {
        let r = GridRange::with_bounds(5, 2);
        assert!(r.is_empty());
        assert_eq!(r.width(), 0);
    }

    #[test]
    fn test_hash_equality_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let a = GridRange::with_bounds(1, 5);
        let b = GridRange::with_bounds(1, 5);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}
