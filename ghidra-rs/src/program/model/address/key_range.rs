/// Inclusive range of database keys.
///
/// This mirrors Ghidra's `KeyRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyRange {
    /// Minimum key, inclusive.
    pub min_key: i64,
    /// Maximum key, inclusive.
    pub max_key: i64,
}

impl KeyRange {
    /// Constructs a key range. Keys are expected to already be ordered.
    pub fn new(min_key: i64, max_key: i64) -> Self {
        Self { min_key, max_key }
    }

    /// Returns true if the key is within this range.
    pub fn contains(self, key: i64) -> bool {
        key >= self.min_key && key <= self.max_key
    }

    /// Returns the number of keys contained within this range.
    pub fn length(self) -> i64 {
        self.max_key - self.min_key + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_is_inclusive() {
        let range = KeyRange::new(10, 12);

        assert!(!range.contains(9));
        assert!(range.contains(10));
        assert!(range.contains(11));
        assert!(range.contains(12));
        assert!(!range.contains(13));
    }

    #[test]
    fn length_matches_java_arithmetic() {
        assert_eq!(KeyRange::new(10, 12).length(), 3);
        assert_eq!(KeyRange::new(-2, 2).length(), 5);
    }
}
