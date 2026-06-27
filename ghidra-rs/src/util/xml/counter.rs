use std::collections::HashMap;

/// A named-bucket counter used internally by XML import/export summary reporting.
///
/// Mirrors `ghidra.util.xml.Counter`.
pub(crate) struct Counter {
    map: HashMap<String, i32>,
}

impl Counter {
    pub(crate) fn new() -> Self {
        Counter { map: HashMap::new() }
    }

    /// Removes all buckets, resetting total count to zero.
    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }

    /// Returns the count for `name` and removes it from the map, or 0 if absent.
    pub(crate) fn get_count_and_remove(&mut self, name: &str) -> i32 {
        self.map.remove(name).unwrap_or(0)
    }

    /// Returns the sum of all bucket counts.
    pub(crate) fn get_total_count(&self) -> i32 {
        self.map.values().sum()
    }

    /// Increments the count for `name` by one.
    pub(crate) fn increment(&mut self, name: &str) {
        *self.map.entry(name.to_string()).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_counter_total_is_zero() {
        let c = Counter::new();
        assert_eq!(c.get_total_count(), 0);
    }

    #[test]
    fn increment_increases_total() {
        let mut c = Counter::new();
        c.increment("A");
        c.increment("A");
        c.increment("B");
        assert_eq!(c.get_total_count(), 3);
    }

    #[test]
    fn get_count_and_remove_returns_count_then_removes() {
        let mut c = Counter::new();
        c.increment("X");
        c.increment("X");
        assert_eq!(c.get_count_and_remove("X"), 2);
        assert_eq!(c.get_count_and_remove("X"), 0);
        assert_eq!(c.get_total_count(), 0);
    }

    #[test]
    fn get_count_and_remove_absent_key_returns_zero() {
        let mut c = Counter::new();
        assert_eq!(c.get_count_and_remove("MISSING"), 0);
    }

    #[test]
    fn clear_resets_everything() {
        let mut c = Counter::new();
        c.increment("A");
        c.increment("B");
        c.clear();
        assert_eq!(c.get_total_count(), 0);
        assert_eq!(c.get_count_and_remove("A"), 0);
    }

    #[test]
    fn total_reflects_multiple_buckets() {
        let mut c = Counter::new();
        c.increment("P");
        c.increment("Q");
        c.increment("Q");
        c.increment("R");
        assert_eq!(c.get_total_count(), 4);
    }
}
