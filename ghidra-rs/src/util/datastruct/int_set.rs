use super::int_key_indexer::IntKeyIndexer;

/// A set of `i32` values.
///
/// Port of `ghidra.util.datastruct.IntSet`.
#[derive(Debug, Clone)]
pub struct IntSet {
    indexer: IntKeyIndexer,
}

impl IntSet {
    /// Constructs a new empty int set.
    ///
    /// `capacity` is the initial storage size; the set will grow if needed.
    pub fn with_capacity(capacity: i32) -> Self {
        Self { indexer: IntKeyIndexer::with_capacity(capacity) }
    }

    /// Constructs a new `IntSet` and populates it with the given array of ints.
    pub fn from_values(values: &[i32]) -> Self {
        let mut set = Self::with_capacity((values.len() as i32 * 3) / 4);
        for &value in values {
            set.add(value);
        }
        set
    }

    /// Returns the number of ints in the set.
    pub fn size(&self) -> i32 {
        self.indexer.get_size()
    }

    /// Returns true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.indexer.get_size() == 0
    }

    /// Returns true if the set contains the given value.
    pub fn contains(&self, value: i32) -> bool {
        self.indexer.get(value) >= 0
    }

    /// Add the int value to the set.
    pub fn add(&mut self, value: i32) {
        self.indexer.put(value);
    }

    /// Removes the int value from the set.
    ///
    /// Returns true if the value was in the set, false otherwise.
    pub fn remove(&mut self, value: i32) -> bool {
        self.indexer.remove(value) >= 0
    }

    /// Removes all values from the set.
    pub fn clear(&mut self) {
        self.indexer.clear();
    }

    /// Returns an array with all the values in the set.
    pub fn get_values(&self) -> Vec<i32> {
        self.indexer.get_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_add_and_contains() {
        let mut set = IntSet::with_capacity(10);
        set.add(5);
        set.add(7);
        set.add(3);
        set.add(6);

        assert_eq!(set.size(), 4);

        assert!(!set.contains(1));
        assert!(!set.contains(2));
        assert!(set.contains(3));
        assert!(!set.contains(4));
        assert!(set.contains(5));
        assert!(set.contains(6));
        assert!(set.contains(7));
        assert!(!set.contains(8));
    }

    #[test]
    fn initialized_from_values() {
        let set = IntSet::from_values(&[5, 6, 7, 3]);

        assert_eq!(set.size(), 4);

        assert!(!set.contains(1));
        assert!(!set.contains(2));
        assert!(set.contains(3));
        assert!(!set.contains(4));
        assert!(set.contains(5));
        assert!(set.contains(6));
        assert!(set.contains(7));
        assert!(!set.contains(8));
    }

    #[test]
    fn remove_single_value() {
        let mut set = IntSet::from_values(&[5, 6, 7, 3]);

        assert_eq!(set.size(), 4);
        assert!(set.remove(6));

        assert!(!set.contains(1));
        assert!(!set.contains(2));
        assert!(set.contains(3));
        assert!(!set.contains(4));
        assert!(set.contains(5));
        assert!(!set.contains(6));
        assert!(set.contains(7));
        assert!(!set.contains(8));
    }

    #[test]
    fn remove_all_values() {
        let mut set = IntSet::from_values(&[5, 6, 7, 3]);

        assert_eq!(set.size(), 4);
        set.remove(6);
        set.remove(3);
        set.remove(5);
        set.remove(7);

        assert_eq!(set.size(), 0);
        assert!(set.is_empty());

        for value in 1..=8 {
            assert!(!set.contains(value));
        }
    }

    #[test]
    fn remove_values_not_in_set() {
        let mut set = IntSet::from_values(&[5, 6, 7, 3]);

        assert_eq!(set.size(), 4);
        assert!(!set.remove(1));
        assert!(!set.remove(2));
        assert!(!set.remove(4));
        assert!(!set.remove(10));

        assert_eq!(set.size(), 4);
        assert!(!set.is_empty());

        assert!(!set.contains(1));
        assert!(!set.contains(2));
        assert!(set.contains(3));
        assert!(!set.contains(4));
        assert!(set.contains(5));
        assert!(set.contains(6));
        assert!(set.contains(7));
        assert!(!set.contains(8));
    }

    #[test]
    fn clear_removes_all_values() {
        let mut set = IntSet::from_values(&[1, 2, 3]);
        set.clear();
        assert_eq!(set.size(), 0);
        assert!(set.is_empty());
    }

    #[test]
    fn get_values_returns_all_stored_values() {
        let set = IntSet::from_values(&[5, 6, 7, 3]);
        let mut values = set.get_values();
        values.sort();
        assert_eq!(values, vec![3, 5, 6, 7]);
    }
}
