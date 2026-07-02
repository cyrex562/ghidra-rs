use super::long_key_indexer::LongKeyIndexer;

/// A hashtable with `i64` keys and arbitrary values.
///
/// Port of `ghidra.util.datastruct.LongObjectHashtable`.
#[derive(Debug, Clone)]
pub struct LongObjectHashtable<T> {
    indexer: LongKeyIndexer,
    values: Vec<Option<T>>,
    capacity: i32,
}

impl<T> LongObjectHashtable<T> {
    /// Creates a table with an initial default capacity.
    pub fn new() -> Self {
        Self::with_capacity(3)
    }

    /// Creates a table with an initial given capacity. The capacity will be
    /// adjusted to the next highest prime in the primes table.
    pub fn with_capacity(capacity: i32) -> Self {
        let indexer = LongKeyIndexer::with_capacity(capacity);
        let capacity = indexer.get_capacity();
        let mut values = Vec::with_capacity(capacity as usize);
        values.resize_with(capacity as usize, || None);
        Self {
            indexer,
            values,
            capacity,
        }
    }

    /// Adds a key/value pair to the hashtable. If the key is already in the
    /// table, the old value is replaced with the new value. If the hashtable
    /// is already full, it will attempt to approximately double in size (it
    /// will use a prime number), and all the current entries will be
    /// rehashed.
    ///
    /// # Panics
    ///
    /// Panics if the maximum capacity is reached.
    pub fn put(&mut self, key: i64, value: T) {
        let index = self.indexer.put(key);

        if index >= self.capacity {
            self.grow();
        }

        self.values[index as usize] = Some(value);
    }

    /// Returns a reference to the value for the given key, or `None` if the
    /// key is not in the table.
    pub fn get(&self, key: i64) -> Option<&T> {
        let index = self.indexer.get(key);
        if index < 0 {
            return None;
        }
        self.values[index as usize].as_ref()
    }

    /// Removes a key from the hashtable.
    ///
    /// Returns the value that was removed, or `None` if either the key was
    /// not found or a `None` had been stored for the specified key.
    pub fn remove(&mut self, key: i64) -> Option<T> {
        let index = self.indexer.remove(key);
        if index < 0 {
            return None;
        }
        self.values[index as usize].take()
    }

    /// Removes all entries from the hashtable.
    pub fn remove_all(&mut self) {
        self.indexer.clear();
        for slot in self.values.iter_mut() {
            *slot = None;
        }
    }

    /// Returns `true` if the given key is in the hashtable.
    pub fn contains(&self, key: i64) -> bool {
        self.indexer.get(key) >= 0
    }

    /// Returns the number of key/value pairs stored in the hashtable.
    pub fn size(&self) -> i32 {
        self.indexer.get_size()
    }

    /// Returns a vector containing all the long keys.
    pub fn get_keys(&self) -> Vec<i64> {
        self.indexer.get_keys()
    }

    /// Resizes the hashtable to allow more entries.
    fn grow(&mut self) {
        self.capacity = self.indexer.get_capacity();
        self.values.resize_with(self.capacity as usize, || None);
    }
}

impl<T> Default for LongObjectHashtable<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let table: LongObjectHashtable<&str> = LongObjectHashtable::new();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut table = LongObjectHashtable::new();
        table.put(1, "one");
        assert_eq!(table.get(1), Some(&"one"));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn get_missing_key_returns_none() {
        let table: LongObjectHashtable<&str> = LongObjectHashtable::new();
        assert_eq!(table.get(42), None);
    }

    #[test]
    fn put_existing_key_replaces_value() {
        let mut table = LongObjectHashtable::new();
        table.put(1, "one");
        table.put(1, "uno");
        assert_eq!(table.get(1), Some(&"uno"));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn remove_existing_key() {
        let mut table = LongObjectHashtable::new();
        table.put(5, "five");
        assert_eq!(table.remove(5), Some("five"));
        assert_eq!(table.get(5), None);
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_none() {
        let mut table: LongObjectHashtable<&str> = LongObjectHashtable::new();
        assert_eq!(table.remove(99), None);
    }

    #[test]
    fn remove_all_clears_table() {
        let mut table = LongObjectHashtable::new();
        table.put(1, "one");
        table.put(2, "two");
        table.remove_all();
        assert_eq!(table.size(), 0);
        assert_eq!(table.get(1), None);
        assert_eq!(table.get(2), None);
    }

    #[test]
    fn contains_reflects_membership() {
        let mut table = LongObjectHashtable::new();
        assert!(!table.contains(3));
        table.put(3, "three");
        assert!(table.contains(3));
        table.remove(3);
        assert!(!table.contains(3));
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut table = LongObjectHashtable::new();
        table.put(1, "one");
        table.put(2, "two");
        table.put(3, "three");
        let mut keys = table.get_keys();
        keys.sort();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn grows_beyond_initial_capacity_and_preserves_values() {
        let mut table = LongObjectHashtable::with_capacity(2);
        for k in 0..50 {
            table.put(k, k * 10);
        }
        assert_eq!(table.size(), 50);
        for k in 0..50 {
            assert_eq!(table.get(k), Some(&(k * 10)));
        }
    }

    #[test]
    fn negative_keys_are_supported() {
        let mut table = LongObjectHashtable::new();
        table.put(-7, "neg");
        assert_eq!(table.get(-7), Some(&"neg"));
        assert_eq!(table.remove(-7), Some("neg"));
        assert_eq!(table.get(-7), None);
    }

    #[test]
    fn large_keys_beyond_i32_range_are_supported() {
        let mut table = LongObjectHashtable::new();
        let big_key: i64 = (i32::MAX as i64) + 12345;
        table.put(big_key, "big");
        assert_eq!(table.get(big_key), Some(&"big"));
    }

    #[test]
    fn default_matches_new() {
        let table: LongObjectHashtable<&str> = LongObjectHashtable::default();
        assert_eq!(table.size(), 0);
    }
}
