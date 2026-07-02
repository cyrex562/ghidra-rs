use super::long_key_indexer::LongKeyIndexer;
use crate::util::exception::NoValueException;

/// A hashtable with `i64` keys and `i64` values.
///
/// Port of `ghidra.util.datastruct.LongLongHashtable`.
#[derive(Debug, Clone)]
pub struct LongLongHashtable {
    indexer: LongKeyIndexer,
    values: Vec<i64>,
    capacity: i32,
}

impl LongLongHashtable {
    /// Creates a table with an initial default capacity.
    pub fn new() -> Self {
        Self::with_capacity(3)
    }

    /// Creates a table with an initial given capacity. The capacity will be
    /// adjusted to the next highest prime in the primes table.
    pub fn with_capacity(capacity: i32) -> Self {
        let indexer = LongKeyIndexer::with_capacity(capacity);
        let capacity = indexer.get_capacity();
        let values = vec![0; capacity as usize];
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
    pub fn put(&mut self, key: i64, value: i64) {
        let index = self.indexer.put(key);

        if index >= self.capacity {
            self.grow();
        }

        self.values[index as usize] = value;
    }

    /// Returns the value for the given key.
    ///
    /// # Errors
    ///
    /// Returns [`NoValueException`] if there is no value for the given key.
    pub fn get(&self, key: i64) -> Result<i64, NoValueException> {
        let index = self.indexer.get(key);
        if index < 0 {
            return Err(NoValueException::new());
        }
        Ok(self.values[index as usize])
    }

    /// Removes a key from the hashtable.
    ///
    /// Returns `true` if the key was found and removed, `false` otherwise.
    pub fn remove(&mut self, key: i64) -> bool {
        self.indexer.remove(key) >= 0
    }

    /// Removes all entries from the hashtable.
    pub fn remove_all(&mut self) {
        self.indexer.clear();
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
        self.values.resize(self.capacity as usize, 0);
    }
}

impl Default for LongLongHashtable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let table = LongLongHashtable::new();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut table = LongLongHashtable::new();
        table.put(1, 15);
        assert_eq!(table.get(1), Ok(15));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn get_missing_key_returns_err() {
        let table = LongLongHashtable::new();
        assert!(table.get(42).is_err());
    }

    #[test]
    fn put_existing_key_replaces_value() {
        let mut table = LongLongHashtable::new();
        table.put(1, 15);
        table.put(1, 25);
        assert_eq!(table.get(1), Ok(25));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn remove_existing_key() {
        let mut table = LongLongHashtable::new();
        table.put(5, 55);
        assert!(table.remove(5));
        assert!(table.get(5).is_err());
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_false() {
        let mut table = LongLongHashtable::new();
        assert!(!table.remove(99));
    }

    #[test]
    fn remove_all_clears_table() {
        let mut table = LongLongHashtable::new();
        table.put(1, 10);
        table.put(2, 20);
        table.remove_all();
        assert_eq!(table.size(), 0);
        assert!(table.get(1).is_err());
        assert!(table.get(2).is_err());
    }

    #[test]
    fn contains_reflects_membership() {
        let mut table = LongLongHashtable::new();
        assert!(!table.contains(3));
        table.put(3, 30);
        assert!(table.contains(3));
        table.remove(3);
        assert!(!table.contains(3));
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut table = LongLongHashtable::new();
        table.put(1, 10);
        table.put(2, 20);
        table.put(3, 30);
        let mut keys = table.get_keys();
        keys.sort();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn grows_beyond_initial_capacity_and_preserves_values() {
        let mut table = LongLongHashtable::with_capacity(2);
        for k in 0..50 {
            table.put(k, k * 3);
        }
        assert_eq!(table.size(), 50);
        for k in 0..50 {
            assert_eq!(table.get(k), Ok(k * 3));
        }
    }

    #[test]
    fn negative_keys_and_values_are_supported() {
        let mut table = LongLongHashtable::new();
        table.put(-7, -75);
        assert_eq!(table.get(-7), Ok(-75));
        assert!(table.remove(-7));
        assert!(table.get(-7).is_err());
    }

    #[test]
    fn large_values_are_preserved() {
        let mut table = LongLongHashtable::new();
        table.put(1, i64::MAX);
        table.put(2, i64::MIN);
        assert_eq!(table.get(1), Ok(i64::MAX));
        assert_eq!(table.get(2), Ok(i64::MIN));
    }

    #[test]
    fn default_matches_new() {
        let table = LongLongHashtable::default();
        assert_eq!(table.size(), 0);
    }
}
