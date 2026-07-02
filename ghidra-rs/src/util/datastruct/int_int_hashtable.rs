use super::int_key_indexer::IntKeyIndexer;
use crate::util::exception::NoValueException;

/// A hashtable with `i32` keys and `i32` values.
///
/// Port of `ghidra.util.datastruct.IntIntHashtable`.
#[derive(Debug, Clone)]
pub struct IntIntHashtable {
    indexer: IntKeyIndexer,
    values: Vec<i32>,
    capacity: i32,
}

impl IntIntHashtable {
    /// Creates a table with an initial default capacity.
    pub fn new() -> Self {
        Self::with_capacity(3)
    }

    /// Creates a table with an initial given capacity. The capacity will be
    /// adjusted to the next highest prime in the primes table.
    pub fn with_capacity(capacity: i32) -> Self {
        let indexer = IntKeyIndexer::with_capacity(capacity);
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
    pub fn put(&mut self, key: i32, value: i32) {
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
    pub fn get(&self, key: i32) -> Result<i32, NoValueException> {
        let index = self.indexer.get(key);
        if index < 0 {
            return Err(NoValueException::new());
        }
        Ok(self.values[index as usize])
    }

    /// Removes a key/value from the hashtable.
    ///
    /// # Errors
    ///
    /// Returns [`NoValueException`] if there is no value for the given key.
    pub fn remove(&mut self, key: i32) -> Result<i32, NoValueException> {
        let index = self.indexer.remove(key);
        if index < 0 {
            return Err(NoValueException::new());
        }
        Ok(self.values[index as usize])
    }

    /// Removes all entries from the hashtable.
    pub fn remove_all(&mut self) {
        self.indexer.clear();
    }

    /// Returns `true` if the given key is in the hashtable.
    pub fn contains(&self, key: i32) -> bool {
        self.indexer.get(key) >= 0
    }

    /// Returns the number of key/value pairs stored in the hashtable.
    pub fn size(&self) -> i32 {
        self.indexer.get_size()
    }

    /// Returns a vector containing all the int keys.
    pub fn get_keys(&self) -> Vec<i32> {
        self.indexer.get_keys()
    }

    /// Resizes the hashtable to allow more entries.
    fn grow(&mut self) {
        self.capacity = self.indexer.get_capacity();
        self.values.resize(self.capacity as usize, 0);
    }
}

impl Default for IntIntHashtable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let table = IntIntHashtable::new();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut table = IntIntHashtable::new();
        table.put(1, 100);
        assert_eq!(table.get(1), Ok(100));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn get_missing_key_returns_err() {
        let table = IntIntHashtable::new();
        assert!(table.get(42).is_err());
    }

    #[test]
    fn put_existing_key_replaces_value() {
        let mut table = IntIntHashtable::new();
        table.put(1, 100);
        table.put(1, 200);
        assert_eq!(table.get(1), Ok(200));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn remove_existing_key() {
        let mut table = IntIntHashtable::new();
        table.put(5, 500);
        assert_eq!(table.remove(5), Ok(500));
        assert!(table.get(5).is_err());
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_err() {
        let mut table = IntIntHashtable::new();
        assert!(table.remove(99).is_err());
    }

    #[test]
    fn remove_all_clears_table() {
        let mut table = IntIntHashtable::new();
        table.put(1, 10);
        table.put(2, 20);
        table.remove_all();
        assert_eq!(table.size(), 0);
        assert!(table.get(1).is_err());
        assert!(table.get(2).is_err());
    }

    #[test]
    fn contains_reflects_membership() {
        let mut table = IntIntHashtable::new();
        assert!(!table.contains(3));
        table.put(3, 30);
        assert!(table.contains(3));
        let _ = table.remove(3);
        assert!(!table.contains(3));
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut table = IntIntHashtable::new();
        table.put(1, 10);
        table.put(2, 20);
        table.put(3, 30);
        let mut keys = table.get_keys();
        keys.sort();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn grows_beyond_initial_capacity_and_preserves_values() {
        let mut table = IntIntHashtable::with_capacity(2);
        for k in 0..50 {
            table.put(k, k * 10);
        }
        assert_eq!(table.size(), 50);
        for k in 0..50 {
            assert_eq!(table.get(k), Ok(k * 10));
        }
    }

    #[test]
    fn negative_keys_are_supported() {
        let mut table = IntIntHashtable::new();
        table.put(-7, -70);
        assert_eq!(table.get(-7), Ok(-70));
        assert_eq!(table.remove(-7), Ok(-70));
        assert!(table.get(-7).is_err());
    }

    #[test]
    fn default_matches_new() {
        let table = IntIntHashtable::default();
        assert_eq!(table.size(), 0);
    }
}
