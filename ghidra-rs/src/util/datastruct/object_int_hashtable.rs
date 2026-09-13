use std::hash::Hash;

use super::object_key_indexer::ObjectKeyIndexer;
use crate::util::exception::NoValueException;

/// A hashtable with arbitrary (`Hash + Eq + Clone`) keys and `i32` values.
///
/// Port of `ghidra.util.datastruct.ObjectIntHashtable<T>`. Java buckets keys
/// by `key.hashCode()`; since Rust has no runtime-reflective `hashCode()`,
/// this is built on [`ObjectKeyIndexer`], which requires `T: Hash + Eq`
/// instead (see that module's docs for the hashing caveat).
#[derive(Debug, Clone)]
pub struct ObjectIntHashtable<T> {
    indexer: ObjectKeyIndexer<T>,
    values: Vec<i32>,
    capacity: i32,
}

impl<T: Hash + Eq + Clone> ObjectIntHashtable<T> {
    /// Creates a table with an initial default capacity.
    pub fn new() -> Self {
        Self::with_capacity(3)
    }

    /// Creates a table with an initial given capacity. The capacity will be
    /// adjusted to the next highest prime in the primes table.
    pub fn with_capacity(capacity: i32) -> Self {
        let indexer = ObjectKeyIndexer::with_capacity(capacity);
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
    /// Panics if the maximum capacity is reached (mirrors Java's
    /// `ArrayIndexOutOfBoundsException`).
    pub fn put(&mut self, key: T, value: i32) {
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
    pub fn get(&self, key: &T) -> Result<i32, NoValueException> {
        let index = self.indexer.get(key);
        if index < 0 {
            return Err(NoValueException::new());
        }
        Ok(self.values[index as usize])
    }

    /// Removes a key from the hashtable.
    ///
    /// Returns `true` if the key was found and removed, `false` otherwise.
    pub fn remove(&mut self, key: &T) -> bool {
        self.indexer.remove(key) >= 0
    }

    /// Removes all entries from the hashtable.
    pub fn remove_all(&mut self) {
        self.indexer.clear();
    }

    /// Returns `true` if the given key is in the hashtable.
    pub fn contains(&self, key: &T) -> bool {
        self.indexer.get(key) >= 0
    }

    /// Returns the number of key/value pairs stored in the hashtable.
    pub fn size(&self) -> i32 {
        self.indexer.get_size()
    }

    /// Returns a vector containing all the key objects.
    pub fn get_keys(&self) -> Vec<T> {
        self.indexer.get_keys()
    }

    /// Resizes the hashtable to allow more entries.
    fn grow(&mut self) {
        self.capacity = self.indexer.get_capacity();
        self.values.resize(self.capacity as usize, 0);
    }
}

impl<T: Hash + Eq + Clone> Default for ObjectIntHashtable<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let table: ObjectIntHashtable<String> = ObjectIntHashtable::new();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut table = ObjectIntHashtable::new();
        table.put("one".to_string(), 1);
        assert_eq!(table.get(&"one".to_string()), Ok(1));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn get_missing_key_returns_err() {
        let table: ObjectIntHashtable<String> = ObjectIntHashtable::new();
        assert!(table.get(&"missing".to_string()).is_err());
    }

    #[test]
    fn put_existing_key_replaces_value() {
        let mut table = ObjectIntHashtable::new();
        table.put("one".to_string(), 1);
        table.put("one".to_string(), 100);
        assert_eq!(table.get(&"one".to_string()), Ok(100));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn remove_existing_key() {
        let mut table = ObjectIntHashtable::new();
        table.put("five".to_string(), 5);
        assert!(table.remove(&"five".to_string()));
        assert!(table.get(&"five".to_string()).is_err());
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_false() {
        let mut table: ObjectIntHashtable<String> = ObjectIntHashtable::new();
        assert!(!table.remove(&"nope".to_string()));
    }

    #[test]
    fn remove_all_clears_table() {
        let mut table = ObjectIntHashtable::new();
        table.put("one".to_string(), 1);
        table.put("two".to_string(), 2);
        table.remove_all();
        assert_eq!(table.size(), 0);
        assert!(table.get(&"one".to_string()).is_err());
    }

    #[test]
    fn contains_reflects_membership() {
        let mut table = ObjectIntHashtable::new();
        assert!(!table.contains(&"three".to_string()));
        table.put("three".to_string(), 3);
        assert!(table.contains(&"three".to_string()));
        table.remove(&"three".to_string());
        assert!(!table.contains(&"three".to_string()));
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut table = ObjectIntHashtable::new();
        table.put("a".to_string(), 1);
        table.put("b".to_string(), 2);
        table.put("c".to_string(), 3);
        let mut keys = table.get_keys();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn grows_beyond_initial_capacity_and_preserves_values() {
        let mut table = ObjectIntHashtable::with_capacity(2);
        for k in 0..50 {
            table.put(format!("key{k}"), k * 10);
        }
        assert_eq!(table.size(), 50);
        for k in 0..50 {
            assert_eq!(table.get(&format!("key{k}")), Ok(k * 10));
        }
    }

    #[test]
    fn works_with_non_string_key_types() {
        let mut table: ObjectIntHashtable<(i32, i32)> = ObjectIntHashtable::new();
        table.put((1, 2), 12);
        table.put((3, 4), 34);
        assert_eq!(table.get(&(1, 2)), Ok(12));
        assert_eq!(table.get(&(3, 4)), Ok(34));
    }

    #[test]
    fn default_matches_new() {
        let table: ObjectIntHashtable<String> = ObjectIntHashtable::default();
        assert_eq!(table.size(), 0);
    }
}
