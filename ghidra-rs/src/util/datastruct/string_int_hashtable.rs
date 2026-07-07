use super::string_key_indexer::{StringKeyIndexer, StringKeyIndexerIter};
use crate::util::exception::NoValueException;

/// A hashtable with `String` keys and `i32` values.
///
/// Port of `ghidra.util.datastruct.StringIntHashtable`.
#[derive(Debug, Clone)]
pub struct StringIntHashtable {
    indexer: StringKeyIndexer,
    values: Vec<i32>,
    capacity: i32,
}

impl StringIntHashtable {
    /// Creates a table with an initial default capacity.
    pub fn new() -> Self {
        Self::with_capacity(3)
    }

    /// Creates a table with an initial given capacity. The capacity will be
    /// adjusted to the next highest prime in the primes table.
    pub fn with_capacity(capacity: i32) -> Self {
        let indexer = StringKeyIndexer::with_capacity(capacity);
        let capacity = indexer.get_capacity();
        let values = vec![0; capacity as usize];
        Self {
            indexer,
            values,
            capacity,
        }
    }

    /// Returns an iterator over the strings in this hash table.
    pub fn get_key_iterator(&self) -> StringKeyIndexerIter<'_> {
        self.indexer.get_key_iterator()
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
    pub fn put(&mut self, key: &str, value: i32) {
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
    pub fn get(&self, key: &str) -> Result<i32, NoValueException> {
        let index = self.indexer.get(key);
        if index < 0 {
            return Err(NoValueException::new());
        }
        Ok(self.values[index as usize])
    }

    /// Removes a key from the hashtable.
    ///
    /// Returns `true` if the key was found and removed, `false` otherwise.
    pub fn remove(&mut self, key: &str) -> bool {
        self.indexer.remove(key) >= 0
    }

    /// Removes all entries from the hashtable.
    pub fn remove_all(&mut self) {
        self.indexer.clear();
    }

    /// Returns `true` if the given key is in the hashtable.
    pub fn contains(&self, key: &str) -> bool {
        self.indexer.get(key) >= 0
    }

    /// Returns the number of key/value pairs stored in the hashtable.
    pub fn size(&self) -> i32 {
        self.indexer.get_size()
    }

    /// Returns a vector containing all the String keys.
    pub fn get_keys(&self) -> Vec<String> {
        self.indexer.get_keys()
    }

    /// Resizes the hashtable to allow more entries.
    fn grow(&mut self) {
        self.capacity = self.indexer.get_capacity();
        self.values.resize(self.capacity as usize, 0);
    }
}

impl Default for StringIntHashtable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let table = StringIntHashtable::new();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn put_and_get() {
        let mut table = StringIntHashtable::new();
        table.put("one", 1);
        assert_eq!(table.get("one"), Ok(1));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn get_missing_key_returns_err() {
        let table = StringIntHashtable::new();
        assert!(table.get("missing").is_err());
    }

    #[test]
    fn put_existing_key_replaces_value() {
        let mut table = StringIntHashtable::new();
        table.put("one", 1);
        table.put("one", 100);
        assert_eq!(table.get("one"), Ok(100));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn remove_existing_key() {
        let mut table = StringIntHashtable::new();
        table.put("five", 5);
        assert!(table.remove("five"));
        assert!(table.get("five").is_err());
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_false() {
        let mut table = StringIntHashtable::new();
        assert!(!table.remove("missing"));
    }

    #[test]
    fn remove_all_clears_table() {
        let mut table = StringIntHashtable::new();
        table.put("one", 1);
        table.put("two", 2);
        table.remove_all();
        assert_eq!(table.size(), 0);
        assert!(table.get("one").is_err());
        assert!(table.get("two").is_err());
    }

    #[test]
    fn contains_reflects_membership() {
        let mut table = StringIntHashtable::new();
        assert!(!table.contains("three"));
        table.put("three", 3);
        assert!(table.contains("three"));
        table.remove("three");
        assert!(!table.contains("three"));
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut table = StringIntHashtable::new();
        table.put("a", 1);
        table.put("b", 2);
        table.put("c", 3);
        let mut keys = table.get_keys();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn key_iterator_visits_all_keys() {
        let mut table = StringIntHashtable::new();
        table.put("a", 1);
        table.put("b", 2);
        table.put("c", 3);
        let mut keys: Vec<String> = table.get_key_iterator().map(|s| s.to_string()).collect();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn grows_beyond_initial_capacity_and_preserves_values() {
        let mut table = StringIntHashtable::with_capacity(2);
        for k in 0..50 {
            let key = format!("key{k}");
            table.put(&key, k * 3);
        }
        assert_eq!(table.size(), 50);
        for k in 0..50 {
            let key = format!("key{k}");
            assert_eq!(table.get(&key), Ok(k * 3));
        }
    }

    #[test]
    fn negative_values_are_supported() {
        let mut table = StringIntHashtable::new();
        table.put("neg", -75);
        assert_eq!(table.get("neg"), Ok(-75));
        assert!(table.remove("neg"));
        assert!(table.get("neg").is_err());
    }

    #[test]
    fn default_matches_new() {
        let table = StringIntHashtable::default();
        assert_eq!(table.size(), 0);
    }
}
