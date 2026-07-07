use crate::util::datastruct::LongDoubleHashtable;

/// A hashtable with `i64` keys and `f64` values that supports adding to values.
///
/// This class extends the behavior of `LongDoubleHashtable` by providing an `add` method
/// that adds a value to the stored value rather than replacing it.
///
/// Port of `ghidra.util.graph.AddableLongDoubleHashtable` (deprecated since Ghidra 10.2).
#[deprecated(note = "Deprecated since Ghidra 10.2")]
#[derive(Debug, Clone)]
pub struct AddableLongDoubleHashtable {
    table: LongDoubleHashtable,
}

#[allow(deprecated)]
impl AddableLongDoubleHashtable {
    /// Creates a table with an initial default capacity.
    pub fn new() -> Self {
        Self {
            table: LongDoubleHashtable::new(),
        }
    }

    /// Creates a table with an initial given capacity. The capacity will be
    /// adjusted to the next highest prime in the primes table.
    pub fn with_capacity(capacity: i32) -> Self {
        Self {
            table: LongDoubleHashtable::with_capacity(capacity),
        }
    }

    /// Adds the value to the stored value rather than replacing it.
    /// If the key is not present, the value is stored as-is.
    pub fn add(&mut self, key: i64, value: f64) {
        if self.table.contains(key) {
            if let Ok(old_value) = self.table.get(key) {
                let new_value = old_value + value;
                self.table.put(key, new_value);
            }
        } else {
            self.table.put(key, value);
        }
    }

    /// Adds a key/value pair to the hashtable. If the key is already in the
    /// table, the old value is replaced with the new value.
    pub fn put(&mut self, key: i64, value: f64) {
        self.table.put(key, value);
    }

    /// Returns the value for the given key.
    pub fn get(&self, key: i64) -> Result<f64, crate::util::exception::NoValueException> {
        self.table.get(key)
    }

    /// Removes a key from the hashtable.
    /// Returns `true` if the key was found and removed, `false` otherwise.
    pub fn remove(&mut self, key: i64) -> bool {
        self.table.remove(key)
    }

    /// Removes all entries from the hashtable.
    pub fn remove_all(&mut self) {
        self.table.remove_all();
    }

    /// Returns `true` if the given key is in the hashtable.
    pub fn contains(&self, key: i64) -> bool {
        self.table.contains(key)
    }

    /// Returns the number of key/value pairs stored in the hashtable.
    pub fn size(&self) -> i32 {
        self.table.size()
    }

    /// Returns a vector containing all the long keys.
    pub fn get_keys(&self) -> Vec<i64> {
        self.table.get_keys()
    }
}

#[allow(deprecated)]
impl Default for AddableLongDoubleHashtable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let table = AddableLongDoubleHashtable::new();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn with_capacity_creates_table() {
        let table = AddableLongDoubleHashtable::with_capacity(10);
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn add_to_nonexistent_key_stores_value() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 5.0);
        assert_eq!(table.get(1), Ok(5.0));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn add_to_existing_key_adds_to_value() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 5.0);
        table.add(1, 3.0);
        assert_eq!(table.get(1), Ok(8.0));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn add_multiple_keys() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 1.5);
        table.add(2, 2.5);
        table.add(1, 0.5);
        assert_eq!(table.get(1), Ok(2.0));
        assert_eq!(table.get(2), Ok(2.5));
        assert_eq!(table.size(), 2);
    }

    #[test]
    fn add_with_negative_values() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 10.0);
        table.add(1, -3.0);
        assert_eq!(table.get(1), Ok(7.0));
    }

    #[test]
    fn add_with_negative_keys() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(-5, 5.5);
        table.add(-5, 2.5);
        assert_eq!(table.get(-5), Ok(8.0));
    }

    #[test]
    fn put_replaces_value() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 5.0);
        table.put(1, 10.0);
        assert_eq!(table.get(1), Ok(10.0));
        assert_eq!(table.size(), 1);
    }

    #[test]
    fn get_missing_key_returns_err() {
        let table = AddableLongDoubleHashtable::new();
        assert!(table.get(42).is_err());
    }

    #[test]
    fn contains_reflects_membership() {
        let mut table = AddableLongDoubleHashtable::new();
        assert!(!table.contains(1));
        table.add(1, 5.0);
        assert!(table.contains(1));
    }

    #[test]
    fn remove_removes_key() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 5.0);
        assert!(table.remove(1));
        assert!(!table.contains(1));
        assert!(table.get(1).is_err());
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_false() {
        let mut table = AddableLongDoubleHashtable::new();
        assert!(!table.remove(99));
    }

    #[test]
    fn remove_all_clears_table() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 1.0);
        table.add(2, 2.0);
        table.add(3, 3.0);
        table.remove_all();
        assert_eq!(table.size(), 0);
        assert!(table.get(1).is_err());
        assert!(table.get(2).is_err());
        assert!(table.get(3).is_err());
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 1.5);
        table.add(2, 2.5);
        table.add(3, 3.5);
        let mut keys = table.get_keys();
        keys.sort();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn default_matches_new() {
        let table = AddableLongDoubleHashtable::default();
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn add_zero_has_no_effect() {
        let mut table = AddableLongDoubleHashtable::new();
        table.add(1, 5.0);
        table.add(1, 0.0);
        assert_eq!(table.get(1), Ok(5.0));
    }

    #[test]
    fn add_multiple_times_accumulates() {
        let mut table = AddableLongDoubleHashtable::new();
        for _ in 0..5 {
            table.add(1, 1.0);
        }
        assert_eq!(table.get(1), Ok(5.0));
    }
}
