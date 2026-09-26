use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::int_list_indexer::IntListIndexer;
use super::prime::next_prime;

const DEFAULT_CAPACITY: i32 = 13;

/// Converts arbitrary keys into compacted `i32` indexes suitable for use as
/// indexes into an array or table.
///
/// Whenever a new key is added, the smallest unused index is allocated and
/// associated with that key. Hashes the keys into linked lists using
/// [`IntListIndexer`], where all values in a list share the same hash code.
/// This does most of the work of a separate-chaining hash table -- the only
/// thing missing is the values, which are stored by the containing
/// structure.
///
/// Port of `ghidra.util.datastruct.ObjectKeyIndexer<T>`. Java's version
/// buckets by `key.hashCode()`; since Rust has no runtime-reflective
/// `hashCode()`, this requires `T: Hash + Eq` and hashes with
/// [`DefaultHasher`] (deterministic across runs, unlike `HashMap`'s
/// randomized default `RandomState`), which is a stand-in for Java's
/// per-object `hashCode()` -- the exact hash values will differ from Java's,
/// but the indexer's correctness does not depend on matching Java's
/// specific hash algorithm.
#[derive(Debug, Clone)]
pub struct ObjectKeyIndexer<T> {
    keys: Vec<Option<T>>,
    indexer: IntListIndexer,
    capacity: i32,
}

impl<T: Hash + Eq + Clone> ObjectKeyIndexer<T> {
    /// Constructs an `ObjectKeyIndexer` with a default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Constructs an `ObjectKeyIndexer` with a given initial capacity
    /// (rounded up to the next prime).
    pub fn with_capacity(capacity: i32) -> Self {
        let capacity = next_prime(capacity);
        Self {
            keys: vec![None; capacity as usize],
            indexer: IntListIndexer::new(capacity, capacity),
            capacity,
        }
    }

    fn hash_code(key: &T) -> i32 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as i32
    }

    /// Returns an index that will always be associated with `key` as long as
    /// the key remains in the table. If the key already exists, the index
    /// where it is stored is returned. If the key is new, a new index is
    /// allocated, the key is stored at that index, and the new index is
    /// returned.
    ///
    /// # Panics
    ///
    /// Panics if this object is at maximum capacity and no new index can be
    /// allocated (mirrors Java's `IndexOutOfBoundsException`).
    pub fn put(&mut self, key: T) -> i32 {
        let mut index = self.find_key(&key);

        if index == -1 {
            if self.indexer.get_size() >= self.capacity {
                self.grow();
            }
            let hashcode = (Self::hash_code(&key) & 0x7FFF_FFFF) % self.capacity;
            index = self.indexer.add(hashcode);

            if index < 0 {
                panic!("IndexOutOfBoundsException (Java parity): Maximum capacity reached");
            }
            self.keys[index as usize] = Some(key);
        }

        index
    }

    /// Returns the index for `key`, or `-1` if the key is not in the table.
    pub fn get(&self, key: &T) -> i32 {
        self.find_key(key)
    }

    /// Removes `key` from the table.
    ///
    /// Returns the index of the key if it was found, or `-1` if it did not
    /// exist in the table.
    pub fn remove(&mut self, key: &T) -> i32 {
        let index = self.find_key(key);
        if index == -1 {
            return -1;
        }

        let hashcode = (Self::hash_code(key) & 0x7FFF_FFFF) % self.capacity;
        self.indexer.remove(hashcode, index);
        self.keys[index as usize] = None;

        index
    }

    /// Returns the number of keys stored in the table.
    pub fn get_size(&self) -> i32 {
        self.indexer.get_size()
    }

    /// Returns the current size of the key table.
    pub fn get_capacity(&self) -> i32 {
        self.capacity
    }

    /// Removes all keys.
    pub fn clear(&mut self) {
        self.indexer.clear();
        self.keys.iter_mut().for_each(|k| *k = None);
    }

    /// Returns all keys stored in this object.
    ///
    /// # Panics
    ///
    /// Panics if the number of keys visited does not match [`Self::get_size`],
    /// which would indicate internal corruption (mirrors Java's
    /// `AssertException`).
    pub fn get_keys(&self) -> Vec<T> {
        let size = self.get_size();
        let mut key_array = Vec::with_capacity(size.max(0) as usize);

        let n_lists = self.indexer.get_num_lists();
        for i in 0..n_lists {
            let mut key_index = self.indexer.first(i);
            while key_index >= 0 {
                let key = self.keys[key_index as usize]
                    .clone()
                    .expect("indexed slot unexpectedly missing a key");
                key_array.push(key);
                key_index = self.indexer.next(key_index);
            }
        }
        assert_eq!(
            key_array.len() as i32,
            size,
            "Trouble in ObjectKeyIndexer.get_keys(), size = {size}  pos = {}",
            key_array.len()
        );
        key_array
    }

    fn find_key(&self, key: &T) -> i32 {
        let hashcode = (Self::hash_code(key) & 0x7FFF_FFFF) % self.capacity;

        let mut p = self.indexer.first(hashcode);
        while p != -1 {
            if self.keys[p as usize].as_ref() == Some(key) {
                return p;
            }
            p = self.indexer.next(p);
        }
        -1
    }

    /// Increases the size of the keys array and the indexer.
    ///
    /// This must be very careful: keys need to map to the same key index
    /// even though they get re-inserted into different hash-bucket lists in
    /// the indexer (whose bucket assignment depends on `capacity`). Since
    /// this is only called when the indexer is full, there are no gaps
    /// (freed indexes) in the keys array; clearing everything and re-adding
    /// in the same order therefore reproduces the same indexes.
    fn grow(&mut self) {
        let new_capacity = next_prime(self.indexer.get_new_capacity());
        self.indexer.grow_capacity(new_capacity);
        self.indexer.grow_num_lists(new_capacity);
        self.indexer.clear();

        let old_keys = std::mem::replace(&mut self.keys, vec![None; new_capacity as usize]);
        self.capacity = new_capacity;
        for old_key in old_keys.into_iter().flatten() {
            self.put(old_key);
        }
    }
}

impl<T: Hash + Eq + Clone> Default for ObjectKeyIndexer<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let idx: ObjectKeyIndexer<String> = ObjectKeyIndexer::new();
        assert_eq!(idx.get_size(), 0);
        // `next_prime` (a fixed lookup table, matching Java's `Prime.nextPrime`) returns the
        // first table entry *strictly greater* than its input; the smallest table entry is 17,
        // so any capacity request at or below that rounds up to 17 (matches `ShortKeyIndexer`'s
        // and `IntKeyIndexer`'s identical convention for the same default capacity of 13).
        assert_eq!(idx.get_capacity(), 17);
    }

    #[test]
    fn with_capacity_rounds_up_to_prime() {
        let idx: ObjectKeyIndexer<String> = ObjectKeyIndexer::with_capacity(10);
        assert_eq!(idx.get_capacity(), 17);
    }

    #[test]
    fn put_new_key_allocates_index() {
        let mut idx = ObjectKeyIndexer::new();
        let i = idx.put("alpha".to_string());
        assert!(i >= 0);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn put_existing_key_returns_same_index() {
        let mut idx = ObjectKeyIndexer::new();
        let a = idx.put("alpha".to_string());
        let b = idx.put("alpha".to_string());
        assert_eq!(a, b);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn get_returns_index_or_negative_one() {
        let mut idx = ObjectKeyIndexer::new();
        assert_eq!(idx.get(&"missing".to_string()), -1);
        let i = idx.put("present".to_string());
        assert_eq!(idx.get(&"present".to_string()), i);
    }

    #[test]
    fn remove_returns_index_and_clears_key() {
        let mut idx = ObjectKeyIndexer::new();
        let i = idx.put("gone".to_string());
        assert_eq!(idx.remove(&"gone".to_string()), i);
        assert_eq!(idx.get(&"gone".to_string()), -1);
        assert_eq!(idx.get_size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_negative_one() {
        let mut idx: ObjectKeyIndexer<String> = ObjectKeyIndexer::new();
        assert_eq!(idx.remove(&"nope".to_string()), -1);
    }

    #[test]
    fn clear_removes_all_keys() {
        let mut idx = ObjectKeyIndexer::new();
        idx.put("a".to_string());
        idx.put("b".to_string());
        idx.clear();
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.get(&"a".to_string()), -1);
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut idx = ObjectKeyIndexer::new();
        idx.put("a".to_string());
        idx.put("b".to_string());
        idx.put("c".to_string());
        let mut keys = idx.get_keys();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn grows_when_capacity_exceeded_and_preserves_keys() {
        let mut idx: ObjectKeyIndexer<i32> = ObjectKeyIndexer::with_capacity(2);
        let initial_capacity = idx.get_capacity();
        let mut indices = Vec::new();
        for k in 0..(initial_capacity * 3) {
            indices.push((k, idx.put(k)));
        }
        assert!(idx.get_capacity() > initial_capacity);
        for (k, i) in indices {
            assert_eq!(idx.get(&k), i);
        }
        assert_eq!(idx.get_size(), initial_capacity * 3);
    }

    #[test]
    fn works_with_non_string_key_types() {
        let mut idx: ObjectKeyIndexer<(i32, i32)> = ObjectKeyIndexer::new();
        let a = idx.put((1, 2));
        let b = idx.put((3, 4));
        assert_ne!(a, b);
        assert_eq!(idx.get(&(1, 2)), a);
        assert_eq!(idx.get(&(3, 4)), b);
    }

    #[test]
    fn default_matches_new() {
        let idx: ObjectKeyIndexer<String> = ObjectKeyIndexer::default();
        assert_eq!(idx.get_capacity(), 17);
        assert_eq!(idx.get_size(), 0);
    }
}
