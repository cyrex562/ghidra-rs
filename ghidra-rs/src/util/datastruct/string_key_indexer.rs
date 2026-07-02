use super::int_list_indexer::IntListIndexer;
use super::prime::next_prime;

const DEFAULT_CAPACITY: i32 = 13;

/// Computes the Java `String.hashCode()` equivalent for a string.
fn java_string_hash(s: &str) -> i32 {
    let mut hash = 0i32;
    for c in s.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(c as i32);
    }
    hash
}

/// Converts arbitrary `String` keys into compacted `i32` indexes suitable for
/// use as indexes into an array or table.
///
/// Whenever a new key is added, the smallest unused index is allocated and
/// associated with that key. Hashes the keys into linked lists using
/// [`IntListIndexer`], where all values in a list share the same hash code.
/// This does most of the work of a separate-chaining hash table -- the only
/// thing missing is the values, which are stored by the containing structure.
#[derive(Debug, Clone)]
pub struct StringKeyIndexer {
    keys: Vec<Option<String>>,
    indexer: IntListIndexer,
    capacity: i32,
}

impl StringKeyIndexer {
    /// Creates a new `StringKeyIndexer` with a default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Creates a new `StringKeyIndexer` with a given initial capacity.
    pub fn with_capacity(capacity: i32) -> Self {
        let capacity = next_prime(capacity);
        Self {
            keys: vec![None; capacity as usize],
            indexer: IntListIndexer::new(capacity, capacity),
            capacity,
        }
    }

    /// Returns an index that will always be associated with the given key as
    /// long as the key remains in the table.
    ///
    /// If the key already exists, the index where that key is stored is
    /// returned. If the key is new, a new index is allocated, the key is
    /// stored at that index, and the new index is returned.
    ///
    /// # Panics
    ///
    /// Panics if this object is at maximum capacity and no new index can be
    /// allocated.
    pub fn put(&mut self, key: &str) -> i32 {
        let mut index = self.find_key(key);

        if index == -1 {
            if self.indexer.get_size() >= self.capacity {
                self.grow();
            }
            let hashcode = (java_string_hash(key) & 0x7fffffff) % self.capacity;
            index = self.indexer.add(hashcode);

            if index < 0 {
                panic!("Maximum capacity reached");
            }
            self.keys[index as usize] = Some(key.to_string());
        }

        index
    }

    /// Returns the index for the given key, or `-1` if the key is not in the
    /// table.
    pub fn get(&self, key: &str) -> i32 {
        self.find_key(key)
    }

    /// Removes the key from the table.
    ///
    /// Returns the index of the key if the key was found, or `-1` if the key
    /// did not exist in the table.
    pub fn remove(&mut self, key: &str) -> i32 {
        let index = self.find_key(key);
        if index == -1 {
            return -1;
        }

        let hashcode = (java_string_hash(key) & 0x7fffffff) % self.capacity;
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
    }

    /// Returns an array containing all the keys stored in this object.
    ///
    /// # Panics
    ///
    /// Panics if the number of keys visited does not match [`Self::get_size`],
    /// which would indicate internal corruption.
    pub fn get_keys(&self) -> Vec<String> {
        let mut key_array = Vec::with_capacity(self.get_size() as usize);

        let n_lists = self.indexer.get_num_lists();
        for i in 0..n_lists {
            let mut key_index = self.indexer.first(i);
            while key_index >= 0 {
                key_array.push(self.keys[key_index as usize].clone().unwrap());
                key_index = self.indexer.next(key_index);
            }
        }
        if key_array.len() != self.get_size() as usize {
            panic!(
                "Trouble in StringKeyIndexer.get_keys(), size = {}  pos= {}",
                self.get_size(),
                key_array.len()
            );
        }
        key_array
    }

    /// Returns an iterator over all the keys.
    pub fn get_key_iterator(&self) -> StringKeyIndexerIter<'_> {
        StringKeyIndexerIter {
            indexer: self,
            n_lists: self.indexer.get_num_lists(),
            index: 0,
            key_index: -1,
        }
    }

    fn find_key(&self, key: &str) -> i32 {
        let hashcode = (java_string_hash(key) & 0x7fffffff) % self.capacity;

        let mut p = self.indexer.first(hashcode);

        while p != -1 {
            if self.keys[p as usize].as_deref() == Some(key) {
                return p;
            }
            p = self.indexer.next(p);
        }
        -1
    }

    /// Increases the size of the keys array and the indexer.
    ///
    /// This method needs to be very careful! It is very important that the
    /// keys get mapped to the same key index even though they are stored in a
    /// different list in the indexer (which is indexed based on the hash code
    /// (mod capacity) of the key). Since this method can only be called when
    /// the indexer is full, we can assume that there are no gaps (freed
    /// indexes) in the keys array. Therefore, if we clear everything and add
    /// them back in the same order that they were stored in the old keys
    /// array, they should be assigned the same index. This is important since
    /// other containing structures may be storing lots of information based
    /// on this index, and we don't want the indexing to change just because
    /// we had to grow.
    fn grow(&mut self) {
        let new_capacity = next_prime(self.indexer.get_new_capacity());
        self.indexer.grow_capacity(new_capacity);
        self.indexer.grow_num_lists(new_capacity);
        self.indexer.clear();

        let old_keys = std::mem::replace(&mut self.keys, vec![None; new_capacity as usize]);
        self.capacity = new_capacity;
        for old_key in old_keys.into_iter().flatten() {
            self.put(&old_key);
        }
    }
}

impl Default for StringKeyIndexer {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over all the keys stored in a [`StringKeyIndexer`].
pub struct StringKeyIndexerIter<'a> {
    indexer: &'a StringKeyIndexer,
    n_lists: i32,
    index: i32,
    key_index: i32,
}

impl<'a> Iterator for StringKeyIndexerIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.key_index < 0 {
            if self.index >= self.n_lists {
                return None;
            }
            self.key_index = self.indexer.indexer.first(self.index);
            self.index += 1;
        }
        let result = self.indexer.keys[self.key_index as usize].as_deref().unwrap();
        self.key_index = self.indexer.indexer.next(self.key_index);
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let idx = StringKeyIndexer::new();
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.get_capacity(), 17);
    }

    #[test]
    fn with_capacity_rounds_up_to_prime() {
        let idx = StringKeyIndexer::with_capacity(10);
        assert_eq!(idx.get_capacity(), 17);
    }

    #[test]
    fn put_new_key_allocates_index() {
        let mut idx = StringKeyIndexer::new();
        let i = idx.put("foo");
        assert!(i >= 0);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn put_existing_key_returns_same_index() {
        let mut idx = StringKeyIndexer::new();
        let a = idx.put("foo");
        let b = idx.put("foo");
        assert_eq!(a, b);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn get_returns_index_or_negative_one() {
        let mut idx = StringKeyIndexer::new();
        assert_eq!(idx.get("bar"), -1);
        let i = idx.put("bar");
        assert_eq!(idx.get("bar"), i);
    }

    #[test]
    fn remove_returns_index_and_clears_key() {
        let mut idx = StringKeyIndexer::new();
        let i = idx.put("baz");
        assert_eq!(idx.remove("baz"), i);
        assert_eq!(idx.get("baz"), -1);
        assert_eq!(idx.get_size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_negative_one() {
        let mut idx = StringKeyIndexer::new();
        assert_eq!(idx.remove("missing"), -1);
    }

    #[test]
    fn clear_removes_all_keys() {
        let mut idx = StringKeyIndexer::new();
        idx.put("a");
        idx.put("b");
        idx.clear();
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.get("a"), -1);
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut idx = StringKeyIndexer::new();
        idx.put("a");
        idx.put("b");
        idx.put("c");
        let mut keys = idx.get_keys();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn key_iterator_visits_all_keys() {
        let mut idx = StringKeyIndexer::new();
        idx.put("a");
        idx.put("b");
        idx.put("c");
        let mut keys: Vec<String> = idx.get_key_iterator().map(|s| s.to_string()).collect();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn key_iterator_empty_when_no_keys() {
        let idx = StringKeyIndexer::new();
        assert_eq!(idx.get_key_iterator().count(), 0);
    }

    #[test]
    fn grows_when_capacity_exceeded_and_preserves_keys() {
        let mut idx = StringKeyIndexer::with_capacity(2);
        let initial_capacity = idx.get_capacity();
        let mut indices = Vec::new();
        for k in 0..(initial_capacity * 3) {
            let key = format!("key{k}");
            indices.push((key.clone(), idx.put(&key)));
        }
        assert!(idx.get_capacity() > initial_capacity);
        for (k, i) in indices {
            assert_eq!(idx.get(&k), i);
        }
        assert_eq!(idx.get_size(), initial_capacity * 3);
    }

    #[test]
    fn java_hash_code_matches_known_values() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("a"), 97);
        assert_eq!(java_string_hash("hello"), 99162322);
    }

    #[test]
    fn default_matches_new() {
        let idx = StringKeyIndexer::default();
        assert_eq!(idx.get_capacity(), 17);
    }
}
