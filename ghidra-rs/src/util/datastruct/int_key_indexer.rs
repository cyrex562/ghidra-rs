use super::int_list_indexer::IntListIndexer;
use super::prime::next_prime;

const DEFAULT_CAPACITY: i32 = 13;

/// Converts arbitrary `i32` keys into compacted `i32` indexes suitable for use
/// as indexes into an array or table.
///
/// Whenever a new key is added, the smallest unused index is allocated and
/// associated with that key. Hashes the keys into linked lists using
/// [`IntListIndexer`], where all values in a list share the same hash code.
/// This does most of the work of a separate-chaining hash table -- the only
/// thing missing is the values, which are stored by the containing structure.
#[derive(Debug, Clone)]
pub struct IntKeyIndexer {
    keys: Vec<i32>,
    indexer: IntListIndexer,
    capacity: i32,
}

impl IntKeyIndexer {
    /// Creates a new `IntKeyIndexer` with a default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Creates a new `IntKeyIndexer` with a given initial capacity.
    pub fn with_capacity(capacity: i32) -> Self {
        let capacity = next_prime(capacity);
        Self {
            keys: vec![0; capacity as usize],
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
    pub fn put(&mut self, key: i32) -> i32 {
        let mut index = self.find_key(key);

        if index == -1 {
            if self.indexer.get_size() >= self.capacity {
                self.grow();
            }
            let hashcode = (key & 0x7fffffff) % self.capacity;
            index = self.indexer.add(hashcode);

            if index < 0 {
                panic!("Maximum capacity reached");
            }
            self.keys[index as usize] = key;
        }

        index
    }

    /// Returns the index for the given key, or `-1` if the key is not in the
    /// table.
    pub fn get(&self, key: i32) -> i32 {
        self.find_key(key)
    }

    /// Removes the key from the table.
    ///
    /// Returns the index of the key if the key was found, or `-1` if the key
    /// did not exist in the table.
    pub fn remove(&mut self, key: i32) -> i32 {
        let index = self.find_key(key);
        if index == -1 {
            return -1;
        }

        let hashcode = (key & 0x7fffffff) % self.capacity;
        self.indexer.remove(hashcode, index);

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
    pub fn get_keys(&self) -> Vec<i32> {
        let mut key_array = vec![0; self.get_size() as usize];
        let mut pos = 0usize;

        let n_lists = self.indexer.get_num_lists();
        for i in 0..n_lists {
            let mut key_index = self.indexer.first(i);
            while key_index >= 0 {
                key_array[pos] = self.keys[key_index as usize];
                pos += 1;
                key_index = self.indexer.next(key_index);
            }
        }
        if pos != self.get_size() as usize {
            panic!(
                "Trouble in IntKeyIndexer.get_keys(), size = {}  pos= {}",
                self.get_size(),
                pos
            );
        }
        key_array
    }

    fn find_key(&self, key: i32) -> i32 {
        let hashcode = (key & 0x7fffffff) % self.capacity;

        let mut p = self.indexer.first(hashcode);

        while p != -1 {
            if self.keys[p as usize] == key {
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

        let old_keys = std::mem::replace(&mut self.keys, vec![0; new_capacity as usize]);
        self.capacity = new_capacity;
        for old_key in old_keys {
            self.put(old_key);
        }
    }
}

impl Default for IntKeyIndexer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let idx = IntKeyIndexer::new();
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.get_capacity(), 17);
    }

    #[test]
    fn with_capacity_rounds_up_to_prime() {
        let idx = IntKeyIndexer::with_capacity(10);
        assert_eq!(idx.get_capacity(), 17);
    }

    #[test]
    fn put_new_key_allocates_index() {
        let mut idx = IntKeyIndexer::new();
        let i = idx.put(42);
        assert!(i >= 0);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn put_existing_key_returns_same_index() {
        let mut idx = IntKeyIndexer::new();
        let a = idx.put(42);
        let b = idx.put(42);
        assert_eq!(a, b);
        assert_eq!(idx.get_size(), 1);
    }

    #[test]
    fn get_returns_index_or_negative_one() {
        let mut idx = IntKeyIndexer::new();
        assert_eq!(idx.get(7), -1);
        let i = idx.put(7);
        assert_eq!(idx.get(7), i);
    }

    #[test]
    fn remove_returns_index_and_clears_key() {
        let mut idx = IntKeyIndexer::new();
        let i = idx.put(5);
        assert_eq!(idx.remove(5), i);
        assert_eq!(idx.get(5), -1);
        assert_eq!(idx.get_size(), 0);
    }

    #[test]
    fn remove_missing_key_returns_negative_one() {
        let mut idx = IntKeyIndexer::new();
        assert_eq!(idx.remove(99), -1);
    }

    #[test]
    fn clear_removes_all_keys() {
        let mut idx = IntKeyIndexer::new();
        idx.put(1);
        idx.put(2);
        idx.clear();
        assert_eq!(idx.get_size(), 0);
        assert_eq!(idx.get(1), -1);
    }

    #[test]
    fn get_keys_returns_all_stored_keys() {
        let mut idx = IntKeyIndexer::new();
        idx.put(1);
        idx.put(2);
        idx.put(3);
        let mut keys = idx.get_keys();
        keys.sort();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn grows_when_capacity_exceeded_and_preserves_keys() {
        let mut idx = IntKeyIndexer::with_capacity(2);
        let initial_capacity = idx.get_capacity();
        let mut indices = Vec::new();
        for k in 0..(initial_capacity * 3) {
            indices.push((k, idx.put(k)));
        }
        assert!(idx.get_capacity() > initial_capacity);
        for (k, i) in indices {
            assert_eq!(idx.get(k), i);
        }
        assert_eq!(idx.get_size(), initial_capacity * 3);
    }

    #[test]
    fn negative_keys_are_supported() {
        let mut idx = IntKeyIndexer::new();
        let i = idx.put(-100);
        assert_eq!(idx.get(-100), i);
        assert_eq!(idx.remove(-100), i);
    }

    #[test]
    fn default_matches_new() {
        let idx = IntKeyIndexer::default();
        assert_eq!(idx.get_capacity(), 17);
    }
}
