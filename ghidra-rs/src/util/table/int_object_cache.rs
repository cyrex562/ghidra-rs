/// A fixed-size index-keyed cache backed by a slot array.
///
/// Mirrors `ghidra.util.table.IntObjectCache`. The Java original uses
/// `SoftReference` so the GC may evict entries under memory pressure; Rust has
/// no equivalent mechanism, so entries are held strongly and never evicted
/// automatically. All other semantics (indexed put/get, no-op on out-of-range
/// access) are preserved.
pub struct IntObjectCache<T> {
    values: Vec<Option<T>>,
}

impl<T> IntObjectCache<T> {
    /// Creates a cache with `size` slots, all initially empty.
    pub fn new(size: usize) -> Self {
        let mut values = Vec::with_capacity(size);
        values.resize_with(size, || None);
        Self { values }
    }

    /// Stores `obj` at `index`. Does nothing if `index` is out of range.
    pub fn put(&mut self, index: usize, obj: T) {
        if let Some(slot) = self.values.get_mut(index) {
            *slot = Some(obj);
        }
    }

    /// Returns a reference to the value at `index`, or `None` if the slot is
    /// empty or `index` is out of range.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.values.get(index)?.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cache_all_empty() {
        let cache: IntObjectCache<i32> = IntObjectCache::new(4);
        for i in 0..4 {
            assert!(cache.get(i).is_none());
        }
    }

    #[test]
    fn put_then_get_returns_value() {
        let mut cache = IntObjectCache::new(8);
        cache.put(3, "hello");
        assert_eq!(cache.get(3), Some(&"hello"));
    }

    #[test]
    fn put_overwrites_previous_value() {
        let mut cache = IntObjectCache::new(4);
        cache.put(1, 10u32);
        cache.put(1, 20u32);
        assert_eq!(cache.get(1), Some(&20u32));
    }

    #[test]
    fn get_out_of_range_returns_none() {
        let cache: IntObjectCache<i32> = IntObjectCache::new(4);
        assert!(cache.get(10).is_none());
    }

    #[test]
    fn put_out_of_range_is_noop() {
        let mut cache: IntObjectCache<i32> = IntObjectCache::new(4);
        cache.put(10, 42); // should not panic
        assert!(cache.get(10).is_none());
    }

    #[test]
    fn empty_cache_size_zero() {
        let mut cache: IntObjectCache<i32> = IntObjectCache::new(0);
        cache.put(0, 1); // should not panic
        assert!(cache.get(0).is_none());
    }

    #[test]
    fn multiple_slots_independent() {
        let mut cache = IntObjectCache::new(5);
        cache.put(0, 100i64);
        cache.put(2, 200i64);
        cache.put(4, 300i64);
        assert_eq!(cache.get(0), Some(&100));
        assert!(cache.get(1).is_none());
        assert_eq!(cache.get(2), Some(&200));
        assert!(cache.get(3).is_none());
        assert_eq!(cache.get(4), Some(&300));
    }
}
