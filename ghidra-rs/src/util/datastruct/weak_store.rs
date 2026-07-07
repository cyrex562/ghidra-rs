use std::sync::{Arc, Mutex, Weak};

struct Inner<T> {
    links: Vec<Weak<T>>,
}

impl<T> Inner<T> {
    fn process_queue(&mut self) {
        self.links.retain(|w| w.strong_count() > 0);
    }
}

/// Store for weakly-referenced object instances.
///
/// Values of type `T` are added via [`add`](WeakStore::add) as [`Arc<T>`]; the
/// store retains only a [`Weak`] pointer. Entries whose referent has been dropped
/// are purged lazily on the next access.
///
/// Unlike a set, duplicate entries (equal or pointer-equal values) are permitted.
/// The primary use case is iterating all currently-live items.
///
/// Thread-safe: all operations acquire an internal mutex.
///
/// Port of `ghidra.util.datastruct.WeakStore`.
pub struct WeakStore<T> {
    inner: Mutex<Inner<T>>,
}

impl<T> WeakStore<T> {
    /// Creates a new empty `WeakStore`.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { links: Vec::new() }),
        }
    }

    /// Returns the number of objects still in the store that have not been dropped.
    pub fn size(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.process_queue();
        inner.links.len()
    }

    /// Returns all currently-live objects in this store.
    pub fn get_values(&self) -> Vec<Arc<T>> {
        let mut inner = self.inner.lock().unwrap();
        inner.process_queue();
        inner.links.iter().filter_map(|w| w.upgrade()).collect()
    }

    /// Adds `value` to the store.
    ///
    /// The store holds a [`Weak`] reference to the underlying `Arc` allocation.
    /// When all external [`Arc<T>`] handles for this value are dropped, the entry
    /// is purged on the next access.
    pub fn add(&self, value: &Arc<T>) {
        let mut inner = self.inner.lock().unwrap();
        inner.process_queue();
        inner.links.push(Arc::downgrade(value));
    }
}

impl<T> Default for WeakStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_store_is_empty() {
        let store: WeakStore<i32> = WeakStore::new();
        assert_eq!(store.size(), 0);
        assert!(store.get_values().is_empty());
    }

    #[test]
    fn default_creates_empty() {
        let store: WeakStore<i32> = WeakStore::default();
        assert_eq!(store.size(), 0);
    }

    #[test]
    fn add_increments_size() {
        let store = WeakStore::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        store.add(&a);
        assert_eq!(store.size(), 1);
        store.add(&b);
        assert_eq!(store.size(), 2);
    }

    #[test]
    fn drop_removes_from_size() {
        let store = WeakStore::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        store.add(&a);
        store.add(&b);
        drop(a);
        assert_eq!(store.size(), 1);
        drop(b);
        assert_eq!(store.size(), 0);
    }

    #[test]
    fn get_values_returns_live_only() {
        let store = WeakStore::new();
        let a = Arc::new("aaa");
        let b = Arc::new("bbb");
        let c = Arc::new("ccc");
        store.add(&a);
        store.add(&b);
        store.add(&c);
        drop(b);
        let values = store.get_values();
        assert_eq!(values.len(), 2);
        assert_eq!(*values[0], "aaa");
        assert_eq!(*values[1], "ccc");
    }

    #[test]
    fn get_values_preserves_insertion_order() {
        let store = WeakStore::new();
        let a = Arc::new(10i32);
        let b = Arc::new(20i32);
        let c = Arc::new(30i32);
        store.add(&a);
        store.add(&b);
        store.add(&c);
        let values: Vec<i32> = store.get_values().iter().map(|v| **v).collect();
        assert_eq!(values, vec![10, 20, 30]);
    }

    #[test]
    fn duplicate_entries_allowed() {
        let store = WeakStore::new();
        let v = Arc::new(42i32);
        store.add(&v);
        store.add(&v);
        assert_eq!(store.size(), 2);
        drop(v);
        assert_eq!(store.size(), 0);
    }

    #[test]
    fn all_dropped_size_is_zero() {
        let store = WeakStore::new();
        let a = Arc::new(1i32);
        let b = Arc::new(2i32);
        let c = Arc::new(3i32);
        store.add(&a);
        store.add(&b);
        store.add(&c);
        drop(a);
        drop(b);
        drop(c);
        assert_eq!(store.size(), 0);
        assert!(store.get_values().is_empty());
    }

    #[test]
    fn size_reflects_live_entries_after_partial_drop() {
        let store = WeakStore::new();
        let items: Vec<Arc<i32>> = (0..5).map(|i| Arc::new(i)).collect();
        for item in &items {
            store.add(item);
        }
        assert_eq!(store.size(), 5);
        drop(items);
        assert_eq!(store.size(), 0);
    }
}
