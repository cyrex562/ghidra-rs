use lru::LruCache;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, Weak};

pub struct WeakReferenceCache<K, V> {
    inner: Mutex<CacheInner<K, V>>,
}

struct CacheInner<K, V> {
    refs: HashMap<K, Weak<V>>,
    hard_cache: LruCache<K, Arc<V>>,
}

impl<K, V> WeakReferenceCache<K, V>
where
    K: Clone + Eq + Hash,
{
    pub fn new(hard_cache_size: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                refs: HashMap::new(),
                hard_cache: LruCache::new(std::num::NonZeroUsize::new(hard_cache_size).unwrap()),
            }),
        }
    }

    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(weak_ref) = inner.refs.get(key) {
            if let Some(v) = weak_ref.upgrade() {
                inner.hard_cache.put(key.clone(), v.clone());
                return Some(v);
            } else {
                inner.refs.remove(key);
            }
        }
        None
    }

    pub fn add(&self, key: K, value: V) -> Arc<V> {
        let mut inner = self.inner.lock().unwrap();
        let arc_v = Arc::new(value);
        inner.hard_cache.put(key.clone(), arc_v.clone());
        inner.refs.insert(key, Arc::downgrade(&arc_v));
        arc_v
    }

    pub fn size(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.refs.len()
    }

    pub fn delete(&self, key: &K) -> Option<Arc<V>> {
        let mut inner = self.inner.lock().unwrap();
        inner.hard_cache.pop(key);
        inner.refs.remove(key).and_then(|w| w.upgrade())
    }

    pub fn get_cached_objects(&self) -> Vec<Arc<V>> {
        let inner = self.inner.lock().unwrap();
        inner.refs.values().filter_map(|w| w.upgrade()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_cache() {
        let cache = WeakReferenceCache::new(2);
        cache.add(1, "one".to_string());
        cache.add(2, "two".to_string());

        assert_eq!(*cache.get(&1).unwrap(), "one");

        // Add more to push out of hard cache
        cache.add(3, "three".to_string());
        // Since hard cache size is 2, one of them (likely 2 if we didn't touch it) might be gone if not referenced elsewhere.
        // But in our test, arc_v is dropped unless we store it.
    }
}
