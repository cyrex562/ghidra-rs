use crate::framework::db::DBRecord;
use crate::program::database::db_object::DbObject;
use crate::program::model::address::key_range::KeyRange;
use std::marker::PhantomData;
use std::sync::Arc;

/// Value used by [`DbObject`] to mean "not associated with any modification count", mirroring
/// `DbCache.INVALID_COUNT`.
pub const INVALID_COUNT: i32 = -1;

/// Type-erased handle to a [`DbCache`], usable by a cached [`DbObject`] without knowing the
/// cache's element type. Mirrors the Java `DbCache<?>` wildcard type that `DbObject` holds a
/// reference to as its owning cache (see `DbObject.cache` / `DbObject.setCache`).
///
/// Port of the subset of `ghidra.program.database.DbCache`'s public API that `DbObject` calls
/// directly.
pub trait DbCacheHandle: Send + Sync {
    /// Stands in for `DbCache.getModificationCount()`.
    fn get_modification_count(&self) -> i32;

    /// Stands in for `DbCache.delete(long)`.
    fn delete(&self, key: i64);

    /// Stands in for `DbCache.keyChanged(long, long)`.
    fn key_changed(&self, old_key: i64, new_key: i64);
}

/// A `DbObject` cache that efficiently manages the use of the database lock and uses a factory
/// to create objects in the cache when they are not present.
/// <P>
/// This version of the cache is designed to be used without first acquiring a database lock. It
/// will first attempt to retrieve the object without acquiring the lock. If that fails, it will
/// acquire the lock, attempt to refresh the object if necessary or possibly create a new instance
/// using the factory and add it to the cache.
///
/// Port of `ghidra.program.database.DbCache`.
pub trait DbCache<T: DbObject>: DbCacheHandle {
    /// Returns the number of objects currently in the cache. A database lock is not required.
    fn size(&self) -> usize;

    /// Adds the given database object to the cache. Returns the object that was cached.
    fn add(&self, db_object: T) -> Arc<T>;

    /// Retrieves the database object with the given key from the cache. This differs from a
    /// plain get() in that it does not require that the database lock be acquired prior to
    /// calling this method. See the Java doc for the full retrieve/refresh/instantiate contract.
    fn get_cached_instance(&self, key: i64) -> Option<Arc<T>>;

    /// Retrieves the object from the cache, but only if it already exists and is valid in the
    /// cache. It will not attempt to refresh the object or instantiate new instances.
    fn get_if_valid(&self, key: i64) -> Option<Arc<T>>;

    /// Retrieves the object with the given key directly from the cache without checking if it is
    /// valid or needs to be refreshed, and without instantiating new instances.
    fn get_raw(&self, key: i64) -> Option<Arc<T>>;

    /// Retrieves the database object with the given record's key from the cache. This form
    /// should be used in conjunction with record iterators to avoid unnecessary record queries
    /// during a possible object refresh.
    fn get_cached_instance_for_record(&self, record: &DBRecord) -> Option<Arc<T>>;

    /// Returns a list of all the cached objects. These objects have not been checked to see if
    /// they are valid or not.
    fn get_cached_objects(&self) -> Vec<Arc<T>>;

    /// Deletes all objects from the cache whose key is contained within the specified key
    /// ranges.
    fn delete_key_ranges(&self, key_ranges: &[KeyRange]);

    /// Marks all the cached objects as invalid. Invalid objects will have to refresh themselves
    /// before they are allowed to be used. If an invalidated object cannot refresh itself, then
    /// the object is removed from the cache and discarded.
    fn invalidate(&self);
}

/// A no-op cache implementation, mirroring `DbCache.DUMMY` / the private `DbCache.DummyCache`
/// inner class. Useful as a placeholder cache for objects that are not (yet) associated with a
/// real cache.
pub struct DummyDbCache<T> {
    _marker: PhantomData<fn() -> T>,
}

impl<T> DummyDbCache<T> {
    /// Creates a new dummy cache instance.
    pub fn new() -> Self {
        DummyDbCache { _marker: PhantomData }
    }
}

impl<T> Default for DummyDbCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: DbObject> DbCacheHandle for DummyDbCache<T> {
    fn get_modification_count(&self) -> i32 {
        0
    }

    fn delete(&self, _key: i64) {
        // do nothing
    }

    fn key_changed(&self, _old_key: i64, _new_key: i64) {
        // do nothing
    }
}

impl<T: DbObject> DbCache<T> for DummyDbCache<T> {
    fn size(&self) -> usize {
        0
    }

    fn add(&self, db_object: T) -> Arc<T> {
        Arc::new(db_object)
    }

    fn get_cached_instance(&self, _key: i64) -> Option<Arc<T>> {
        None
    }

    fn get_if_valid(&self, _key: i64) -> Option<Arc<T>> {
        None
    }

    fn get_raw(&self, _key: i64) -> Option<Arc<T>> {
        None
    }

    fn get_cached_instance_for_record(&self, _record: &DBRecord) -> Option<Arc<T>> {
        None
    }

    fn get_cached_objects(&self) -> Vec<Arc<T>> {
        Vec::new()
    }

    fn delete_key_ranges(&self, _key_ranges: &[KeyRange]) {
        // do nothing
    }

    fn invalidate(&self) {
        // do nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::DbObjectState;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    /// A database object whose `refresh()` always succeeds, mirroring a concrete `DbObject`
    /// subclass that can always reconstruct its state from the database.
    struct MockDbObject {
        state: DbObjectState,
    }

    impl MockDbObject {
        fn new(key: i64) -> Self {
            MockDbObject {
                state: DbObjectState::new(key),
            }
        }
    }

    impl DbObject for MockDbObject {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            true
        }
    }

    struct MockDbCache {
        objects: Mutex<HashMap<i64, Arc<MockDbObject>>>,
        modification_count: AtomicI32,
        self_handle: std::sync::Weak<MockDbCache>,
    }

    impl MockDbCache {
        fn new() -> Arc<Self> {
            Arc::new_cyclic(|weak| MockDbCache {
                objects: Mutex::new(HashMap::new()),
                modification_count: AtomicI32::new(0),
                self_handle: weak.clone(),
            })
        }
    }

    impl DbCacheHandle for MockDbCache {
        fn get_modification_count(&self) -> i32 {
            self.modification_count.load(Ordering::SeqCst)
        }

        fn delete(&self, key: i64) {
            if let Some(obj) = self.objects.lock().unwrap().remove(&key) {
                obj.set_deleted();
            }
        }

        fn key_changed(&self, old_key: i64, new_key: i64) {
            let mut objects = self.objects.lock().unwrap();
            if let Some(obj) = objects.remove(&old_key) {
                obj.set_invalid();
                objects.insert(new_key, obj);
            }
        }
    }

    impl DbCache<MockDbObject> for MockDbCache {
        fn size(&self) -> usize {
            self.objects.lock().unwrap().len()
        }

        fn add(&self, db_object: MockDbObject) -> Arc<MockDbObject> {
            let arc_obj = Arc::new(db_object);
            if let Some(handle) = self.self_handle.upgrade() {
                let handle: Arc<dyn DbCacheHandle> = handle;
                arc_obj.set_cache(handle);
            }
            self.objects
                .lock()
                .unwrap()
                .insert(arc_obj.get_key(), arc_obj.clone());
            arc_obj
        }

        fn get_cached_instance(&self, key: i64) -> Option<Arc<MockDbObject>> {
            self.objects.lock().unwrap().get(&key).cloned()
        }

        fn get_if_valid(&self, key: i64) -> Option<Arc<MockDbObject>> {
            self.objects
                .lock()
                .unwrap()
                .get(&key)
                .filter(|obj| obj.is_valid())
                .cloned()
        }

        fn get_raw(&self, key: i64) -> Option<Arc<MockDbObject>> {
            self.objects.lock().unwrap().get(&key).cloned()
        }

        fn get_cached_instance_for_record(&self, record: &DBRecord) -> Option<Arc<MockDbObject>> {
            let key = match record.get_key() {
                crate::framework::db::Field::Long(Some(value)) => *value,
                _ => return None,
            };
            self.get_cached_instance(key)
        }

        fn get_cached_objects(&self) -> Vec<Arc<MockDbObject>> {
            self.objects.lock().unwrap().values().cloned().collect()
        }

        fn delete_key_ranges(&self, key_ranges: &[KeyRange]) {
            let mut objects = self.objects.lock().unwrap();
            let doomed: Vec<i64> = objects
                .keys()
                .copied()
                .filter(|key| key_ranges.iter().any(|range| range.contains(*key)))
                .collect();
            for key in doomed {
                if let Some(obj) = objects.remove(&key) {
                    obj.set_deleted();
                }
            }
        }

        fn invalidate(&self) {
            self.modification_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn as_trait_object(cache: Arc<MockDbCache>) -> Arc<dyn DbCache<MockDbObject>> {
        cache
    }

    #[test]
    fn add_and_get_cached_instance_round_trips_through_trait_object() {
        let cache = as_trait_object(MockDbCache::new());

        let added = cache.add(MockDbObject::new(7));
        assert_eq!(added.get_key(), 7);
        assert_eq!(cache.size(), 1);

        let fetched = cache.get_cached_instance(7).expect("object should be cached");
        assert_eq!(fetched.get_key(), 7);
        assert!(fetched.is_valid());
    }

    #[test]
    fn invalidate_bumps_modification_count_and_marks_objects_stale() {
        let cache = as_trait_object(MockDbCache::new());
        let obj = cache.add(MockDbObject::new(1));
        assert!(obj.is_valid());

        cache.invalidate();

        assert_eq!(cache.get_modification_count(), 1);
        assert!(!obj.is_valid());

        assert!(obj.refresh_if_needed());
        assert!(obj.is_valid());
    }

    #[test]
    fn delete_by_key_removes_from_cache_and_marks_deleted() {
        let cache = as_trait_object(MockDbCache::new());
        let obj = cache.add(MockDbObject::new(3));

        cache.delete(3);

        assert!(cache.get_cached_instance(3).is_none());
        assert!(!obj.is_valid());
        assert!(!obj.refresh_if_needed());
    }

    #[test]
    fn delete_key_ranges_removes_matching_keys_only() {
        let cache = as_trait_object(MockDbCache::new());
        cache.add(MockDbObject::new(10));
        cache.add(MockDbObject::new(20));
        cache.add(MockDbObject::new(30));

        cache.delete_key_ranges(&[KeyRange::new(15, 25)]);

        assert_eq!(cache.size(), 2);
        assert!(cache.get_cached_instance(20).is_none());
        assert!(cache.get_cached_instance(10).is_some());
        assert!(cache.get_cached_instance(30).is_some());
    }

    #[test]
    fn key_changed_moves_object_and_invalidates_it() {
        let cache = as_trait_object(MockDbCache::new());
        let obj = cache.add(MockDbObject::new(1));
        assert!(obj.is_valid());

        cache.key_changed(1, 2);

        assert!(cache.get_cached_instance(1).is_none());
        let moved = cache.get_cached_instance(2).expect("object should be at new key");
        assert!(!moved.is_valid());
    }

    #[test]
    fn dummy_cache_is_always_empty_and_never_invalid() {
        let dummy: DummyDbCache<MockDbObject> = DummyDbCache::new();
        assert_eq!(dummy.size(), 0);
        assert_eq!(dummy.get_modification_count(), 0);
        assert!(dummy.get_cached_instance(1).is_none());

        let added = dummy.add(MockDbObject::new(1));
        // Dummy never actually caches: querying it back returns nothing.
        assert!(dummy.get_cached_instance(1).is_none());
        assert_eq!(added.get_key(), 1);
    }
}
