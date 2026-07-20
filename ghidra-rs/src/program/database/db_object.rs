//! Port of `ghidra.program.database.DbObject`.

use crate::framework::db::DBRecord;
use crate::program::database::db_cache::{DbCacheHandle, INVALID_COUNT};
use crate::util::lock::Lock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

/// A no-op cache handle used as the initial owner of a [`DbObjectState`] before it is added to a
/// real cache, mirroring `DbCache.DUMMY`.
struct NoCacheHandle;

impl DbCacheHandle for NoCacheHandle {
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

/// Bookkeeping state shared by every [`DbObject`], mirroring the private/protected fields of the
/// Java `DbObject` base class: `key`, `deleted`, `cache`, `lastValidModificationCount`, and
/// `refreshing`. A concrete database object type embeds this in a field and exposes it via
/// [`DbObject::state`]; the default trait methods do the rest.
///
/// Java's `refreshIfNeeded(DBRecord)` is `synchronized`, but a Java monitor is reentrant for the
/// owning thread, so that modifier serializes concurrent callers without blocking the recursive
/// re-entry that `refreshing` is designed to short-circuit (see `doRefresh`). A plain
/// (non-reentrant) Rust mutex would deadlock on that same recursive re-entry, so this port omits
/// it and relies solely on the `refreshing` flag, matching the recursion-guard behavior that
/// `synchronized` plus `refreshing` produce together in Java.
pub struct DbObjectState {
    key: AtomicI64,
    deleted: AtomicBool,
    cache: Mutex<Arc<dyn DbCacheHandle>>,
    last_valid_modification_count: AtomicI32,
    refreshing: AtomicBool,
}

impl DbObjectState {
    /// Constructs state for a new database object with the given key, initially owned by a
    /// no-op cache. Mirrors `DbObject(long key)`.
    pub fn new(key: i64) -> Self {
        DbObjectState {
            key: AtomicI64::new(key),
            deleted: AtomicBool::new(false),
            cache: Mutex::new(Arc::new(NoCacheHandle)),
            last_valid_modification_count: AtomicI32::new(0),
            refreshing: AtomicBool::new(false),
        }
    }

    /// Stands in for `DbObject.getKey()`.
    pub fn get_key(&self) -> i64 {
        self.key.load(Ordering::SeqCst)
    }

    /// Stands in for `DbObject.setCache(DbCache<?>)`.
    pub fn set_cache(&self, cache: Arc<dyn DbCacheHandle>) {
        let modification_count = cache.get_modification_count();
        *self.cache.lock().unwrap() = cache;
        self.last_valid_modification_count
            .store(modification_count, Ordering::SeqCst);
    }

    /// Returns the cache this object currently belongs to.
    pub fn cache(&self) -> Arc<dyn DbCacheHandle> {
        self.cache.lock().unwrap().clone()
    }

    /// Raw getter for the `deleted` field.
    pub fn is_deleted_flag(&self) -> bool {
        self.deleted.load(Ordering::SeqCst)
    }

    /// Stands in for `DbObject.setDeleted()`.
    pub fn set_deleted(&self) {
        self.deleted.store(true, Ordering::SeqCst);
    }

    /// Stands in for `DbObject.setInvalid()`.
    pub fn set_invalid(&self) {
        self.last_valid_modification_count
            .store(INVALID_COUNT, Ordering::SeqCst);
    }

    /// Stands in for `DbObject.setValid()`.
    pub fn set_valid(&self) {
        let modification_count = self.cache().get_modification_count();
        self.last_valid_modification_count
            .store(modification_count, Ordering::SeqCst);
    }

    /// Stands in for `DbObject.keyChanged(long)`.
    pub fn key_changed(&self, new_key: i64) {
        let old_key = self.key.swap(new_key, Ordering::SeqCst);
        self.cache().key_changed(old_key, new_key);
    }

    /// Stands in for `DbObject.needsRefreshing()`.
    pub fn needs_refreshing(&self) -> bool {
        if self.is_deleted_flag() {
            return false;
        }
        self.last_valid_modification_count.load(Ordering::SeqCst) != self.cache().get_modification_count()
    }

    /// Stands in for `DbObject.isValid()`.
    pub fn is_valid(&self) -> bool {
        if self.is_deleted_flag() {
            return false;
        }
        self.last_valid_modification_count.load(Ordering::SeqCst) == self.cache().get_modification_count()
    }

    /// Raw getter for the `refreshing` recursion guard.
    pub fn is_refreshing(&self) -> bool {
        self.refreshing.load(Ordering::SeqCst)
    }

    /// Raw setter for the `refreshing` recursion guard.
    pub fn set_refreshing(&self, refreshing: bool) {
        self.refreshing.store(refreshing, Ordering::SeqCst);
    }
}

/// Base behavior for objects stored in the database.
/// <P>
/// The general contract for database objects is that there should only ever be one instance for
/// a specific database object at any given time. To facilitate this, instances of database
/// objects should be stored in a [`DbCache`](crate::program::database::db_cache::DbCache) and
/// the cache should be queried before creating any new instances.
/// <P>
/// Database objects have keys that are used by the database record and also serve as the key for
/// cache lookup. They are marked as invalid when a database cache is invalidated and can be
/// revived on a refresh as long as they haven't been deleted.
///
/// Port of `ghidra.program.database.DbObject`.
pub trait DbObject: Send + Sync {
    /// Accessor for this object's bookkeeping state (key, cache, deleted/valid tracking).
    /// Implementors hold a [`DbObjectState`] field and return a reference to it.
    fn state(&self) -> &DbObjectState;

    /// Tells the object to refresh its state from the database using the specified record if
    /// provided. The record may be `None`, in which case the object is generally expected to be
    /// able to retrieve its own record from the database as needed.
    /// <P>
    /// This method generally should not be called directly as it provides no recursion
    /// protection. Instead, most clients should call [`DbObject::refresh_if_needed`] instead,
    /// which WILL provide recursion protection.
    ///
    /// Returns true if the object was able to refresh itself. Returns false if `record` is
    /// `None` and the object was deleted.
    ///
    /// Stands in for the abstract `DbObject.refresh(DBRecord)`.
    fn refresh(&self, record: Option<&DBRecord>) -> bool;

    /// Special method for setting the cache and should ONLY be used by a `DbCache` when an
    /// object is added to the cache. Stands in for `DbObject.setCache(DbCache<?>)`.
    fn set_cache(&self, cache: Arc<dyn DbCacheHandle>) {
        self.state().set_cache(cache);
    }

    /// Get the database key for this object. Stands in for `DbObject.getKey()`.
    fn get_key(&self) -> i64 {
        self.state().get_key()
    }

    /// Marks the object as deleted. Stands in for `DbObject.setDeleted()`.
    fn set_deleted(&self) {
        self.state().set_deleted();
    }

    /// Invalidate this object. This does not necessarily mean that this object can never be used
    /// again. If the object can refresh itself, it may still be usable. Stands in for
    /// `DbObject.setInvalid()`.
    fn set_invalid(&self) {
        self.state().set_invalid();
    }

    /// Marks this object as valid. Note that this call does no checking on its own, should be
    /// used very carefully, and only when the caller is absolutely sure that the object is
    /// valid. Stands in for `DbObject.setValid()`.
    fn set_valid(&self) {
        self.state().set_valid();
    }

    /// Method for updating the cache if an object's record key changed. This is a very unusual
    /// situation and should generally be avoided. Stands in for `DbObject.keyChanged(long)`.
    fn key_changed(&self, new_key: i64) {
        self.state().key_changed(new_key);
    }

    /// Returns true if the object needs to be refreshed prior to further use. Stands in for
    /// `DbObject.needsRefreshing()`.
    fn needs_refreshing(&self) -> bool {
        self.state().needs_refreshing()
    }

    /// Return true if the object is known to be valid at this time. Stands in for
    /// `DbObject.isValid()`.
    fn is_valid(&self) -> bool {
        self.state().is_valid()
    }

    /// Refreshes the object's state from the database if it is possibly stale. Stands in for
    /// `DbObject.refreshIfNeeded()`.
    fn refresh_if_needed(&self) -> bool {
        self.refresh_if_needed_with_record(None)
    }

    /// Refreshes the object's state if it is stale, using the given record if provided. If the
    /// object has already been deleted, it will immediately return false. Stands in for
    /// `DbObject.refreshIfNeeded(DBRecord)`.
    fn refresh_if_needed_with_record(&self, record: Option<&DBRecord>) -> bool {
        if self.state().needs_refreshing() {
            self.do_refresh(record);
        }
        !self.state().is_deleted_flag()
    }

    /// Checks if this object has been deleted, in which case any use of the object is not
    /// allowed. Stands in for `DbObject.checkDeleted()`, which mirrors a thrown
    /// `ConcurrentModificationException`.
    ///
    /// # Errors
    /// Returns `Err` if the object has been deleted from the database.
    fn check_deleted(&self) -> Result<(), String> {
        if !self.refresh_if_needed() {
            return Err("Object has been deleted.".to_string());
        }
        Ok(())
    }

    /// Internal method for performing a refresh on a database object. This method may be called
    /// recursively, which it can detect and short circuit. Stands in for
    /// `DbObject.doRefresh(DBRecord)`.
    fn do_refresh(&self, record: Option<&DBRecord>) {
        if self.state().is_refreshing() {
            // NOTE: We need to correct such recursion cases which should be
            // avoided since object is not in a valid state until refresh completed.
            return;
        }
        self.state().set_refreshing(true);
        if self.refresh(record) {
            // Object is valid
            self.set_valid();
        }
        else {
            // if refresh failed, object has been deleted
            self.state().cache().delete(self.get_key());
            self.set_deleted();
        }
        self.state().set_refreshing(false);
    }

    /// This method provides a cheap (lock free) way to test if an object is valid. If this
    /// object is invalid and not deleted, then the lock will be used to refresh as needed. A
    /// deleted object will not be refreshed. Stands in for `DbObject.validate(Lock)`.
    fn validate(&self, lock: &Lock<()>) -> bool {
        if self.is_valid() {
            return true;
        }
        if self.state().is_deleted_flag() {
            return false;
        }

        let _guard = lock.read();
        self.refresh_if_needed()
    }

    /// Returns true if this object has been deleted. Note: once an object has been deleted, it
    /// will never be "refreshed". Stands in for `DbObject.isDeleted(Lock)`.
    fn is_deleted(&self, lock: &Lock<()>) -> bool {
        self.state().is_deleted_flag() || !self.validate(lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct MockCache {
        modification_count: AtomicI32,
        deleted_keys: Mutex<Vec<i64>>,
        key_changes: Mutex<Vec<(i64, i64)>>,
    }

    impl MockCache {
        fn new() -> Arc<Self> {
            Arc::new(MockCache {
                modification_count: AtomicI32::new(0),
                deleted_keys: Mutex::new(Vec::new()),
                key_changes: Mutex::new(Vec::new()),
            })
        }

        fn invalidate(&self) {
            self.modification_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl DbCacheHandle for MockCache {
        fn get_modification_count(&self) -> i32 {
            self.modification_count.load(Ordering::SeqCst)
        }

        fn delete(&self, key: i64) {
            self.deleted_keys.lock().unwrap().push(key);
        }

        fn key_changed(&self, old_key: i64, new_key: i64) {
            self.key_changes.lock().unwrap().push((old_key, new_key));
        }
    }

    /// A mock database object whose `refresh` behavior is controlled by a shared flag, allowing
    /// tests to simulate both a successful refresh and a refresh that discovers the object has
    /// been deleted from the database.
    struct MockDbObject {
        state: DbObjectState,
        refresh_succeeds: AtomicBool,
        refresh_calls: AtomicUsize,
    }

    impl MockDbObject {
        fn new(key: i64) -> Self {
            MockDbObject {
                state: DbObjectState::new(key),
                refresh_succeeds: AtomicBool::new(true),
                refresh_calls: AtomicUsize::new(0),
            }
        }
    }

    impl DbObject for MockDbObject {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            self.refresh_succeeds.load(Ordering::SeqCst)
        }
    }

    fn as_trait_object(obj: Arc<MockDbObject>) -> Arc<dyn DbObject> {
        obj
    }

    #[test]
    fn new_object_is_valid_once_added_to_a_cache() {
        let cache = MockCache::new();
        let obj = as_trait_object(Arc::new(MockDbObject::new(5)));

        obj.set_cache(cache.clone());

        assert_eq!(obj.get_key(), 5);
        assert!(obj.is_valid());
        assert!(!obj.needs_refreshing());
    }

    #[test]
    fn invalidate_marks_object_stale_and_refresh_revalidates_it() {
        let cache = MockCache::new();
        let obj = as_trait_object(Arc::new(MockDbObject::new(1)));
        obj.set_cache(cache.clone());
        assert!(obj.is_valid());

        cache.invalidate();
        assert!(obj.needs_refreshing());
        assert!(!obj.is_valid());

        assert!(obj.refresh_if_needed());
        assert!(obj.is_valid());
        assert!(!obj.needs_refreshing());
    }

    #[test]
    fn failed_refresh_deletes_the_object_from_its_cache() {
        let cache = MockCache::new();
        let mock = Arc::new(MockDbObject::new(9));
        mock.refresh_succeeds.store(false, Ordering::SeqCst);
        let obj = as_trait_object(mock);
        obj.set_cache(cache.clone());

        cache.invalidate();
        assert!(!obj.refresh_if_needed());

        assert!(obj.is_deleted(&Lock::new_unit("test")));
        assert_eq!(*cache.deleted_keys.lock().unwrap(), vec![9]);

        // Once deleted, the object never refreshes again, even if the cache is invalidated
        // again.
        cache.invalidate();
        assert!(!obj.refresh_if_needed());
    }

    #[test]
    fn check_deleted_errors_only_after_deletion() {
        let cache = MockCache::new();
        let mock = Arc::new(MockDbObject::new(2));
        let obj = as_trait_object(mock.clone());
        obj.set_cache(cache.clone());

        assert!(obj.check_deleted().is_ok());

        mock.refresh_succeeds.store(false, Ordering::SeqCst);
        cache.invalidate();

        let err = obj.check_deleted().expect_err("object should be deleted");
        assert_eq!(err, "Object has been deleted.");
    }

    #[test]
    fn key_changed_updates_key_and_notifies_cache() {
        let cache = MockCache::new();
        let obj = as_trait_object(Arc::new(MockDbObject::new(1)));
        obj.set_cache(cache.clone());

        obj.key_changed(2);

        assert_eq!(obj.get_key(), 2);
        assert_eq!(*cache.key_changes.lock().unwrap(), vec![(1, 2)]);
    }

    #[test]
    fn recursive_refresh_is_short_circuited() {
        struct RecursingDbObject {
            state: DbObjectState,
            recursive_calls: AtomicUsize,
        }

        impl DbObject for RecursingDbObject {
            fn state(&self) -> &DbObjectState {
                &self.state
            }

            fn refresh(&self, record: Option<&DBRecord>) -> bool {
                // Simulate a subclass whose refresh() implementation re-enters
                // refresh_if_needed(); the `refreshing` guard must make the nested call a no-op
                // (rather than recursing into refresh() again), while still reporting the object
                // as not-deleted.
                self.recursive_calls.fetch_add(1, Ordering::SeqCst);
                assert!(self.refresh_if_needed_with_record(record));
                true
            }
        }

        let cache = MockCache::new();
        let obj = RecursingDbObject {
            state: DbObjectState::new(1),
            recursive_calls: AtomicUsize::new(0),
        };
        obj.set_cache(cache.clone());
        cache.invalidate();

        assert!(obj.refresh_if_needed());
        assert_eq!(obj.recursive_calls.load(Ordering::SeqCst), 1);
        assert!(obj.is_valid());
    }
}
