//! Port of `ghidra.util.timer.GTimerCache`.
//!
//! Caches key/value entries for a limited time and cache size. Entries are removed after the
//! cache duration has passed. If the cache ever exceeds its capacity, the least-recently-used
//! entry is removed.
//!
//! Java's implementation uses a `LinkedHashMap` in "access order" mode: iterating the map
//! presents entries oldest-first, and both `get`/`put` move an entry to the back (making it
//! youngest). This means entries closest to (or past) expiration are presented first.
//!
//! ## Rust shape: a `HashMap` plus an explicit access-order `VecDeque<K>`
//!
//! Rust's standard library has no access-order `LinkedHashMap` equivalent, so this port pairs a
//! plain `HashMap<K, CachedValue<V>>` (O(1) lookup) with a `VecDeque<K>` tracking access order
//! (front = least-recently-accessed/oldest, back = most-recently-accessed/youngest) -- the same
//! two invariants Java's single `LinkedHashMap` maintains together.
//!
//! ## `valueRemoved`/`valueAdded`/`shouldRemoveFromCache`: hooks, not subclassing
//!
//! Java's class is designed to be *subclassed*, overriding three `protected` methods. Rust has no
//! subclassing; following this crate's [`CachingPool`](crate::generic::cache::CachingPool)
//! precedent (which takes a `BasicFactory` trait object as its "customization point"), this port
//! takes a [`GTimerCacheHooks<K, V>`] trait object at construction, with default (no-op /
//! always-remove) implementations matching Java's own base-class bodies.
//!
//! ## `Arc<dyn GTimer>`, not a global static timer
//!
//! Same rationale as [`CachingPool`](crate::generic::cache::CachingPool): [`new`](GTimerCache::new)
//! defaults to [`StdGTimer`], while [`with_timer`](GTimerCache::new) constructors accept a
//! substitute [`GTimer`] for testing.
//!
//! ## Deviation: `Duration` cannot be negative
//!
//! Java validates `lifetime.isZero() || lifetime.isNegative()`. Rust's [`std::time::Duration`] is
//! unsigned and cannot represent a negative value at all, so the "negative" half of that check is
//! unreachable by construction here; only the zero case is checked (and panics, mirroring Java's
//! `IllegalArgumentException`).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::util::timer::{GTimer, GTimerMonitor, StdGTimer};

/// Hook trait mirroring the three `protected` methods Java's `GTimerCache` is designed to be
/// subclassed to override. Default implementations match Java's own base-class bodies exactly:
/// no-op `value_removed`/`value_added`, and `should_remove_from_cache` always returns `true`.
pub trait GTimerCacheHooks<K, V>: Send + Sync {
    /// Called when an item is being removed from the cache (evicted by capacity, expired, or
    /// explicitly removed/replaced/cleared). Port of `GTimerCache.valueRemoved(K, V)`.
    fn value_removed(&self, _key: &K, _value: &V) {}

    /// Called when a value is being added to the cache. Port of `GTimerCache.valueAdded(K, V)`.
    fn value_added(&self, _key: &K, _value: &V) {}

    /// Called when an item's cache time has expired, to determine if the item should actually be
    /// removed from the cache. Port of `GTimerCache.shouldRemoveFromCache(K, V)`.
    fn should_remove_from_cache(&self, _key: &K, _value: &V) -> bool {
        true
    }
}

/// The default hook set, matching an unsubclassed Java `GTimerCache` used directly.
struct DefaultGTimerCacheHooks;
impl<K, V> GTimerCacheHooks<K, V> for DefaultGTimerCacheHooks {}

struct CachedValue<V> {
    value: V,
    last_accessed: Instant,
}

struct Inner<K, V> {
    capacity: usize,
    lifetime_millis: i64,
    /// Access order: front = least-recently-accessed (oldest), back = most-recently-accessed.
    order: VecDeque<K>,
    map: HashMap<K, CachedValue<V>>,
    timer_monitor: Option<Box<dyn GTimerMonitor>>,
}

/// Port of `ghidra.util.timer.GTimerCache<K, V>`. See the module docs for the shape/hook/timer
/// deviations from the Java original.
pub struct GTimerCache<K, V> {
    timer: Arc<dyn GTimer>,
    hooks: Arc<dyn GTimerCacheHooks<K, V>>,
    inner: Arc<Mutex<Inner<K, V>>>,
}

impl<K, V> GTimerCache<K, V>
where
    K: Clone + Eq + Hash + Send + 'static,
    V: Clone + PartialEq + Send + 'static,
{
    /// Constructs a new `GTimerCache` with a duration for cached entries and a maximum number of
    /// entries to cache. Port of `GTimerCache(Duration, int)`. Uses [`StdGTimer`] and the default
    /// (no-op) hooks, matching an unsubclassed Java `GTimerCache` used directly.
    pub fn new(lifetime: Duration, capacity: usize) -> Self {
        Self::with_timer_and_hooks(lifetime, capacity, Arc::new(StdGTimer), Arc::new(DefaultGTimerCacheHooks))
    }

    /// As [`new`](Self::new), but with explicit [`GTimerCacheHooks`], for callers that need the
    /// `valueRemoved`/`valueAdded`/`shouldRemoveFromCache` customization points Java exposes via
    /// subclassing.
    pub fn with_hooks(lifetime: Duration, capacity: usize, hooks: Arc<dyn GTimerCacheHooks<K, V>>) -> Self {
        Self::with_timer_and_hooks(lifetime, capacity, Arc::new(StdGTimer), hooks)
    }

    /// As [`new`](Self::new), but with an explicit [`GTimer`] and [`GTimerCacheHooks`].
    pub fn with_timer_and_hooks(
        lifetime: Duration,
        capacity: usize,
        timer: Arc<dyn GTimer>,
        hooks: Arc<dyn GTimerCacheHooks<K, V>>,
    ) -> Self {
        if lifetime.is_zero() {
            panic!("IllegalArgumentException: The duration must be a time > 0!");
        }
        if capacity < 1 {
            panic!("IllegalArgumentException: The capacity must be > 0!");
        }
        GTimerCache {
            timer,
            hooks,
            inner: Arc::new(Mutex::new(Inner {
                capacity,
                lifetime_millis: lifetime.as_millis() as i64,
                order: VecDeque::new(),
                map: HashMap::new(),
                timer_monitor: None,
            })),
        }
    }

    /// Sets the capacity for this cache. If this cache currently has more values than the new
    /// capacity, the oldest values are removed. Port of `GTimerCache.setCapacity(int)`.
    pub fn set_capacity(&self, capacity: usize) {
        if capacity < 1 {
            panic!("IllegalArgumentException: The capacity must be > 0!");
        }
        let mut guard = self.inner.lock().unwrap();
        guard.capacity = capacity;
        if guard.map.len() <= capacity {
            return;
        }
        let n = guard.map.len() - capacity;
        for _ in 0..n {
            let Some(k) = guard.order.pop_front() else { break };
            if let Some(cv) = guard.map.remove(&k) {
                self.hooks.value_removed(&k, &cv.value);
            }
        }
    }

    /// Sets the duration for keeping cached values. Port of `GTimerCache.setDuration(Duration)`.
    pub fn set_duration(&self, duration: Duration) {
        if duration.is_zero() {
            panic!("IllegalArgumentException: The duration must be a time > 0!");
        }
        {
            let mut guard = self.inner.lock().unwrap();
            guard.lifetime_millis = duration.as_millis() as i64;
            if let Some(mon) = guard.timer_monitor.take() {
                mon.cancel();
            }
        }
        // This will purge any older values and reset the timer to the correct delay.
        timer_expired(&self.inner, &self.hooks, &self.timer);
    }

    /// Adds a key/value entry to the cache. Port of `GTimerCache.put(K, V)`.
    ///
    /// Returns the previous value associated with the key, or `None` if there was none.
    pub fn put(&self, key: K, value: V) -> Option<V> {
        let mut guard = self.inner.lock().unwrap();
        let now = Instant::now();

        let previous_cv = guard.map.remove(&key);
        if previous_cv.is_some() {
            if let Some(pos) = guard.order.iter().position(|k| k == &key) {
                guard.order.remove(pos);
            }
        }
        let previous_value = previous_cv.map(|cv| cv.value);

        guard.map.insert(key.clone(), CachedValue { value: value.clone(), last_accessed: now });
        guard.order.push_back(key.clone());

        // Port of `removeEldestEntry`, which Java's underlying `LinkedHashMap.put()` triggers
        // internally as part of the insertion above (i.e. *before* the changed-value hooks
        // below run). Only a genuinely new key can grow `map` past capacity -- overwriting an
        // existing key never changes `map.len()`.
        if guard.map.len() > guard.capacity {
            if let Some(evict_key) = guard.order.pop_front() {
                if let Some(evict_cv) = guard.map.remove(&evict_key) {
                    self.hooks.value_removed(&evict_key, &evict_cv.value);
                }
            }
        }

        let changed = match &previous_value {
            Some(prev) => prev != &value,
            None => true,
        };
        if changed {
            if let Some(prev) = &previous_value {
                self.hooks.value_removed(&key, prev);
            }
            self.hooks.value_added(&key, &value);
        }

        if guard.timer_monitor.is_none() {
            let lifetime = guard.lifetime_millis;
            let mon = schedule_expiry_timer(
                Arc::clone(&self.inner),
                Arc::clone(&self.hooks),
                Arc::clone(&self.timer),
                lifetime,
            );
            guard.timer_monitor = Some(mon);
        }

        previous_value
    }

    /// Removes the cache entry with the given key. Port of `GTimerCache.remove(K)`.
    ///
    /// Returns the value removed, or `None` if the key wasn't in the cache.
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut guard = self.inner.lock().unwrap();
        let removed = guard.map.remove(key)?;
        if let Some(pos) = guard.order.iter().position(|k| k == key) {
            guard.order.remove(pos);
        }
        self.hooks.value_removed(key, &removed.value);
        Some(removed.value)
    }

    /// Returns `true` if the cache contains a value for the given key. Port of
    /// `GTimerCache.containsKey(K)`. Does not affect access order (matches Java: `containsKey`
    /// does not trigger `LinkedHashMap`'s access-order reordering).
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.lock().unwrap().map.contains_key(key)
    }

    /// Returns the number of entries in the cache. Port of `GTimerCache.size()`.
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }

    /// Returns the value for the given key, also resetting the time associated with this entry.
    /// Port of `GTimerCache.get(K)`.
    pub fn get(&self, key: &K) -> Option<V> {
        let mut guard = self.inner.lock().unwrap();
        if !guard.map.contains_key(key) {
            return None;
        }
        if let Some(pos) = guard.order.iter().position(|k| k == key) {
            guard.order.remove(pos);
        }
        guard.order.push_back(key.clone());
        let cv = guard.map.get_mut(key).expect("just confirmed present");
        cv.last_accessed = Instant::now();
        Some(cv.value.clone())
    }

    /// Clears all the values in the cache. The `value_removed` hook is called for each entry
    /// that was in the cache, oldest first (matching Java's `LinkedHashMap` iteration order).
    /// Port of `GTimerCache.clear()`.
    pub fn clear(&self) {
        let mut guard = self.inner.lock().unwrap();
        let keys: Vec<K> = guard.order.iter().cloned().collect();
        for k in &keys {
            if let Some(cv) = guard.map.get(k) {
                self.hooks.value_removed(k, &cv.value);
            }
        }
        guard.map.clear();
        guard.order.clear();
    }
}

fn schedule_expiry_timer<K, V>(
    inner: Arc<Mutex<Inner<K, V>>>,
    hooks: Arc<dyn GTimerCacheHooks<K, V>>,
    timer: Arc<dyn GTimer>,
    delay_millis: i64,
) -> Box<dyn GTimerMonitor>
where
    K: Clone + Eq + Hash + Send + 'static,
    V: Clone + PartialEq + Send + 'static,
{
    let timer_for_cb = Arc::clone(&timer);
    timer.schedule_runnable(
        delay_millis,
        Box::new(move || {
            timer_expired(&inner, &hooks, &timer_for_cb);
        }),
    )
}

/// Port of the private `GTimerCache.timerExpired()`. A free function (rather than a method) so it
/// can be called both directly (from [`GTimerCache::set_duration`]) and recursively from the
/// scheduled `'static` timer callback without needing a self-referential `Arc<GTimerCache>`.
fn timer_expired<K, V>(
    inner: &Arc<Mutex<Inner<K, V>>>,
    hooks: &Arc<dyn GTimerCacheHooks<K, V>>,
    timer: &Arc<dyn GTimer>,
) where
    K: Clone + Eq + Hash + Send + 'static,
    V: Clone + PartialEq + Send + 'static,
{
    let mut guard = inner.lock().unwrap();
    guard.timer_monitor = None;
    let event_time = Instant::now();

    // Gather and remove every currently-expired entry, oldest first. Since `order` is
    // maintained in access order, once a non-expired entry is reached, none that follow can be
    // expired either -- matches Java's `break` on the first non-expired entry.
    let mut expired: Vec<(K, CachedValue<V>)> = Vec::new();
    loop {
        let is_expired = match guard.order.front() {
            None => false,
            Some(k) => {
                let cv = guard.map.get(k).expect("order/map must stay in sync");
                event_time.duration_since(cv.last_accessed).as_millis() as i64 >= guard.lifetime_millis
            }
        };
        if !is_expired {
            break;
        }
        let k = guard.order.pop_front().expect("checked Some above");
        let cv = guard.map.remove(&k).expect("order/map must stay in sync");
        expired.push((k, cv));
    }

    for (k, cv) in expired {
        if hooks.should_remove_from_cache(&k, &cv.value) {
            hooks.value_removed(&k, &cv.value);
        } else {
            // The client wants to keep the entry in the cache. Treat this like adding a new
            // entry: reset its access time and reinstate it as the youngest (back of `order`).
            let mut cv = cv;
            cv.last_accessed = Instant::now();
            guard.order.push_back(k.clone());
            guard.map.insert(k, cv);
        }
    }

    if guard.order.is_empty() {
        return;
    }

    let first_key = guard.order.front().expect("checked non-empty above").clone();
    let first = guard.map.get(&first_key).expect("order/map must stay in sync");
    let elapsed = event_time.duration_since(first.last_accessed).as_millis() as i64;
    let remaining = guard.lifetime_millis - elapsed;

    let mon = schedule_expiry_timer(Arc::clone(inner), Arc::clone(hooks), Arc::clone(timer), remaining);
    guard.timer_monitor = Some(mon);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct Removed {
        key: String,
        value: i32,
    }

    struct RecordingHooks {
        removed: StdMutex<Vec<Removed>>,
    }

    impl RecordingHooks {
        fn new() -> Arc<Self> {
            Arc::new(RecordingHooks { removed: StdMutex::new(Vec::new()) })
        }
        fn removed_snapshot(&self) -> Vec<Removed> {
            self.removed.lock().unwrap().clone()
        }
    }

    impl GTimerCacheHooks<String, i32> for RecordingHooks {
        fn value_removed(&self, key: &String, value: &i32) {
            self.removed.lock().unwrap().push(Removed { key: key.clone(), value: *value });
        }
    }

    const KEEP_TIME_MS: u64 = 100;
    const MAX_SIZE: usize = 4;

    fn build() -> (GTimerCache<String, i32>, Arc<RecordingHooks>) {
        let hooks = RecordingHooks::new();
        let cache = GTimerCache::with_hooks(
            Duration::from_millis(KEEP_TIME_MS),
            MAX_SIZE,
            hooks.clone() as Arc<dyn GTimerCacheHooks<String, i32>>,
        );
        (cache, hooks)
    }

    fn k(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn value_expiring() {
        let (cache, hooks) = build();
        cache.put(k("AAA"), 5);
        assert_eq!(cache.size(), 1);
        assert!(cache.contains_key(&k("AAA")));

        std::thread::sleep(Duration::from_millis(KEEP_TIME_MS - 10));
        assert_eq!(cache.size(), 1);
        assert!(cache.contains_key(&k("AAA")));
        assert!(hooks.removed_snapshot().is_empty());

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(cache.size(), 0);
        assert!(cache.get(&k("AAA")).is_none());
        assert!(!cache.contains_key(&k("AAA")));
        let removed = hooks.removed_snapshot();
        assert!(!removed.is_empty());
        assert_eq!(removed[0], Removed { key: k("AAA"), value: 5 });
    }

    #[test]
    fn accessing_value_keeps_alive_longer() {
        let (cache, _hooks) = build();
        cache.put(k("AAA"), 5);
        std::thread::sleep(Duration::from_millis(KEEP_TIME_MS - 50));
        assert_eq!(cache.get(&k("AAA")), Some(5));
        std::thread::sleep(Duration::from_millis(KEEP_TIME_MS - 10));
        assert_eq!(cache.size(), 1);
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn accessing_value_reorders_values() {
        let (cache, hooks) = build();
        cache.put(k("AAA"), 5);
        cache.put(k("BBB"), 8);
        cache.get(&k("AAA"));
        std::thread::sleep(Duration::from_millis(KEEP_TIME_MS + 60));
        assert_eq!(cache.size(), 0);
        let removed = hooks.removed_snapshot();
        assert_eq!(removed.len(), 2);
        assert_eq!(removed[0], Removed { key: k("BBB"), value: 8 });
        assert_eq!(removed[1], Removed { key: k("AAA"), value: 5 });
    }

    #[test]
    fn maxsize_evicts_oldest_over_capacity() {
        let (cache, hooks) = build();
        cache.put(k("A"), 1);
        cache.put(k("B"), 2);
        cache.put(k("C"), 3);
        cache.put(k("D"), 4);
        cache.put(k("E"), 5);
        cache.put(k("F"), 6);

        assert_eq!(cache.size(), 4);
        let removed = hooks.removed_snapshot();
        assert_eq!(removed.len(), 2);
        assert_eq!(removed[0], Removed { key: k("A"), value: 1 });
        assert_eq!(removed[1], Removed { key: k("B"), value: 2 });
    }

    #[test]
    fn remove_prevents_later_expiry_callback() {
        let (cache, hooks) = build();
        cache.put(k("A"), 1);
        let removed_value = cache.remove(&k("A"));
        assert_eq!(removed_value, Some(1));

        std::thread::sleep(Duration::from_millis(KEEP_TIME_MS + 60));
        assert_eq!(cache.size(), 0);
        assert_eq!(hooks.removed_snapshot().len(), 1);
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let (cache, _hooks) = build();
        cache.put(k("A"), 1);
        assert_eq!(cache.remove(&k("B")), None);
    }

    #[test]
    fn clear_calls_removed_for_every_entry() {
        let (cache, hooks) = build();
        cache.put(k("A"), 1);
        cache.put(k("B"), 2);
        cache.clear();
        assert_eq!(hooks.removed_snapshot().len(), 2);
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn set_capacity_smaller_evicts_oldest() {
        let (cache, hooks) = build();
        cache.put(k("A"), 1);
        cache.put(k("B"), 2);
        cache.put(k("C"), 3);
        cache.put(k("D"), 4);
        assert_eq!(cache.size(), 4);

        cache.set_capacity(2);
        assert_eq!(cache.size(), 2);
        assert_eq!(hooks.removed_snapshot().len(), 2);
    }

    #[test]
    fn set_capacity_larger_leaves_cache_untouched() {
        let (cache, hooks) = build();
        cache.put(k("A"), 1);
        cache.put(k("B"), 2);
        cache.put(k("C"), 3);
        cache.put(k("D"), 4);
        assert_eq!(cache.size(), 4);

        cache.set_capacity(6);
        assert_eq!(cache.size(), 4);
        assert_eq!(hooks.removed_snapshot().len(), 0);
    }

    #[test]
    fn set_duration_shorter_with_time_still_remaining() {
        let (cache, _hooks) = build();
        cache.put(k("A"), 1);
        cache.set_duration(Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(cache.size(), 1);
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn set_duration_shorter_with_immediate_expiration() {
        let (cache, hooks) = build();
        cache.put(k("A"), 1);
        std::thread::sleep(Duration::from_millis(50));
        cache.set_duration(Duration::from_millis(40));
        assert_eq!(cache.size(), 0);
        assert_eq!(hooks.removed_snapshot().len(), 1);
    }

    #[test]
    fn set_duration_longer_extends_life() {
        let (cache, _hooks) = build();
        cache.put(k("A"), 1);
        std::thread::sleep(Duration::from_millis(50));
        cache.set_duration(Duration::from_millis(150));
        assert_eq!(cache.size(), 1);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cache.size(), 1);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn putting_new_value_with_same_key_reports_old_value_and_calls_removed() {
        let (cache, hooks) = build();
        assert_eq!(cache.put(k("A"), 1), None);
        assert_eq!(cache.put(k("A"), 2), Some(1));
        let removed = hooks.removed_snapshot();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], Removed { key: k("A"), value: 1 });
    }

    #[test]
    fn putting_equal_value_with_same_key_does_not_call_removed() {
        let (cache, hooks) = build();
        assert_eq!(cache.put(k("A"), 1), None);
        assert_eq!(cache.put(k("A"), 1), Some(1));
        assert_eq!(hooks.removed_snapshot().len(), 0);
    }

    /// Faithful port of Java's `KeepOnceTestTimerCache`: `should_remove_from_cache` keeps the
    /// entry the first time it expires (returning `false`) and removes it the second time.
    #[test]
    fn timer_expired_but_should_remove_returned_false_keeps_item_once() {
        struct KeepOnceHooks {
            should_remove: StdMutex<bool>,
            removed: StdMutex<Vec<Removed>>,
        }
        impl GTimerCacheHooks<String, i32> for KeepOnceHooks {
            fn value_removed(&self, key: &String, value: &i32) {
                self.removed.lock().unwrap().push(Removed { key: key.clone(), value: *value });
            }
            fn should_remove_from_cache(&self, _key: &String, _value: &i32) -> bool {
                let mut sr = self.should_remove.lock().unwrap();
                if *sr {
                    return true;
                }
                *sr = true;
                false
            }
        }
        let hooks = Arc::new(KeepOnceHooks {
            should_remove: StdMutex::new(false),
            removed: StdMutex::new(Vec::new()),
        });
        let cache: GTimerCache<String, i32> = GTimerCache::with_hooks(
            Duration::from_millis(KEEP_TIME_MS),
            MAX_SIZE,
            hooks.clone() as Arc<dyn GTimerCacheHooks<String, i32>>,
        );

        cache.put(k("A"), 1);
        std::thread::sleep(Duration::from_millis(110));
        assert_eq!(cache.size(), 1, "first expiration: item should remain in cache");
        assert_eq!(hooks.removed.lock().unwrap().len(), 0);

        std::thread::sleep(Duration::from_millis(110));
        assert_eq!(cache.size(), 0);
        assert_eq!(hooks.removed.lock().unwrap().len(), 1);
    }

    #[test]
    #[should_panic(expected = "IllegalArgumentException: The duration must be a time > 0!")]
    fn zero_duration_panics() {
        let _c: GTimerCache<String, i32> = GTimerCache::new(Duration::from_millis(0), 4);
    }

    #[test]
    #[should_panic(expected = "IllegalArgumentException: The capacity must be > 0!")]
    fn zero_capacity_panics() {
        let _c: GTimerCache<String, i32> = GTimerCache::new(Duration::from_millis(100), 0);
    }

    #[test]
    #[should_panic(expected = "IllegalArgumentException: The capacity must be > 0!")]
    fn set_capacity_zero_panics() {
        let (cache, _hooks) = build();
        cache.set_capacity(0);
    }

    #[test]
    fn default_hooks_are_no_ops_when_using_new() {
        let cache: GTimerCache<String, i32> = GTimerCache::new(Duration::from_millis(KEEP_TIME_MS), MAX_SIZE);
        cache.put(k("A"), 1);
        cache.remove(&k("A"));
        // No panic and no observable side effect beyond the cache's own bookkeeping -- proves
        // `GTimerCache::new` works standalone without requiring a caller-supplied hooks impl.
        assert_eq!(cache.size(), 0);
    }
}
