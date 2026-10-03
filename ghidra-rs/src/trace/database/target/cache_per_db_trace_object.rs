//! Per-object cache for range/point queries against a trace object's values.
//!
//! Java source: `ghidra.trace.database.target.CachePerDBTraceObject`.
//!
//! The Java class is `public class CachePerDBTraceObject` with no supertype, composed *into*
//! `DBTraceObject` (`private final CachePerDBTraceObject cache = new CachePerDBTraceObject();`,
//! not yet ported -- see [`crate::trace::seam_stubs::DBTraceObject`]), so it is ported as a plain
//! struct here too.
//!
//! # Shape choices
//!
//! - Java's `record Cached<T>(boolean isMiss, T value)` shares a single static `MISS` sentinel
//!   (`new Cached<>(true, null)`) across every `T` via an unchecked cast, since a record field
//!   can't be conditionally absent. Rust has no null, so [`Cached`] is ported as a proper `Miss`/
//!   `Hit(T)` enum instead of a `(bool, T)` pair -- the same information, without the unchecked
//!   cast or the possibility of a "hit" that is actually a disguised null.
//! - `NavigableMap<Long, DBTraceObjectValue>` / `NavigableMap<SnapKey, DBTraceObjectValue>` become
//!   [`BTreeMap`], whose `range` gives the same floor/sub-map queries `doStreamPerKey`/
//!   `doGetValue` need.
//! - `Stream<DBTraceObjectValue>` becomes `Vec<Arc<DBTraceObjectValue>>`: every other stream-typed
//!   Java method in this package that has already been ported
//!   ([`TraceObject::get_values`](crate::trace::model::target::trace_object::TraceObject::get_values),
//!   for instance) returns an eagerly-collected `Vec` rather than a lazy iterator, and
//!   [`DBTraceObjectValue`](crate::trace::database::target::db_trace_object_value::DBTraceObjectValue)
//!   is a concrete (non-trait) struct, so entries are shared via `Arc` the same way
//!   [`DBTraceObjectValPath`](crate::trace::database::target::db_trace_object_val_path::DBTraceObjectValPath)
//!   already shares them.
//! - `perKeyCache` is a `LinkedHashMap` with `removeEldestEntry` overridden to cap it at
//!   [`MAX_CACHE_KEYS`] entries. Java's `LinkedHashMap` (default, insertion-order mode) evicts the
//!   *first-inserted* key once the map exceeds that size, and -- this is the faithfully-preserved
//!   part -- re-`put`-ing an *existing* key does **not** move it back to the end of that order (
//!   insertion-order mode only reorders on first insertion, never on update). [`PerKeyCache`]
//!   reproduces this with a side `VecDeque` recording first-insertion order, consulted only when a
//!   *new* key is inserted.
//!
//! # Not reproduced
//!
//! - The `comparator` field on `Dimension`-adjacent classes elsewhere in this package memoizes a
//!   `Comparator`; `CachePerDBTraceObject` has no such field, so nothing was elided here.
//! - `Objects.requireNonNull(value)` in `notifyValueCreated`/`notifyValueDeleted` has no Rust
//!   equivalent: a `&DBTraceObjectValue`/`Arc<DBTraceObjectValue>` reference can never be null, so
//!   the check can never fail and is simply omitted.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use crate::trace::database::target::db_trace_object_value::DBTraceObjectValue;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// The result of a cache lookup: either a genuine miss, or a hit carrying the (possibly itself
/// "empty", e.g. `None`/an empty `Vec`) cached value.
///
/// Port of `CachePerDBTraceObject.Cached<T>`. See the module docs for why this is an enum instead
/// of Java's `(isMiss, value)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cached<T> {
    /// Mirrors `Cached.MISS` / `Cached.miss()`: nothing usable was cached.
    Miss,
    /// Mirrors `Cached.hit(T)`: a genuine cached result, which may itself be "no value" (e.g. an
    /// empty `Vec` or `None`) without that being a cache miss.
    Hit(T),
}

impl<T> Cached<T> {
    /// Mirrors `Cached.isMiss()`.
    pub fn is_miss(&self) -> bool {
        matches!(self, Cached::Miss)
    }

    /// The cached value, or `None` if this was a [`Cached::Miss`].
    ///
    /// There is no direct equivalent of Java's `value()` record accessor (which returns `null`
    /// on a miss): every caller in `DBTraceObject.java` guards with `!cached.isMiss()` before
    /// reading `value()`, so this total, `Option`-returning form captures the same guarded-access
    /// pattern without a possible null dereference.
    pub fn into_value(self) -> Option<T> {
        match self {
            Cached::Miss => None,
            Cached::Hit(value) => Some(value),
        }
    }
}

/// The maximum number of distinct keys tracked by [`CachePerDBTraceObject`]'s per-key cache.
///
/// Mirrors `CachePerDBTraceObject.MAX_CACHE_KEYS`.
const MAX_CACHE_KEYS: usize = 200;

/// How far beyond a queried span [`CachePerDBTraceObject::expand_lifespan`] widens the cached
/// range, to take advantage of spatial locality in the time dimension.
///
/// Mirrors `CachePerDBTraceObject.EXPANSION`.
const EXPANSION: i64 = 10;

/// The key `doStreamAnyKey`'s map is ordered by: primarily by snap, secondarily by entry key.
///
/// Mirrors the private `record SnapKey(long snap, String key)`. Java's `compareTo` also handles a
/// `null` key (sorting a null key after any non-null one, via reference-equality-checked null
/// tests before falling back to `String.compareTo`); the only constructor, `forValue`, always
/// supplies a real key (`DBTraceObjectValue.getEntryKey()` never returns null), so that branch of
/// the Java method is dead code and has no Rust equivalent here -- `key` is a plain `String`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SnapKey {
    snap: i64,
    key: String,
}

impl SnapKey {
    /// Mirrors `SnapKey.forValue(DBTraceObjectValue)`.
    fn for_value(value: &DBTraceObjectValue) -> SnapKey {
        SnapKey { snap: value.get_min_snap(), key: value.get_entry_key() }
    }
}

/// A cached query result, plus the (possibly expanded) span it covers.
///
/// Mirrors the private `record CachedLifespanValues<K>(Lifespan span, NavigableMap<K,
/// DBTraceObjectValue> values)`.
struct CachedLifespanValues<K: Ord> {
    span: Lifespan,
    values: BTreeMap<K, Arc<DBTraceObjectValue>>,
}

/// The size-bounded, insertion-order-evicting per-key cache backing
/// [`CachePerDBTraceObject::per_key_cache`].
///
/// Mirrors the `LinkedHashMap<String, CachedLifespanValues<Long>>` field whose
/// `removeEldestEntry` override caps it at [`MAX_CACHE_KEYS`]. See the module docs for why a
/// re-`put` of an existing key does not reorder [`PerKeyCache::order`].
#[derive(Default)]
struct PerKeyCache {
    values: HashMap<String, CachedLifespanValues<i64>>,
    /// First-insertion order of the keys currently (or formerly) in `values`, used only to find
    /// the eldest entry to evict. A key already evicted and later reinserted is pushed again,
    /// exactly as it would occupy a new position in a real `LinkedHashMap` after being removed
    /// and re-added.
    order: VecDeque<String>,
}

impl PerKeyCache {
    fn get(&self, key: &str) -> Option<&CachedLifespanValues<i64>> {
        self.values.get(key)
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut CachedLifespanValues<i64>> {
        self.values.get_mut(key)
    }

    /// Mirrors the `LinkedHashMap.put` call plus the `removeEldestEntry` override it triggers.
    fn put(&mut self, key: String, value: CachedLifespanValues<i64>) {
        if !self.values.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.values.insert(key, value);
        if self.values.len() > MAX_CACHE_KEYS {
            if let Some(eldest) = self.order.pop_front() {
                self.values.remove(&eldest);
            }
        }
    }
}

/// Filters `map`'s values to those intersecting `lifespan`. Mirrors `doStreamAnyKey`.
fn do_stream_any_key(
    map: &BTreeMap<SnapKey, Arc<DBTraceObjectValue>>,
    lifespan: Lifespan,
) -> Vec<Arc<DBTraceObjectValue>> {
    map.values().filter(|v| lifespan.intersects(v.get_lifespan())).cloned().collect()
}

/// Mirrors `doStreamPerKey`: finds the floor entry (the last entry starting at or before
/// `lifespan`'s minimum) if it still covers that minimum, then returns every entry from there
/// through `lifespan`'s maximum, in the requested direction.
fn do_stream_per_key(
    map: &BTreeMap<i64, Arc<DBTraceObjectValue>>,
    lifespan: Lifespan,
    forward: bool,
) -> Vec<Arc<DBTraceObjectValue>> {
    let mut min = lifespan.lmin();
    if let Some((&floor_key, floor_value)) = map.range(..=min).next_back() {
        if floor_value.get_lifespan().contains(min) {
            min = floor_key;
        }
    }
    let max = lifespan.lmax();
    if min > max {
        return Vec::new();
    }
    let sub = map.range(min..=max);
    if forward {
        sub.map(|(_, v)| Arc::clone(v)).collect()
    } else {
        sub.rev().map(|(_, v)| Arc::clone(v)).collect()
    }
}

/// Mirrors `doGetValue`: the floor entry at or before `snap`, if its lifespan still covers `snap`.
fn do_get_value(
    map: &BTreeMap<i64, Arc<DBTraceObjectValue>>,
    snap: i64,
) -> Option<Arc<DBTraceObjectValue>> {
    let (_, floor_value) = map.range(..=snap).next_back()?;
    if !floor_value.get_lifespan().contains(snap) {
        return None;
    }
    Some(Arc::clone(floor_value))
}

/// Per-object cache of value-stream/point queries, keyed by entry key (or unkeyed, for
/// "any key" queries) and by the span queried.
///
/// Port of `ghidra.trace.database.target.CachePerDBTraceObject`.
#[derive(Default)]
pub struct CachePerDBTraceObject {
    per_key_cache: PerKeyCache,
    any_key_cache: Option<CachedLifespanValues<SnapKey>>,
}

impl CachePerDBTraceObject {
    /// Constructs an empty cache. Mirrors the implicit no-arg constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks the "any key" cache for a value stream covering `lifespan`. Mirrors
    /// `streamValues(Lifespan)`.
    pub fn stream_values(&self, lifespan: Lifespan) -> Cached<Vec<Arc<DBTraceObjectValue>>> {
        let Some(cache) = &self.any_key_cache else {
            return Cached::Miss;
        };
        if !cache.span.encloses(lifespan) {
            return Cached::Miss;
        }
        Cached::Hit(do_stream_any_key(&cache.values, lifespan))
    }

    /// Checks the per-key cache for a value stream covering `lifespan` at `key`. Mirrors the
    /// `streamValues(Lifespan, String, boolean)` overload (renamed: Rust has no overloading).
    pub fn stream_values_by_key(
        &self,
        lifespan: Lifespan,
        key: &str,
        forward: bool,
    ) -> Cached<Vec<Arc<DBTraceObjectValue>>> {
        let Some(cache) = self.per_key_cache.get(key) else {
            return Cached::Miss;
        };
        if !cache.span.encloses(lifespan) {
            return Cached::Miss;
        }
        Cached::Hit(do_stream_per_key(&cache.values, lifespan, forward))
    }

    /// Checks the per-key cache for the value at `key` as of `snap`. Mirrors `getValue(long,
    /// String)`.
    pub fn get_value(&self, snap: i64, key: &str) -> Cached<Option<Arc<DBTraceObjectValue>>> {
        let Some(cache) = self.per_key_cache.get(key) else {
            return Cached::Miss;
        };
        if !cache.span.contains(snap) {
            return Cached::Miss;
        }
        Cached::Hit(do_get_value(&cache.values, snap))
    }

    /// Widens `lifespan` by [`EXPANSION`] on each side, clamping to [`Lifespan::ALL`]'s bounds on
    /// overflow. Mirrors `expandLifespan(Lifespan)`.
    ///
    /// # Panics
    /// Panics if `lifespan` is [`Lifespan::EMPTY`], mirroring Java's `NoSuchElementException` from
    /// `Empty.lmin()`/`Empty.lmax()`.
    pub fn expand_lifespan(&self, lifespan: Lifespan) -> Lifespan {
        // Java's `long` arithmetic wraps silently past `Long.MIN_VALUE`/`MAX_VALUE`, and detects
        // that by comparing the wrapped result against the original value. `wrapping_sub`/
        // `wrapping_add` reproduce that exactly; ordinary `-`/`+` would instead panic (in a debug
        // build) or silently do the same wrapping without the detection Java performs afterward.
        let mut min = lifespan.lmin().wrapping_sub(EXPANSION);
        if min > lifespan.lmin() {
            min = Lifespan::ALL.lmin();
        }
        let mut max = lifespan.lmax().wrapping_add(EXPANSION);
        if max < lifespan.lmax() {
            max = Lifespan::ALL.lmax();
        }
        Lifespan::span(min, max)
    }

    /// Collects `values` into an any-key map, panicking on a duplicate `(snap, key)` pair.
    /// Mirrors `collectAnyKey` plus the `IllegalStateException` `mergeValues` throws for
    /// `Collectors.toMap`'s merge function on a collision.
    fn collect_any_key(
        &self,
        values: Vec<Arc<DBTraceObjectValue>>,
    ) -> BTreeMap<SnapKey, Arc<DBTraceObjectValue>> {
        let mut map = BTreeMap::new();
        for value in values {
            let key = SnapKey::for_value(&value);
            if let Some(existing) = map.get(&key) {
                panic!("Conflicting values: {existing}, {value}");
            }
            map.insert(key, value);
        }
        map
    }

    /// Collects `values` into a per-key map keyed by each value's minimum snap, panicking on a
    /// duplicate key. Mirrors `collectPerKey` plus `mergeValues`'s `IllegalStateException`.
    fn collect_per_key(
        &self,
        values: Vec<Arc<DBTraceObjectValue>>,
    ) -> BTreeMap<i64, Arc<DBTraceObjectValue>> {
        let mut map = BTreeMap::new();
        for value in values {
            let key = value.get_lifespan().lmin();
            if let Some(existing) = map.get(&key) {
                panic!("Conflicting values: {existing}, {value}");
            }
            map.insert(key, value);
        }
        map
    }

    /// Populates the "any key" cache from a fresh query result and returns the (still-filtered)
    /// answer to the original request. Mirrors `offerStreamAnyKey`.
    pub fn offer_stream_any_key(
        &mut self,
        expanded: Lifespan,
        values: Vec<Arc<DBTraceObjectValue>>,
        lifespan: Lifespan,
    ) -> Vec<Arc<DBTraceObjectValue>> {
        let map = self.collect_any_key(values);
        let result = do_stream_any_key(&map, lifespan);
        self.any_key_cache = Some(CachedLifespanValues { span: expanded, values: map });
        result
    }

    /// Populates the per-key cache at `key` from a fresh query result and returns the answer to
    /// the original request. Mirrors `offerStreamPerKey`.
    pub fn offer_stream_per_key(
        &mut self,
        expanded: Lifespan,
        values: Vec<Arc<DBTraceObjectValue>>,
        lifespan: Lifespan,
        key: &str,
        forward: bool,
    ) -> Vec<Arc<DBTraceObjectValue>> {
        let map = self.collect_per_key(values);
        let result = do_stream_per_key(&map, lifespan, forward);
        self.per_key_cache.put(key.to_string(), CachedLifespanValues { span: expanded, values: map });
        result
    }

    /// Populates the per-key cache at `key` from a fresh query result and returns the point
    /// answer to the original request. Mirrors `offerGetValue`.
    pub fn offer_get_value(
        &mut self,
        expanded: Lifespan,
        values: Vec<Arc<DBTraceObjectValue>>,
        snap: i64,
        key: &str,
    ) -> Option<Arc<DBTraceObjectValue>> {
        let map = self.collect_per_key(values);
        let result = do_get_value(&map, snap);
        self.per_key_cache.put(key.to_string(), CachedLifespanValues { span: expanded, values: map });
        result
    }

    /// Folds a newly created value into whichever caches currently cover its lifespan. Mirrors
    /// `notifyValueCreated(DBTraceObjectValue)`.
    pub fn notify_value_created(&mut self, value: Arc<DBTraceObjectValue>) {
        if let Some(cache) = &mut self.any_key_cache {
            if cache.span.intersects(value.get_lifespan()) {
                cache.values.insert(SnapKey::for_value(&value), Arc::clone(&value));
            }
        }
        if let Some(cache) = self.per_key_cache.get_mut(&value.get_entry_key()) {
            if cache.span.intersects(value.get_lifespan()) {
                cache.values.insert(value.get_lifespan().lmin(), value);
            }
        }
    }

    /// Removes a deleted value from whichever caches currently hold it. Mirrors
    /// `notifyValueDeleted(DBTraceObjectValue)`.
    pub fn notify_value_deleted(&mut self, value: &DBTraceObjectValue) {
        if let Some(cache) = &mut self.any_key_cache {
            cache.values.remove(&SnapKey::for_value(value));
        }
        if let Some(cache) = self.per_key_cache.get_mut(&value.get_entry_key()) {
            cache.values.remove(&value.get_lifespan().lmin());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage;
    use crate::trace::seam_stubs::{DBTraceObject, DBTraceObjectManager};
    use std::any::Any;

    struct MockManager;
    impl DBTraceObjectManager for MockManager {}

    /// A minimal, non-object, root-value storage record: just enough of
    /// [`TraceObjectValueStorage`] to build a [`DBTraceObjectValue`] carrying a given entry key
    /// and lifespan, for exercising the cache in isolation from the rest of the object graph.
    struct MockStorage {
        entry_key: String,
        lifespan: Lifespan,
    }

    impl TraceObjectValueStorage for MockStorage {
        fn get_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockManager)
        }
        fn get_wrapper(&self) -> Option<Arc<DBTraceObjectValue>> {
            None
        }
        fn get_parent(&self) -> Option<Box<dyn DBTraceObject>> {
            None
        }
        fn get_entry_key(&self) -> String {
            self.entry_key.clone()
        }
        fn do_set_lifespan(&mut self, lifespan: Lifespan) {
            self.lifespan = lifespan;
        }
        fn get_lifespan(&self) -> Lifespan {
            self.lifespan
        }
        fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>> {
            None
        }
        fn get_value(&self) -> Box<dyn Any + Send + Sync> {
            Box::new(0i64)
        }
        fn is_deleted(&self) -> bool {
            false
        }
        fn do_delete(&mut self) {}
    }

    /// A root-value entry (no parent/child) with the given key and lifespan, suitable as a plain
    /// data point for exercising the cache in isolation from the rest of the object graph.
    fn value(key: &str, min: i64, max: i64) -> Arc<DBTraceObjectValue> {
        let storage: Box<dyn TraceObjectValueStorage> =
            Box::new(MockStorage { entry_key: key.to_string(), lifespan: Lifespan::span(min, max) });
        Arc::new(DBTraceObjectValue::new(Arc::new(MockManager), storage))
    }

    #[test]
    fn fresh_cache_misses_every_query() {
        let cache = CachePerDBTraceObject::new();
        assert!(cache.stream_values(Lifespan::span(0, 10)).is_miss());
        assert!(cache.stream_values_by_key(Lifespan::span(0, 10), "k", true).is_miss());
        assert!(cache.get_value(5, "k").is_miss());
    }

    #[test]
    fn expand_lifespan_widens_by_expansion_on_both_sides() {
        let cache = CachePerDBTraceObject::new();
        let expanded = cache.expand_lifespan(Lifespan::span(100, 200));
        assert_eq!(expanded, Lifespan::span(90, 210));
    }

    #[test]
    fn expand_lifespan_clamps_to_lifespan_all_on_overflow() {
        let cache = CachePerDBTraceObject::new();
        let expanded = cache.expand_lifespan(Lifespan::span(i64::MIN + 2, i64::MAX - 2));
        assert_eq!(expanded, Lifespan::ALL);
    }

    #[test]
    #[should_panic(expected = "lmin() on an empty lifespan")]
    fn expand_lifespan_panics_on_empty_lifespan() {
        CachePerDBTraceObject::new().expand_lifespan(Lifespan::EMPTY);
    }

    #[test]
    fn offer_get_value_populates_cache_and_answers_the_query() {
        let mut cache = CachePerDBTraceObject::new();
        let v = value("k", 0, 10);
        let expanded = Lifespan::span(-10, 20);
        let result = cache.offer_get_value(expanded, vec![Arc::clone(&v)], 5, "k");
        assert!(result.is_some());
        assert_eq!(result.unwrap().get_entry_key(), "k");

        // Now a hit, without needing to offer again.
        let cached = cache.get_value(5, "k");
        assert!(!cached.is_miss());
        assert!(cached.into_value().unwrap().is_some());
    }

    #[test]
    fn get_value_misses_outside_the_cached_span() {
        let mut cache = CachePerDBTraceObject::new();
        let v = value("k", 0, 10);
        cache.offer_get_value(Lifespan::span(0, 10), vec![v], 5, "k");
        // 50 falls outside the cached span entirely, so this is a genuine miss, not a hit
        // reporting "no value".
        assert!(cache.get_value(50, "k").is_miss());
    }

    #[test]
    fn get_value_hits_with_no_value_when_cached_span_covers_a_gap() {
        let mut cache = CachePerDBTraceObject::new();
        let v = value("k", 0, 5);
        // Cache covers [0, 20], but the only value's lifespan ends at 5.
        cache.offer_get_value(Lifespan::span(0, 20), vec![v], 2, "k");
        let cached = cache.get_value(10, "k");
        assert!(!cached.is_miss());
        assert!(cached.into_value().unwrap().is_none());
    }

    #[test]
    fn offer_stream_per_key_orders_forward_and_backward() {
        let mut cache = CachePerDBTraceObject::new();
        let a = value("k", 0, 4);
        let b = value("k", 5, 9);
        let c = value("k", 10, 14);
        let expanded = Lifespan::span(0, 14);
        let forward =
            cache.offer_stream_per_key(expanded, vec![Arc::clone(&a), Arc::clone(&b), Arc::clone(&c)], Lifespan::span(0, 14), "k", true);
        assert_eq!(forward.iter().map(|v| v.get_min_snap()).collect::<Vec<_>>(), vec![0, 5, 10]);

        let backward = cache.stream_values_by_key(Lifespan::span(0, 14), "k", false).into_value().unwrap();
        assert_eq!(backward.iter().map(|v| v.get_min_snap()).collect::<Vec<_>>(), vec![10, 5, 0]);
    }

    #[test]
    fn offer_stream_any_key_filters_to_intersecting_values() {
        let mut cache = CachePerDBTraceObject::new();
        let a = value("a", 0, 4);
        let b = value("b", 10, 14);
        let expanded = Lifespan::span(0, 14);
        let result = cache.offer_stream_any_key(expanded, vec![a, b], Lifespan::span(0, 4));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get_entry_key(), "a");
    }

    #[test]
    fn stream_values_misses_when_cached_span_does_not_enclose_the_query() {
        let mut cache = CachePerDBTraceObject::new();
        let a = value("a", 0, 4);
        cache.offer_stream_any_key(Lifespan::span(0, 4), vec![a], Lifespan::span(0, 4));
        // The cached span is exactly [0, 4]; a query reaching past it is a miss even though it
        // overlaps.
        assert!(cache.stream_values(Lifespan::span(0, 10)).is_miss());
    }

    #[test]
    fn notify_value_created_updates_a_live_any_key_cache() {
        let mut cache = CachePerDBTraceObject::new();
        let a = value("a", 0, 4);
        cache.offer_stream_any_key(Lifespan::span(0, 20), vec![a], Lifespan::span(0, 4));

        let b = value("b", 10, 14);
        cache.notify_value_created(Arc::clone(&b));

        let result = cache.stream_values(Lifespan::span(0, 20)).into_value().unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn notify_value_created_ignored_when_outside_cached_span() {
        let mut cache = CachePerDBTraceObject::new();
        let a = value("a", 0, 4);
        cache.offer_stream_any_key(Lifespan::span(0, 4), vec![a], Lifespan::span(0, 4));

        // Outside the cached span [0, 4], so the create notification is a no-op for this cache.
        let b = value("b", 100, 104);
        cache.notify_value_created(b);

        let result = cache.stream_values(Lifespan::span(0, 4)).into_value().unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn notify_value_deleted_removes_from_both_caches() {
        let mut cache = CachePerDBTraceObject::new();
        let a = value("k", 0, 4);
        cache.offer_stream_any_key(Lifespan::span(0, 20), vec![Arc::clone(&a)], Lifespan::span(0, 4));
        cache.offer_get_value(Lifespan::span(0, 20), vec![Arc::clone(&a)], 2, "k");

        cache.notify_value_deleted(&a);

        assert_eq!(cache.stream_values(Lifespan::span(0, 20)).into_value().unwrap().len(), 0);
        assert!(cache.get_value(2, "k").into_value().unwrap().is_none());
    }

    #[test]
    fn per_key_cache_evicts_first_inserted_key_once_over_capacity() {
        let mut cache = CachePerDBTraceObject::new();
        for i in 0..MAX_CACHE_KEYS {
            let key = format!("k{i}");
            let v = value(&key, 0, 4);
            cache.offer_get_value(Lifespan::span(0, 4), vec![v], 2, &key);
        }
        // The cache is now exactly at capacity; every key is still present.
        assert!(!cache.get_value(2, "k0").is_miss());

        // One more insertion evicts "k0", the first-inserted key.
        let v = value("k_new", 0, 4);
        cache.offer_get_value(Lifespan::span(0, 4), vec![v], 2, "k_new");
        assert!(cache.get_value(2, "k0").is_miss());
        assert!(!cache.get_value(2, "k1").is_miss());
        assert!(!cache.get_value(2, "k_new").is_miss());
    }

    #[test]
    fn per_key_cache_re_put_of_existing_key_does_not_reorder_eviction() {
        // Faithful to Java's `LinkedHashMap` in insertion-order mode: re-inserting an *existing*
        // key does not move it to the end of the eviction order, only a brand-new key does.
        let mut cache = CachePerDBTraceObject::new();
        for i in 0..MAX_CACHE_KEYS {
            let key = format!("k{i}");
            let v = value(&key, 0, 4);
            cache.offer_get_value(Lifespan::span(0, 4), vec![v], 2, &key);
        }
        // Re-offer "k0" (already present): a real LinkedHashMap would NOT move it to the end.
        let v0_again = value("k0", 0, 4);
        cache.offer_get_value(Lifespan::span(0, 4), vec![v0_again], 2, "k0");

        // One brand-new key now evicts "k0" anyway, since re-putting it did not save its place.
        let v = value("k_new", 0, 4);
        cache.offer_get_value(Lifespan::span(0, 4), vec![v], 2, "k_new");
        assert!(cache.get_value(2, "k0").is_miss());
    }

    #[test]
    fn conflicting_any_key_values_panic_like_mergevalues_throws() {
        let cache = CachePerDBTraceObject::new();
        let a = value("k", 0, 4);
        let b = value("k", 0, 4);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cache.collect_any_key(vec![a, b])
        }));
        assert!(result.is_err());
    }
}
