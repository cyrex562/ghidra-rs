//! Operations shared by the trace's DB-backed "data settings" property map and its per-space
//! delegates.
//!
//! Java source: `ghidra.trace.database.data.DBTraceDataSettingsOperations`.
//!
//! This interface was selected as a dependency-cycle cut-point, so it is ported as a trait. It
//! extends `TraceAddressSnapRangePropertyMapOperations<DBTraceSettingsEntry>`, where
//! `DBTraceSettingsEntry` is a nested, DB-record-backed type of the (not yet ported)
//! `DBTraceDataSettingsAdapter`; that entry type is represented here by the placeholder
//! [`DBTraceSettingsEntry`](crate::trace::seam_stubs::DBTraceSettingsEntry) trait, and `T` in the
//! supertrait becomes `Box<dyn DBTraceSettingsEntry>`.
//!
//! Two adjustments from a literal translation, both following precedent already established by
//! [`TraceAddressSnapRangePropertyMapOperations`]:
//!
//! - The static factory calls `TraceAddressSnapRangeQuery.at(Address, long)` and
//!   `TraceAddressSnapRangeQuery.intersecting(AddressRange, Lifespan)` have no constructible
//!   target -- `TraceAddressSnapRangeQuery` is the opaque marker
//!   [`seam_stubs::TraceAddressSnapRangeQuery`](crate::trace::seam_stubs::TraceAddressSnapRangeQuery)
//!   -- so, exactly like `make_shape`, they become required methods
//!   ([`query_at`](DBTraceDataSettingsOperations::query_at)/
//!   [`query_intersecting`](DBTraceDataSettingsOperations::query_intersecting)) that implementors
//!   supply.
//! - `doExactOrNew`'s `put(address, lifespan, null)` relies on the underlying map's `put`
//!   treating a `null` value as "allocate and store a blank entry for me". `T` here is a trait
//!   object, which has no null value, so blank-entry construction becomes its own required method,
//!   [`new_entry`](DBTraceDataSettingsOperations::new_entry).
//!
//! `getLock()` returning a plain `java.util.concurrent.locks.ReadWriteLock` is instead split into
//! [`read_lock`](DBTraceDataSettingsOperations::read_lock)/
//! [`write_lock`](DBTraceDataSettingsOperations::write_lock), mirroring the convention already
//! used for this exact shape elsewhere in the crate (e.g.
//! [`DBTraceDelegatingManager`](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager)).
//! They return an owned `Arc<dyn Lock>` rather than a borrowed `&dyn Lock`: several default
//! methods below need to hold the lock (via [`LockHold`]) across a call to a `&mut self` method
//! inherited from the `put`-family of the `SpatialMap` supertrait, which a lock reference borrowed
//! from `&self` cannot outlive.
//!
//! The static `assertKnownType(Object)` check is not ported as a separate item: the value domain
//! it validates (a `Long`, `String`, or `byte[]`) is instead captured directly by the
//! [`SettingsValue`] enum used for `setValue`/`getValue`, which makes the runtime check
//! structurally unrepresentable to violate.
//!
//! Java's `isEmpty(Lifespan, Address)` and `clear(Lifespan, Address, String)` are renamed to
//! [`is_empty_at`](DBTraceDataSettingsOperations::is_empty_at)/
//! [`clear_setting`](DBTraceDataSettingsOperations::clear_setting) to avoid colliding with the
//! zero-argument `is_empty`/`clear` already declared by the `SpatialMap` supertrait -- Rust has no
//! overloading.

use std::sync::Arc;

use crate::program::model::address::range::AddressRange;
use crate::program::model::address::Address;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::map::trace_address_snap_range_property_map_operations::TraceAddressSnapRangePropertyMapOperations;
use crate::trace::seam_stubs::{DBTraceSettingsEntry, TraceAddressSnapRangeQuery};
use crate::util::lock_hold::{Lock, LockHold};

/// The value held by a [`DBTraceSettingsEntry`], mirroring the narrow set of types Java's
/// `Object value` parameter (to `setValue`/`getValue`) is allowed to hold.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingsValue {
    Long(i64),
    Str(String),
    Bytes(Vec<u8>),
}

/// Builds a span with the same bounds as `lifespan`, without requiring `Lifespan: Clone`.
///
/// `Lifespan` (already ported, reused verbatim) has no `clone_box`-style method; `with_min` gives
/// us one for free, since "a new span with the given lower endpoint and this span's upper
/// endpoint", called with the span's own lower endpoint, reconstructs an equivalent span.
fn dup_lifespan(lifespan: Lifespan) -> Lifespan {
    lifespan.with_min(lifespan.lmin())
}

/// Two spans are equal here iff they have the same bounds, mirroring `Lifespan`'s record-style
/// `equals`.
fn lifespans_equal(a: Lifespan, b: Lifespan) -> bool {
    a.lmin() == b.lmin() && a.lmax() == b.lmax()
}

/// Operations shared by the trace's DB-backed "data settings" property map and its per-space
/// delegates.
///
/// Port of `ghidra.trace.database.data.DBTraceDataSettingsOperations`.
pub trait DBTraceDataSettingsOperations:
    TraceAddressSnapRangePropertyMapOperations<Box<dyn DBTraceSettingsEntry>>
{
    /// Builds the query matching the single-address, single-snap point `(address, snap)`.
    ///
    /// Stands in for the Java static factory `TraceAddressSnapRangeQuery.at(Address, long)`; see
    /// the module documentation for why this is a required method rather than a free constructor
    /// call.
    fn query_at(&self, address: Address, snap: i64) -> Box<dyn TraceAddressSnapRangeQuery>;

    /// Builds the query matching everything intersecting `range` over `span`.
    ///
    /// Stands in for the Java static factory
    /// `TraceAddressSnapRangeQuery.intersecting(AddressRange, Lifespan)`.
    fn query_intersecting(
        &self,
        range: AddressRange,
        span: Lifespan,
    ) -> Box<dyn TraceAddressSnapRangeQuery>;

    /// Allocates a new, blank entry, not yet associated with any shape.
    ///
    /// Stands in for the Java `put(address, lifespan, null)` idiom of relying on the underlying
    /// map to allocate a fresh record when handed a `null` value; see the module documentation.
    fn new_entry(&self) -> Box<dyn DBTraceSettingsEntry>;

    /// Adjusts (or removes) `entry` to make way for `span`, e.g. by truncating/splitting its
    /// lifespan or deleting it outright.
    ///
    /// Required (no Java default). Mirrors `makeWay(DBTraceSettingsEntry, Lifespan)`.
    fn make_way(&mut self, entry: Box<dyn DBTraceSettingsEntry>, span: Lifespan);

    /// The lock guarding reads of the underlying entries.
    ///
    /// Stands in for `getLock().readLock()`; see the module documentation for why this is a
    /// separate, owned-lock-returning method rather than a `getLock(): ReadWriteLock` accessor.
    fn read_lock(&self) -> Arc<dyn Lock>;

    /// The lock guarding writes to the underlying entries.
    ///
    /// Stands in for `getLock().writeLock()`.
    fn write_lock(&self) -> Arc<dyn Lock>;

    /// Finds the entry whose lifespan exactly matches `lifespan` at `address`, named `name`.
    ///
    /// Mirrors the default `doGetExactEntry(Lifespan, Address, String)`.
    fn do_get_exact_entry(
        &self,
        lifespan: Lifespan,
        address: Address,
        name: &str,
    ) -> Option<Box<dyn DBTraceSettingsEntry>> {
        let query = self.query_at(address, lifespan.lmin());
        self.reduce(query).values().into_iter().find(|entry| {
            lifespans_equal(entry.get_lifespan(), lifespan)
                && entry.name().as_deref() == Some(name)
        })
    }

    /// Makes way for `span` at `address`, restricted to entries named `name` (or every entry, if
    /// `name` is `None`).
    ///
    /// Mirrors the default `doMakeWay(Lifespan, Address, String)`.
    fn do_make_way(&mut self, span: Lifespan, address: Address, name: Option<&str>) {
        let range = AddressRange::new(address.clone(), address);
        let query = self.query_intersecting(range, span);
        let entries = self.reduce(query).values();
        for entry in entries {
            let keep_going = match name {
                None => true,
                Some(n) => entry.name().as_deref() == Some(n),
            };
            if keep_going {
                self.make_way(entry, span);
            }
        }
    }

    /// Returns the exact entry at `(lifespan, address, name)`, creating one (after making way for
    /// it) if none exists yet.
    ///
    /// Mirrors the default `doExactOrNew(Lifespan, Address, String)`.
    fn do_exact_or_new(
        &mut self,
        lifespan: Lifespan,
        address: Address,
        name: &str,
    ) -> Box<dyn DBTraceSettingsEntry> {
        if let Some(exact) = self.do_get_exact_entry(lifespan, address.clone(), name) {
            return exact;
        }
        self.do_make_way(lifespan, address.clone(), Some(name));
        let blank = self.new_entry();
        let mut entry = self.put_address(address, dup_lifespan(lifespan), blank);
        entry.set_name(name.to_string());
        entry
    }

    /// Finds the entry at `(snap, address)` named `name`, regardless of its lifespan's exact
    /// bounds.
    ///
    /// Mirrors the default `doGetEntry(long, Address, String)`.
    fn do_get_entry(
        &self,
        snap: i64,
        address: Address,
        name: &str,
    ) -> Option<Box<dyn DBTraceSettingsEntry>> {
        let query = self.query_at(address, snap);
        self.reduce(query)
            .values()
            .into_iter()
            .find(|entry| entry.name().as_deref() == Some(name))
    }

    /// Sets the named long-valued setting over `lifespan` at `address`.
    ///
    /// Mirrors the default `setLong(Lifespan, Address, String, long)`.
    fn set_long(&mut self, lifespan: Lifespan, address: Address, name: &str, value: i64) {
        let lock = self.write_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_exact_or_new(lifespan, address, name)
            .set_long(value);
    }

    /// Gets the named long-valued setting at `(snap, address)`.
    ///
    /// Mirrors the default `getLong(long, Address, String)`.
    fn get_long(&self, snap: i64, address: Address, name: &str) -> Option<i64> {
        let lock = self.read_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_get_entry(snap, address, name)
            .and_then(|entry| entry.get_long())
    }

    /// Sets the named string-valued setting over `lifespan` at `address`.
    ///
    /// Mirrors the default `setString(Lifespan, Address, String, String)`.
    fn set_string(
        &mut self,
        lifespan: Lifespan,
        address: Address,
        name: &str,
        value: String,
    ) {
        let lock = self.write_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_exact_or_new(lifespan, address, name)
            .set_string(value);
    }

    /// Gets the named string-valued setting at `(snap, address)`.
    ///
    /// Mirrors the default `getString(long, Address, String)`.
    fn get_string(&self, snap: i64, address: Address, name: &str) -> Option<String> {
        let lock = self.read_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_get_entry(snap, address, name)
            .and_then(|entry| entry.get_string())
    }

    /// Sets the named setting over `lifespan` at `address` to `value`.
    ///
    /// Mirrors the default `setValue(Lifespan, Address, String, Object)`. The Java
    /// `assertKnownType` runtime check is not needed: `value`'s type, [`SettingsValue`], already
    /// restricts it to a known variant.
    fn set_value(
        &mut self,
        lifespan: Lifespan,
        address: Address,
        name: &str,
        value: SettingsValue,
    ) {
        let lock = self.write_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_exact_or_new(lifespan, address, name)
            .set_value(value);
    }

    /// Gets the named setting's value at `(snap, address)`.
    ///
    /// Mirrors the default `getValue(long, Address, String)`.
    fn get_value(&self, snap: i64, address: Address, name: &str) -> Option<SettingsValue> {
        let lock = self.read_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_get_entry(snap, address, name)
            .map(|entry| entry.get_value())
    }

    /// Clears the named setting (or every setting, if `name` is `None`) over `span` at `address`.
    ///
    /// Mirrors the default `clear(Lifespan, Address, String)`. Renamed to avoid colliding with
    /// the zero-argument `clear` declared by the `SpatialMap` supertrait.
    fn clear_setting(&mut self, span: Lifespan, address: Address, name: Option<&str>) {
        let lock = self.write_lock();
        let _hold = LockHold::lock(lock.as_ref());
        self.do_make_way(span, address, name);
    }

    /// Returns the names of every setting defined over `lifespan` at `address`.
    ///
    /// Mirrors the default `getSettingNames(Lifespan, Address)`.
    fn get_setting_names(&self, lifespan: Lifespan, address: Address) -> Vec<String> {
        let lock = self.read_lock();
        let _hold = LockHold::lock(lock.as_ref());
        let range = AddressRange::new(address.clone(), address);
        let query = self.query_intersecting(range, lifespan);
        self.reduce(query)
            .values()
            .into_iter()
            .filter_map(|entry| entry.name())
            .collect()
    }

    /// Checks whether no settings are defined over `lifespan` at `address`.
    ///
    /// Mirrors the default `isEmpty(Lifespan, Address)`. Renamed to avoid colliding with the
    /// zero-argument `is_empty` declared by the `SpatialMap` supertrait.
    fn is_empty_at(&self, lifespan: Lifespan, address: Address) -> bool {
        let lock = self.read_lock();
        let _hold = LockHold::lock(lock.as_ref());
        let range = AddressRange::new(address.clone(), address);
        let query = self.query_intersecting(range, lifespan);
        self.reduce(query).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::util::database::spatial::spatial_map::SpatialMap;
    use std::sync::Mutex;



    fn full_lifespan() -> Lifespan {
        Lifespan::span(i64::MIN, i64::MAX)
    }

    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        y1: i64,
        y2: i64,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.y1, self.y2)
        }

        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }

        fn immutable(
            &self,
            x1: Address,
            x2: Address,
            y1: i64,
            y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockRange {
                range: AddressRange::new(x1, x2),
                y1,
                y2,
            })
        }
    }

    /// This test map's `reduce` does not actually interpret this marker (see `MockMap::reduce`'s
    /// doc), matching the same simplification already used by every sibling test in this crate
    /// for the same opaque stub type.
    struct MockQuery;
    impl TraceAddressSnapRangeQuery for MockQuery {}

    struct MockEntry {
        name: Option<String>,
        lifespan: (i64, i64),
        value: SettingsValue,
    }

    impl Default for MockEntry {
        fn default() -> Self {
            MockEntry {
                name: None,
                lifespan: (0, 0),
                value: SettingsValue::Long(0),
            }
        }
    }

    /// A standalone (not storage-backed) implementation, used only as the transient "blank"
    /// value [`MockMap::new_entry`] hands to `put`, which reads it and discards it -- mirroring
    /// how the Java `null` this stands in for is never itself mutated.
    impl DBTraceSettingsEntry for MockEntry {
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.lifespan.0, self.lifespan.1)
        }

        fn name(&self) -> Option<String> {
            self.name.clone()
        }

        fn set_name(&mut self, name: String) {
            self.name = Some(name);
        }

        fn get_long(&self) -> Option<i64> {
            match self.value {
                SettingsValue::Long(v) => Some(v),
                _ => None,
            }
        }

        fn set_long(&mut self, value: i64) {
            self.value = SettingsValue::Long(value);
        }

        fn get_string(&self) -> Option<String> {
            match &self.value {
                SettingsValue::Str(v) => Some(v.clone()),
                _ => None,
            }
        }

        fn set_string(&mut self, value: String) {
            self.value = SettingsValue::Str(value);
        }

        fn get_value(&self) -> SettingsValue {
            self.value.clone()
        }

        fn set_value(&mut self, value: SettingsValue) {
            self.value = value;
        }
    }

    /// A live handle into `MockMap`'s shared storage: mutations are visible to every other handle
    /// (and to the owning map), mirroring how mutating a Java `DBTraceSettingsEntry` mutates the
    /// shared underlying DB record.
    struct EntryHandle {
        store: Arc<Mutex<Vec<(MockRange, MockEntry)>>>,
        index: usize,
    }

    impl DBTraceSettingsEntry for EntryHandle {
        fn get_lifespan(&self) -> Lifespan {
            let (min, max) = self.store.lock().unwrap()[self.index].1.lifespan;
            Lifespan::span(min, max)
        }

        fn name(&self) -> Option<String> {
            self.store.lock().unwrap()[self.index].1.name.clone()
        }

        fn set_name(&mut self, name: String) {
            self.store.lock().unwrap()[self.index].1.name = Some(name);
        }

        fn get_long(&self) -> Option<i64> {
            match self.store.lock().unwrap()[self.index].1.value {
                SettingsValue::Long(v) => Some(v),
                _ => None,
            }
        }

        fn set_long(&mut self, value: i64) {
            self.store.lock().unwrap()[self.index].1.value = SettingsValue::Long(value);
        }

        fn get_string(&self) -> Option<String> {
            match &self.store.lock().unwrap()[self.index].1.value {
                SettingsValue::Str(v) => Some(v.clone()),
                _ => None,
            }
        }

        fn set_string(&mut self, value: String) {
            self.store.lock().unwrap()[self.index].1.value = SettingsValue::Str(value);
        }

        fn get_value(&self) -> SettingsValue {
            self.store.lock().unwrap()[self.index].1.value.clone()
        }

        fn set_value(&mut self, value: SettingsValue) {
            self.store.lock().unwrap()[self.index].1.value = value;
        }
    }

    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    /// A single-space, in-memory implementation, sufficient to prove object-safety and exercise
    /// the default methods' read-modify-write and make-way behavior end to end.
    ///
    /// `reduce` ignores its query and returns a full alias of the same shared storage --
    /// `TraceAddressSnapRangeQuery` is an opaque marker stub with no members to interpret (see its
    /// doc in `seam_stubs`), and every sibling test of the traits it appears in does the same.
    /// None of the behavior these tests check (round-tripping, make-way, clearing, listing names)
    /// depends on `reduce` narrowing by address, since each scenario below only ever populates the
    /// one address/name combination it then queries.
    struct MockMap {
        entries: Arc<Mutex<Vec<(MockRange, MockEntry)>>>,
        read_lock: Arc<dyn Lock>,
        write_lock: Arc<dyn Lock>,
    }

    impl MockMap {
        fn new() -> Self {
            MockMap {
                entries: Arc::new(Mutex::new(vec![])),
                read_lock: Arc::new(NoopLock),
                write_lock: Arc::new(NoopLock),
            }
        }
    }

    impl
        SpatialMap<
            Box<dyn TraceAddressSnapRange>,
            Box<dyn DBTraceSettingsEntry>,
            Box<dyn TraceAddressSnapRangeQuery>,
        > for MockMap
    {
        fn put(
            &mut self,
            shape: Box<dyn TraceAddressSnapRange>,
            value: Box<dyn DBTraceSettingsEntry>,
        ) -> Box<dyn DBTraceSettingsEntry> {
            let mock_range = MockRange {
                range: shape.get_range(),
                y1: shape.get_y1(),
                y2: shape.get_y2(),
            };
            let mock_entry = MockEntry {
                name: value.name(),
                lifespan: (mock_range.y1, mock_range.y2),
                value: value.get_value(),
            };
            let index = {
                let mut guard = self.entries.lock().unwrap();
                guard.push((mock_range, mock_entry));
                guard.len() - 1
            };
            Box::new(EntryHandle {
                store: self.entries.clone(),
                index,
            })
        }

        fn remove_shape_value(
            &mut self,
            _shape: &Box<dyn TraceAddressSnapRange>,
            _value: &Box<dyn DBTraceSettingsEntry>,
        ) -> bool {
            false
        }

        fn remove_entry(
            &mut self,
            _entry: &(Box<dyn TraceAddressSnapRange>, Box<dyn DBTraceSettingsEntry>),
        ) -> bool {
            false
        }

        fn size(&self) -> usize {
            self.entries.lock().unwrap().len()
        }

        fn is_empty(&self) -> bool {
            self.entries.lock().unwrap().is_empty()
        }

        fn entries(&self) -> Vec<(Box<dyn TraceAddressSnapRange>, Box<dyn DBTraceSettingsEntry>)> {
            let guard = self.entries.lock().unwrap();
            (0..guard.len())
                .map(|i| {
                    let shape = guard[i].0.clone();
                    (
                        Box::new(shape) as Box<dyn TraceAddressSnapRange>,
                        Box::new(EntryHandle {
                            store: self.entries.clone(),
                            index: i,
                        }) as Box<dyn DBTraceSettingsEntry>,
                    )
                })
                .collect()
        }

        fn ordered_entries(
            &self,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, Box<dyn DBTraceSettingsEntry>)> {
            self.entries()
        }

        fn keys(&self) -> Vec<Box<dyn TraceAddressSnapRange>> {
            self.entries().into_iter().map(|(s, _)| s).collect()
        }

        fn ordered_keys(&self) -> Vec<Box<dyn TraceAddressSnapRange>> {
            self.keys()
        }

        fn values(&self) -> Vec<Box<dyn DBTraceSettingsEntry>> {
            self.entries().into_iter().map(|(_, v)| v).collect()
        }

        fn ordered_values(&self) -> Vec<Box<dyn DBTraceSettingsEntry>> {
            self.values()
        }

        fn reduce(
            &self,
            _query: Box<dyn TraceAddressSnapRangeQuery>,
        ) -> Box<
            dyn SpatialMap<
                Box<dyn TraceAddressSnapRange>,
                Box<dyn DBTraceSettingsEntry>,
                Box<dyn TraceAddressSnapRangeQuery>,
            >,
        > {
            Box::new(MockMap {
                entries: self.entries.clone(),
                read_lock: self.read_lock.clone(),
                write_lock: self.write_lock.clone(),
            })
        }

        fn first_entry(
            &self,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn DBTraceSettingsEntry>)> {
            self.entries().into_iter().next()
        }

        fn first_key(&self) -> Option<Box<dyn TraceAddressSnapRange>> {
            self.first_entry().map(|(s, _)| s)
        }

        fn first_value(&self) -> Option<Box<dyn DBTraceSettingsEntry>> {
            self.first_entry().map(|(_, v)| v)
        }

        fn clear(&mut self) {
            self.entries.lock().unwrap().clear();
        }
    }

    impl TraceAddressSnapRangePropertyMapOperations<Box<dyn DBTraceSettingsEntry>> for MockMap {
        fn make_shape(
            &self,
            x1: Address,
            x2: Address,
            y1: i64,
            y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockRange {
                range: AddressRange::new(x1, x2),
                y1,
                y2,
            })
        }

        fn get_address_set_view_filtered(
            &self,
            span: Lifespan,
            predicate: Box<dyn Fn(&Box<dyn DBTraceSettingsEntry>) -> bool + Send + Sync>,
        ) -> Box<dyn AddressSetView> {
            let mut set = crate::program::model::address::AddressSet::new();
            for (shape, entry) in self.entries() {
                if shape.get_y1() <= span.lmax()
                    && span.lmin() <= shape.get_y2()
                    && predicate(&entry)
                {
                    set.add_range_object(&shape.get_range());
                }
            }
            Box::new(set)
        }

        fn get_address_set_view(&self, span: Lifespan) -> Box<dyn AddressSetView> {
            self.get_address_set_view_filtered(span, Box::new(|_| true))
        }

        fn delete_value(&mut self, value: Box<dyn DBTraceSettingsEntry>) {
            let name = value.name();
            self.entries
                .lock()
                .unwrap()
                .retain(|(_, e)| e.name != name);
        }
    }

    impl DBTraceDataSettingsOperations for MockMap {
        fn query_at(&self, _address: Address, _snap: i64) -> Box<dyn TraceAddressSnapRangeQuery> {
            Box::new(MockQuery)
        }

        fn query_intersecting(
            &self,
            _range: AddressRange,
            _span: Lifespan,
        ) -> Box<dyn TraceAddressSnapRangeQuery> {
            Box::new(MockQuery)
        }

        fn new_entry(&self) -> Box<dyn DBTraceSettingsEntry> {
            Box::new(MockEntry::default())
        }

        fn make_way(&mut self, entry: Box<dyn DBTraceSettingsEntry>, _span: Lifespan) {
            let name = entry.name();
            let lifespan = entry.get_lifespan();
            let bounds = (lifespan.lmin(), lifespan.lmax());
            self.entries
                .lock()
                .unwrap()
                .retain(|(_, e)| !(e.name == name && e.lifespan == bounds));
        }

        fn read_lock(&self) -> Arc<dyn Lock> {
            self.read_lock.clone()
        }

        fn write_lock(&self) -> Arc<dyn Lock> {
            self.write_lock.clone()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[test]
    fn set_long_then_get_long_round_trips() {
        let mut map = MockMap::new();
        map.set_long(full_lifespan(), addr(0x1000), "alignment", 4);
        assert_eq!(map.get_long(0, addr(0x1000), "alignment"), Some(4));
    }

    #[test]
    fn set_string_then_get_string_round_trips() {
        let mut map = MockMap::new();
        map.set_string(full_lifespan(), addr(0x1000), "format", "hex".to_string());
        assert_eq!(
            map.get_string(0, addr(0x1000), "format"),
            Some("hex".to_string())
        );
        // Wrong-typed accessor returns None, mirroring the Java entry's type-tagged getters.
        assert_eq!(map.get_long(0, addr(0x1000), "format"), None);
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let mut map = MockMap::new();
        map.set_value(
            full_lifespan(),
            addr(0x2000),
            "endian",
            SettingsValue::Str("big".to_string()),
        );
        assert_eq!(
            map.get_value(0, addr(0x2000), "endian"),
            Some(SettingsValue::Str("big".to_string()))
        );
    }

    #[test]
    fn get_long_on_missing_setting_is_none() {
        let map = MockMap::new();
        assert_eq!(map.get_long(0, addr(0x3000), "nope"), None);
    }

    #[test]
    fn setting_a_second_name_at_the_same_address_does_not_clobber_the_first() {
        let mut map = MockMap::new();
        map.set_long(full_lifespan(), addr(0x1000), "a", 1);
        map.set_long(full_lifespan(), addr(0x1000), "b", 2);
        assert_eq!(map.get_long(0, addr(0x1000), "a"), Some(1));
        assert_eq!(map.get_long(0, addr(0x1000), "b"), Some(2));
    }

    #[test]
    fn clear_setting_removes_it() {
        let mut map = MockMap::new();
        map.set_long(full_lifespan(), addr(0x1000), "a", 1);
        assert!(!map.is_empty_at(full_lifespan(), addr(0x1000)));
        map.clear_setting(full_lifespan(), addr(0x1000), Some("a"));
        assert!(map.is_empty_at(full_lifespan(), addr(0x1000)));
        assert_eq!(map.get_long(0, addr(0x1000), "a"), None);
    }

    #[test]
    fn get_setting_names_lists_every_name_at_the_address() {
        let mut map = MockMap::new();
        map.set_long(full_lifespan(), addr(0x1000), "a", 1);
        map.set_string(full_lifespan(), addr(0x1000), "b", "x".to_string());
        let mut names = map.get_setting_names(full_lifespan(), addr(0x1000));
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let mut map = MockMap::new();
        map.set_long(full_lifespan(), addr(0x1000), "a", 7);
        let boxed: Box<dyn DBTraceDataSettingsOperations> = Box::new(map);
        assert_eq!(boxed.get_long(0, addr(0x1000), "a"), Some(7));
    }
}
