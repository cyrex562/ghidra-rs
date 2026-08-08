//! A convenience for tracking the time structure of a trace and querying the trace accordingly.
//!
//! Java source: `ghidra.trace.model.TraceTimeViewport`.
//!
//! The Java interface declares four generic nested interfaces (`Occlusion<T>`,
//! `QueryOcclusion<T>`, `RangeQueryOcclusion<T>`, `SetQueryOcclusion<T>`) plus generic methods
//! on `TraceTimeViewport` itself (e.g. `<T> T getTop(Function<Long, T> func)`). Rust trait
//! objects cannot carry a method-level type parameter, so every occurrence of the Java `T` is
//! represented here as `&dyn std::any::Any` / `Box<dyn std::any::Any>`, keeping every trait in
//! this module object-safe (usable as `Box<dyn TraceTimeViewport>`, `&dyn Occlusion`, etc.).
//!
//! Java's `QueryOcclusion`/`RangeQueryOcclusion`/`SetQueryOcclusion` override `Occlusion`'s
//! abstract methods with *default* implementations built from their own new abstract methods.
//! Rust has no equivalent of overriding a supertrait's required method with a subtrait default,
//! so those defaults are exposed here as separate, explicitly-named helper methods (e.g.
//! [`QueryOcclusion::occluded_by_query`]); an implementor that wants the Java default behavior
//! simply has its `Occlusion::occluded`/`Occlusion::remove` delegate to them.
//!
//! [`QueryOcclusion::query`] returns `Arc<dyn Any>` rather than `Box<dyn Any>`: the default
//! `occluded`/`remove` methods below rely on Java's `==` reference-identity check (`found ==
//! object`) to skip "self occlusion". That identity is only meaningful if `query`'s results
//! and the `object` passed in by the caller can share the *same* underlying allocation;
//! `Arc` (cloned from a canonical, persistently-stored handle) makes that possible, whereas a
//! freshly-`Box`ed copy could never compare equal to anything.
use std::any::Any;
use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::address_set::{AddressSet, AddressSetView};
use crate::program::model::address::range::AddressRange;
use crate::trace::model::lifespan::Lifespan;
use crate::util::function::Runnable;

/// Tests whether two `dyn Any` references point at the same object, mirroring Java's `==`
/// reference-identity comparisons in the default `occluded`/`remove` methods below.
fn is_same_object(a: &dyn Any, b: &dyn Any) -> bool {
    std::ptr::eq(a as *const dyn Any as *const (), b as *const dyn Any as *const ())
}

/// A mechanism for detecting when one object occludes (hides) parts of another, and for
/// removing the occluded parts.
///
/// Java: `TraceTimeViewport.Occlusion<T>`.
pub trait Occlusion {
    /// Checks whether `object`, occupying `range` over `span`, is occluded by some other,
    /// more-recent object.
    fn occluded(&self, object: &dyn Any, range: &AddressRange, span: Lifespan) -> bool;

    /// Removes from `remains` the parts occluded by some other, more-recent object.
    fn remove(&self, object: &dyn Any, remains: &mut AddressSet, span: Lifespan);
}

/// An [`Occlusion`] whose occluding objects are found by querying a range and span.
///
/// Java: `TraceTimeViewport.QueryOcclusion<T>`.
pub trait QueryOcclusion: Occlusion {
    /// Finds the objects, other than the one under test, that occupy `range` over `span`.
    fn query(&self, range: &AddressRange, span: Lifespan) -> Vec<Arc<dyn Any>>;

    /// Checks whether `item` (found by [`Self::query`]) occludes `range` at `snap`.
    fn item_occludes(&self, range: &AddressRange, item: &dyn Any, snap: i64) -> bool;

    /// Removes from `remains` the parts occluded by `item` at `snap`.
    fn remove_item(&self, remains: &mut AddressSet, item: &dyn Any, snap: i64);

    /// Default implementation of [`Occlusion::occluded`], expressed via [`Self::query`] and
    /// [`Self::item_occludes`].
    ///
    /// Java: `QueryOcclusion.occluded` (default method).
    fn occluded_by_query(&self, object: &dyn Any, range: &AddressRange, span: Lifespan) -> bool {
        for found in self.query(range, span) {
            if is_same_object(found.as_ref(), object) {
                continue;
            }
            if self.item_occludes(range, found.as_ref(), span.lmax()) {
                return true;
            }
        }
        false
    }

    /// Default implementation of [`Occlusion::remove`], expressed via [`Self::query`] and
    /// [`Self::remove_item`].
    ///
    /// Java: `QueryOcclusion.remove` (default method).
    fn remove_by_query(&self, object: &dyn Any, remains: &mut AddressSet, span: Lifespan) {
        let (Some(min), Some(max)) = (remains.min_address(), remains.max_address()) else {
            return;
        };
        let query_range = AddressRange::new(min, max);
        for found in self.query(&query_range, span) {
            if is_same_object(found.as_ref(), object) {
                continue;
            }
            self.remove_item(remains, found.as_ref(), span.lmax());
            if remains.is_empty() {
                return;
            }
        }
    }
}

/// A [`QueryOcclusion`] whose occluding items each occupy a single [`AddressRange`].
///
/// Java: `TraceTimeViewport.RangeQueryOcclusion<T>`.
pub trait RangeQueryOcclusion: QueryOcclusion {
    /// Returns the address range occupied by `t` at `snap`.
    fn range(&self, t: &dyn Any, snap: i64) -> AddressRange;

    /// Default implementation of [`QueryOcclusion::item_occludes`] for range-based occlusion.
    ///
    /// Java: `RangeQueryOcclusion.itemOccludes` (default method).
    fn item_occludes_by_range(&self, range: &AddressRange, t: &dyn Any, snap: i64) -> bool {
        self.range(t, snap).intersects(range)
    }

    /// Default implementation of [`QueryOcclusion::remove_item`] for range-based occlusion.
    ///
    /// Java: `RangeQueryOcclusion.removeItem` (default method).
    fn remove_item_by_range(&self, remains: &mut AddressSet, t: &dyn Any, snap: i64) {
        remains.delete_range_object(&self.range(t, snap));
    }
}

/// A [`QueryOcclusion`] whose occluding items each occupy an arbitrary [`AddressSetView`].
///
/// Java: `TraceTimeViewport.SetQueryOcclusion<T>`.
pub trait SetQueryOcclusion: QueryOcclusion {
    /// Returns the address set occupied by `t` at `snap`.
    fn set(&self, t: &dyn Any, snap: i64) -> Box<dyn AddressSetView>;

    /// Default implementation of [`QueryOcclusion::item_occludes`] for set-based occlusion.
    ///
    /// Java: `SetQueryOcclusion.itemOccludes` (default method).
    fn item_occludes_by_set(&self, range: &AddressRange, t: &dyn Any, snap: i64) -> bool {
        self.set(t, snap)
            .intersects_range(range.min_address(), range.max_address())
    }

    /// Default implementation of [`QueryOcclusion::remove_item`] for set-based occlusion.
    ///
    /// Java: `SetQueryOcclusion.removeItem` (default method).
    fn remove_item_by_set(&self, remains: &mut AddressSet, t: &dyn Any, snap: i64) {
        let set = self.set(t, snap);
        let mut ranges = set.address_ranges_ordered(true);
        while ranges.has_next() {
            let Some(range) = ranges.next_range() else {
                break;
            };
            remains.delete_range_object(&range);
            if remains.is_empty() {
                return;
            }
        }
    }
}

/// A convenience for tracking the time structure of a trace and querying the trace accordingly.
///
/// Java: `ghidra.trace.model.TraceTimeViewport`.
pub trait TraceTimeViewport {
    /// Sets the snapshot for this viewport.
    fn set_snap(&mut self, snap: i64);

    /// Adds a listener for when the forking structure of this viewport changes.
    ///
    /// This can occur when the snap changes or when any snapshot involved changes.
    fn add_change_listener(&mut self, l: Runnable);

    /// Removes a previously-added listener for forking structure changes.
    fn remove_change_listener(&mut self, l: &Runnable);

    /// Checks if this view is forked.
    ///
    /// The view is considered forked if any snap previous to this has a schedule with an
    /// initial snap other than the immediately-preceding one. Such forks "break" the linearity
    /// of the trace's usual time line.
    fn is_forked(&self) -> bool;

    /// Checks if the given lifespan contains any upper snap among the involved spans.
    fn contains_any_upper(&self, lifespan: Lifespan) -> bool;

    /// Checks if any part of the given object is occluded by more-recent objects.
    ///
    /// `object` is used to avoid "self occlusion".
    fn is_completely_visible(
        &self,
        range: &AddressRange,
        lifespan: Lifespan,
        object: &dyn Any,
        occlusion: &dyn Occlusion,
    ) -> bool;

    /// Computes the parts of a given object that are visible past more-recent objects.
    fn compute_visible_parts(
        &self,
        set: &dyn AddressSetView,
        lifespan: Lifespan,
        object: &dyn Any,
        occlusion: &dyn Occlusion,
    ) -> AddressSet;

    /// Gets the spans involved in the view in most-recent-first order.
    fn get_ordered_spans(&self) -> Vec<Lifespan>;

    /// Gets the spans involved in the view in least-recent-first order.
    fn get_reversed_spans(&self) -> Vec<Lifespan>;

    /// Gets the snaps involved in the view in most-recent-first order.
    ///
    /// The first is always this view's snap. Following are the source snaps of each previous
    /// snapshot's schedule where applicable.
    fn get_ordered_snaps(&self) -> Vec<i64>;

    /// Gets the snaps involved in the view in least-recent-first order.
    fn get_reversed_snaps(&self) -> Vec<i64>;

    /// Gets the first non-`None` result of `func`, applied to the most-recent snaps first.
    ///
    /// Typically, `func` both retrieves an object and tests for its suitability.
    fn get_top(&self, func: &dyn Fn(i64) -> Option<Box<dyn Any>>) -> Option<Box<dyn Any>>;

    /// Merges iterators from each involved snap into a single iterator.
    ///
    /// Typically, the resulting iterator is passed through a filter to test each object's
    /// suitability. `comparator` must yield the same order as each iterator produced by
    /// `iter_func`.
    fn merged_iterator(
        &self,
        iter_func: &dyn Fn(i64) -> Box<dyn Iterator<Item = Box<dyn Any>>>,
        comparator: &dyn Fn(&dyn Any, &dyn Any) -> Ordering,
    ) -> Box<dyn Iterator<Item = Box<dyn Any>>>;

    /// Unions address sets from each involved snap.
    fn unioned_addresses(&self, set_func: &dyn Fn(i64) -> Box<dyn AddressSetView>) -> Box<dyn AddressSetView>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::{Arc, Mutex};



    /// A concrete, testable object identity: an "item" placed at a range, born at a snap.
    #[derive(Debug, PartialEq, Eq)]
    struct Item {
        id: u32,
        birth_snap: i64,
    }

    /// An occlusion where each [`Item`] occupies a fixed [`AddressRange`] from its birth snap
    /// onward: more-recently-born items occlude the same range in older items.
    ///
    /// Items are stored behind `Arc` (rather than by value) so that [`QueryOcclusion::query`]
    /// can hand back references that share identity with the canonical, persistently-stored
    /// item -- required for the `found == object` self-exclusion check in
    /// [`QueryOcclusion::occluded_by_query`]/[`QueryOcclusion::remove_by_query`] to ever work.
    struct RangeOcclusion {
        space: Arc<AddressSpace>,
        items: Vec<(Arc<Item>, AddressRange)>,
    }

    impl RangeOcclusion {
        /// Returns the canonical, identity-preserving handle for the item with the given id.
        fn object_for(&self, id: u32) -> Arc<Item> {
            Arc::clone(
                &self
                    .items
                    .iter()
                    .find(|(item, _)| item.id == id)
                    .expect("item not registered")
                    .0,
            )
        }
    }

    impl QueryOcclusion for RangeOcclusion {
        fn query(&self, range: &AddressRange, span: Lifespan) -> Vec<Arc<dyn Any>> {
            // Mirrors how a real `TraceTimeViewport` would drive this: a caller invokes
            // `occluded`/`remove` once per involved layer, so `span` here identifies a single
            // layer (an item's `birth_snap`) rather than a broad range of snaps.
            self.items
                .iter()
                .filter(|(item, r)| span.contains(item.birth_snap) && r.intersects(range))
                .map(|(item, _)| Arc::clone(item) as Arc<dyn Any>)
                .collect()
        }

        fn item_occludes(&self, range: &AddressRange, item: &dyn Any, snap: i64) -> bool {
            self.item_occludes_by_range(range, item, snap)
        }

        fn remove_item(&self, remains: &mut AddressSet, item: &dyn Any, snap: i64) {
            self.remove_item_by_range(remains, item, snap)
        }
    }

    impl RangeQueryOcclusion for RangeOcclusion {
        fn range(&self, t: &dyn Any, _snap: i64) -> AddressRange {
            let item = t.downcast_ref::<Item>().expect("expected Item");
            self.items
                .iter()
                .find(|(i, _)| i.id == item.id)
                .map(|(_, r)| r.clone())
                .expect("item not registered")
        }
    }

    impl Occlusion for RangeOcclusion {
        fn occluded(&self, object: &dyn Any, range: &AddressRange, span: Lifespan) -> bool {
            self.occluded_by_query(object, range, span)
        }

        fn remove(&self, object: &dyn Any, remains: &mut AddressSet, span: Lifespan) {
            self.remove_by_query(object, remains, span)
        }
    }

    fn setup() -> (Arc<AddressSpace>, RangeOcclusion) {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let addr = |off: i64| Address::new(space.clone(), off);
        let old = Arc::new(Item { id: 1, birth_snap: 0 });
        let newer = Arc::new(Item { id: 2, birth_snap: 5 });
        let occlusion = RangeOcclusion {
            space: space.clone(),
            items: vec![
                (old, AddressRange::new(addr(0x1000), addr(0x1010))),
                (newer, AddressRange::new(addr(0x1005), addr(0x1020))),
            ],
        };
        (space, occlusion)
    }

    #[test]
    fn occluded_by_query_detects_overlap_from_newer_item() {
        let (space, occlusion) = setup();
        let addr = |off: i64| Address::new(space.clone(), off);
        let old = occlusion.object_for(1);
        let span = Lifespan::span(0, 10);
        let range = AddressRange::new(addr(0x1000), addr(0x1010));

        assert!(occlusion.occluded(&*old, &range, span));
    }

    #[test]
    fn occluded_by_query_is_false_without_conflicting_items() {
        let (space, occlusion) = setup();
        let addr = |off: i64| Address::new(space.clone(), off);
        let newer = occlusion.object_for(2);
        // Scoped to the newer item's own layer: querying it finds only itself, which the
        // `found == object` identity check excludes.
        let span = Lifespan::span(5, 5);
        let range = AddressRange::new(addr(0x1005), addr(0x1020));

        assert!(!occlusion.occluded(&*newer, &range, span));
    }

    #[test]
    fn remove_by_query_shrinks_remains_to_visible_parts() {
        let (space, occlusion) = setup();
        let addr = |off: i64| Address::new(space.clone(), off);
        let old = occlusion.object_for(1);
        // A real caller drives `remove` once per more-recent layer; here that's just the
        // newer item's layer.
        let span = Lifespan::span(5, 5);

        let mut remains = AddressSet::new();
        remains.add_range(&addr(0x1000), &addr(0x1010));

        occlusion.remove(&*old, &mut remains, span);

        // [0x1000, 0x1010] minus the newer item's [0x1005, 0x1020] leaves [0x1000, 0x1004].
        assert!(remains.contains(&addr(0x1000)));
        assert!(remains.contains(&addr(0x1004)));
        assert!(!remains.contains(&addr(0x1005)));
        assert!(!remains.contains(&addr(0x1010)));
    }

    /// A minimal, single-span viewport used to exercise [`TraceTimeViewport`] as a trait object.
    struct MockViewport {
        snap: i64,
        forked: bool,
        listeners: Vec<Runnable>,
    }

    impl TraceTimeViewport for MockViewport {
        fn set_snap(&mut self, snap: i64) {
            self.snap = snap;
        }

        fn add_change_listener(&mut self, l: Runnable) {
            self.listeners.push(l);
        }

        fn remove_change_listener(&mut self, l: &Runnable) {
            self.listeners.retain(|existing| {
                !std::ptr::eq(
                    existing.as_ref() as *const (dyn Fn() + Send + Sync) as *const (),
                    l.as_ref() as *const (dyn Fn() + Send + Sync) as *const (),
                )
            });
        }

        fn is_forked(&self) -> bool {
            self.forked
        }

        fn contains_any_upper(&self, lifespan: Lifespan) -> bool {
            lifespan.contains(self.snap)
        }

        fn is_completely_visible(
            &self,
            range: &AddressRange,
            lifespan: Lifespan,
            object: &dyn Any,
            occlusion: &dyn Occlusion,
        ) -> bool {
            !occlusion.occluded(object, range, lifespan)
        }

        fn compute_visible_parts(
            &self,
            set: &dyn AddressSetView,
            lifespan: Lifespan,
            object: &dyn Any,
            occlusion: &dyn Occlusion,
        ) -> AddressSet {
            let mut remains = AddressSet::from_set(set);
            occlusion.remove(object, &mut remains, lifespan);
            remains
        }

        fn get_ordered_spans(&self) -> Vec<Lifespan> {
            vec![Lifespan::span(0, self.snap)]
        }

        fn get_reversed_spans(&self) -> Vec<Lifespan> {
            self.get_ordered_spans()
        }

        fn get_ordered_snaps(&self) -> Vec<i64> {
            vec![self.snap]
        }

        fn get_reversed_snaps(&self) -> Vec<i64> {
            vec![self.snap]
        }

        fn get_top(&self, func: &dyn Fn(i64) -> Option<Box<dyn Any>>) -> Option<Box<dyn Any>> {
            func(self.snap)
        }

        fn merged_iterator(
            &self,
            iter_func: &dyn Fn(i64) -> Box<dyn Iterator<Item = Box<dyn Any>>>,
            _comparator: &dyn Fn(&dyn Any, &dyn Any) -> Ordering,
        ) -> Box<dyn Iterator<Item = Box<dyn Any>>> {
            iter_func(self.snap)
        }

        fn unioned_addresses(
            &self,
            set_func: &dyn Fn(i64) -> Box<dyn AddressSetView>,
        ) -> Box<dyn AddressSetView> {
            set_func(self.snap)
        }
    }

    #[test]
    fn usable_as_trait_object_and_wires_occlusion_through() {
        let (space, occlusion) = setup();
        let addr = |off: i64| Address::new(space.clone(), off);
        let old = occlusion.object_for(1);

        let mut viewport: Box<dyn TraceTimeViewport> = Box::new(MockViewport {
            snap: 10,
            forked: false,
            listeners: Vec::new(),
        });

        viewport.set_snap(7);
        assert!(!viewport.is_forked());

        // Scoped to the newer item's own layer, matching how a real caller would drive
        // occlusion checks one more-recent layer at a time.
        let span = Lifespan::span(5, 5);
        let range = AddressRange::new(addr(0x1000), addr(0x1010));
        assert!(!viewport.is_completely_visible(&range, span, &*old, &occlusion));

        let mut set = AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1010));
        let visible = viewport.compute_visible_parts(&set, span, &*old, &occlusion);
        assert!(visible.contains(&addr(0x1000)));
        assert!(!visible.contains(&addr(0x1005)));

        assert_eq!(viewport.get_ordered_snaps(), vec![7]);
    }

    #[test]
    fn change_listener_add_and_remove_by_identity() {
        let mut viewport = MockViewport {
            snap: 0,
            forked: false,
            listeners: Vec::new(),
        };

        let called = Arc::new(Mutex::new(0));
        let called_clone = Arc::clone(&called);
        let listener: Runnable = Box::new(move || {
            *called_clone.lock().unwrap() += 1;
        });

        viewport.add_change_listener(listener);
        assert_eq!(viewport.listeners.len(), 1);
        viewport.listeners[0]();
        assert_eq!(*called.lock().unwrap(), 1);

        let other: Runnable = Box::new(|| {});
        viewport.remove_change_listener(&other);
        assert_eq!(viewport.listeners.len(), 1, "removing an unrelated listener is a no-op");
    }
}
