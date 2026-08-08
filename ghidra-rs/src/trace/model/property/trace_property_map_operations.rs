//! Operations on a map from address-snap pairs to user-defined values in a trace.
//!
//! Java source: `ghidra.trace.model.property.TracePropertyMapOperations`.
//!
//! The Java interface is generic in the value type `T` and declares two overloads of `set`
//! (one keyed by a single [`Address`], one by an [`AddressRange`]); Rust has no method
//! overloading, so they are ported as [`set`](TracePropertyMapOperations::set) and
//! [`set_range`](TracePropertyMapOperations::set_range), mirroring the `put_address`/`put_range`
//! naming already used for the analogous overloads on
//! [`TraceAddressSnapRangePropertyMapOperations`](crate::trace::model::map::TraceAddressSnapRangePropertyMapOperations).
//! `Class<T>` is represented as `TypeId`, matching this crate's existing convention for ported
//! `getValueClass` methods (e.g. [`Data::get_value_class`](crate::program::model::listing::data::Data::get_value_class)).
//! `Map.Entry<TraceAddressSnapRange, T>` is represented as the tuple
//! `(Box<dyn TraceAddressSnapRange>, T)`.
//!
//! This type was selected as a dependency-cycle cut-point, so it is ported as a trait rather than
//! being defined alongside its (not yet ported) implementors.
use std::any::TypeId;

use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressSetView};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;

/// A map from address-snap pairs to user-defined values in a trace.
///
/// Port of `ghidra.trace.model.property.TracePropertyMapOperations<T>`.
pub trait TracePropertyMapOperations<T>: Send + Sync
where
    T: 'static,
{
    /// Returns the class of values stored in the map.
    ///
    /// Port of `getValueClass()`.
    fn get_value_class(&self) -> TypeId;

    /// Sets a value at the given address over the given lifespan.
    ///
    /// Port of the `set(Lifespan, Address, T)` overload; see
    /// [`set_range`](Self::set_range) for the `AddressRange`-keyed overload.
    fn set(&mut self, lifespan: Box<dyn Lifespan>, address: Address, value: T);

    /// Sets a value over the given range and lifespan.
    ///
    /// Port of the `set(Lifespan, AddressRange, T)` overload. Setting a value of `None`
    /// (Java's `null`) still creates an entry, so that unit-typed maps function.
    ///
    /// When setting an overlapping value, existing entries are deleted or truncated to make
    /// space for the new entry. If an existing entry overlaps and its starting snap is
    /// contained in the new entry's span, the existing entry is deleted, regardless of whether
    /// or not its ending snap is also contained in the new entry's span. If the starting snap
    /// of the existing entry precedes the span of the new entry, the existing entry is
    /// truncated -- its ending snap is set to one less than the new entry's starting snap.
    /// Address ranges are never truncated.
    fn set_range(&mut self, lifespan: Box<dyn Lifespan>, range: AddressRange, value: T);

    /// Gets the value at the given address-snap pair.
    ///
    /// Port of `get(long, Address)`.
    fn get(&self, snap: i64, address: &Address) -> Option<T>;

    /// Gets the entry at the given address-snap pair.
    ///
    /// Port of `getEntry(long, Address)`. Returns the range and value, or `None` if no entry
    /// covers the pair (Java's `null`).
    fn get_entry(&self, snap: i64, address: &Address) -> Option<(Box<dyn TraceAddressSnapRange>, T)>;

    /// Gets the entries intersecting the given bounds.
    ///
    /// Port of `getEntries(Lifespan, AddressRange)`.
    fn get_entries(
        &self,
        lifespan: Box<dyn Lifespan>,
        range: AddressRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, T)>;

    /// Gets the union of address ranges for entries which intersect the given span.
    ///
    /// Port of `getAddressSetView(Lifespan)`.
    fn get_address_set_view(&self, span: Box<dyn Lifespan>) -> Box<dyn AddressSetView>;

    /// Removes or truncates entries so that the given box contains no entries.
    ///
    /// Port of `clear(Lifespan, AddressRange)`. Applies the same truncation rule as
    /// [`set_range`](Self::set_range), except that no replacement entry is created. Returns
    /// `true` if any entry was affected.
    fn clear(&mut self, span: Box<dyn Lifespan>, range: AddressRange) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }
        fn lmax(&self) -> i64 {
            self.max
        }
        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }
        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }
        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        y1: i64,
        y2: i64,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.y1,
                max: self.y2,
            })
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

    /// A trivial in-memory implementation, sufficient to exercise real overlap/truncation
    /// behavior and prove object-safety.
    struct MockMap {
        entries: Vec<(MockRange, i32)>,
    }

    impl TracePropertyMapOperations<i32> for MockMap {
        fn get_value_class(&self) -> TypeId {
            TypeId::of::<i32>()
        }

        fn set(&mut self, lifespan: Box<dyn Lifespan>, address: Address, value: i32) {
            self.set_range(lifespan, AddressRange::new(address.clone(), address), value)
        }

        fn set_range(&mut self, lifespan: Box<dyn Lifespan>, range: AddressRange, value: i32) {
            let (lmin, lmax) = (lifespan.lmin(), lifespan.lmax());
            self.entries.retain_mut(|(shape, _)| {
                if !shape.range.intersects(&range) || shape.y2 < lmin || lmax < shape.y1 {
                    return true;
                }
                if shape.y1 >= lmin {
                    false
                } else {
                    shape.y2 = lmin - 1;
                    true
                }
            });
            self.entries.push((
                MockRange {
                    range,
                    y1: lmin,
                    y2: lmax,
                },
                value,
            ));
        }

        fn get(&self, snap: i64, address: &Address) -> Option<i32> {
            self.get_entry(snap, address).map(|(_, v)| v)
        }

        fn get_entry(
            &self,
            snap: i64,
            address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries
                .iter()
                .find(|(shape, _)| shape.range.contains(address) && shape.y1 <= snap && snap <= shape.y2)
                .map(|(shape, v)| (Box::new(shape.clone()) as Box<dyn TraceAddressSnapRange>, *v))
        }

        fn get_entries(
            &self,
            lifespan: Box<dyn Lifespan>,
            range: AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries
                .iter()
                .filter(|(shape, _)| {
                    shape.range.intersects(&range) && shape.y1 <= lifespan.lmax() && lifespan.lmin() <= shape.y2
                })
                .map(|(shape, v)| (Box::new(shape.clone()) as Box<dyn TraceAddressSnapRange>, *v))
                .collect()
        }

        fn get_address_set_view(&self, span: Box<dyn Lifespan>) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for (shape, _) in &self.entries {
                if shape.y1 <= span.lmax() && span.lmin() <= shape.y2 {
                    set.add_range_object(&shape.range);
                }
            }
            Box::new(set)
        }

        fn clear(&mut self, span: Box<dyn Lifespan>, range: AddressRange) -> bool {
            let (lmin, lmax) = (span.lmin(), span.lmax());
            let before = self.entries.len();
            let mut truncated = false;
            self.entries.retain_mut(|(shape, _)| {
                if !shape.range.intersects(&range) || shape.y2 < lmin || lmax < shape.y1 {
                    return true;
                }
                if shape.y1 >= lmin {
                    false
                } else {
                    shape.y2 = lmin - 1;
                    truncated = true;
                    true
                }
            });
            self.entries.len() != before || truncated
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[test]
    fn set_then_get_round_trips_value() {
        let mut map = MockMap { entries: vec![] };
        map.set(Box::new(MockLifespan { min: 0, max: 10 }), addr(0x1000), 42);
        assert_eq!(map.get(5, &addr(0x1000)), Some(42));
        assert_eq!(map.get(5, &addr(0x2000)), None);
        assert_eq!(map.get(20, &addr(0x1000)), None);
    }

    #[test]
    fn set_range_truncates_overlapping_earlier_entry() {
        let mut map = MockMap { entries: vec![] };
        map.set_range(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x2000)),
            1,
        );
        map.set_range(
            Box::new(MockLifespan { min: 5, max: 15 }),
            AddressRange::new(addr(0x1000), addr(0x2000)),
            2,
        );
        assert_eq!(map.get(3, &addr(0x1000)), Some(1));
        assert_eq!(map.get(4, &addr(0x1000)), Some(1));
        assert_eq!(map.get(5, &addr(0x1000)), Some(2));
    }

    #[test]
    fn set_range_deletes_entry_starting_within_new_span() {
        let mut map = MockMap { entries: vec![] };
        map.set_range(
            Box::new(MockLifespan { min: 5, max: 8 }),
            AddressRange::new(addr(0x1000), addr(0x2000)),
            1,
        );
        map.set_range(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x2000)),
            2,
        );
        assert_eq!(map.get(6, &addr(0x1000)), Some(2));
        assert_eq!(map.entries.len(), 1);
    }

    #[test]
    fn get_entries_returns_only_intersecting_entries() {
        let mut map = MockMap { entries: vec![] };
        map.set_range(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x1010)),
            1,
        );
        map.set_range(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x2000), addr(0x2010)),
            2,
        );
        let found = map.get_entries(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x1010)),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, 1);
    }

    #[test]
    fn get_address_set_view_unions_intersecting_ranges() {
        let mut map = MockMap { entries: vec![] };
        map.set_range(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x1010)),
            1,
        );
        map.set_range(
            Box::new(MockLifespan { min: 100, max: 200 }),
            AddressRange::new(addr(0x2000), addr(0x2010)),
            2,
        );
        let set = map.get_address_set_view(Box::new(MockLifespan { min: 0, max: 10 }));
        assert!(set.contains(&addr(0x1000)));
        assert!(!set.contains(&addr(0x2000)));
    }

    #[test]
    fn clear_removes_entries_in_box_and_reports_change() {
        let mut map = MockMap { entries: vec![] };
        map.set_range(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x1010)),
            1,
        );
        let cleared = map.clear(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x1010)),
        );
        assert!(cleared);
        assert_eq!(map.get(5, &addr(0x1000)), None);

        let cleared_again = map.clear(
            Box::new(MockLifespan { min: 0, max: 10 }),
            AddressRange::new(addr(0x1000), addr(0x1010)),
        );
        assert!(!cleared_again);
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let mut map = MockMap { entries: vec![] };
        map.set(Box::new(MockLifespan { min: 0, max: 0 }), addr(0x1000), 7);
        let boxed: Box<dyn TracePropertyMapOperations<i32>> = Box::new(map);
        assert_eq!(boxed.get_value_class(), TypeId::of::<i32>());
        assert_eq!(boxed.get(0, &addr(0x1000)), Some(7));
    }
}
