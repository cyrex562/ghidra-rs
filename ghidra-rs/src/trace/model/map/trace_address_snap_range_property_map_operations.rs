//! Operations common to trace property maps keyed by `(AddressRange, Lifespan)` rectangles.
//!
//! Java source: `ghidra.trace.model.map.TraceAddressSnapRangePropertyMapOperations`.
//!
//! In the original, this interface extends `SpatialMap<TraceAddressSnapRange, T,
//! TraceAddressSnapRangeQuery>` and its `put` overloads each construct a new
//! `ImmutableTraceAddressSnapRange` (via one of that class's constructors) before delegating to
//! `SpatialMap.put(shape, value)`. `ImmutableTraceAddressSnapRange` was itself ported as a trait
//! (a cycle cut-point; see
//! [`immutable_trace_address_snap_range`](crate::trace::model::immutable_trace_address_snap_range)),
//! so there is no concrete, constructible type to call `new ImmutableTraceAddressSnapRange(...)`
//! on here. This mirrors the same problem already solved by
//! [`TraceAddressSnapRange::immutable`](crate::trace::model::trace_address_snap_range::TraceAddressSnapRange::immutable):
//! rather than a default method, shape construction is exposed as a required
//! [`make_shape`](TraceAddressSnapRangePropertyMapOperations::make_shape) method that
//! implementors provide, and the `put` overloads become default methods built on top of it.
//!
//! `TraceAddressSnapRangeQuery` (a nested type of the unported
//! `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree`) is represented by the
//! opaque marker stub
//! [`seam_stubs::TraceAddressSnapRangeQuery`](crate::trace::seam_stubs::TraceAddressSnapRangeQuery),
//! since this interface only ever passes it through as the `Q` type parameter of the `SpatialMap`
//! supertrait and never calls any of its members.
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressSetView};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::TraceAddressSnapRangeQuery;
use crate::util::database::spatial::spatial_map::SpatialMap;

/// Operations common to trace property maps keyed by `(AddressRange, Lifespan)` rectangles.
///
/// Port of `ghidra.trace.model.map.TraceAddressSnapRangePropertyMapOperations<T>`.
pub trait TraceAddressSnapRangePropertyMapOperations<T>:
    SpatialMap<Box<dyn TraceAddressSnapRange>, T, Box<dyn TraceAddressSnapRangeQuery>>
{
    /// Constructs a new rectangle shape spanning the given address and snap bounds.
    ///
    /// Replaces the Java `put` overloads' direct calls to `new
    /// ImmutableTraceAddressSnapRange(...)`; see the module documentation for why this is a
    /// required method rather than a free constructor call.
    fn make_shape(
        &self,
        x1: Address,
        x2: Address,
        y1: i64,
        y2: i64,
    ) -> Box<dyn TraceAddressSnapRange>;

    /// Associates `value` with the single-address, single-snap rectangle at `(address, lifespan)`.
    ///
    /// Mirrors the Java default `put(Address, Lifespan, T)`.
    fn put_address(&mut self, address: Address, lifespan: Lifespan, value: T) -> T {
        let shape = self.make_shape(address.clone(), address, lifespan.lmin(), lifespan.lmax());
        self.put(shape, value)
    }

    /// Associates `value` with the rectangle spanning `[min_address, max_address]` by
    /// `[min_snap, max_snap]`.
    ///
    /// Mirrors the Java default `put(Address, Address, long, long, T)`.
    fn put_bounds(
        &mut self,
        min_address: Address,
        max_address: Address,
        min_snap: i64,
        max_snap: i64,
        value: T,
    ) -> T {
        let shape = self.make_shape(min_address, max_address, min_snap, max_snap);
        self.put(shape, value)
    }

    /// Associates `value` with the rectangle spanning `[min_address, max_address]` at the single
    /// snap `snap`.
    ///
    /// Mirrors the Java default `put(Address, Address, long, T)`.
    fn put_bounds_at_snap(
        &mut self,
        min_address: Address,
        max_address: Address,
        snap: i64,
        value: T,
    ) -> T {
        self.put_bounds(min_address, max_address, snap, snap, value)
    }

    /// Associates `value` with the rectangle over `range` by `lifespan`.
    ///
    /// Mirrors the Java default `put(AddressRange, Lifespan, T)`.
    fn put_range(&mut self, range: AddressRange, lifespan: Lifespan, value: T) -> T {
        let shape = self.make_shape(
            range.min_address().clone(),
            range.max_address().clone(),
            lifespan.lmin(),
            lifespan.lmax(),
        );
        self.put(shape, value)
    }

    /// Returns the addresses covered by entries overlapping `span` whose value satisfies
    /// `predicate`.
    ///
    /// Mirrors `getAddressSetView(Lifespan, Predicate<T>)`.
    fn get_address_set_view_filtered(
        &self,
        span: Lifespan,
        predicate: Box<dyn Fn(&T) -> bool + Send + Sync>,
    ) -> Box<dyn AddressSetView>;

    /// Returns the addresses covered by entries overlapping `span`.
    ///
    /// Mirrors `getAddressSetView(Lifespan)`.
    fn get_address_set_view(&self, span: Lifespan) -> Box<dyn AddressSetView>;

    /// For maps where values are the entries, removes a value.
    ///
    /// Mirrors `deleteValue(T)`.
    fn delete_value(&mut self, value: T);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;



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

    /// A trivial in-memory implementation, sufficient to exercise the default methods and prove
    /// object-safety.
    struct MockMap {
        entries: Vec<(Box<dyn TraceAddressSnapRange>, i32)>,
    }

    impl SpatialMap<Box<dyn TraceAddressSnapRange>, i32, Box<dyn TraceAddressSnapRangeQuery>>
        for MockMap
    {
        fn put(&mut self, shape: Box<dyn TraceAddressSnapRange>, value: i32) -> i32 {
            self.entries.push((shape, value));
            value
        }

        fn remove_shape_value(
            &mut self,
            _shape: &Box<dyn TraceAddressSnapRange>,
            value: &i32,
        ) -> bool {
            let before = self.entries.len();
            self.entries.retain(|(_, v)| v != value);
            self.entries.len() != before
        }

        fn remove_entry(&mut self, _entry: &(Box<dyn TraceAddressSnapRange>, i32)) -> bool {
            false
        }

        fn size(&self) -> usize {
            self.entries.len()
        }

        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        fn entries(&self) -> Vec<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries
                .iter()
                .map(|(s, v)| (s.get_bounds(), *v))
                .collect()
        }

        fn ordered_entries(&self) -> Vec<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries()
        }

        fn keys(&self) -> Vec<Box<dyn TraceAddressSnapRange>> {
            self.entries.iter().map(|(s, _)| s.get_bounds()).collect()
        }

        fn ordered_keys(&self) -> Vec<Box<dyn TraceAddressSnapRange>> {
            self.keys()
        }

        fn values(&self) -> Vec<i32> {
            self.entries.iter().map(|(_, v)| *v).collect()
        }

        fn ordered_values(&self) -> Vec<i32> {
            self.values()
        }

        fn reduce(
            &self,
            _query: Box<dyn TraceAddressSnapRangeQuery>,
        ) -> Box<
            dyn SpatialMap<Box<dyn TraceAddressSnapRange>, i32, Box<dyn TraceAddressSnapRangeQuery>>,
        > {
            Box::new(MockMap {
                entries: self.entries(),
            })
        }

        fn first_entry(&self) -> Option<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries.first().map(|(s, v)| (s.get_bounds(), *v))
        }

        fn first_key(&self) -> Option<Box<dyn TraceAddressSnapRange>> {
            self.first_entry().map(|(s, _)| s)
        }

        fn first_value(&self) -> Option<i32> {
            self.first_entry().map(|(_, v)| v)
        }

        fn clear(&mut self) {
            self.entries.clear();
        }
    }

    impl TraceAddressSnapRangePropertyMapOperations<i32> for MockMap {
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
            predicate: Box<dyn Fn(&i32) -> bool + Send + Sync>,
        ) -> Box<dyn AddressSetView> {
            let mut set = crate::program::model::address::AddressSet::new();
            for (shape, value) in &self.entries {
                if shape.get_y1() <= span.lmax()
                    && span.lmin() <= shape.get_y2()
                    && predicate(value)
                {
                    set.add_range_object(&shape.get_range());
                }
            }
            Box::new(set)
        }

        fn get_address_set_view(&self, span: Lifespan) -> Box<dyn AddressSetView> {
            self.get_address_set_view_filtered(span, Box::new(|_| true))
        }

        fn delete_value(&mut self, value: i32) {
            self.entries.retain(|(_, v)| *v != value);
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[test]
    fn put_address_stores_single_point_rectangle() {
        let mut map = MockMap { entries: vec![] };
        map.put_address(addr(0x1000), Lifespan::span(5, 5), 42);
        assert_eq!(map.size(), 1);
        let (shape, value) = map.first_entry().unwrap();
        assert_eq!(value, 42);
        assert_eq!(shape.get_x1().offset(), 0x1000);
        assert_eq!(shape.get_x2().offset(), 0x1000);
        assert_eq!(shape.get_y1(), 5);
        assert_eq!(shape.get_y2(), 5);
    }

    #[test]
    fn put_bounds_at_snap_uses_same_min_and_max_snap() {
        let mut map = MockMap { entries: vec![] };
        map.put_bounds_at_snap(addr(0x1000), addr(0x2000), 7, 99);
        let (shape, _) = map.first_entry().unwrap();
        assert_eq!(shape.get_y1(), 7);
        assert_eq!(shape.get_y2(), 7);
    }

    #[test]
    fn put_range_uses_range_bounds_and_lifespan() {
        let mut map = MockMap { entries: vec![] };
        let range = AddressRange::new(addr(0x1000), addr(0x2000));
        map.put_range(range, Lifespan::span(1, 2), 7);
        let (shape, value) = map.first_entry().unwrap();
        assert_eq!(value, 7);
        assert_eq!(shape.get_x1().offset(), 0x1000);
        assert_eq!(shape.get_x2().offset(), 0x2000);
    }

    #[test]
    fn delete_value_removes_matching_entries() {
        let mut map = MockMap { entries: vec![] };
        map.put_address(addr(0x1000), Lifespan::span(0, 0), 1);
        map.put_address(addr(0x2000), Lifespan::span(0, 0), 2);
        map.delete_value(1);
        assert_eq!(map.size(), 1);
        assert_eq!(map.first_value(), Some(2));
    }

    #[test]
    fn get_address_set_view_filtered_only_includes_matching_values() {
        let mut map = MockMap { entries: vec![] };
        map.put_bounds(addr(0x1000), addr(0x1010), 0, 10, 1);
        map.put_bounds(addr(0x2000), addr(0x2010), 0, 10, 2);
        let set = map.get_address_set_view_filtered(
            Lifespan::span(0, 10),
            Box::new(|v: &i32| *v == 2),
        );
        assert!(!set.contains(&addr(0x1000)));
        assert!(set.contains(&addr(0x2000)));
    }

    #[test]
    fn get_address_set_view_excludes_entries_outside_span() {
        let mut map = MockMap { entries: vec![] };
        map.put_bounds(addr(0x1000), addr(0x1010), 100, 200, 1);
        let set = map.get_address_set_view(Lifespan::span(0, 10));
        assert!(set.is_empty());
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let mut map = MockMap { entries: vec![] };
        map.put_address(addr(0x1000), Lifespan::span(0, 0), 5);
        let boxed: Box<dyn TraceAddressSnapRangePropertyMapOperations<i32>> = Box::new(map);
        assert_eq!(boxed.size(), 1);
    }
}
