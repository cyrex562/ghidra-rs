//! A trace property map restricted to (and aware of) a single address space.
//!
//! Java source: `ghidra.trace.model.map.TraceAddressSnapRangePropertyMapSpace`.
//!
//! The Java interface adds a single accessor, `getAddressSpace()`, on top of
//! [`TraceAddressSnapRangePropertyMapOperations`]. It is ported as its own trait (a cycle
//! cut-point) rather than folded into that supertrait, mirroring the original's separation
//! between space-agnostic map operations and the per-space map.
use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::map::trace_address_snap_range_property_map_operations::TraceAddressSnapRangePropertyMapOperations;

/// A trace property map restricted to a single address space.
///
/// Port of `ghidra.trace.model.map.TraceAddressSnapRangePropertyMapSpace<T>`.
pub trait TraceAddressSnapRangePropertyMapSpace<T>:
    TraceAddressSnapRangePropertyMapOperations<T>
{
    /// Returns the address space this map is restricted to.
    ///
    /// Mirrors the Java `getAddressSpace()`.
    fn get_address_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{Address, AddressSetView, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::TraceAddressSnapRangeQuery;
    use crate::util::database::spatial::spatial_map::SpatialMap;



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

    /// A trivial in-memory implementation, sufficient to exercise the space accessor alongside
    /// the inherited default methods and prove object-safety.
    struct MockSpaceMap {
        space: Arc<AddressSpace>,
        entries: Vec<(Box<dyn TraceAddressSnapRange>, i32)>,
    }

    impl SpatialMap<Box<dyn TraceAddressSnapRange>, i32, Box<dyn TraceAddressSnapRangeQuery>>
        for MockSpaceMap
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
            Box::new(MockSpaceMap {
                space: self.space.clone(),
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

    impl TraceAddressSnapRangePropertyMapOperations<i32> for MockSpaceMap {
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

    impl TraceAddressSnapRangePropertyMapSpace<i32> for MockSpaceMap {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[test]
    fn get_address_space_returns_constructor_space() {
        let map = MockSpaceMap {
            space: ram_space(),
            entries: vec![],
        };
        assert_eq!(map.get_address_space().name(), "ram");
    }

    #[test]
    fn inherited_default_methods_still_work_through_the_subtrait() {
        let mut map = MockSpaceMap {
            space: ram_space(),
            entries: vec![],
        };
        map.put_address(addr(0x1000), Lifespan::span(5, 5), 42);
        assert_eq!(map.size(), 1);
        let (shape, value) = map.first_entry().unwrap();
        assert_eq!(value, 42);
        assert_eq!(shape.get_x1().offset(), 0x1000);
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let mut map = MockSpaceMap {
            space: ram_space(),
            entries: vec![],
        };
        map.put_address(addr(0x2000), Lifespan::span(0, 0), 7);
        let boxed: Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>> = Box::new(map);
        assert_eq!(boxed.get_address_space().name(), "ram");
        assert_eq!(boxed.size(), 1);
    }
}
