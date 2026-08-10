//! A trace property map keyed by `(AddressRange, Lifespan)` rectangles.
//!
//! Java source: `ghidra.trace.model.map.TraceAddressSnapRangePropertyMap`.
//!
//! The Java interface overloads `getRegisterSpace` on the reference type (`TraceThread` vs.
//! `TraceStackFrame`); Rust has no overloading, so each overload gets its own method, following
//! the same split used by
//! [`TraceCodeManager`](crate::trace::model::listing::trace_code_manager::TraceCodeManager)'s
//! `get_code_register_space`/`get_code_register_space_for_stack_frame`.
use crate::trace::model::map::trace_address_snap_range_property_map_operations::TraceAddressSnapRangePropertyMapOperations;
use crate::trace::model::map::trace_address_snap_range_property_map_space::TraceAddressSnapRangePropertyMapSpace;
use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::seam_stubs::TraceThread;

/// A trace property map keyed by `(AddressRange, Lifespan)` rectangles.
///
/// Port of `ghidra.trace.model.map.TraceAddressSnapRangePropertyMap<T>`.
pub trait TraceAddressSnapRangePropertyMap<T>: TraceAddressSnapRangePropertyMapOperations<T> {
    /// Returns the name of this map, as used to look it up by name.
    ///
    /// Mirrors the Java `getName()`.
    fn get_name(&self) -> String;

    /// Get the space bound to the given thread's innermost register space.
    ///
    /// `create_if_absent`: true to create the space if it's not already present.
    ///
    /// Returns the space, or `None` if absent and not created.
    ///
    /// Mirrors the Java `getRegisterSpace(TraceThread, boolean)`.
    fn get_register_space(
        &self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<T>>>;

    /// Get the space bound to the given stack frame's register space.
    ///
    /// `create_if_absent`: true to create the space if it's not already present.
    ///
    /// Returns the space, or `None` if absent and not created.
    ///
    /// Mirrors the Java `getRegisterSpace(TraceStackFrame, boolean)`.
    fn get_register_space_for_stack_frame(
        &self,
        frame: &dyn TraceStackFrame,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<T>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::TraceAddressSnapRangeQuery;
    use crate::util::database::spatial::spatial_map::SpatialMap;
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

    struct MockThread;
    impl TraceThread for MockThread {}

    struct MockStackFrame;

    impl crate::trace::model::target::iface::TraceObjectInterface for MockStackFrame {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceStackFrame for MockStackFrame {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack(&self) -> Box<dyn crate::trace::model::stack::trace_stack::TraceStack> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_level(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program_counter(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_program_counter(&mut self, _span: Lifespan, _pc: Address) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_pointer(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_stack_pointer(&mut self, _span: Lifespan, _sp: Address) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_comment(&self, _snap: i64) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_comment(&mut self, _snap: i64, _comment: Option<String>) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A single-space, in-memory implementation, sufficient to prove object-safety and exercise
    /// the name/register-space accessors.
    struct MockPropertyMap {
        name: String,
        space: Arc<AddressSpace>,
        register_space: bool,
        entries: Vec<(Box<dyn TraceAddressSnapRange>, i32)>,
    }

    impl SpatialMap<Box<dyn TraceAddressSnapRange>, i32, Box<dyn TraceAddressSnapRangeQuery>>
        for MockPropertyMap
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
            Box::new(MockPropertyMap {
                name: self.name.clone(),
                space: self.space.clone(),
                register_space: self.register_space,
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

    impl TraceAddressSnapRangePropertyMapOperations<i32> for MockPropertyMap {
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

    impl TraceAddressSnapRangePropertyMapSpace<i32> for MockPropertyMap {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    impl TraceAddressSnapRangePropertyMap<i32> for MockPropertyMap {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_register_space(
            &self,
            _thread: &dyn TraceThread,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> {
            if self.register_space || create_if_absent {
                Some(Box::new(MockPropertyMap {
                    name: self.name.clone(),
                    space: self.space.clone(),
                    register_space: true,
                    entries: vec![],
                }))
            } else {
                None
            }
        }

        fn get_register_space_for_stack_frame(
            &self,
            _frame: &dyn TraceStackFrame,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> {
            self.get_register_space(&MockThread, create_if_absent)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn map(name: &str) -> MockPropertyMap {
        MockPropertyMap {
            name: name.to_string(),
            space: ram_space(),
            register_space: false,
            entries: vec![],
        }
    }

    #[test]
    fn get_name_returns_constructor_name() {
        let m = map("mymap");
        assert_eq!(m.get_name(), "mymap");
    }

    #[test]
    fn get_register_space_returns_none_when_absent_and_not_created() {
        let m = map("mymap");
        assert!(m.get_register_space(&MockThread, false).is_none());
    }

    #[test]
    fn get_register_space_creates_when_requested() {
        let m = map("mymap");
        let space = m.get_register_space(&MockThread, true).unwrap();
        assert_eq!(space.get_address_space().name(), "ram");
    }

    #[test]
    fn get_register_space_for_stack_frame_creates_when_requested() {
        let m = map("mymap");
        let space = m
            .get_register_space_for_stack_frame(&MockStackFrame, true)
            .unwrap();
        assert_eq!(space.get_address_space().name(), "ram");
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let mut m = map("mymap");
        m.put_address(addr(0x1000), Lifespan::span(0, 0), 5);
        let boxed: Box<dyn TraceAddressSnapRangePropertyMap<i32>> = Box::new(m);
        assert_eq!(boxed.get_name(), "mymap");
        assert_eq!(boxed.size(), 1);
    }
}
