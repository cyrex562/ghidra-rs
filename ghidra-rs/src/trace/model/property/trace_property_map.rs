//! A range map for storing properties in a trace.
//!
//! Java source: `ghidra.trace.model.property.TracePropertyMap`.
//!
//! Technically, each range is actually a "box" in two dimensions: time and space. Time is
//! represented by the span of snapshots covered, and space is represented by the range of
//! addresses covered. Currently, no effort is made to optimize coverage for entries having the
//! same value. For operations on entries, see
//! [`TracePropertyMapOperations`](super::trace_property_map_operations::TracePropertyMapOperations).
//!
//! This interface is the root of a multi-space property map. For memory spaces, clients can
//! generally use the operations inherited on this interface. For register spaces, clients must
//! use [`get_property_map_register_space`](TracePropertyMap::get_property_map_register_space) or
//! similar.
//!
//! This type was selected as a dependency-cycle cut-point, so it is ported as a trait rather than
//! being defined alongside its (not yet ported) implementors.
use crate::program::model::address::AddressSpace;
use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::model::thread::TraceThread;
use std::sync::Arc;

use super::trace_property_map_operations::TracePropertyMapOperations;
use super::trace_property_map_space::TracePropertyMapSpace;

/// A range map for storing properties in a trace.
///
/// Port of `ghidra.trace.model.property.TracePropertyMap<T>`.
pub trait TracePropertyMap<T>: TracePropertyMapOperations<T>
where
    T: 'static,
{
    /// Gets the map space for the given address space.
    ///
    /// Port of `getPropertyMapSpace(AddressSpace, boolean)`. Returns `None` if there is no such
    /// space (Java's `null`).
    fn get_property_map_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Box<dyn TracePropertyMapSpace<T>>>;

    /// Gets the map space for the registers of a given thread and frame.
    ///
    /// Port of `getPropertyMapRegisterSpace(TraceThread, int, boolean)`. Returns `None` if there
    /// is no such space (Java's `null`).
    fn get_property_map_register_space(
        &self,
        thread: &dyn TraceThread,
        frame_level: i32,
        create_if_absent: bool,
    ) -> Option<Box<dyn TracePropertyMapSpace<T>>>;

    /// Gets the map space for the registers of a given frame (which knows its thread).
    ///
    /// Port of the default method `getPropertyMapRegisterSpace(TraceStackFrame, boolean)`. The
    /// Java default delegates to
    /// [`get_property_map_register_space`](Self::get_property_map_register_space) via
    /// `frame.getStack().getThread()` and `frame.getLevel()`; since `TraceStack` (the frame's
    /// container) is still only a marker placeholder with no `get_thread` accessor, this is left
    /// unimplemented rather than guessing at that navigation.
    fn get_property_map_register_space_for_frame(
        &self,
        _frame: &dyn TraceStackFrame,
        _create_if_absent: bool,
    ) -> Option<Box<dyn TracePropertyMapSpace<T>>> {
        unimplemented!(
            "TracePropertyMap::get_property_map_register_space_for_frame requires the ported \
             TraceStack (getThread)"
        )
    }

    /// Deletes this property and removes all of its maps.
    ///
    /// Port of `delete()`. The property can be re-created with the same or different value type.
    fn delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use std::any::TypeId;



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

    /// A trivial single-space in-memory implementation, sufficient to prove object-safety and
    /// exercise `delete`/`get_property_map_space` behavior.
    struct MockMap {
        deleted: bool,
        entries: Vec<(MockRange, i32)>,
    }

    impl TracePropertyMapOperations<i32> for MockMap {
        fn get_value_class(&self) -> TypeId {
            TypeId::of::<i32>()
        }

        fn set(&mut self, lifespan: Lifespan, address: Address, value: i32) {
            self.set_range(lifespan, AddressRange::new(address.clone(), address), value)
        }

        fn set_range(&mut self, lifespan: Lifespan, range: AddressRange, value: i32) {
            self.entries.push((
                MockRange {
                    range,
                    y1: lifespan.lmin(),
                    y2: lifespan.lmax(),
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
            lifespan: Lifespan,
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

        fn get_address_set_view(&self, span: Lifespan) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for (shape, _) in &self.entries {
                if shape.y1 <= span.lmax() && span.lmin() <= shape.y2 {
                    set.add_range_object(&shape.range);
                }
            }
            Box::new(set)
        }

        fn clear(&mut self, _span: Lifespan, _range: AddressRange) -> bool {
            let had = !self.entries.is_empty();
            self.entries.clear();
            had
        }
    }

    /// Only ever returned opaquely by [`TracePropertyMap::get_property_map_space`] in this
    /// module's tests (never actually exercised), so every method is unimplemented.
    struct MockSpace;

    impl TracePropertyMapOperations<i32> for MockSpace {
        fn get_value_class(&self) -> TypeId {
            TypeId::of::<i32>()
        }

        fn set(&mut self, _lifespan: Lifespan, _address: Address, _value: i32) {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange, _value: i32) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get(&self, _snap: i64, _address: &Address) -> Option<i32> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, i32)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_entries(
            &self,
            _lifespan: Lifespan,
            _range: AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, i32)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_set_view(&self, _span: Lifespan) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn clear(&mut self, _span: Lifespan, _range: AddressRange) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TracePropertyMapSpace<i32> for MockSpace {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn trace_register_utils(&self) -> &dyn crate::trace::seam_stubs::TraceRegisterUtils {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockThread;

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl crate::trace::model::target::iface::TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            0
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: crate::trace::model::lifespan::Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            true
        }
    }

    impl TracePropertyMap<i32> for MockMap {
        fn get_property_map_space(
            &self,
            _space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TracePropertyMapSpace<i32>>> {
            if self.deleted {
                None
            } else {
                Some(Box::new(MockSpace))
            }
        }

        fn get_property_map_register_space(
            &self,
            _thread: &dyn TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TracePropertyMapSpace<i32>>> {
            None
        }

        fn delete(&mut self) {
            self.deleted = true;
            self.entries.clear();
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[test]
    fn delete_clears_entries_and_map_space() {
        let mut map = MockMap {
            deleted: false,
            entries: vec![],
        };
        map.set(Lifespan::span(0, 10), addr(0x1000), 42);
        assert_eq!(map.get(5, &addr(0x1000)), Some(42));
        assert!(map.get_property_map_space(&ram_space(), false).is_some());

        map.delete();

        assert_eq!(map.get(5, &addr(0x1000)), None);
        assert!(map.get_property_map_space(&ram_space(), false).is_none());
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let mut map = MockMap {
            deleted: false,
            entries: vec![],
        };
        map.set(Lifespan::span(0, 0), addr(0x1000), 7);
        let boxed: Box<dyn TracePropertyMap<i32>> = Box::new(map);
        assert_eq!(boxed.get(0, &addr(0x1000)), Some(7));
        assert!(boxed
            .get_property_map_register_space(&MockThread, 0, false)
            .is_none());
    }
}
