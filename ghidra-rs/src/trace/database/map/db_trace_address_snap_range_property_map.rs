//! Port of `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap`.
//!
//! This class was selected as a dependency-cycle cut-point, so only its own public surface --
//! beyond the [`TraceAddressSnapRangePropertyMap`] and [`DBTraceDelegatingManager`] contracts it
//! already implements -- is ported here:
//!
//! - [`get_active_spaces`](DBTraceAddressSnapRangePropertyMap::get_active_spaces) --
//!   `AbstractDBTraceSpaceBasedManager.getActiveSpaces()`, used by the Java `size()` override to
//!   count entries "in memory spaces only" (no register spaces).
//! - [`delete_data`](DBTraceAddressSnapRangePropertyMap::delete_data) -- a method the Java source
//!   itself notes is "not declared in interface": an addition specific to this class, used by its
//!   own `deleteValue` override for maps where the entry (`DR`) doubles as the value (`T`).
//!
//! The Java `getForSpace(AddressSpace, boolean)` override is a pure passthrough to
//! `AbstractDBTraceSpaceBasedManager.getForSpace`, which is exactly what
//! [`DBTraceDelegatingManager::get_for_space`] already requires, so it is not redeclared here.
//! Likewise `readLock()`/`writeLock()` map directly onto
//! [`DBTraceDelegatingManager::read_lock`]/[`write_lock`](DBTraceDelegatingManager::write_lock).
//!
//! The class's constructor -- and the `DBHandle`/`OpenMode`/`Language`/`DBTrace`/
//! `DBTraceThreadManager` dependencies it takes -- is implementation, not public contract, so it
//! is not represented here.
//!
//! `DR` stands in for the Java class's `DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>`
//! type parameter.
use crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager;
use crate::trace::model::map::trace_address_snap_range_property_map::TraceAddressSnapRangePropertyMap;
use crate::trace::model::map::trace_address_snap_range_property_map_space::TraceAddressSnapRangePropertyMapSpace;
use crate::trace::seam_stubs::AbstractDBTraceAddressSnapRangePropertyMapData;

/// A trace-database-backed [`TraceAddressSnapRangePropertyMap`], delegating per-address-space
/// work to one [`TraceAddressSnapRangePropertyMapSpace`] per space.
///
/// Port of `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap<T, DR>`.
pub trait DBTraceAddressSnapRangePropertyMap<T, DR>:
    TraceAddressSnapRangePropertyMap<T>
    + DBTraceDelegatingManager<Box<dyn TraceAddressSnapRangePropertyMapSpace<T>>>
where
    DR: AbstractDBTraceAddressSnapRangePropertyMapData,
{
    /// Returns every currently-active per-space delegate.
    ///
    /// Mirrors `AbstractDBTraceSpaceBasedManager.getActiveSpaces()`.
    fn get_active_spaces(&self) -> Vec<Box<dyn TraceAddressSnapRangePropertyMapSpace<T>>>;

    /// Deletes the backing data record directly.
    ///
    /// Mirrors `deleteData(DR)`.
    fn delete_data(&self, data: &DR);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{TraceAddressSnapRangeQuery, TraceThread};
    use crate::util::database::spatial::spatial_map::SpatialMap;
    use crate::util::lock_hold::Lock;
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

        fn get_stack(&self) -> Box<dyn crate::trace::seam_stubs::TraceStack> {
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

    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockData {
        space: Arc<AddressSpace>,
    }

    impl AbstractDBTraceAddressSnapRangePropertyMapData for MockData {
        fn address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    /// A single-space, in-memory implementation, sufficient to prove object-safety and exercise
    /// the space-delegating and data-deleting behavior a real DB-backed map would provide.
    struct MockDbMap {
        name: String,
        space: Arc<AddressSpace>,
        read_lock: NoopLock,
        write_lock: NoopLock,
        entries: Vec<(Box<dyn TraceAddressSnapRange>, i32)>,
        deleted_data_calls: std::cell::RefCell<Vec<Arc<AddressSpace>>>,
    }

    impl SpatialMap<Box<dyn TraceAddressSnapRange>, i32, Box<dyn TraceAddressSnapRangeQuery>>
        for MockDbMap
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
            Box::new(MockDbMap {
                name: self.name.clone(),
                space: self.space.clone(),
                read_lock: NoopLock,
                write_lock: NoopLock,
                entries: self.entries(),
                deleted_data_calls: std::cell::RefCell::new(vec![]),
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

    impl crate::trace::model::map::trace_address_snap_range_property_map_operations::TraceAddressSnapRangePropertyMapOperations<i32>
        for MockDbMap
    {
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

    impl TraceAddressSnapRangePropertyMapSpace<i32> for MockDbMap {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    impl TraceAddressSnapRangePropertyMap<i32> for MockDbMap {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_register_space(
            &self,
            _thread: &dyn TraceThread,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> {
            None
        }

        fn get_register_space_for_stack_frame(
            &self,
            _frame: &dyn TraceStackFrame,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> {
            None
        }
    }

    impl DBTraceDelegatingManager<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> for MockDbMap {
        fn read_lock(&self) -> &dyn Lock {
            &self.read_lock
        }

        fn write_lock(&self) -> &dyn Lock {
            &self.write_lock
        }

        fn get_for_space(
            &self,
            space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> {
            if Arc::ptr_eq(space, &self.space) {
                Some(Box::new(MockDbMap {
                    name: self.name.clone(),
                    space: self.space.clone(),
                    read_lock: NoopLock,
                    write_lock: NoopLock,
                    entries: self.entries(),
                    deleted_data_calls: std::cell::RefCell::new(vec![]),
                }))
            } else {
                None
            }
        }
    }

    impl DBTraceAddressSnapRangePropertyMap<i32, MockData> for MockDbMap {
        fn get_active_spaces(&self) -> Vec<Box<dyn TraceAddressSnapRangePropertyMapSpace<i32>>> {
            vec![Box::new(MockDbMap {
                name: self.name.clone(),
                space: self.space.clone(),
                read_lock: NoopLock,
                write_lock: NoopLock,
                entries: self.entries(),
                deleted_data_calls: std::cell::RefCell::new(vec![]),
            })]
        }

        fn delete_data(&self, data: &MockData) {
            self.deleted_data_calls.borrow_mut().push(data.address_space());
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn map(name: &str) -> MockDbMap {
        MockDbMap {
            name: name.to_string(),
            space: ram_space(),
            read_lock: NoopLock,
            write_lock: NoopLock,
            entries: vec![],
            deleted_data_calls: std::cell::RefCell::new(vec![]),
        }
    }

    #[test]
    fn get_active_spaces_reports_own_entries() {
        let mut m = map("mymap");
        let space = m.space.clone();
        m.put(
            Box::new(MockRange {
                range: AddressRange::new(
                    Address::new(space.clone(), 0x1000),
                    Address::new(space, 0x1000),
                ),
                y1: 0,
                y2: 0,
            }),
            5,
        );
        let active = m.get_active_spaces();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].get_address_space().name(), "ram");
        assert_eq!(active[0].size(), 1);
    }

    #[test]
    fn delete_data_forwards_the_records_address_space() {
        let m = map("mymap");
        let data = MockData {
            space: m.space.clone(),
        };
        m.delete_data(&data);
        assert_eq!(m.deleted_data_calls.borrow().len(), 1);
        assert_eq!(m.deleted_data_calls.borrow()[0].name(), "ram");
    }

    #[test]
    fn dyn_trait_object_is_usable_via_supertraits() {
        let m = map("mymap");
        let space = m.space.clone();
        let obj: &dyn DBTraceAddressSnapRangePropertyMap<i32, MockData> = &m;
        assert_eq!(obj.get_name(), "mymap");
        obj.read_lock().lock();
        obj.read_lock().unlock();
        assert!(obj.get_for_space(&space, false).is_some());
    }
}
