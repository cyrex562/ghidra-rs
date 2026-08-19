//! Port of `ghidra.trace.model.memory.TraceMemoryManager`.
//!
//! A store of memory observations over time in a trace.
//!
//! The manager is not bound to any particular address space and may be used to access
//! information about any memory address. For register spaces, use
//! [`TraceMemoryManager::get_memory_register_space`].
//!
//! Adaptations from a literal translation:
//!
//! - Java's `addRegion(String, Lifespan, AddressRange, Collection<TraceMemoryFlag>)` and its
//!   varargs sibling `addRegion(String, Lifespan, AddressRange, TraceMemoryFlag...)` collapse into
//!   a single [`TraceMemoryManager::add_region`] taking `&[TraceMemoryFlag]`, which already covers
//!   both call shapes -- the same collapsing
//!   [`TraceMemoryRegion::set_flags`](crate::trace::model::memory::trace_memory_region::TraceMemoryRegion::set_flags)
//!   uses. Likewise, `createRegion`'s collection/varargs pair collapses into one
//!   [`TraceMemoryManager::create_region`] default.
//! - `createRegion`'s Java `throws TraceOverlappedRegionException, DuplicateNameException` is
//!   wider than what its default body (a straight call to `addRegion`) can actually raise, so the
//!   port only propagates [`TraceOverlappedRegionException`], matching `add_region`'s error type.
//! - `Predicate<TraceMemoryRegion>` and `Predicate<TraceMemoryState>` become `&dyn Fn(...) -> bool`,
//!   per the convention already established by
//!   [`TraceMemoryOperations`](crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations).
//! - `Entry<TraceAddressSnapRange, TraceMemoryState>` becomes a `(Box<dyn TraceAddressSnapRange>,
//!   TraceMemoryState)` pair, matching `TraceMemoryOperations`'s own convention.
//! - Reuses [`TraceThread`](crate::trace::model::thread::TraceThread), matching
//!   [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
//!   usage.
//! - `TraceOverlappedRegionException` is not yet ported; its
//!   [`crate::trace::seam_stubs::TraceOverlappedRegionException`] placeholder is reused verbatim,
//!   for the same reason.
//!
//! This interface's methods largely re-declare, one-for-one, methods
//! [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)
//! already declares as a dependency-cycle cut-point (region and overlay-space management, plus
//! `get_state_changes`). Those share this trait's exact signatures, so an implementor of both
//! traits can forward one to the other (see `DBTraceMemoryManager`'s test `MockManager`).
//! `get_memory_space` and the three `get_memory_register_space` overloads are the exception: here
//! they return `Option<Box<dyn TraceMemorySpace>>` (the model type), where
//! `DBTraceMemoryManager`'s same-named methods return `Option<Arc<dyn DBTraceMemorySpace>>` (its
//! own concrete delegate type) -- two distinct trait methods that happen to share a name, exactly
//! as `TraceMemoryOperations::get_state` and `DBTraceMemoryManager::get_state` already do.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSetView, AddressSpace};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
use crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations;
use crate::trace::model::memory::trace_memory_region::TraceMemoryRegion;
use crate::trace::model::memory::trace_memory_space::TraceMemorySpace;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::TraceOverlappedRegionException;
use crate::trace::model::thread::TraceThread;
use crate::util::exception::DuplicateNameException;

/// A store of memory observations over time in a trace.
///
/// Port of `ghidra.trace.model.memory.TraceMemoryManager`. See the module documentation for the
/// overload-collapsing and stub-reuse deviations from a literal translation.
pub trait TraceMemoryManager: TraceMemoryOperations {
    // ---- overlay address spaces ----

    /// Create a new address space with the given name based upon the given space.
    ///
    /// The purpose of overlay spaces in traces is often to store bytes for things other than
    /// memory or registers. Some targets may expose other byte-based storage, or provide
    /// alternative views of memory. Mirrors `createOverlayAddressSpace(String, AddressSpace)`.
    fn create_overlay_address_space(
        &self,
        name: &str,
        base: &Arc<AddressSpace>,
    ) -> Result<Arc<AddressSpace>, DuplicateNameException>;

    /// Get or create an overlay address space.
    ///
    /// If the space already exists, and it overlays the given base, the existing space is
    /// returned. If it overlays a different space, `None` is returned. If the space does not
    /// exist, it is created with the given base space. Mirrors
    /// `getOrCreateOverlayAddressSpace(String, AddressSpace)`.
    fn get_or_create_overlay_address_space(
        &self,
        name: &str,
        base: &Arc<AddressSpace>,
    ) -> Option<Arc<AddressSpace>>;

    /// Delete an overlay address space. Mirrors `deleteOverlayAddressSpace(String)`.
    fn delete_overlay_address_space(&self, name: &str);

    // ---- regions ----

    /// Add a new region with the given properties.
    ///
    /// Regions model the memory mappings of a debugging target. As such, they are never allowed
    /// to overlap. Additionally, to ensure [`Self::get_live_region_by_path`] returns a unique
    /// region, duplicate paths cannot exist in the same snap.
    ///
    /// Regions have a "full name" (path) as well as a short name. The path is immutable and can
    /// be used to reliably retrieve the same region later. The short name should be something
    /// suitable for display on the screen. Short names are mutable and can be -- but probably
    /// shouldn't be -- duplicated. Mirrors `addRegion(String, Lifespan, AddressRange,
    /// Collection<TraceMemoryFlag>)` and its varargs sibling.
    fn add_region(
        &self,
        path: &str,
        lifespan: Lifespan,
        range: AddressRange,
        flags: &[TraceMemoryFlag],
    ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>>;

    /// Add a region created at the given snap, with no specified destruction snap. Mirrors
    /// `createRegion(String, long, AddressRange, Collection<TraceMemoryFlag>)` and its varargs
    /// sibling.
    fn create_region(
        &self,
        path: &str,
        snap: i64,
        range: AddressRange,
        flags: &[TraceMemoryFlag],
    ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>> {
        self.add_region(path, Lifespan::now_on(snap), range, flags)
    }

    /// Get all the regions in this manager. Mirrors `getAllRegions()`.
    fn get_all_regions(&self) -> Vec<Box<dyn TraceMemoryRegion>>;

    /// Get the region with the given path at the given snap. Mirrors
    /// `getLiveRegionByPath(long, String)`.
    fn get_live_region_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceMemoryRegion>>;

    /// Get the region at the given address and snap. Mirrors `getRegionContaining(long,
    /// Address)`.
    fn get_region_containing(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceMemoryRegion>>;

    /// Collect regions intersecting the given lifespan and range. Mirrors
    /// `getRegionsIntersecting(Lifespan, AddressRange)`.
    fn get_regions_intersecting(
        &self,
        lifespan: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceMemoryRegion>>;

    /// Collect regions at the given snap. Mirrors `getRegionsAtSnap(long)`.
    fn get_regions_at_snap(&self, snap: i64) -> Vec<Box<dyn TraceMemoryRegion>>;

    /// Get the addresses contained by regions at the given snap.
    ///
    /// The implementation may provide a view that updates with changes. Mirrors
    /// `getRegionsAddressSet(long)`.
    fn get_regions_address_set(&self, snap: i64) -> Box<dyn AddressSetView>;

    /// Get the addresses contained by regions at the given snap satisfying the given predicate.
    ///
    /// The implementation may provide a view that updates with changes. Mirrors
    /// `getRegionsAddressSetWith(long, Predicate<TraceMemoryRegion>)`.
    fn get_regions_address_set_with(
        &self,
        snap: i64,
        predicate: &dyn Fn(&dyn TraceMemoryRegion) -> bool,
    ) -> Box<dyn AddressSetView>;

    // ---- spaces ----

    /// Obtain a memory space bound to a particular address space.
    ///
    /// * `create_if_absent` - true to create the space if it's not already present.
    ///
    /// Mirrors `getMemorySpace(AddressSpace, boolean)`.
    fn get_memory_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceMemorySpace>>;

    /// Obtain a "memory" space bound to the register address space for a given thread and stack
    /// frame.
    ///
    /// * `frame` - the "level" of the given stack frame. 0 is the innermost frame.
    /// * `create_if_absent` - true to create the space if it's not already present.
    ///
    /// Mirrors `getMemoryRegisterSpace(TraceThread, int, boolean)`.
    fn get_memory_register_space_at_frame(
        &self,
        thread: &dyn TraceThread,
        frame: i32,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceMemorySpace>>;

    /// Obtain a "memory" space bound to the register address space for frame 0 of a given
    /// thread. Mirrors `getMemoryRegisterSpace(TraceThread, boolean)`.
    fn get_memory_register_space(
        &self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceMemorySpace>>;

    /// Obtain a "memory" space bound to the register address space for a stack frame.
    ///
    /// Note this is simply a convenience, and does not in any way bind the space to the lifespan
    /// of the given frame. Nor, if the frame is moved, will this space move with it. Mirrors
    /// `getMemoryRegisterSpace(TraceStackFrame, boolean)`.
    fn get_memory_register_space_for_frame(
        &self,
        frame: &dyn TraceStackFrame,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceMemorySpace>>;

    // ---- misc ----

    /// Collect all the state changes between two given snaps. Mirrors `getStateChanges(long,
    /// long)`.
    fn get_state_changes(
        &self,
        from: i64,
        to: i64,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::program::model::address::{AddressSet, AddressSpaceType};
    use crate::program::model::mem::MemBuffer;
    use crate::trace::model::trace::Trace;
    use crate::util::task::TaskMonitor;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockRegion {
        path: String,
        range: AddressRange,
    }

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockRegion {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl crate::trace::model::target::iface::TraceObjectInterface for MockRegion {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceMemoryRegion for MockRegion {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_path(&self) -> String {
            self.path.clone()
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name_at(&mut self, _snap: i64, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            self.path.clone()
        }
        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_range_at(
            &mut self,
            _snap: i64,
            _range: AddressRange,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self, _snap: i64) -> AddressRange {
            self.range.clone()
        }
        fn set_min_address(
            &mut self,
            _snap: i64,
            _min: Address,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_min_address(&self, _snap: i64) -> Address {
            self.range.min_address().clone()
        }
        fn set_max_address(
            &mut self,
            _snap: i64,
            _max: Address,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_address(&self, _snap: i64) -> Address {
            self.range.max_address().clone()
        }
        fn set_length(
            &mut self,
            _snap: i64,
            _length: u64,
        ) -> Result<(), crate::trace::model::memory::trace_memory_region::SetLengthError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_length(&self, _snap: i64) -> u64 {
            self.range.length()
        }
        fn set_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_flags(
            &self,
            _snap: i64,
        ) -> std::collections::HashSet<TraceMemoryFlag> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_read(&mut self, _snap: i64, _read: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_read(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_write(&mut self, _snap: i64, _write: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_write(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_execute(&mut self, _snap: i64, _execute: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_execute(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_volatile(&mut self, _snap: i64, _vol: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_volatile(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn delete(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove(&mut self, _snap: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
    }

    /// A single-region, single-space in-memory manager: proves [`TraceMemoryManager::add_region`],
    /// [`TraceMemoryManager::create_region`]'s `Lifespan::now_on` translation, and
    /// [`TraceMemoryManager::get_live_region_by_path`] behave like the Java class the interface
    /// documents (regions keyed by path, `createRegion` opening an unbounded lifespan).
    struct MockManager {
        regions: Mutex<HashMap<String, (Lifespan, AddressRange)>>,
    }

    impl MockManager {
        fn new() -> Self {
            MockManager { regions: Mutex::new(HashMap::new()) }
        }
    }

    impl TraceMemoryOperations for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_state(&mut self, _snap: i64, _range: &AddressRange, _state: TraceMemoryState) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_state(&self, _snap: i64, _address: &Address) -> TraceMemoryState {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_view_state(&self, _snap: i64, _address: &Address) -> (i64, TraceMemoryState) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_most_recent_state_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_view_most_recent_state_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_view_most_recent_state_entry_where(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_addresses_with_state_in(
            &self,
            _span: Lifespan,
            _set: &dyn AddressSetView,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_addresses_with_state(
            &self,
            _snap: i64,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_addresses_with_state_over(
            &self,
            _lifespan: Lifespan,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_states(
            &self,
            _snap: i64,
            _range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_most_recent_states(
            &self,
            _within: &dyn TraceAddressSnapRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_most_recent_states_in(
            &self,
            _snap: i64,
            _range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_bytes(&mut self, _snap: i64, _start: &Address, _buf: &mut [u8]) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bytes(&self, _snap: i64, _start: &Address, _buf: &mut [u8]) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_view_bytes(&self, _snap: i64, _start: &Address, _buf: &mut [u8]) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn find_bytes(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _data: &[u8],
            _mask: Option<&[u8]>,
            _forward: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Address> {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_bytes(&mut self, _snap: i64, _start: &Address, _len: i32) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_buffer_at(&self, _snap: i64, _start: &Address, _big_endian: bool) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_snap_of_most_recent_change_to_block(&self, _snap: i64, _address: &Address) -> Option<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_block_size(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn pack(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceMemoryManager for MockManager {
        fn create_overlay_address_space(
            &self,
            _name: &str,
            _base: &Arc<AddressSpace>,
        ) -> Result<Arc<AddressSpace>, DuplicateNameException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_or_create_overlay_address_space(
            &self,
            _name: &str,
            _base: &Arc<AddressSpace>,
        ) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn delete_overlay_address_space(&self, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_region(
            &self,
            path: &str,
            lifespan: Lifespan,
            range: AddressRange,
            _flags: &[TraceMemoryFlag],
        ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>> {
            self.regions
                .lock()
                .unwrap()
                .insert(path.to_string(), (lifespan, range.clone()));
            Ok(Box::new(MockRegion { path: path.to_string(), range }))
        }
        fn get_all_regions(&self) -> Vec<Box<dyn TraceMemoryRegion>> {
            self.regions
                .lock()
                .unwrap()
                .iter()
                .map(|(path, (_, range))| {
                    Box::new(MockRegion { path: path.clone(), range: range.clone() })
                        as Box<dyn TraceMemoryRegion>
                })
                .collect()
        }
        fn get_live_region_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceMemoryRegion>> {
            let regions = self.regions.lock().unwrap();
            let (lifespan, range) = regions.get(path)?;
            if !lifespan.contains(snap) {
                return None;
            }
            Some(Box::new(MockRegion { path: path.to_string(), range: range.clone() }))
        }
        fn get_region_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceMemoryRegion>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_regions_intersecting(
            &self,
            _lifespan: Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceMemoryRegion>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_regions_at_snap(&self, _snap: i64) -> Vec<Box<dyn TraceMemoryRegion>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_regions_address_set(&self, _snap: i64) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_regions_address_set_with(
            &self,
            _snap: i64,
            _predicate: &dyn Fn(&dyn TraceMemoryRegion) -> bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_space(
            &self,
            _space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_register_space_at_frame(
            &self,
            _thread: &dyn TraceThread,
            _frame: i32,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_register_space(
            &self,
            _thread: &dyn TraceThread,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_register_space_for_frame(
            &self,
            _frame: &dyn TraceStackFrame,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_state_changes(
            &self,
            _from: i64,
            _to: i64,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn TraceMemoryManager) {}
        assert_object_safe(&MockManager::new());
    }

    #[test]
    fn create_region_opens_an_unbounded_lifespan_starting_at_snap() {
        let mgr = MockManager::new();
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 0xff));

        mgr.create_region("Regions[0]", 5, range.clone(), &[TraceMemoryFlag::Read])
            .unwrap_or_else(|_| unreachable!("MockManager::add_region never fails"));

        assert!(mgr.get_live_region_by_path(4, "Regions[0]").is_none(), "not yet created at snap 4");
        let region = mgr.get_live_region_by_path(5, "Regions[0]").expect("present from snap 5 on");
        assert_eq!(region.get_path(), "Regions[0]");
        assert!(
            mgr.get_live_region_by_path(1_000_000, "Regions[0]").is_some(),
            "createRegion leaves the destruction snap open"
        );
    }

    #[test]
    fn get_all_regions_reflects_every_added_region() {
        let mgr = MockManager::new();
        let space = ram_space();
        mgr.add_region(
            "Regions[0]",
            Lifespan::ALL,
            AddressRange::new(addr(&space, 0), addr(&space, 0xf)),
            &[],
        )
        .unwrap_or_else(|_| unreachable!("MockManager::add_region never fails"));
        mgr.add_region(
            "Regions[1]",
            Lifespan::ALL,
            AddressRange::new(addr(&space, 0x100), addr(&space, 0x1ff)),
            &[],
        )
        .unwrap_or_else(|_| unreachable!("MockManager::add_region never fails"));

        let mut paths: Vec<String> =
            mgr.get_all_regions().iter().map(|r| r.get_path()).collect();
        paths.sort();
        assert_eq!(paths, vec!["Regions[0]".to_string(), "Regions[1]".to_string()]);
    }
}
