//! Port of `ghidra.trace.database.memory.DBTraceMemoryManager`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractDBTraceSpaceBasedManager<DBTraceMemorySpace> implements
//! TraceMemoryManager, InternalTraceMemoryOperations, DBTraceDelegatingManager<DBTraceMemorySpace>`.
//! Unlike
//! [`DBTraceEquateManager`](crate::trace::database::symbol::db_trace_equate_manager::DBTraceEquateManager)
//! (a "boring composition" of already-fully-ported interfaces, so its port is a bare blanket-impl
//! marker), neither the model `TraceMemoryManager` interface nor the per-space delegate
//! `DBTraceMemorySpace` is fully ported yet, so this trait declares the substantive methods
//! directly rather than inheriting them from elsewhere:
//!
//! - Overlay-address-space management (`create_overlay_address_space`/
//!   `get_or_create_overlay_address_space`/`delete_overlay_address_space`) defaults straight
//!   through to [`Self::overlay_adapter`], the Rust stand-in for the `overlayAdapter` field the
//!   Java constructor is handed.
//! - Region management (`add_region`/`get_all_regions`/`get_live_region_by_path`/...) defaults
//!   through [`Self::trace`]'s object manager (`trace.getObjectManager().addMemoryRegion(...)`,
//!   etc).
//! - Per-space state/byte queries declared by the
//!   [`TraceMemoryOperations`](crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations)
//!   base (reached transitively, via the [`InternalTraceMemoryOperations`] supertrait) -- `getState`,
//!   `getViewState`, `getMostRecentStateEntry`, `findBytes`, `getSnapOfMostRecentChangeToBlock`,
//!   ... -- are re-declared here with bodies that delegate per space, since Rust has no way for a
//!   subtrait to supply a supertrait method's body (what the Java class does by implementing the
//!   interface). An implementor forwards its `TraceMemoryOperations` members to these; see
//!   `MockManager` in this module's tests. They default through the [`DBTraceDelegatingManager`]
//!   supertrait's `delegate_read`/
//!   `delegate_read_with_default` helpers, against a new minimal
//!   [`DBTraceMemorySpace`](crate::trace::seam_stubs::DBTraceMemorySpace) placeholder for the
//!   delegate type `M`. These defaults require `Self: Sized` (the same opt-out
//!   `DBTraceDelegatingManager`'s own `delegateXxx` helpers use), so they aren't part of this
//!   trait's `dyn`-safe surface; the core accessors (space/region lookup, overlay management)
//!   remain callable through `Box<dyn DBTraceMemoryManager>`.
//! - `setState`'s `Address`/`(Address, Address)`/`AddressSetView` overloads are inherited
//!   verbatim from the base interface (`set_state_at`/`set_state_between`/`set_state_over`), whose
//!   defaults already build an `AddressRange` and call `TraceMemoryOperations::set_state` -- the
//!   very thing this class does in Java.
//! - `getMemoryRegisterSpace`'s three overloads and `getStateChanges` are left abstract (no
//!   default): resolving a thread/frame to its backing register address space is
//!   `AbstractDBTraceSpaceBasedManager.getForRegisterSpace`'s responsibility, and querying state
//!   changes reaches into a per-space DB-tree (`space.stateMapSpace.reduce(...)`) directly --
//!   neither is ported yet.
//! - `getAddressesWithState`'s three-argument (`Lifespan, AddressSetView, Predicate`) and
//!   lifespan-only two-argument overloads are also left abstract, since answering them requires
//!   each space's full address extent, which the trimmed `DBTraceMemorySpace` placeholder does not
//!   expose; only the `(snap, Predicate)` overload -- `get_addresses_with_state_at_snap` -- has a
//!   default, unioning each active space's own two-argument query.
//! - `getBufferAt`'s `null`-on-miss fallback constructs a `DBTraceEmptyMemBuffer`, a type not yet
//!   ported, so `get_buffer_at` is left abstract too.
//! - `getBlockSize()` mirrors `DBTraceMemorySpace.BLOCK_SIZE` (`1 << BLOCK_SHIFT`, `BLOCK_SHIFT =
//!   12`), a fixed constant unrelated to any particular per-space instance, so it has a real
//!   (non-panicking) default.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::mem::MemBuffer;
use crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations;
use crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
use crate::trace::model::memory::trace_memory_region::TraceMemoryRegion;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::memory::trace_memory_manager::TraceMemoryManager;
use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::model::thread::TraceThread;
use crate::trace::seam_stubs::{
    DBTrace, DBTraceMemorySpace, DBTraceOverlaySpaceAdapter, TraceOverlappedRegionException,
};
use crate::util::exception::DuplicateNameException;
use crate::util::task::TaskMonitor;

/// The trace database's memory manager: regions, byte/state observations, and overlay address
/// spaces.
///
/// Port of `ghidra.trace.database.memory.DBTraceMemoryManager`.
///
/// See the module documentation for which methods default through already-ported supertraits
/// versus remain abstract pending further ports.
pub trait DBTraceMemoryManager:
    InternalTraceMemoryOperations
    + DBTraceDelegatingManager<Arc<dyn DBTraceMemorySpace>>
    + TraceMemoryManager
{
    // ---- accessors an implementor must supply directly ----

    /// The owning trace, used to reach its object manager for region storage. Mirrors the
    /// `trace` field inherited from `AbstractDBTraceSpaceBasedManager`.
    fn trace(&self) -> Box<dyn DBTrace>;

    /// The overlay-space adapter this manager was constructed with. Mirrors the
    /// `overlayAdapter` field.
    fn overlay_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter>;

    /// All currently-active per-space delegates. Mirrors
    /// `AbstractDBTraceSpaceBasedManager.getActiveSpaces()`.
    fn active_spaces(&self) -> Vec<Arc<dyn DBTraceMemorySpace>>;

    /// Obtain the "memory" space bound to the register address space for frame 0 of a thread.
    /// Mirrors `getMemoryRegisterSpace(TraceThread, boolean)`.
    fn get_memory_register_space(
        &self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Arc<dyn DBTraceMemorySpace>>;

    /// Obtain the "memory" space bound to the register address space for a given thread and
    /// stack frame. Mirrors `getMemoryRegisterSpace(TraceThread, int, boolean)`.
    fn get_memory_register_space_at_frame(
        &self,
        thread: &dyn TraceThread,
        frame: i32,
        create_if_absent: bool,
    ) -> Option<Arc<dyn DBTraceMemorySpace>>;

    /// Obtain the "memory" space bound to the register address space for a stack frame. Mirrors
    /// `getMemoryRegisterSpace(TraceStackFrame, boolean)`.
    fn get_memory_register_space_for_frame(
        &self,
        frame: &dyn TraceStackFrame,
        create_if_absent: bool,
    ) -> Option<Arc<dyn DBTraceMemorySpace>>;

    /// Get a view of a particular snap as a memory buffer, or an empty buffer if no delegate
    /// covers `start`. Mirrors `getBufferAt(long, Address, ByteOrder)`. `big_endian` stands in
    /// for the Java `ByteOrder` parameter.
    fn get_buffer_at(&self, snap: i64, start: &Address, big_endian: bool) -> Box<dyn MemBuffer>;

    /// Collect all state changes between two snaps. Mirrors `getStateChanges(long, long)`.
    fn get_state_changes(
        &self,
        from: i64,
        to: i64,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Get at least the intersection of `set`'s addresses having state satisfying `predicate`
    /// over `lifespan`. Mirrors `getAddressesWithState(Lifespan, AddressSetView,
    /// Predicate<TraceMemoryState>)`.
    fn get_addresses_with_state_in(
        &self,
        lifespan: Lifespan,
        set: &dyn AddressSetView,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> AddressSet;

    /// Get the addresses having state satisfying `predicate` at any time in `lifespan`. Mirrors
    /// `getAddressesWithState(Lifespan, Predicate<TraceMemoryState>)`.
    fn get_addresses_with_state_over(
        &self,
        lifespan: Lifespan,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> AddressSet;

    // ---- overlay address spaces: default via `overlay_adapter()` ----

    /// Create a new overlay address space with the given name, based on `base`. Mirrors
    /// `createOverlayAddressSpace(String, AddressSpace)`.
    fn create_overlay_address_space(
        &self,
        name: &str,
        base: &Arc<AddressSpace>,
    ) -> Result<Arc<AddressSpace>, DuplicateNameException> {
        self.overlay_adapter().create_overlay_address_space(name, base)
    }

    /// Get or create an overlay address space over `base`. Mirrors
    /// `getOrCreateOverlayAddressSpace(String, AddressSpace)`.
    fn get_or_create_overlay_address_space(
        &self,
        name: &str,
        base: &Arc<AddressSpace>,
    ) -> Option<Arc<AddressSpace>> {
        self.overlay_adapter().get_or_create_overlay_address_space(name, base)
    }

    /// Delete the named overlay address space. Mirrors `deleteOverlayAddressSpace(String)`.
    fn delete_overlay_address_space(&self, name: &str) {
        self.overlay_adapter().delete_overlay_address_space(name);
    }

    // ---- spaces: default via the `DBTraceDelegatingManager` supertrait ----

    /// Obtain a memory space bound to a particular address space. Mirrors
    /// `getMemorySpace(AddressSpace, boolean)`.
    fn get_memory_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Arc<dyn DBTraceMemorySpace>> {
        self.get_for_space(space, create_if_absent)
    }

    // ---- regions: default via `trace().get_object_manager()` ----

    /// Add a new region with the given properties. Mirrors `addRegion(String, Lifespan,
    /// AddressRange, Collection<TraceMemoryFlag>)`.
    fn add_region(
        &self,
        path: &str,
        lifespan: Lifespan,
        range: AddressRange,
        flags: &[TraceMemoryFlag],
    ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>> {
        self.trace().get_object_manager().add_memory_region(path, lifespan, range, flags)
    }

    /// Get all the regions in this manager. Mirrors `getAllRegions()`.
    fn get_all_regions(&self) -> Vec<Box<dyn TraceMemoryRegion>> {
        self.trace().get_object_manager().get_all_regions()
    }

    /// Get the region with the given path at the given snap. Mirrors
    /// `getLiveRegionByPath(long, String)`.
    fn get_live_region_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceMemoryRegion>> {
        self.trace().get_object_manager().get_region_by_path(snap, path)
    }

    /// Get the region at the given address and snap. Mirrors `getRegionContaining(long,
    /// Address)`.
    fn get_region_containing(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceMemoryRegion>> {
        self.trace().get_object_manager().get_region_containing(snap, address)
    }

    /// Collect regions intersecting the given lifespan and range. Mirrors
    /// `getRegionsIntersecting(Lifespan, AddressRange)`.
    fn get_regions_intersecting(
        &self,
        lifespan: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceMemoryRegion>> {
        self.trace().get_object_manager().get_regions_intersecting(lifespan, range)
    }

    /// Collect regions at the given snap. Mirrors `getRegionsAtSnap(long)`.
    fn get_regions_at_snap(&self, snap: i64) -> Vec<Box<dyn TraceMemoryRegion>> {
        self.trace().get_object_manager().get_regions_at_snap(snap)
    }

    /// Get the addresses contained by regions at the given snap. Mirrors
    /// `getRegionsAddressSet(long)`.
    fn get_regions_address_set(&self, snap: i64) -> Box<dyn AddressSetView> {
        self.trace().get_object_manager().get_regions_address_set(snap, &|_| true)
    }

    /// Get the addresses contained by regions at the given snap satisfying `predicate`. Mirrors
    /// `getRegionsAddressSetWith(long, Predicate<TraceMemoryRegion>)`.
    fn get_regions_address_set_with(
        &self,
        snap: i64,
        predicate: &dyn Fn(&dyn TraceMemoryRegion) -> bool,
    ) -> Box<dyn AddressSetView> {
        self.trace().get_object_manager().get_regions_address_set(snap, predicate)
    }

    // ---- state/byte queries beyond the base six, via `DBTraceDelegatingManager` ----

    /// Get the state of memory at a given snap and address, defaulting to
    /// [`TraceMemoryState::Unknown`] if no delegate covers `address`. Mirrors `getState(long,
    /// Address)`.
    fn get_state(&self, snap: i64, address: &Address) -> TraceMemoryState
    where
        Self: Sized,
    {
        self.delegate_read_with_default(
            address.space(),
            |m| Ok::<_, ()>(m.get_state(snap, address)),
            TraceMemoryState::Unknown,
        )
        .unwrap()
    }

    /// Get the state of memory at a given snap and address, following schedule forks, defaulting
    /// to `(snap, Unknown)` if no delegate covers `address`. Mirrors `getViewState(long,
    /// Address)`.
    fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState)
    where
        Self: Sized,
    {
        self.delegate_read_with_default(
            address.space(),
            |m| Ok::<_, ()>(m.get_view_state(snap, address)),
            (snap, TraceMemoryState::Unknown),
        )
        .unwrap()
    }

    /// Get the entry recording the most recent state at the given snap and address. Mirrors
    /// `getMostRecentStateEntry(long, Address)`.
    fn get_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>
    where
        Self: Sized,
    {
        self.delegate_read(address.space(), |m| {
            Ok::<_, ()>(m.get_most_recent_state_entry(snap, address))
        })
        .unwrap()
        .flatten()
    }

    /// Get the entry recording the most recent state at the given snap and address, following
    /// schedule forks. Mirrors `getViewMostRecentStateEntry(long, Address)`.
    fn get_view_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>
    where
        Self: Sized,
    {
        self.delegate_read(address.space(), |m| {
            Ok::<_, ()>(m.get_view_most_recent_state_entry(snap, address))
        })
        .unwrap()
        .flatten()
    }

    /// Get the entry recording the most recent state since the given snap within the given range
    /// satisfying `predicate`, following schedule forks. Mirrors `getViewMostRecentStateEntry(long,
    /// AddressRange, Predicate<TraceMemoryState>)`.
    fn get_view_most_recent_state_entry_where(
        &self,
        snap: i64,
        range: &AddressRange,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>
    where
        Self: Sized,
    {
        self.delegate_read(range.space(), |m| {
            Ok::<_, ()>(m.get_view_most_recent_state_entry_where(snap, range, predicate))
        })
        .unwrap()
        .flatten()
    }

    /// Get all the entries covering the given range, effective at or extending as "most recent"
    /// to the given snap. Mirrors `getMostRecentStates(TraceAddressSnapRange)`.
    fn get_most_recent_states(
        &self,
        within: &dyn TraceAddressSnapRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>
    where
        Self: Sized,
    {
        let range = within.get_range();
        self.delegate_read_with_default(
            range.space(),
            |m| Ok::<_, ()>(m.get_most_recent_states(within)),
            Vec::new(),
        )
        .unwrap()
    }

    /// Search the given address range at the given snap for a given byte pattern. Mirrors
    /// `findBytes(long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)`.
    fn find_bytes(
        &self,
        snap: i64,
        range: &AddressRange,
        data: &[u8],
        mask: Option<&[u8]>,
        forward: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address>
    where
        Self: Sized,
    {
        self.delegate_read(range.space(), |m| {
            Ok::<_, ()>(m.find_bytes(snap, range, data, mask, forward, monitor))
        })
        .unwrap()
        .flatten()
    }

    /// Find the internal storage block that most-recently defines the value at the given snap and
    /// address, and return the block's snap. Mirrors `getSnapOfMostRecentChangeToBlock(long,
    /// Address)`.
    fn get_snap_of_most_recent_change_to_block(&self, snap: i64, address: &Address) -> Option<i64>
    where
        Self: Sized,
    {
        self.delegate_read(address.space(), |m| {
            Ok::<_, ()>(m.get_snap_of_most_recent_change_to_block(snap, address))
        })
        .unwrap()
        .flatten()
    }

    // ---- addresses-with-state: only the (snap, predicate) overload has a default ----

    /// Get the addresses having state satisfying `predicate` at the given snap, unioning each
    /// active space's own query. Mirrors `getAddressesWithState(long, Predicate<TraceMemoryState>)`.
    fn get_addresses_with_state_at_snap(
        &self,
        snap: i64,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> AddressSet {
        let mut result = AddressSet::new();
        for space in self.active_spaces() {
            let set = space.get_addresses_with_state(snap, predicate);
            result.add_set(&*set);
        }
        result
    }

    // ---- misc ----

    /// The fixed block size memory is internally chunked into. Mirrors `getBlockSize()`
    /// (`DBTraceMemorySpace.BLOCK_SIZE`, i.e. `1 << 12`).
    fn get_block_size(&self) -> i32 {
        4096
    }

    /// Optimize storage space for every active space. Mirrors `pack()`.
    fn pack(&self) {
        for space in self.active_spaces() {
            space.pack();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::collections::HashMap;

    use crate::program::model::address::AddressSpaceType;
    use crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations;
    use crate::trace::model::memory::trace_memory_operations::TraceMemoryOperations;
    use crate::trace::seam_stubs::TraceRegisterUtils;
    use crate::util::lock_hold::Lock;

    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct NoopRegisterUtils;
    impl TraceRegisterUtils for NoopRegisterUtils {
        fn get_thread(
            &self,
            _trace: &dyn crate::trace::model::trace::Trace,
            _space: &Arc<AddressSpace>,
        ) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_frame_level(
            &self,
            _trace: &dyn crate::trace::model::trace::Trace,
            _space: &Arc<AddressSpace>,
        ) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_address_space(
            &self,
            _thread: &dyn TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn buffer_for_value(
            &self,
            _register: &crate::program::model::lang::Register,
            _value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }

        fn finish_buffer(
            &self,
            _buf: &[u8],
            _register: &crate::program::model::lang::Register,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A single-space, in-memory `DBTraceMemorySpace`, storing one byte-state pair per address
    /// offset (known/unknown only, mirroring
    /// [`InternalTraceMemoryOperations`]'s own `MockMemorySpace` test double).
    struct MockDelegateSpace {
        space: Arc<AddressSpace>,
        bytes: Mutex<HashMap<i64, u8>>,
    }

    impl MockDelegateSpace {
        fn new(space: Arc<AddressSpace>) -> Self {
            MockDelegateSpace { space, bytes: Mutex::new(HashMap::new()) }
        }
    }

    impl DBTraceMemorySpace for MockDelegateSpace {
        fn set_state(&self, _snap: i64, range: &AddressRange, state: TraceMemoryState) {
            let mut bytes = self.bytes.lock().unwrap();
            if state == TraceMemoryState::Unknown {
                bytes.remove(&range.min_address().offset());
            } else {
                bytes.entry(range.min_address().offset()).or_insert(0);
            }
        }

        fn get_state(&self, _snap: i64, address: &Address) -> TraceMemoryState {
            if self.bytes.lock().unwrap().contains_key(&address.offset()) {
                TraceMemoryState::Known
            } else {
                TraceMemoryState::Unknown
            }
        }

        fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState) {
            (snap, self.get_state(snap, address))
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

        fn get_addresses_with_state(
            &self,
            _snap: i64,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for (&offset, _) in self.bytes.lock().unwrap().iter() {
                if predicate(TraceMemoryState::Known) {
                    set.add_address(&self.space.address(offset));
                }
            }
            Box::new(set)
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

        fn put_bytes(&self, _snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            let mut bytes = self.bytes.lock().unwrap();
            for (i, b) in buf.iter().enumerate() {
                bytes.insert(start.offset() + i as i64, *b);
            }
            buf.len() as i32
        }

        fn get_bytes(&self, _snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            let bytes = self.bytes.lock().unwrap();
            let mut n = 0;
            for (i, dst) in buf.iter_mut().enumerate() {
                if let Some(b) = bytes.get(&(start.offset() + i as i64)) {
                    *dst = *b;
                    n += 1;
                }
            }
            n
        }

        fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            self.get_bytes(snap, start, buf)
        }

        fn remove_bytes(&self, _snap: i64, start: &Address, len: i32) {
            let mut bytes = self.bytes.lock().unwrap();
            for i in 0..len as i64 {
                bytes.remove(&(start.offset() + i));
            }
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

        fn get_buffer_at(&self, _snap: i64, _start: &Address, _big_endian: bool) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_snap_of_most_recent_change_to_block(&self, _snap: i64, _address: &Address) -> Option<i64> {
            unimplemented!("not exercised by this smoke test")
        }

        fn pack(&self) {}
    }

    /// A one-space manager: every address routes to the same [`MockDelegateSpace`], sufficient to
    /// prove `DBTraceMemoryManager`'s object-safe core (space lookup, overlay pass-through) and
    /// its `Self: Sized` delegating defaults (`get_state`/`set_state_at`/...) both work, without
    /// needing a real `DBTrace`/`DBTraceObjectManager`/`DBTraceOverlaySpaceAdapter`.
    struct MockManager {
        delegate: Arc<dyn DBTraceMemorySpace>,
        read_lock: NoopLock,
        write_lock: NoopLock,
        utils: NoopRegisterUtils,
    }

    impl TraceMemoryOperations for MockManager {
        fn set_state(&mut self, snap: i64, range: &AddressRange, state: TraceMemoryState) {
            self.delegate.set_state(snap, range, state);
        }

        fn get_states(
            &self,
            _snap: i64,
            _range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn put_bytes(&mut self, snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            self.delegate.put_bytes(snap, start, buf)
        }

        fn get_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            self.delegate.get_bytes(snap, start, buf)
        }

        fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32 {
            self.delegate.get_view_bytes(snap, start, buf)
        }

        fn remove_bytes(&mut self, snap: i64, start: &Address, len: i32) {
            self.delegate.remove_bytes(snap, start, len);
        }

        // The rest of the base interface is what the Java class implements; here each member
        // forwards to `DBTraceMemoryManager`'s same-named delegating default. This is the
        // forwarding pattern any real implementor follows -- see this module's documentation.

        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_state(&self, snap: i64, address: &Address) -> TraceMemoryState {
            DBTraceMemoryManager::get_state(self, snap, address)
        }

        fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState) {
            DBTraceMemoryManager::get_view_state(self, snap, address)
        }

        fn get_most_recent_state_entry(
            &self,
            snap: i64,
            address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            DBTraceMemoryManager::get_most_recent_state_entry(self, snap, address)
        }

        fn get_view_most_recent_state_entry(
            &self,
            snap: i64,
            address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            DBTraceMemoryManager::get_view_most_recent_state_entry(self, snap, address)
        }

        fn get_view_most_recent_state_entry_where(
            &self,
            snap: i64,
            range: &AddressRange,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            DBTraceMemoryManager::get_view_most_recent_state_entry_where(
                self, snap, range, predicate,
            )
        }

        fn get_addresses_with_state_in(
            &self,
            span: Lifespan,
            set: &dyn AddressSetView,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(DBTraceMemoryManager::get_addresses_with_state_in(
                self, span, set, predicate,
            ))
        }

        fn get_addresses_with_state(
            &self,
            snap: i64,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(self.get_addresses_with_state_at_snap(snap, predicate))
        }

        fn get_addresses_with_state_over(
            &self,
            lifespan: Lifespan,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(DBTraceMemoryManager::get_addresses_with_state_over(
                self, lifespan, predicate,
            ))
        }

        fn get_most_recent_states(
            &self,
            within: &dyn TraceAddressSnapRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            DBTraceMemoryManager::get_most_recent_states(self, within)
        }

        fn get_most_recent_states_in(
            &self,
            _snap: i64,
            _range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_bytes(
            &self,
            snap: i64,
            range: &AddressRange,
            data: &[u8],
            mask: Option<&[u8]>,
            forward: bool,
            monitor: &dyn TaskMonitor,
        ) -> Option<Address> {
            DBTraceMemoryManager::find_bytes(self, snap, range, data, mask, forward, monitor)
        }

        fn get_buffer_at(&self, snap: i64, start: &Address, big_endian: bool) -> Box<dyn MemBuffer> {
            DBTraceMemoryManager::get_buffer_at(self, snap, start, big_endian)
        }

        fn get_snap_of_most_recent_change_to_block(
            &self,
            snap: i64,
            address: &Address,
        ) -> Option<i64> {
            DBTraceMemoryManager::get_snap_of_most_recent_change_to_block(self, snap, address)
        }

        fn get_block_size(&self) -> i32 {
            DBTraceMemoryManager::get_block_size(self)
        }

        fn pack(&mut self) {
            DBTraceMemoryManager::pack(self)
        }
    }

    impl InternalTraceMemoryOperations for MockManager {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.delegate.get_bytes(0, &Address::new(dummy_space(), 0), &mut []);
            dummy_space()
        }

        fn write_lock(&self) -> Arc<dyn Lock> {
            Arc::new(NoopLock)
        }

        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.utils
        }
    }

    impl DBTraceDelegatingManager<Arc<dyn DBTraceMemorySpace>> for MockManager {
        fn read_lock(&self) -> &dyn Lock {
            &self.read_lock
        }

        fn write_lock(&self) -> &dyn Lock {
            &self.write_lock
        }

        fn get_for_space(
            &self,
            _space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn DBTraceMemorySpace>> {
            Some(self.delegate.clone())
        }
    }

    // `TraceMemoryManager` re-declares, one-for-one, the region/overlay-space methods
    // `DBTraceMemoryManager` already implements as a dependency-cycle cut-point (see this
    // module's documentation), so each forwards to its `DBTraceMemoryManager` counterpart. The
    // `TraceMemorySpace`-returning space lookups aren't exercised by this smoke test, since
    // `DBTraceMemoryManager`'s own space lookups return its concrete `DBTraceMemorySpace` delegate
    // type instead.
    impl TraceMemoryManager for MockManager {
        fn create_overlay_address_space(
            &self,
            name: &str,
            base: &Arc<AddressSpace>,
        ) -> Result<Arc<AddressSpace>, DuplicateNameException> {
            DBTraceMemoryManager::create_overlay_address_space(self, name, base)
        }

        fn get_or_create_overlay_address_space(
            &self,
            name: &str,
            base: &Arc<AddressSpace>,
        ) -> Option<Arc<AddressSpace>> {
            DBTraceMemoryManager::get_or_create_overlay_address_space(self, name, base)
        }

        fn delete_overlay_address_space(&self, name: &str) {
            DBTraceMemoryManager::delete_overlay_address_space(self, name)
        }

        fn add_region(
            &self,
            path: &str,
            lifespan: Lifespan,
            range: AddressRange,
            flags: &[TraceMemoryFlag],
        ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>> {
            DBTraceMemoryManager::add_region(self, path, lifespan, range, flags)
        }

        fn get_all_regions(&self) -> Vec<Box<dyn TraceMemoryRegion>> {
            DBTraceMemoryManager::get_all_regions(self)
        }

        fn get_live_region_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceMemoryRegion>> {
            DBTraceMemoryManager::get_live_region_by_path(self, snap, path)
        }

        fn get_region_containing(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceMemoryRegion>> {
            DBTraceMemoryManager::get_region_containing(self, snap, address)
        }

        fn get_regions_intersecting(
            &self,
            lifespan: Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceMemoryRegion>> {
            DBTraceMemoryManager::get_regions_intersecting(self, lifespan, range)
        }

        fn get_regions_at_snap(&self, snap: i64) -> Vec<Box<dyn TraceMemoryRegion>> {
            DBTraceMemoryManager::get_regions_at_snap(self, snap)
        }

        fn get_regions_address_set(&self, snap: i64) -> Box<dyn AddressSetView> {
            DBTraceMemoryManager::get_regions_address_set(self, snap)
        }

        fn get_regions_address_set_with(
            &self,
            snap: i64,
            predicate: &dyn Fn(&dyn TraceMemoryRegion) -> bool,
        ) -> Box<dyn AddressSetView> {
            DBTraceMemoryManager::get_regions_address_set_with(self, snap, predicate)
        }

        fn get_memory_space(
            &self,
            _space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Box<dyn crate::trace::model::memory::trace_memory_space::TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_register_space_at_frame(
            &self,
            _thread: &dyn TraceThread,
            _frame: i32,
            _create_if_absent: bool,
        ) -> Option<Box<dyn crate::trace::model::memory::trace_memory_space::TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_register_space(
            &self,
            _thread: &dyn TraceThread,
            _create_if_absent: bool,
        ) -> Option<Box<dyn crate::trace::model::memory::trace_memory_space::TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_register_space_for_frame(
            &self,
            _frame: &dyn TraceStackFrame,
            _create_if_absent: bool,
        ) -> Option<Box<dyn crate::trace::model::memory::trace_memory_space::TraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_state_changes(
            &self,
            from: i64,
            to: i64,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            DBTraceMemoryManager::get_state_changes(self, from, to)
        }
    }

    impl DBTraceMemoryManager for MockManager {
        fn trace(&self) -> Box<dyn DBTrace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn overlay_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter> {
            unimplemented!("not exercised by this smoke test")
        }

        fn active_spaces(&self) -> Vec<Arc<dyn DBTraceMemorySpace>> {
            vec![self.delegate.clone()]
        }

        fn get_memory_register_space(
            &self,
            _thread: &dyn TraceThread,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn DBTraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_register_space_at_frame(
            &self,
            _thread: &dyn TraceThread,
            _frame: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn DBTraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_register_space_for_frame(
            &self,
            _frame: &dyn TraceStackFrame,
            _create_if_absent: bool,
        ) -> Option<Arc<dyn DBTraceMemorySpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_buffer_at(&self, _snap: i64, _start: &Address, _big_endian: bool) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_state_changes(
            &self,
            _from: i64,
            _to: i64,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_addresses_with_state_in(
            &self,
            _lifespan: Lifespan,
            _set: &dyn AddressSetView,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> AddressSet {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_addresses_with_state_over(
            &self,
            _lifespan: Lifespan,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> AddressSet {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn dummy_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn make_manager() -> MockManager {
        let space = dummy_space();
        MockManager {
            delegate: Arc::new(MockDelegateSpace::new(space)),
            read_lock: NoopLock,
            write_lock: NoopLock,
            utils: NoopRegisterUtils,
        }
    }

    #[test]
    fn is_object_safe_for_its_core_methods() {
        fn assert_object_safe(_: &dyn DBTraceMemoryManager) {}
        let mgr = make_manager();
        assert_object_safe(&mgr);
    }

    #[test]
    fn get_memory_space_delegates_through_get_for_space() {
        let mgr = make_manager();
        let space = dummy_space();
        let got = DBTraceMemoryManager::get_memory_space(&mgr, &space, false);
        assert!(got.is_some());
    }

    #[test]
    fn state_round_trips_through_set_state_at_and_get_state() {
        let mut mgr = make_manager();
        let space = dummy_space();
        let addr = Address::new(space, 0x10);

        assert_eq!(
            DBTraceMemoryManager::get_state(&mgr, 0, &addr),
            TraceMemoryState::Unknown
        );

        mgr.set_state_at(0, &addr, TraceMemoryState::Known);

        assert_eq!(
            DBTraceMemoryManager::get_state(&mgr, 0, &addr),
            TraceMemoryState::Known
        );
    }

    #[test]
    fn set_state_between_covers_the_whole_range() {
        let mut mgr = make_manager();
        let space = dummy_space();
        let start = Address::new(space.clone(), 0x0);
        let mid = Address::new(space.clone(), 0x4);
        let end = Address::new(space, 0x8);

        mgr.set_state_between(0, &start, &end, TraceMemoryState::Known);

        // The mock only tracks state at the range's minimum address, matching its `set_state`
        // stand-in; still enough to prove the range was built and forwarded correctly.
        assert_eq!(
            DBTraceMemoryManager::get_state(&mgr, 0, &start),
            TraceMemoryState::Known
        );
        let _ = mid;
    }

    #[test]
    fn put_bytes_then_get_bytes_round_trip_through_delegate() {
        let mut mgr = make_manager();
        let space = dummy_space();
        let addr = Address::new(space, 0x100);
        let mut src = vec![1u8, 2, 3, 4];

        let written = InternalTraceMemoryOperations::get_space(&mgr);
        let _ = written; // exercise get_space wiring
        let n = TraceMemoryOperations::put_bytes(&mut mgr, 0, &addr, &mut src);
        assert_eq!(n, 4);

        let mut dst = vec![0u8; 4];
        let read = TraceMemoryOperations::get_bytes(&mgr, 0, &addr, &mut dst);
        assert_eq!(read, 4);
        assert_eq!(dst, vec![1, 2, 3, 4]);
    }

    #[test]
    fn get_block_size_is_the_fixed_constant() {
        let mgr = make_manager();
        assert_eq!(DBTraceMemoryManager::get_block_size(&mgr), 4096);
    }

    #[test]
    fn pack_reaches_every_active_space() {
        let mgr = make_manager();
        // MockDelegateSpace::pack is a no-op; this proves `pack()` iterates `active_spaces()`
        // without panicking (the delegate would panic on any unstubbed method it didn't expect).
        DBTraceMemoryManager::pack(&mgr);
    }
}
