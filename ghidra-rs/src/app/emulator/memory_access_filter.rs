//! Port of `ghidra.app.emulator.MemoryAccessFilter`.
//!
//! A means of intercepting and/or modifying the emulator's memory access.
//!
//! Several of these filters may be chained together, each being invoked in the reverse of the
//! order added. In this way, the first added gets the "final say," but it also is farthest from
//! the original request.
//!
//! # Shape
//!
//! Java's class forms an intrusive doubly-linked chain (`prevFilter`/`nextFilter` fields declared
//! directly on each filter instance), spliced together by `addFilter`/`dispose` and anchored at
//! the head by `FilteredMemoryState.setFilter`. Representing that as `Rc<RefCell<dyn
//! MemoryAccessFilter>>` nodes would invite exactly the shared-mutable-graph idiom this crate's
//! `OWNERSHIP_MIGRATION.md` steers away from; since this is a small, closed, arena-shaped graph (a
//! chain, not an open type hierarchy), it is ported as an arena + typed ID instead, per that
//! document's convention: [`MemoryAccessFilterChain`] owns every filter node (`prev`/`next` links,
//! the `filterOnExecutionOnly` flag, and a boxed [`MemoryAccessFilterCallbacks`] standing in for
//! the abstract `processRead`/`processWrite` overrides a Java subclass would supply), and callers
//! hold a `Copy` [`MemoryAccessFilterId`] rather than a shared, aliasable reference to the filter
//! itself.
//!
//! `Emulator`/`FilteredMemoryState` (the `emu` field and `addFilter(Emulator)`'s registration
//! step) are not threaded through here:
//! [`Emulator::add_memory_access_filter`](crate::app::emulator::Emulator::add_memory_access_filter)
//! and [`FilteredMemoryState`](crate::app::seam_stubs::FilteredMemoryState) currently treat
//! filters as an opaque `Box<dyn` [`MemoryAccessFilter`](crate::app::seam_stubs::MemoryAccessFilter)
//! `>` marker (see that trait's own docs), and retrofitting them to hold a chain-aware type is out
//! of scope for this port -- the same "don't retrofit an already-committed trait" call
//! [`AbstractMemoryState`](crate::pcode::memstate::AbstractMemoryState) made for its own analogous
//! situation. Instead, [`MemoryAccessFilterChain::filter_read`]/
//! [`filter_write`](MemoryAccessFilterChain::filter_write) take the emulator's `is_executing`
//! state as a plain `bool` parameter, standing in for Java's `emu.isExecuting()` call -- a
//! `FilteredMemoryState` implementation that embeds a `MemoryAccessFilterChain` supplies that bit
//! itself when calling in.
//!
//! # Deprecation
//!
//! Deprecated since Ghidra 12.1 and scheduled for removal: `Please use PcodeEmulator instead. For
//! similar callbacks, see PcodeEmulationCallbacks`.

use std::sync::Arc;

use slotmap::{new_key_type, SlotMap};

use crate::program::model::address::AddressSpace;

new_key_type! {
    /// A `Copy` handle to one filter registered within a [`MemoryAccessFilterChain`]. Cheap to
    /// pass around and store -- the chain is the only owner of the real filter data. Only
    /// meaningful against the `MemoryAccessFilterChain` that minted it.
    pub struct MemoryAccessFilterId;
}

/// The behavior a memory access filter supplies: hooks invoked after a read or write.
///
/// Mirrors the two abstract methods `MemoryAccessFilter.processRead`/`processWrite`, the concrete
/// behavior a Java subclass would override.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub trait MemoryAccessFilterCallbacks: Send + Sync {
    /// Invoked after a read.
    ///
    /// * `spc` - the space read from
    /// * `off` - the offset within the space
    /// * `size` - the number of bytes read
    /// * `values` - the bytes read
    ///
    /// Mirrors the protected abstract `processRead(AddressSpace, long, int, byte[])`.
    fn process_read(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32, values: &mut [u8]);

    /// Invoked *after* a write.
    ///
    /// * `spc` - the space written to
    /// * `off` - the offset within the space
    /// * `size` - the number of bytes written
    /// * `values` - the bytes written
    ///
    /// Mirrors the protected abstract `processWrite(AddressSpace, long, int, byte[])`.
    fn process_write(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32, values: &mut [u8]);
}

#[allow(deprecated)]
struct FilterNode {
    callbacks: Box<dyn MemoryAccessFilterCallbacks>,
    filter_on_execution_only: bool,
    prev: Option<MemoryAccessFilterId>,
    next: Option<MemoryAccessFilterId>,
}

/// Owns a chain of memory access filters, mirroring the intrusive linked structure Java's
/// `MemoryAccessFilter` instances form among themselves. See the module docs for the full
/// composition rationale.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[allow(deprecated)]
pub struct MemoryAccessFilterChain {
    filters: SlotMap<MemoryAccessFilterId, FilterNode>,
    /// The most-recently-added filter -- the first one invoked. Mirrors what
    /// `FilteredMemoryState.setFilter` would store as its own head reference.
    head: Option<MemoryAccessFilterId>,
}

#[allow(deprecated)]
impl MemoryAccessFilterChain {
    /// Creates an empty filter chain.
    pub fn new() -> Self {
        Self { filters: SlotMap::with_key(), head: None }
    }

    /// Registers a new filter, making it the new head of the chain -- it will be invoked *first*,
    /// ahead of every filter already registered (see the struct's own docs on ordering).
    ///
    /// Mirrors `addFilter(Emulator emu)`, minus the `Emulator`/`FilteredMemoryState` registration
    /// plumbing (see the module docs). `filter_on_execution_only` starts `true`, mirroring the
    /// Java field's default.
    pub fn add_filter(&mut self, callbacks: Box<dyn MemoryAccessFilterCallbacks>) -> MemoryAccessFilterId {
        let id = self.filters.insert(FilterNode {
            callbacks,
            filter_on_execution_only: true,
            prev: None,
            next: self.head,
        });
        if let Some(old_head) = self.head {
            self.filters[old_head].prev = Some(id);
        }
        self.head = Some(id);
        id
    }

    /// Dispose the given filter, unlinking it from the chain.
    ///
    /// Mirrors `dispose()`.
    ///
    /// # Panics
    /// Panics if `id` does not belong to this chain (already disposed, or minted by a different
    /// chain) -- mirroring the Java `NullPointerException` that would result from splicing
    /// against a stale/foreign filter's `prevFilter`/`nextFilter` fields.
    pub fn dispose(&mut self, id: MemoryAccessFilterId) {
        let node =
            self.filters.remove(id).expect("dispose: filter is not registered in this chain");
        if let Some(next) = node.next {
            self.filters[next].prev = node.prev;
        }
        if let Some(prev) = node.prev {
            self.filters[prev].next = node.next;
        } else {
            self.head = node.next;
        }
    }

    /// Mirrors `filterOnExecutionOnly()`.
    ///
    /// # Panics
    /// Panics if `id` is not registered in this chain.
    pub fn filter_on_execution_only(&self, id: MemoryAccessFilterId) -> bool {
        self.filters[id].filter_on_execution_only
    }

    /// Mirrors `setFilterOnExecutionOnly(boolean)`.
    ///
    /// # Panics
    /// Panics if `id` is not registered in this chain.
    pub fn set_filter_on_execution_only(
        &mut self,
        id: MemoryAccessFilterId,
        filter_on_execution_only: bool,
    ) {
        self.filters[id].filter_on_execution_only = filter_on_execution_only;
    }

    /// Invoke every filter's [`process_read`](MemoryAccessFilterCallbacks::process_read) hook, in
    /// most-recently-added-first order.
    ///
    /// `is_executing` stands in for Java's `emu.isExecuting()` (see the module docs).
    ///
    /// Mirrors the package-private final `filterRead(AddressSpace, long, int, byte[])`.
    ///
    /// # Preserved quirk: a skipped filter short-circuits the rest of the chain
    /// Java's `filterRead` returns immediately -- without invoking `processRead` *or* recursing
    /// into `nextFilter` -- whenever `filterOnExecutionOnly() && !emu.isExecuting()` for the
    /// *current* filter. This means the first filter in the chain to fail that check stops every
    /// filter after it from being invoked too, not merely itself. Reproduced here as-is via the
    /// same early loop exit, rather than "fixed" to only skip the individual filter that opted
    /// out.
    pub fn filter_read(
        &mut self,
        is_executing: bool,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        values: &mut [u8],
    ) {
        let mut cur = self.head;
        while let Some(id) = cur {
            let node = self.filters.get_mut(id).expect("chain link points to a live node");
            if node.filter_on_execution_only && !is_executing {
                // Do not filter idle queries -- and (per the preserved quirk above) do not visit
                // any filter further down the chain either.
                return;
            }
            node.callbacks.process_read(spc, off, size, values);
            cur = node.next;
        }
    }

    /// Invoke every filter's [`process_write`](MemoryAccessFilterCallbacks::process_write) hook,
    /// in most-recently-added-first order.
    ///
    /// Mirrors the package-private final `filterWrite(AddressSpace, long, int, byte[])`. See
    /// [`filter_read`](Self::filter_read)'s own docs for the preserved short-circuit quirk, which
    /// applies identically here.
    pub fn filter_write(
        &mut self,
        is_executing: bool,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        values: &mut [u8],
    ) {
        let mut cur = self.head;
        while let Some(id) = cur {
            let node = self.filters.get_mut(id).expect("chain link points to a live node");
            if node.filter_on_execution_only && !is_executing {
                return;
            }
            node.callbacks.process_write(spc, off, size, values);
            cur = node.next;
        }
    }
}

#[allow(deprecated)]
impl Default for MemoryAccessFilterChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use std::sync::Mutex;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// Records every `process_read`/`process_write` call it receives (by a caller-supplied tag),
    /// and optionally mutates the byte buffer so tests can observe filters actually running.
    struct RecordingFilter {
        tag: &'static str,
        log: std::sync::Arc<Mutex<Vec<&'static str>>>,
    }

    #[allow(deprecated)]
    impl MemoryAccessFilterCallbacks for RecordingFilter {
        fn process_read(&mut self, _spc: &Arc<AddressSpace>, _off: i64, _size: i32, values: &mut [u8]) {
            self.log.lock().unwrap().push(self.tag);
            if !values.is_empty() {
                values[0] = values[0].wrapping_add(1);
            }
        }
        fn process_write(&mut self, _spc: &Arc<AddressSpace>, _off: i64, _size: i32, _values: &mut [u8]) {
            self.log.lock().unwrap().push(self.tag);
        }
    }

    #[test]
    fn filters_are_invoked_most_recently_added_first() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        chain.add_filter(Box::new(RecordingFilter { tag: "first", log: log.clone() }));
        chain.add_filter(Box::new(RecordingFilter { tag: "second", log: log.clone() }));
        chain.add_filter(Box::new(RecordingFilter { tag: "third", log: log.clone() }));

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(true, &space, 0, 4, &mut values);

        // "third" was added last, so it gets the "final say" farthest from the original request
        // -- meaning it's actually invoked *first* here, per the class's own doc comment.
        assert_eq!(*log.lock().unwrap(), vec!["third", "second", "first"]);
    }

    #[test]
    fn filter_on_execution_only_true_by_default_skips_when_not_executing() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let id = chain.add_filter(Box::new(RecordingFilter { tag: "f", log: log.clone() }));
        assert!(chain.filter_on_execution_only(id));

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(false, &space, 0, 4, &mut values);
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn filter_on_execution_only_false_still_runs_when_not_executing() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let id = chain.add_filter(Box::new(RecordingFilter { tag: "f", log: log.clone() }));
        chain.set_filter_on_execution_only(id, false);

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(false, &space, 0, 4, &mut values);
        assert_eq!(*log.lock().unwrap(), vec!["f"]);
    }

    /// Preserved quirk (see `filter_read`'s own docs): when the *first* filter in the chain opts
    /// out of idle queries, every filter after it is skipped too -- not just that one filter.
    #[test]
    fn a_skipped_head_filter_short_circuits_the_rest_of_the_chain() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        // Added first, so it ends up farthest from the head (invoked last, if reached at all).
        let always_runs = chain.add_filter(Box::new(RecordingFilter { tag: "always", log: log.clone() }));
        chain.set_filter_on_execution_only(always_runs, false);
        // Added last, so it's the head (invoked first) and defaults to execution-only.
        chain.add_filter(Box::new(RecordingFilter { tag: "execution-only-head", log: log.clone() }));

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(false, &space, 0, 4, &mut values);

        // Even though "always" itself doesn't care about execution state, it's never reached: the
        // head filter's early return stops the whole chain.
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn process_read_can_observe_and_mutate_the_byte_buffer() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        chain.add_filter(Box::new(RecordingFilter { tag: "f", log }));

        let space = ram_space();
        let mut values = [10u8, 20, 30];
        chain.filter_read(true, &space, 0, 3, &mut values);
        assert_eq!(values, [11, 20, 30]);
    }

    #[test]
    fn dispose_removes_a_middle_filter_and_relinks_its_neighbors() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        chain.add_filter(Box::new(RecordingFilter { tag: "first", log: log.clone() }));
        let middle = chain.add_filter(Box::new(RecordingFilter { tag: "second", log: log.clone() }));
        chain.add_filter(Box::new(RecordingFilter { tag: "third", log: log.clone() }));

        chain.dispose(middle);

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(true, &space, 0, 4, &mut values);
        assert_eq!(*log.lock().unwrap(), vec!["third", "first"]);
    }

    #[test]
    fn dispose_the_head_promotes_the_next_filter_to_head() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        chain.add_filter(Box::new(RecordingFilter { tag: "first", log: log.clone() }));
        let head = chain.add_filter(Box::new(RecordingFilter { tag: "second", log: log.clone() }));

        chain.dispose(head);

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(true, &space, 0, 4, &mut values);
        assert_eq!(*log.lock().unwrap(), vec!["first"]);
    }

    #[test]
    fn dispose_the_only_filter_empties_the_chain() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let id = chain.add_filter(Box::new(RecordingFilter { tag: "only", log: log.clone() }));
        chain.dispose(id);

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_read(true, &space, 0, 4, &mut values);
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    #[should_panic(expected = "dispose: filter is not registered in this chain")]
    fn disposing_an_unregistered_filter_panics() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        let id = chain.add_filter(Box::new(RecordingFilter { tag: "only", log }));
        chain.dispose(id);
        chain.dispose(id);
    }

    #[test]
    fn filter_write_also_respects_ordering_and_execution_gate() {
        let mut chain = MemoryAccessFilterChain::new();
        let log = std::sync::Arc::new(Mutex::new(Vec::new()));
        chain.add_filter(Box::new(RecordingFilter { tag: "first", log: log.clone() }));
        chain.add_filter(Box::new(RecordingFilter { tag: "second", log: log.clone() }));

        let space = ram_space();
        let mut values = [0u8; 4];
        chain.filter_write(true, &space, 0, 4, &mut values);
        assert_eq!(*log.lock().unwrap(), vec!["second", "first"]);
    }

    #[test]
    fn default_matches_new() {
        let chain = MemoryAccessFilterChain::default();
        assert!(chain.head.is_none());
    }
}
