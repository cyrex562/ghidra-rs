//! Port of `ghidra.trace.model.memory.TraceMemoryOperations`.
//!
//! Operations for mutating memory regions, values, and state within a trace.
//!
//! This models memory over the course of an arbitrary number of snaps. Observations of memory are
//! recorded with [`TraceMemoryOperations::put_bytes`] and retrieved with
//! [`TraceMemoryOperations::get_bytes`] and friends; an observed value is presumed unchanged until
//! another observation is made, so entries are extended into the future until they would collide
//! with another entry. Recording bytes implies [`TraceMemoryState::Known`] at the same location
//! and snap; a *missing* state entry is equivalent to [`TraceMemoryState::Unknown`] (see
//! [`TraceMemoryState::IMPLIED_BY_NULL`]).
//!
//! Negative snaps are "scratch space" and are not presumed to have any temporal relation to their
//! neighbors, so most-recent queries may decline to retrieve anything across them.
//!
//! Adaptations from a literal translation:
//!
//! - Java overloads `setState`/`getStates`/`getAddressesWithState`/`getMostRecentStates`/
//!   `getBufferAt` on their parameter types. Rust has no overloading, so each variant carries a
//!   suffix naming what distinguishes it (`set_state_at`, `set_state_between`, `set_state_over`,
//!   `get_addresses_with_state_in`, ...), the same convention
//!   [`DBTraceMemorySpace`](crate::trace::seam_stubs::DBTraceMemorySpace) and
//!   [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)
//!   already use for these very methods; the names here match theirs.
//! - The **register-taking overloads** (`setState(TracePlatform, long, Register, ...)`,
//!   `getValue`, `putBytes(TracePlatform, long, Register, ByteBuffer)`, ...) are *not* redeclared
//!   here. In Java they are abstract on this interface and implemented by
//!   `InternalTraceMemoryOperations`; Rust has no way for a subtrait to supply a supertrait
//!   method's body, so they live -- under the established `_on_platform` suffix -- on
//!   [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations),
//!   together with the host-platform convenience overloads that Java defaults onto them
//!   (`get_value`, `set_state_for_register`, ...). Keeping each Java method under exactly one Rust
//!   name across the crate matters more than which trait declares it, since two same-named
//!   members on a supertrait/subtrait pair silently cannot interoperate.
//! - `ByteBuffer` position/limit-bounded parameters become `&mut [u8]` slices (`&[u8]` where
//!   read-only), per
//!   [`MemBuffer`](crate::program::model::mem::MemBuffer)'s established convention. `findBytes`'s
//!   nullable `mask` becomes `Option<&[u8]>`.
//! - `ByteOrder` becomes a `big_endian: bool`, matching
//!   [`MemBuffer::is_big_endian`](crate::program::model::mem::MemBuffer::is_big_endian).
//! - `Entry<TraceAddressSnapRange, TraceMemoryState>` becomes a `(Box<dyn TraceAddressSnapRange>,
//!   TraceMemoryState)` pair, `Entry<Long, TraceMemoryState>` an `(i64, TraceMemoryState)` pair,
//!   and `Collection`/`Iterable` of entries a `Vec` of those pairs. Java methods returning a
//!   nullable entry return `Option`.
//! - `Predicate<TraceMemoryState>` becomes `&dyn Fn(TraceMemoryState) -> bool`. The nested Java
//!   enum `StatePredicate` (whose identity implementations exist so caching layers can recognize
//!   them, which lambdas defeat) is ported as the [`StatePredicate`] enum below.
//! - The static helpers `oneState` and `isStateEntirely` become the free functions [`one_state`]
//!   and [`is_state_entirely`], per the convention established by
//!   [`TraceSymbolManager`](crate::trace::model::symbol::trace_symbol_manager)'s
//!   `primality_compare` for static interface methods.

use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::mem::MemBuffer;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::util::task::TaskMonitor;

/// Checks whether `states` represents a single uniform state across `range`, returning `None` if
/// the entries disagree or don't fully cover `range`. An empty collection yields
/// [`TraceMemoryState::IMPLIED_BY_NULL`].
///
/// Every entry *must* intersect `range`, or the result is undefined; passing the same range that
/// produced `states` via [`TraceMemoryOperations::get_states`] satisfies that requirement.
///
/// Mirrors the static `TraceMemoryOperations.oneState(AddressRange, Collection)`. The Java loop
/// never advances its iterator (so it neither compares past the first entry nor terminates for
/// more than one entry); this port implements the evident intent: compare every entry's state
/// against the first, deleting each entry's range from what remains to be covered.
pub fn one_state(
    range: &AddressRange,
    states: &[(Box<dyn TraceAddressSnapRange>, TraceMemoryState)],
) -> Option<TraceMemoryState> {
    let mut iter = states.iter();
    let Some((first_range, first_state)) = iter.next() else {
        return Some(TraceMemoryState::IMPLIED_BY_NULL);
    };
    let mut remains = AddressSet::from_range(range.clone());
    remains.delete_range_object(&first_range.get_range());
    for (entry_range, state) in iter {
        if state != first_state {
            return None;
        }
        remains.delete_range_object(&entry_range.get_range());
    }
    if remains.is_empty() {
        Some(*first_state)
    } else {
        None
    }
}

/// Checks whether `state_entries` represents `state` across the whole of `range`. As a special
/// case, an empty collection matches iff `state` is [`TraceMemoryState::Unknown`].
///
/// Mirrors the static `TraceMemoryOperations.isStateEntirely(AddressRange, Collection,
/// TraceMemoryState)`.
pub fn is_state_entirely(
    range: &AddressRange,
    state_entries: &[(Box<dyn TraceAddressSnapRange>, TraceMemoryState)],
    state: TraceMemoryState,
) -> bool {
    one_state(range, state_entries) == Some(state)
}

/// Built-in predicates for filtering/testing state entries.
///
/// Port of the nested Java enum `TraceMemoryOperations.StatePredicate implements
/// Predicate<TraceMemoryState>`. Use of these built-ins over an ad-hoc closure is recommended for
/// two reasons: they handle the conventional cases (notably that a missing entry means
/// [`TraceMemoryState::Unknown`]), and caching implementations can recognize the identity of a
/// named predicate where they cannot recognize a closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatePredicate {
    /// Matches only [`TraceMemoryState::Known`].
    IsKnown,
    /// Matches only [`TraceMemoryState::Error`].
    IsError,
    /// Matches anything other than [`TraceMemoryState::Unknown`] (which is also what Java's
    /// `null` state means).
    IsKnownOrError,
}

impl StatePredicate {
    /// Tests `state` against this predicate. Mirrors `Predicate.test(TraceMemoryState)`.
    pub fn test(self, state: TraceMemoryState) -> bool {
        match self {
            StatePredicate::IsKnown => state == TraceMemoryState::Known,
            StatePredicate::IsError => state == TraceMemoryState::Error,
            StatePredicate::IsKnownOrError => !state.implied_by_null(),
        }
    }
}

/// Operations for mutating memory regions, values, and state within a trace.
///
/// Port of `ghidra.trace.model.memory.TraceMemoryOperations`. See the module documentation for
/// the overload-naming and ownership deviations from a literal translation, and for where the
/// register-taking overloads live.
pub trait TraceMemoryOperations: Send + Sync {
    /// Get the trace to which the memory manager belongs. Mirrors `getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace>;

    // ---- state ----

    /// Set the state of memory over a given time and address range. Mirrors `setState(long,
    /// AddressRange, TraceMemoryState)`.
    ///
    /// Setting [`TraceMemoryState::Known`] this way is not recommended; writing bytes updates the
    /// state automatically.
    fn set_state(&mut self, snap: i64, range: &AddressRange, state: TraceMemoryState);

    /// Set the state of memory at a single address. Mirrors `setState(long, Address,
    /// TraceMemoryState)`.
    fn set_state_at(&mut self, snap: i64, address: &Address, state: TraceMemoryState) {
        self.set_state(snap, &AddressRange::new(address.clone(), address.clone()), state);
    }

    /// Set the state of memory between two addresses, inclusive. Mirrors `setState(long, Address,
    /// Address, TraceMemoryState)`.
    fn set_state_between(
        &mut self,
        snap: i64,
        start: &Address,
        end: &Address,
        state: TraceMemoryState,
    ) {
        self.set_state(snap, &AddressRange::new(start.clone(), end.clone()), state);
    }

    /// Set the state of memory over a given time and address set. Mirrors `setState(long,
    /// AddressSetView, TraceMemoryState)`.
    fn set_state_over(&mut self, snap: i64, set: &dyn AddressSetView, state: TraceMemoryState) {
        for range in set.address_ranges() {
            self.set_state(snap, &range, state);
        }
    }

    /// Get the state of memory at a given snap and address. Mirrors `getState(long, Address)`.
    ///
    /// Where Java returns `null` for a location whose state was never set, this returns
    /// [`TraceMemoryState::Unknown`] -- the state that `null` implies (see
    /// [`TraceMemoryState::IMPLIED_BY_NULL`]).
    fn get_state(&self, snap: i64, address: &Address) -> TraceMemoryState;

    /// Get the state of memory at a given snap and address, following schedule forks, along with
    /// the snap at which it was found. Mirrors `getViewState(long, Address)`.
    fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState);

    /// Get the entry recording the most recent state at the given snap and address. Mirrors
    /// `getMostRecentStateEntry(long, Address)`.
    ///
    /// The entry may cover more addresses and snaps than requested. Its lifespan is the
    /// meaningful part: the lower bound is the snap the state actually took effect, and one past
    /// the upper bound is the next change.
    fn get_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Get the entry recording the most recent state at the given snap and address, following
    /// schedule forks. Mirrors `getViewMostRecentStateEntry(long, Address)`.
    fn get_view_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Get the entry recording the most recent state since the given snap within the given range
    /// that satisfies `predicate`, following schedule forks. Mirrors
    /// `getViewMostRecentStateEntry(long, AddressRange, Predicate<TraceMemoryState>)`.
    fn get_view_most_recent_state_entry_where(
        &self,
        snap: i64,
        range: &AddressRange,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Get at least the intersection of `set`'s addresses whose state at `snap` satisfies
    /// `predicate`. Mirrors `getAddressesWithState(long, AddressSetView,
    /// Predicate<TraceMemoryState>)`.
    fn get_addresses_with_state_at(
        &self,
        snap: i64,
        set: &dyn AddressSetView,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Box<dyn AddressSetView> {
        self.get_addresses_with_state_in(Lifespan::at(snap), set, predicate)
    }

    /// Get at least the intersection of `set`'s addresses whose state over `span` satisfies
    /// `predicate`. Mirrors `getAddressesWithState(Lifespan, AddressSetView,
    /// Predicate<TraceMemoryState>)`.
    ///
    /// The implementation may return a *larger* set than requested; within `set`, though, only
    /// ranges satisfying the predicate may be present. Intersect with `set` if a strict
    /// intersection is required. Because [`TraceMemoryState::Unknown`] is not stored explicitly,
    /// compute the unknown addresses by subtracting the [`StatePredicate::IsKnownOrError`] result
    /// from `set`.
    fn get_addresses_with_state_in(
        &self,
        span: Lifespan,
        set: &dyn AddressSetView,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Box<dyn AddressSetView>;

    /// Get the addresses whose state at `snap` satisfies `predicate`. Mirrors
    /// `getAddressesWithState(long, Predicate<TraceMemoryState>)`.
    ///
    /// The implementation may return a view that updates with changes. Behavior is not well
    /// defined for predicates testing for [`TraceMemoryState::Unknown`].
    fn get_addresses_with_state(
        &self,
        snap: i64,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Box<dyn AddressSetView>;

    /// Get the addresses whose state satisfies `predicate` at any time in `lifespan`. Mirrors
    /// `getAddressesWithState(Lifespan, Predicate<TraceMemoryState>)`.
    fn get_addresses_with_state_over(
        &self,
        lifespan: Lifespan,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Box<dyn AddressSetView>;

    /// Get all the entries covering the given range effective at the given snap. Mirrors
    /// `getStates(long, AddressRange)`.
    ///
    /// [`TraceMemoryState::Unknown`] entries do not appear; gaps in the result are implied to be
    /// unknown.
    fn get_states(
        &self,
        snap: i64,
        range: &AddressRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Check whether a range of addresses is entirely [`TraceMemoryState::Known`] at the given
    /// snap. Mirrors `isKnown(long, AddressRange)`.
    fn is_known(&self, snap: i64, range: &AddressRange) -> bool {
        is_state_entirely(range, &self.get_states(snap, range), TraceMemoryState::Known)
    }

    /// Get all the entries intersecting `within`, effective at or extending as "most recent" to
    /// its upper snap bound. Mirrors `getMostRecentStates(TraceAddressSnapRange)`.
    ///
    /// Here "most recent" means the latest state other than [`TraceMemoryState::Unknown`]. The
    /// returned entries *can* overlap: [`TraceMemoryState::Known`] entries may not overlap one
    /// another (they are split and truncated to extend as far into the future as possible without
    /// overlapping), but a [`TraceMemoryState::Error`] entry may overlap a *less* recent known
    /// entry -- so that the most-recent-known bytes are still obtainable after a failed read.
    fn get_most_recent_states(
        &self,
        within: &dyn TraceAddressSnapRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Get all the entries covering `range`, effective at or extending as "most recent" to `snap`.
    /// Mirrors `getMostRecentStates(long, AddressRange)`.
    ///
    /// Java defaults this onto [`Self::get_most_recent_states`] with a freshly constructed
    /// `ImmutableTraceAddressSnapRange(min, max, Long.MIN_VALUE, snap)`.
    /// [`ImmutableTraceAddressSnapRange`](crate::trace::model::immutable_trace_address_snap_range::ImmutableTraceAddressSnapRange)
    /// was a dependency-cycle cut-point and is ported as a trait with no canonical constructor, so
    /// -- exactly as for
    /// [`TraceAddressSnapRange::immutable`](crate::trace::model::trace_address_snap_range::TraceAddressSnapRange::immutable)
    /// -- this stays a required method rather than a default. Implementors should build that same
    /// `[min, max] x [i64::MIN, snap]` rectangle.
    fn get_most_recent_states_in(
        &self,
        snap: i64,
        range: &AddressRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    // ---- bytes ----

    /// Write `buf` at the given snap and address, returning the number of bytes written. Mirrors
    /// `putBytes(long, Address, ByteBuffer)`.
    ///
    /// The affected region also becomes [`TraceMemoryState::Known`], and the written bytes are
    /// assumed effective for all future snaps up to the next write.
    fn put_bytes(&mut self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Read the most recent bytes from the given snap and address into `buf`, returning the number
    /// of bytes read. Mirrors `getBytes(long, Address, ByteBuffer)`.
    ///
    /// Where memory has no defined value, the corresponding bytes of `buf` are unspecified: an
    /// implementation may leave them alone or zero them.
    fn get_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Read the most recent bytes from the given snap and address, following schedule forks.
    /// Mirrors `getViewBytes(long, Address, ByteBuffer)`.
    ///
    /// Unlike [`Self::get_bytes`], this checks for [`TraceMemoryState::Known`] among each involved
    /// snap range and prefers the most recent; where memory was never known, `buf` is left
    /// unmodified.
    fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Search `range` at `snap` for `data`, returning the minimum address of the match. Mirrors
    /// `findBytes(long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)`.
    ///
    /// `mask` is `None` for Java's `null`, i.e. match all bytes exactly. `forward` selects the
    /// lowest matching address rather than the highest.
    fn find_bytes(
        &self,
        snap: i64,
        range: &AddressRange,
        data: &[u8],
        mask: Option<&[u8]>,
        forward: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address>;

    /// Remove `len` bytes of observations from the given time and location. Mirrors
    /// `removeBytes(long, Address, int)`.
    ///
    /// Only observations made at *exactly* `snap` are removed; the affected region's state is
    /// deleted too (i.e. becomes [`TraceMemoryState::Unknown`]). Use is discouraged: the more
    /// observations follow the deleted one in the same range, the more expensive this is.
    fn remove_bytes(&mut self, snap: i64, start: &Address, len: i32);

    /// Get a view of a particular snap as a memory buffer. Mirrors `getBufferAt(long, Address,
    /// ByteOrder)`, with `big_endian` standing in for the `ByteOrder`.
    ///
    /// The bytes read by this buffer are the most recent bytes written before `snap`.
    fn get_buffer_at(&self, snap: i64, start: &Address, big_endian: bool) -> Box<dyn MemBuffer>;

    /// Get a view of a particular snap as a memory buffer, using the base language's byte order.
    /// Mirrors `getBufferAt(long, Address)`.
    fn get_buffer_at_base_order(&self, snap: i64, start: &Address) -> Box<dyn MemBuffer> {
        let big_endian = self.get_trace().get_base_language().is_big_endian();
        self.get_buffer_at(snap, start, big_endian)
    }

    // ---- storage ----

    /// Find the internal storage block that most-recently defines the value at the given snap and
    /// address, and return that block's snap. Mirrors `getSnapOfMostRecentChangeToBlock(long,
    /// Address)`.
    ///
    /// This exposes part of the internal storage so clients can optimize difference computations
    /// by eliminating ranges defined by the same block. Implementations that cannot answer return
    /// the given snap; `None` reports that no block defines the location.
    fn get_snap_of_most_recent_change_to_block(&self, snap: i64, address: &Address) -> Option<i64>;

    /// The block size used by internal storage, or 0 if the implementation cannot answer. Mirrors
    /// `getBlockSize()`.
    fn get_block_size(&self) -> i32;

    /// Optimize storage space -- clean up garbage, apply compression, and so on. Mirrors `pack()`.
    ///
    /// Trace memory is often sparse and therefore compressible, and observations are rarely
    /// modified or deleted, so packing is recommended whenever the trace is saved to disk.
    fn pack(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// A bare [`TraceAddressSnapRange`] carrying only an X-axis range and a lifespan.
    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        lifespan: Lifespan,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Lifespan {
            self.lifespan
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
                lifespan: Lifespan::span(y1, y2),
            })
        }
    }

    fn entry(
        space: &Arc<AddressSpace>,
        min: i64,
        max: i64,
        state: TraceMemoryState,
    ) -> (Box<dyn TraceAddressSnapRange>, TraceMemoryState) {
        (
            Box::new(MockRange {
                range: AddressRange::new(addr(space, min), addr(space, max)),
                lifespan: Lifespan::ALL,
            }),
            state,
        )
    }

    /// A single-space, in-memory implementor storing one state per address offset, enough to
    /// exercise this trait's defaults (`set_state_at`/`set_state_between`/`set_state_over`,
    /// `is_known`, `get_addresses_with_state_at`) against real behavior. Records the lifespan of
    /// the last `get_addresses_with_state_in` call so the snap-taking default's translation can be
    /// checked.
    struct MockMemory {
        space: Arc<AddressSpace>,
        states: BTreeMap<i64, TraceMemoryState>,
        last_span: Mutex<Option<Lifespan>>,
    }

    impl MockMemory {
        fn new() -> Self {
            MockMemory {
                space: ram_space(),
                states: BTreeMap::new(),
                last_span: Mutex::new(None),
            }
        }
    }

    impl TraceMemoryOperations for MockMemory {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by these tests")
        }

        fn set_state(&mut self, _snap: i64, range: &AddressRange, state: TraceMemoryState) {
            let min = range.min_address().offset();
            let max = range.max_address().offset();
            for offset in min..=max {
                if state.implied_by_null() {
                    self.states.remove(&offset);
                } else {
                    self.states.insert(offset, state);
                }
            }
        }

        fn get_state(&self, _snap: i64, address: &Address) -> TraceMemoryState {
            TraceMemoryState::or_implied(self.states.get(&address.offset()).copied())
        }

        fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState) {
            (snap, self.get_state(snap, address))
        }

        fn get_most_recent_state_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by these tests")
        }

        fn get_view_most_recent_state_entry(
            &self,
            _snap: i64,
            _address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by these tests")
        }

        fn get_view_most_recent_state_entry_where(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by these tests")
        }

        fn get_addresses_with_state_in(
            &self,
            span: Lifespan,
            set: &dyn AddressSetView,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            *self.last_span.lock().unwrap() = Some(span);
            let mut result = AddressSet::new();
            for (&offset, &state) in self.states.iter() {
                let address = addr(&self.space, offset);
                if set.contains(&address) && predicate(state) {
                    result.add_address(&address);
                }
            }
            Box::new(result)
        }

        fn get_addresses_with_state(
            &self,
            snap: i64,
            predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            let all = AddressSet::from_start_end(
                addr(&self.space, 0),
                addr(&self.space, i32::MAX as i64),
            );
            self.get_addresses_with_state_at(snap, &all, predicate)
        }

        fn get_addresses_with_state_over(
            &self,
            _lifespan: Lifespan,
            _predicate: &dyn Fn(TraceMemoryState) -> bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by these tests")
        }

        fn get_states(
            &self,
            _snap: i64,
            range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            let mut result: Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> = Vec::new();
            let min = range.min_address().offset();
            let max = range.max_address().offset();
            for (&offset, &state) in self.states.range(min..=max) {
                result.push(entry(&self.space, offset, offset, state));
            }
            result
        }

        fn get_most_recent_states(
            &self,
            _within: &dyn TraceAddressSnapRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            unimplemented!("not exercised by these tests")
        }

        fn get_most_recent_states_in(
            &self,
            snap: i64,
            range: &AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)> {
            let within = MockRange {
                range: range.clone(),
                lifespan: Lifespan::span(i64::MIN, snap),
            };
            self.get_most_recent_states(&within)
        }

        fn put_bytes(&mut self, _snap: i64, _start: &Address, _buf: &mut [u8]) -> i32 {
            unimplemented!("not exercised by these tests")
        }

        fn get_bytes(&self, _snap: i64, _start: &Address, _buf: &mut [u8]) -> i32 {
            unimplemented!("not exercised by these tests")
        }

        fn get_view_bytes(&self, _snap: i64, _start: &Address, _buf: &mut [u8]) -> i32 {
            unimplemented!("not exercised by these tests")
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
            unimplemented!("not exercised by these tests")
        }

        fn remove_bytes(&mut self, _snap: i64, _start: &Address, _len: i32) {
            unimplemented!("not exercised by these tests")
        }

        fn get_buffer_at(
            &self,
            _snap: i64,
            _start: &Address,
            _big_endian: bool,
        ) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }

        fn get_snap_of_most_recent_change_to_block(
            &self,
            snap: i64,
            _address: &Address,
        ) -> Option<i64> {
            Some(snap)
        }

        fn get_block_size(&self) -> i32 {
            0
        }

        fn pack(&mut self) {}
    }

    // --- one_state / is_state_entirely ---

    #[test]
    fn one_state_of_no_entries_is_the_state_null_implies() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));
        assert_eq!(one_state(&range, &[]), Some(TraceMemoryState::Unknown));
    }

    #[test]
    fn one_state_needs_full_coverage_and_agreement() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));

        let covered = [entry(&space, 0, 10, TraceMemoryState::Known)];
        assert_eq!(one_state(&range, &covered), Some(TraceMemoryState::Known));

        let partial = [entry(&space, 0, 4, TraceMemoryState::Known)];
        assert_eq!(one_state(&range, &partial), None);

        let disagreeing = [
            entry(&space, 0, 4, TraceMemoryState::Known),
            entry(&space, 5, 10, TraceMemoryState::Error),
        ];
        assert_eq!(one_state(&range, &disagreeing), None);
    }

    #[test]
    fn is_state_entirely_matches_unknown_for_an_empty_collection() {
        let space = ram_space();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 10));

        assert!(is_state_entirely(&range, &[], TraceMemoryState::Unknown));
        assert!(!is_state_entirely(&range, &[], TraceMemoryState::Known));

        let known = [entry(&space, 0, 10, TraceMemoryState::Known)];
        assert!(is_state_entirely(&range, &known, TraceMemoryState::Known));
        assert!(!is_state_entirely(&range, &known, TraceMemoryState::Error));
    }

    // --- StatePredicate ---

    #[test]
    fn state_predicates_match_the_java_enum_bodies() {
        assert!(StatePredicate::IsKnown.test(TraceMemoryState::Known));
        assert!(!StatePredicate::IsKnown.test(TraceMemoryState::Error));
        assert!(!StatePredicate::IsKnown.test(TraceMemoryState::Unknown));

        assert!(StatePredicate::IsError.test(TraceMemoryState::Error));
        assert!(!StatePredicate::IsError.test(TraceMemoryState::Known));

        assert!(StatePredicate::IsKnownOrError.test(TraceMemoryState::Known));
        assert!(StatePredicate::IsKnownOrError.test(TraceMemoryState::Error));
        assert!(
            !StatePredicate::IsKnownOrError.test(TraceMemoryState::Unknown),
            "Java's IS_KNOWN_OR_ERROR rejects both null and UNKNOWN"
        );
    }

    // --- trait defaults ---

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn TraceMemoryOperations) {}
        assert_object_safe(&MockMemory::new());
    }

    #[test]
    fn set_state_at_affects_exactly_one_address() {
        let mut mem = MockMemory::new();
        let space = mem.space.clone();

        mem.set_state_at(0, &addr(&space, 0x10), TraceMemoryState::Known);

        assert_eq!(mem.get_state(0, &addr(&space, 0x10)), TraceMemoryState::Known);
        assert_eq!(mem.get_state(0, &addr(&space, 0x11)), TraceMemoryState::Unknown);
    }

    #[test]
    fn set_state_between_covers_the_inclusive_range() {
        let mut mem = MockMemory::new();
        let space = mem.space.clone();

        mem.set_state_between(
            0,
            &addr(&space, 0x10),
            &addr(&space, 0x12),
            TraceMemoryState::Error,
        );

        for offset in 0x10..=0x12 {
            assert_eq!(mem.get_state(0, &addr(&space, offset)), TraceMemoryState::Error);
        }
        assert_eq!(mem.get_state(0, &addr(&space, 0x13)), TraceMemoryState::Unknown);
    }

    #[test]
    fn set_state_over_visits_every_range_of_the_set() {
        let mut mem = MockMemory::new();
        let space = mem.space.clone();
        let mut set = AddressSet::new();
        set.add_range(&addr(&space, 0), &addr(&space, 1));
        set.add_range(&addr(&space, 8), &addr(&space, 9));

        mem.set_state_over(0, &set, TraceMemoryState::Known);

        assert_eq!(mem.get_state(0, &addr(&space, 1)), TraceMemoryState::Known);
        assert_eq!(mem.get_state(0, &addr(&space, 4)), TraceMemoryState::Unknown);
        assert_eq!(mem.get_state(0, &addr(&space, 8)), TraceMemoryState::Known);
    }

    #[test]
    fn is_known_requires_the_whole_range_to_be_known() {
        let mut mem = MockMemory::new();
        let space = mem.space.clone();
        let range = AddressRange::new(addr(&space, 0), addr(&space, 3));

        assert!(!mem.is_known(0, &range), "nothing observed yet");

        mem.set_state_between(0, &addr(&space, 0), &addr(&space, 2), TraceMemoryState::Known);
        assert!(!mem.is_known(0, &range), "address 3 is still unknown");

        mem.set_state_at(0, &addr(&space, 3), TraceMemoryState::Known);
        assert!(mem.is_known(0, &range));

        mem.set_state_at(0, &addr(&space, 3), TraceMemoryState::Error);
        assert!(!mem.is_known(0, &range), "a differing state breaks uniformity");
    }

    #[test]
    fn get_addresses_with_state_at_a_snap_queries_that_single_snap() {
        let mut mem = MockMemory::new();
        let space = mem.space.clone();
        mem.set_state_at(7, &addr(&space, 0x20), TraceMemoryState::Known);
        mem.set_state_at(7, &addr(&space, 0x21), TraceMemoryState::Error);
        let mut set = AddressSet::new();
        set.add_range(&addr(&space, 0), &addr(&space, 0xFF));

        let known = mem.get_addresses_with_state_at(7, &set, &|s| StatePredicate::IsKnown.test(s));

        assert_eq!(
            *mem.last_span.lock().unwrap(),
            Some(Lifespan::at(7)),
            "the snap-taking overload delegates with Lifespan.at(snap)"
        );
        assert!(known.contains(&addr(&space, 0x20)));
        assert!(!known.contains(&addr(&space, 0x21)));

        let known_or_error =
            mem.get_addresses_with_state_at(7, &set, &|s| StatePredicate::IsKnownOrError.test(s));
        assert!(known_or_error.contains(&addr(&space, 0x21)));
    }
}
