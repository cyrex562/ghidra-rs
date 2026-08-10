//! Port of `ghidra.trace.database.listing.DBTraceCodeSpace`.
//!
//! A space managed by the `DBTraceCodeManager`. It was selected as a dependency-cycle
//! cut-point, and this port promotes the minimal marker previously stubbed in
//! [`seam_stubs`](crate::trace::seam_stubs) (only a bare `get_address_space`/panicking
//! `get_trace`/`get_thread` -- see those methods' docs below for why they keep panicking
//! defaults).
//!
//! The Java class formally `implements TraceCodeSpace, DBTraceSpaceBased`. Neither is declared
//! as a Rust supertrait here:
//! - [`TraceCodeSpace`](crate::trace::model::listing::trace_code_space::TraceCodeSpace) (via its
//!   `TraceCodeOperations` supertrait) requires six view accessors with no defaults, each
//!   returning the *model*-level view traits (`TraceCodeUnitsView`, etc). This class's own
//!   accessors of the same name instead return the more specific database-level view types
//!   (`DBTraceCodeUnitsView`, etc), the same covariant-narrowing conflict already documented on
//!   [`AbstractDBTraceCodeUnit::get_trace`](crate::trace::database::listing::abstract_db_trace_code_unit::AbstractDBTraceCodeUnit::get_trace).
//!   Following that precedent, this trait simply declares its own identically-named methods
//!   rather than the supertrait; a type implementing both must disambiguate with UFCS.
//! - [`DBTraceSpaceBased`](crate::trace::database::space::db_trace_space_based::DBTraceSpaceBased)
//!   (via `TraceSpaceMixin`) requires a `trace_register_utils` accessor and an `&mut self`
//!   `invalidate_cache`, neither of which this class's two existing marker implementors (in
//!   [`AbstractDBTraceCodeUnit`](crate::trace::database::listing::abstract_db_trace_code_unit)'s
//!   and
//!   [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view)'s
//!   tests) supply. Requiring it now would break those tests for no benefit yet, so -- as with
//!   `TraceCodeSpace` above -- this trait declares its own `invalidate_cache(&self)` (matching
//!   the real class's lock-guarded, interior-mutable implementation) instead of the supertrait.
//!
//! [`Self::clear_platform`] and [`Self::bytes_changed`] mirror real, non-trivial methods
//! (`clearPlatform`/`bytesChanged`), but their bodies traverse the raw
//! `DBTraceAddressSnapRangePropertyMapSpace`-backed storage directly (chunked iteration, per-unit
//! `platform`/`getDataType()` checks, `unitRemoved` bookkeeping) rather than through any
//! currently-ported or object-safe view API. Like `AbstractDBTraceCodeUnit`'s `byteCache` (see
//! that module's docs), that traversal is this class's *implementation*, not additional public
//! surface reachable through other trait methods -- so both are declared here (for signature
//! fidelity) but left for a concrete implementation to supply, defaulting to panicking.
//!
//! The constructor and its six `createXxxView` factory methods are not reproduced: Rust traits
//! have no constructors, and the factory methods exist only to be overridden by the constructor
//! itself (there are no other callers).

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::trace::database::listing::db_trace_defined_units_view::DBTraceDefinedUnitsView;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::model::thread::TraceThread;
use crate::trace::seam_stubs::{
    DBTrace, DBTraceCodeUnitsView, DBTraceDataView, DBTraceDefinedDataView, DBTraceGuestPlatform,
    DBTraceInstructionsView, DBTraceUndefinedDataView,
};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A space managed by the `DBTraceCodeManager`.
///
/// Port of `ghidra.trace.database.listing.DBTraceCodeSpace`.
///
/// See the module documentation for the object-safety-driven deviations from a literal
/// translation.
pub trait DBTraceCodeSpace: Send + Sync {
    /// The address space this code space is bound to. Mirrors the constructor-injected `space`
    /// field / `DBTraceCodeSpace.getAddressSpace()`.
    fn get_address_space(&self) -> Arc<AddressSpace>;

    /// Mirrors the covariantly-narrowed `DBTraceCodeSpace.getTrace()` (the `trace` field's
    /// getter), which narrows the inherited `TraceSpaceMixin.getTrace()`'s `Trace` return type to
    /// `DBTrace`.
    ///
    /// Defaults to panicking, matching this trait's established growth convention (inherited
    /// from the placeholder it replaces) for members not yet needed by any existing implementor,
    /// so those implementors keep compiling unchanged.
    fn get_trace(&self) -> Box<dyn DBTrace> {
        unimplemented!("DBTraceCodeSpace::get_trace not overridden")
    }

    /// Mirrors `DBTraceCodeSpace.getThread()` (inherited from `TraceSpaceMixin`; always `None`
    /// for a plain memory-address code space).
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn get_thread(&self) -> Box<dyn TraceThread> {
        unimplemented!("DBTraceCodeSpace::get_thread not overridden")
    }

    /// The composed view over every kind of unit (instructions, defined data, undefined data).
    /// Mirrors the `codeUnits` field accessor.
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn code_units(&self) -> Box<dyn DBTraceCodeUnitsView> {
        unimplemented!("DBTraceCodeSpace::code_units not overridden")
    }

    /// The instructions view. Mirrors the `instructions` field accessor.
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn instructions(&self) -> Box<dyn DBTraceInstructionsView> {
        unimplemented!("DBTraceCodeSpace::instructions not overridden")
    }

    /// The composed view over both defined and undefined data. Mirrors the `data` field
    /// accessor.
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn data(&self) -> Box<dyn DBTraceDataView> {
        unimplemented!("DBTraceCodeSpace::data not overridden")
    }

    /// The defined-data view. Mirrors the `definedData` field accessor.
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn defined_data(&self) -> Box<dyn DBTraceDefinedDataView> {
        unimplemented!("DBTraceCodeSpace::defined_data not overridden")
    }

    /// The undefined-data view. Mirrors the `undefinedData` field accessor.
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn undefined_data(&self) -> Box<dyn DBTraceUndefinedDataView> {
        unimplemented!("DBTraceCodeSpace::undefined_data not overridden")
    }

    /// The composed view over both instructions and defined data. Mirrors the `definedUnits`
    /// field accessor.
    ///
    /// Defaults to panicking; see [`Self::get_trace`]'s docs for why.
    fn defined_units(&self) -> Box<dyn DBTraceDefinedUnitsView> {
        unimplemented!("DBTraceCodeSpace::defined_units not overridden")
    }

    /// Invalidates every per-kind view's cache. Mirrors `DBTraceCodeSpace.invalidateCache()`,
    /// minus the two raw map-space invalidations (`instructionMapSpace`/`dataMapSpace`), which
    /// aren't part of this trait's object-safe surface -- see the module documentation.
    ///
    /// A real lock-guarded implementation should still wrap this in its write lock, matching the
    /// Java method's `try (LockHold hold = LockHold.lock(lock.writeLock()))`; that's left to the
    /// implementor since this trait doesn't carry a lock of its own.
    fn invalidate_cache(&self) {
        self.instructions().invalidate_cache();
        self.defined_data().invalidate_cache();
        self.undefined_data().invalidate_cache();
    }

    /// Clear all units belonging to the given guest platform, within `range` during `span`.
    /// Mirrors the package-visible `clearPlatform(Lifespan, AddressRange, DBTraceGuestPlatform,
    /// TaskMonitor)`.
    ///
    /// Left unimplemented; see the module documentation for why the real chunked-traversal
    /// algorithm isn't reproduced here.
    fn clear_platform(
        &self,
        _span: Lifespan,
        _range: &AddressRange,
        _guest: &dyn DBTraceGuestPlatform,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        unimplemented!("DBTraceCodeSpace::clear_platform not overridden")
    }

    /// Notify this space that some bytes changed, so that any affected unit(s) can be truncated,
    /// deleted, and/or replaced. Mirrors `DBTraceCodeSpace.bytesChanged(Set<TraceAddressSnapRange>,
    /// long, Address, byte[], byte[])`.
    ///
    /// Left unimplemented; see the module documentation for why the real affected-unit traversal
    /// isn't reproduced here.
    fn bytes_changed(
        &self,
        _changed: &[Box<dyn TraceAddressSnapRange>],
        _snap: i64,
        _start: &Address,
        _old_bytes: &[u8],
        _new_bytes: &[u8],
    ) {
        unimplemented!("DBTraceCodeSpace::bytes_changed not overridden")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use std::sync::Mutex;

    /// A view standing in for the instructions/defined-data/undefined-data fields:
    /// `invalidate_cache` bumps a shared counter so the aggregate default in
    /// [`DBTraceCodeSpace::invalidate_cache`] can be proven to reach all three.
    struct CountingView(Arc<Mutex<u32>>);

    impl DBTraceInstructionsView for CountingView {
        fn invalidate_cache(&self) {
            *self.0.lock().unwrap() += 1;
        }
    }
    impl DBTraceDefinedDataView for CountingView {
        fn invalidate_cache(&self) {
            *self.0.lock().unwrap() += 1;
        }
    }
    impl DBTraceUndefinedDataView for CountingView {
        fn invalidate_cache(&self) {
            *self.0.lock().unwrap() += 1;
        }
    }

    struct MockCodeSpace {
        address_space: Arc<AddressSpace>,
        invalidations: Arc<Mutex<u32>>,
    }

    impl DBTraceCodeSpace for MockCodeSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.address_space.clone()
        }
        fn instructions(&self) -> Box<dyn DBTraceInstructionsView> {
            Box::new(CountingView(self.invalidations.clone()))
        }
        fn defined_data(&self) -> Box<dyn DBTraceDefinedDataView> {
            Box::new(CountingView(self.invalidations.clone()))
        }
        fn undefined_data(&self) -> Box<dyn DBTraceUndefinedDataView> {
            Box::new(CountingView(self.invalidations.clone()))
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn invalidate_cache_reaches_instructions_defined_and_undefined_data() {
        let space =
            MockCodeSpace { address_space: ram_space(), invalidations: Arc::new(Mutex::new(0)) };
        space.invalidate_cache();
        assert_eq!(*space.invalidations.lock().unwrap(), 3);
    }

    #[test]
    fn is_object_safe_and_reachable_through_a_dyn_trait() {
        let space =
            MockCodeSpace { address_space: ram_space(), invalidations: Arc::new(Mutex::new(0)) };
        let boxed: Box<dyn DBTraceCodeSpace> = Box::new(space);
        assert_eq!(boxed.get_address_space().name(), "ram");
        boxed.invalidate_cache();
    }
}
