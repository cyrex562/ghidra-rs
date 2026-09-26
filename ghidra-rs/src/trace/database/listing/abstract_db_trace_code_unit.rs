//! Port of `ghidra.trace.database.listing.AbstractDBTraceCodeUnit`.
//!
//! An abstract implementation of a table-backed code unit, stored as a data entry in an
//! address-snap-range property map.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java class is generic in `T extends AbstractDBTraceCodeUnit<T>` (the concrete unit type,
//! used only to parameterize the storage tree it's constructed with). None of its nine public
//! methods reference `T`, so it is dropped here rather than reproduced as an unused Rust type
//! parameter.
//!
//! The Java class also `extends AbstractDBTraceAddressSnapRangePropertyMapData<T>` (whose
//! `getX1`/`getX2`/`getY1`/`getY2` come from its own `implements TraceAddressSnapRange`) and
//! `implements DBTraceCodeUnitAdapter` (a bare marker in this port, carrying no members of its
//! own). Rather than reproducing `getX1`/`getX2`/`getY1`/`getY2` again, this trait declares
//! [`TraceAddressSnapRange`] as a supertrait and reuses its identically-named defaults directly.
//!
//! Two adaptations, both already established elsewhere in this package for the same reasons:
//! - The constructor-injected `protected final DBTraceCodeSpace space` field is exposed as the
//!   required [`Self::space`] accessor, the same translation used for
//!   [`AbstractBaseDBTraceCodeUnitsMemoryView::manager`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView::manager).
//! - `getTrace()` returns `DBTrace`, covariantly narrowing what `TraceCodeUnit::get_trace`
//!   (reachable from concrete unit types like
//!   [`DBTraceData`](crate::trace::database::listing::db_trace_data::DBTraceData)) declares as
//!   `Trace`. Rust cannot re-override an inherited method covariantly (the same issue documented
//!   on [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit)), so this
//!   trait simply declares its own `get_trace` returning `Box<dyn DBTrace>`: a second, separately
//!   dispatched method reachable under the same name, exactly as
//!   [`DBTraceDefinedUnitsView`](crate::trace::database::listing::db_trace_defined_units_view::DBTraceDefinedUnitsView)
//!   already established for `clear`. A type implementing both must disambiguate with UFCS (e.g.
//!   `AbstractDBTraceCodeUnit::get_trace(&x)`).
//!
//! `getBytes(ByteBuffer, int)` is not re-declared: per
//! [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit)'s docs, it is
//! already covered by the inherited `MemBuffer::get_bytes_into`, which has the same shape once the
//! Java `ByteBuffer`'s position/limit markers are replaced by an ordinary `&mut [u8]` slice. The
//! protected `byteCache` field and the DB-traversal logic that populates it
//! (`space.trace.getMemoryManager().get(...).getViewBytes(...)`, behind a `space.trace.lockRead()`
//! guard) are therefore this class's *implementation* of that shape, not additional public
//! surface -- and depend on `DBTrace`/`DBTraceMemorySpace` members this trait has no other need
//! for, so they are left for a concrete `MemBuffer` implementation to supply.
//!
//! The constructor's `DBTraceAddressSnapRangePropertyMapTree<T, ?> tree`, `DBCachedObjectStore<?>
//! store`, and `DBRecord record` parameters are storage wiring, not part of the public instance
//! API, so none are reproduced here.

use crate::program::model::address::Address;
use crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::DBTrace;
use crate::trace::model::thread::TraceThread;

/// An abstract implementation of a table-backed code unit.
///
/// Port of `ghidra.trace.database.listing.AbstractDBTraceCodeUnit<T>`.
///
/// See the module documentation for the object-safety-driven deviations from a literal
/// translation.
pub trait AbstractDBTraceCodeUnit: TraceAddressSnapRange {
    /// The space this unit belongs to. Mirrors the constructor-injected `space` field.
    fn space(&self) -> &dyn DBTraceCodeSpace;

    /// Persists a new lifespan for this unit's storage record. Mirrors the protected
    /// `doSetLifespan(Lifespan)`.
    fn do_set_lifespan(&mut self, lifespan: Lifespan);

    /// Mirrors `AbstractDBTraceCodeUnit.getAddress()`.
    fn get_address(&self) -> Address {
        self.get_x1()
    }

    /// Mirrors `AbstractDBTraceCodeUnit.getMaxAddress()`.
    fn get_max_address(&self) -> Address {
        self.get_x2()
    }

    /// Mirrors `AbstractDBTraceCodeUnit.getLength()`.
    fn get_length(&self) -> i32 {
        self.get_range().length() as i32
    }

    /// Mirrors `AbstractDBTraceCodeUnit.getThread()`.
    fn get_thread(&self) -> Box<dyn TraceThread> {
        self.space().get_thread()
    }

    /// Mirrors `AbstractDBTraceCodeUnit.getTrace()`. See the module documentation for why this is
    /// a sibling method rather than an override of `TraceCodeUnit::get_trace`.
    fn get_trace(&self) -> Box<dyn DBTrace> {
        self.space().get_trace()
    }

    /// Mirrors `AbstractDBTraceCodeUnit.getStartSnap()`.
    fn get_start_snap(&self) -> i64 {
        self.get_y1()
    }

    /// Mirrors `AbstractDBTraceCodeUnit.setEndSnap(long)`.
    fn set_end_snap(&mut self, end_snap: i64) {
        let new_lifespan = self.get_lifespan().with_max(end_snap);
        self.do_set_lifespan(new_lifespan);
    }

    /// Mirrors `AbstractDBTraceCodeUnit.getEndSnap()`.
    fn get_end_snap(&self) -> i64 {
        self.get_y2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;



    /// A bare `TraceAddressSnapRange`, standing in for the boxed rectangles
    /// `get_bounds`/`immutable` return -- distinct from [`MockUnit`] since those don't need a
    /// `space` to satisfy the supertrait's contract.
    #[derive(Clone)]
    struct SimpleRange {
        range: AddressRange,
        lifespan: Lifespan,
    }

    impl TraceAddressSnapRange for SimpleRange {
        fn get_lifespan(&self) -> Lifespan {
            self.lifespan
        }
        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }
        fn immutable(&self, x1: Address, x2: Address, y1: i64, y2: i64) -> Box<dyn TraceAddressSnapRange> {
            Box::new(SimpleRange {
                range: AddressRange::new(x1, x2),
                lifespan: Lifespan::span(y1, y2),
            })
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

    struct MockDBTrace;
    impl DBTrace for MockDBTrace {}

    struct MockCodeSpace {
        address_space: Arc<AddressSpace>,
    }

    impl DBTraceCodeSpace for MockCodeSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.address_space.clone()
        }
        fn get_trace(&self) -> Box<dyn DBTrace> {
            Box::new(MockDBTrace)
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            Box::new(MockThread)
        }
    }

    /// A single code unit backed by an in-memory range/lifespan/space -- enough to prove
    /// object-safety and exercise real address/length/snap/space-delegation behavior without a
    /// real R*-tree-backed record.
    struct MockUnit {
        range: AddressRange,
        min_snap: i64,
        max_snap: i64,
        space: MockCodeSpace,
    }

    impl TraceAddressSnapRange for MockUnit {
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.min_snap, self.max_snap)
        }
        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(SimpleRange {
                range: self.range.clone(),
                lifespan: Lifespan::span(self.min_snap, self.max_snap),
            })
        }
        fn immutable(&self, x1: Address, x2: Address, y1: i64, y2: i64) -> Box<dyn TraceAddressSnapRange> {
            Box::new(SimpleRange {
                range: AddressRange::new(x1, x2),
                lifespan: Lifespan::span(y1, y2),
            })
        }
    }

    impl AbstractDBTraceCodeUnit for MockUnit {
        fn space(&self) -> &dyn DBTraceCodeSpace {
            &self.space
        }
        fn do_set_lifespan(&mut self, lifespan: Lifespan) {
            self.min_snap = lifespan.lmin();
            self.max_snap = lifespan.lmax();
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn make_unit() -> MockUnit {
        let space = ram_space();
        MockUnit {
            range: AddressRange::new(
                Address::new(space.clone(), 0x1000),
                Address::new(space.clone(), 0x1003),
            ),
            min_snap: 0,
            max_snap: 10,
            space: MockCodeSpace { address_space: space },
        }
    }

    #[test]
    fn get_address_and_max_address_derive_from_range() {
        let unit = make_unit();
        assert_eq!(unit.get_address().offset(), 0x1000);
        assert_eq!(unit.get_max_address().offset(), 0x1003);
    }

    #[test]
    fn get_length_computes_range_length() {
        let unit = make_unit();
        assert_eq!(unit.get_length(), 4);
    }

    #[test]
    fn get_start_and_end_snap_derive_from_lifespan() {
        let unit = make_unit();
        assert_eq!(unit.get_start_snap(), 0);
        assert_eq!(unit.get_end_snap(), 10);
    }

    #[test]
    fn set_end_snap_updates_lifespan_via_do_set_lifespan_and_leaves_start_snap_alone() {
        let mut unit = make_unit();
        unit.set_end_snap(99);
        assert_eq!(unit.get_end_snap(), 99);
        assert_eq!(unit.get_start_snap(), 0);
    }

    #[test]
    fn get_thread_and_get_trace_delegate_to_the_space() {
        let unit = make_unit();
        let _thread: Box<dyn TraceThread> = unit.get_thread();
        let _trace: Box<dyn DBTrace> = AbstractDBTraceCodeUnit::get_trace(&unit);
    }

    #[test]
    fn is_object_safe_and_reachable_through_a_dyn_trait() {
        fn assert_object_safe(_: &dyn AbstractDBTraceCodeUnit) {}
        let unit = make_unit();
        assert_object_safe(&unit);

        let boxed: Box<dyn AbstractDBTraceCodeUnit> = Box::new(unit);
        assert_eq!(boxed.get_address().offset(), 0x1000);
        assert_eq!(boxed.get_length(), 4);
    }
}
