//! Port of `ghidra.trace.database.listing.AbstractBaseDBTraceCodeUnitsMemoryView`.

use std::sync::Arc;

use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressRangeIterator, AddressSet, AddressSetView,
    AddressSpace,
};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::{
    AbstractBaseDBTraceCodeUnitsView, DBTraceCodeManager, DBTraceCodeSpace, DBTraceUtils,
};
use crate::util::lock_hold::{Lock, LockHold};

/// An abstract implementation of [`TraceBaseCodeUnitsView`] for composing views of many address
/// spaces.
///
/// Port of `ghidra.trace.database.listing.AbstractBaseDBTraceCodeUnitsMemoryView<T, M>`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// `T` mirrors the Java class's `T extends DBTraceCodeUnitAdapter` type parameter (the unit type
/// this view composes) and `M` its `M extends AbstractBaseDBTraceCodeUnitsView<T>` (the per-space
/// view type it delegates to, obtained via [`Self::get_view`]). Unlike
/// [`AbstractSingleDBTraceCodeUnitsView`](crate::trace::database::listing::abstract_single_db_trace_code_units_view::AbstractSingleDBTraceCodeUnitsView),
/// no bound of `T: DBTraceCodeUnitAdapter` is reproduced here, since none of this trait's methods
/// ever call a `DBTraceCodeUnitAdapter` member on a `T` value -- they only ever receive, hold, and
/// return `T`s opaquely.
///
/// The Java class's constructor-injected `protected final DBTraceCodeManager manager` field is
/// exposed as the required [`Self::manager`] accessor (the same translation used elsewhere in this
/// crate for constructor-injected fields, e.g.
/// [`InternalBaseCodeUnitsView::get_space`](crate::trace::seam_stubs::InternalBaseCodeUnitsView::get_space)).
///
/// The Java class formally `implements DBTraceDelegatingManager<M>`
/// ([already ported](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager)
/// as its own cycle cut-point), concretely overriding `readLock`/`writeLock`/`getForSpace` by
/// delegating to the `manager` field. Rust cannot let this trait provide default bodies for
/// *another* trait's required (non-default) methods, so rather than declaring
/// `DBTraceDelegatingManager<M>` as a supertrait (which would force every implementor to
/// hand-write those three one-line overrides anyway, just to satisfy the supertrait bound), this
/// trait simply declares [`Self::read_lock`]/[`Self::write_lock`]/[`Self::get_for_space`] as its
/// own default methods with the same names and bodies. A concrete type wanting to also be usable
/// as `dyn DBTraceDelegatingManager<M>` can implement that trait separately, delegating each
/// method to the identically-named default here.
pub trait AbstractBaseDBTraceCodeUnitsMemoryView<T, M>
where
    M: AbstractBaseDBTraceCodeUnitsView<T>,
{
    /// The code manager from which individual per-space views are retrieved. Mirrors the
    /// constructor-injected `manager` field.
    fn manager(&self) -> &dyn DBTraceCodeManager;

    /// Get the individual view from the given space. Mirrors the abstract
    /// `getView(DBTraceCodeSpace)`.
    fn get_view(&self, space: Arc<dyn DBTraceCodeSpace>) -> M;

    /// Mirrors `DBTraceDelegatingManager.readLock()`, delegating to the manager's lock. See this
    /// trait's docs for why this is a plain default method rather than an override of
    /// `DBTraceDelegatingManager::read_lock`.
    fn read_lock(&self) -> &dyn Lock {
        self.manager().read_lock()
    }

    /// Mirrors `DBTraceDelegatingManager.writeLock()`, delegating to the manager's lock. See this
    /// trait's docs for why this is a plain default method rather than an override of
    /// `DBTraceDelegatingManager::write_lock`.
    fn write_lock(&self) -> &dyn Lock {
        self.manager().write_lock()
    }

    /// Mirrors the `@Override public M getForSpace(AddressSpace, boolean)`: look up the space via
    /// the manager, then wrap it with [`Self::get_view`]. See this trait's docs for why this is a
    /// plain default method rather than an override of `DBTraceDelegatingManager::get_for_space`.
    fn get_for_space(&self, space: &Arc<AddressSpace>, create_if_absent: bool) -> Option<M> {
        let code_space = self.manager().get_for_space(space, create_if_absent)?;
        Some(self.get_view(code_space))
    }

    /// Mirrors `getSpace()`, which the Java class always answers `null` (this composite view
    /// isn't bound to a single space).
    fn get_space(&self) -> Option<Arc<AddressSpace>> {
        None
    }

    /// Create the appropriate unit (possibly caching) when there is no view or space for the
    /// given address's space. Mirrors `nullOrUndefined(long, Address)`.
    ///
    /// Views composing undefined units should generate (possibly delegating to a view) an
    /// undefined unit. Others should leave this `None`.
    fn null_or_undefined(&self, _snap: i64, _address: &Address) -> Option<T> {
        None
    }

    /// The address set when there is no view or space for the given range's space. Mirrors
    /// `emptyOrFullAddressSetUndefined(AddressRange)`.
    ///
    /// Views composing undefined units should return the whole range. Others should leave this
    /// empty.
    fn empty_or_full_address_set_undefined(&self, _within: &AddressRange) -> Box<dyn AddressSetView> {
        Box::new(AddressSet::new())
    }

    /// The result of contains, covers, or intersects when there is no view or space for an
    /// address space. Mirrors `falseOrTrueUndefined()`.
    ///
    /// Views composing undefined units should return `true`, since the address is known to be in
    /// an unpopulated space. Others should leave this `false`.
    fn false_or_true_undefined(&self) -> bool {
        false
    }

    /// The result of iteration when there is no view or space for the given range's space.
    /// Mirrors `emptyOrFullIterableUndefined(long, AddressRange, boolean)`.
    ///
    /// Views composing undefined units should return an iterable that generates (possibly
    /// caching) undefined units. Others should leave this empty.
    fn empty_or_full_iterable_undefined(&self, _snap: i64, _range: &AddressRange, _forward: bool) -> Vec<T> {
        Vec::new()
    }

    /// Mirrors the `TraceAddressSnapRange`-taking overload of
    /// `emptyOrFullIterableUndefined(TraceAddressSnapRange)`.
    fn empty_or_full_iterable_undefined_tasr(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<T> {
        Vec::new()
    }

    /// Mirrors `TraceBaseCodeUnitsView#getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace> {
        self.manager().get_trace()
    }

    /// Compute the address preceding the given one.
    ///
    /// If this address is the minimum in its space, then this will choose the maximum address of
    /// the previous space, if it exists. Mirrors `prevAddress(Address)`.
    fn prev_address(&self, address: &Address) -> Option<Address> {
        if let Ok(prev) = address.previous() {
            return Some(prev);
        }
        let factory = self.manager().get_base_language().get_address_factory();
        let mut ranges = factory.get_address_set().address_ranges_from(address, false);
        let mut prev_range = ranges.next_range()?;
        if prev_range.contains(address) {
            prev_range = ranges.next_range()?;
        }
        Some(prev_range.max_address().clone())
    }

    /// Compute the address following the given one.
    ///
    /// If the address is the maximum in its space, then this will choose the minimum address of
    /// the next space, if it exists. Mirrors `nextAddress(Address)`.
    fn next_address(&self, address: &Address) -> Option<Address> {
        if let Ok(next) = address.next() {
            return Some(next);
        }
        let factory = self.manager().get_base_language().get_address_factory();
        let mut ranges = factory.get_address_set().address_ranges_from(address, true);
        let mut next_range = ranges.next_range()?;
        if next_range.contains(address) {
            next_range = ranges.next_range()?;
        }
        Some(next_range.min_address().clone())
    }

    /// Mirrors `TraceBaseCodeUnitsView#size()`: the number of units, summed over every active
    /// space's view.
    fn size(&self) -> i32 {
        let mut sum = 0;
        for space in self.manager().get_active_spaces() {
            sum += self.get_view(space).size();
        }
        sum
    }

    /// Mirrors `TraceBaseCodeUnitsView#getBefore(long, Address)`.
    fn get_before(&self, snap: i64, address: &Address) -> Option<T> {
        let prev = self.prev_address(address)?;
        self.get_floor(snap, &prev)
    }

    /// Mirrors `TraceBaseCodeUnitsView#getFloor(long, Address)`.
    fn get_floor(&self, snap: i64, address: &Address) -> Option<T> {
        let _hold = LockHold::lock(self.read_lock());
        let factory = self.manager().get_trace().get_base_address_factory();
        let set = DBTraceUtils::get_address_set(factory.as_ref(), address, false);
        let mut ranges = set.address_ranges_ordered(false);
        while let Some(range) = ranges.next_range() {
            let candidate = match self.get_for_space(range.space(), false) {
                None => self.null_or_undefined(snap, range.max_address()),
                Some(m) => m.get_floor(snap, range.max_address()),
            };
            if candidate.is_some() {
                return candidate;
            }
        }
        None
    }

    /// Mirrors `TraceBaseCodeUnitsView#getContaining(long, Address)`.
    fn get_containing(&self, snap: i64, address: &Address) -> Option<T> {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(address.space(), false) {
            None => self.null_or_undefined(snap, address),
            Some(m) => m.get_containing(snap, address),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#getAt(long, Address)`.
    fn get_at(&self, snap: i64, address: &Address) -> Option<T> {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(address.space(), false) {
            None => self.null_or_undefined(snap, address),
            Some(m) => m.get_at(snap, address),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#getCeiling(long, Address)`.
    fn get_ceiling(&self, snap: i64, address: &Address) -> Option<T> {
        let _hold = LockHold::lock(self.read_lock());
        let factory = self.manager().get_trace().get_base_address_factory();
        let set = DBTraceUtils::get_address_set(factory.as_ref(), address, true);
        let mut ranges = set.address_ranges_ordered(true);
        while let Some(range) = ranges.next_range() {
            let candidate = match self.get_for_space(range.space(), false) {
                None => self.null_or_undefined(snap, range.min_address()),
                Some(m) => m.get_ceiling(snap, range.min_address()),
            };
            if candidate.is_some() {
                return candidate;
            }
        }
        None
    }

    /// Mirrors `TraceBaseCodeUnitsView#getAfter(long, Address)`.
    fn get_after(&self, snap: i64, address: &Address) -> Option<T> {
        let next = self.next_address(address)?;
        self.get_ceiling(snap, &next)
    }

    /// Mirrors the `get(long, Address, Address, boolean)` overload. Named to match
    /// [`TraceBaseCodeUnitsView::get_between`].
    fn get_between(&self, snap: i64, min: &Address, max: &Address, forward: bool) -> Vec<T> {
        if min.same_address_space(max) {
            let range = AddressRange::new(min.clone(), max.clone());
            return self.get_in_range(snap, &range, forward);
        }
        let factory = self.manager().get_trace().get_base_address_factory();
        let set = factory.get_address_set_range(min, max);
        self.get_in_set(snap, &set, forward)
    }

    /// Mirrors the `get(long, AddressSetView, boolean)` overload. Named to match
    /// [`TraceBaseCodeUnitsView::get_in_set`].
    fn get_in_set(&self, snap: i64, set: &dyn AddressSetView, forward: bool) -> Vec<T> {
        let mut result = Vec::new();
        let mut ranges = set.address_ranges_ordered(forward);
        while let Some(range) = ranges.next_range() {
            result.extend(self.get_in_range(snap, &range, forward));
        }
        result
    }

    /// Mirrors the `get(long, AddressRange, boolean)` overload. Named to match
    /// [`TraceBaseCodeUnitsView::get_in_range`].
    fn get_in_range(&self, snap: i64, range: &AddressRange, forward: bool) -> Vec<T> {
        match self.get_for_space(range.space(), false) {
            None => self.empty_or_full_iterable_undefined(snap, range, forward),
            Some(m) => m.get_in_range(snap, range, forward),
        }
    }

    /// Mirrors the `get(long, Address, boolean)` overload. Named to match
    /// [`TraceBaseCodeUnitsView::get_from`].
    fn get_from(&self, snap: i64, start: &Address, forward: bool) -> Vec<T> {
        let factory = self.manager().get_trace().get_base_address_factory();
        let set = DBTraceUtils::get_address_set(factory.as_ref(), start, forward);
        self.get_in_set(snap, &set, forward)
    }

    /// Mirrors the `get(long, boolean)` overload. Named to match
    /// [`TraceBaseCodeUnitsView::get_all`].
    fn get_all(&self, snap: i64, forward: bool) -> Vec<T> {
        let factory = self.manager().get_trace().get_base_address_factory();
        let set = factory.get_address_set();
        self.get_in_set(snap, &set, forward)
    }

    /// Mirrors `TraceBaseCodeUnitsView#getIntersecting(TraceAddressSnapRange)`.
    fn get_intersecting(&self, tasr: &dyn TraceAddressSnapRange) -> Vec<T> {
        let x1 = tasr.get_x1();
        match self.get_for_space(x1.space(), false) {
            None => self.empty_or_full_iterable_undefined_tasr(tasr),
            Some(m) => m.get_intersecting(tasr),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#getAddressSetView(long, AddressRange)`. Named to match
    /// [`TraceBaseCodeUnitsView::get_address_set_view_within`].
    fn get_address_set_view_within(&self, snap: i64, within: &AddressRange) -> Box<dyn AddressSetView> {
        match self.get_for_space(within.space(), false) {
            None => self.empty_or_full_address_set_undefined(within),
            Some(m) => m.get_address_set_view_within(snap, within),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#getAddressSetView(long)`.
    fn get_address_set_view(&self, snap: i64) -> Box<dyn AddressSetView> {
        let factory = self.manager().get_trace().get_base_address_factory();
        let mut result = AddressSet::new();
        let all = factory.get_address_set();
        let mut ranges = all.address_ranges_ordered(true);
        while let Some(range) = ranges.next_range() {
            match self.get_for_space(range.space(), false) {
                None => result.add_set(self.empty_or_full_address_set_undefined(&range).as_ref()),
                Some(m) => result.add_set(m.get_address_set_view(snap).as_ref()),
            }
        }
        Box::new(result)
    }

    /// Mirrors `TraceBaseCodeUnitsView#containsAddress(long, Address)`.
    fn contains_address(&self, snap: i64, address: &Address) -> bool {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(address.space(), false) {
            None => self.false_or_true_undefined(),
            Some(m) => m.contains_address(snap, address),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: &dyn Lifespan, range: &AddressRange) -> bool {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(range.space(), false) {
            None => self.false_or_true_undefined(),
            Some(m) => m.covers_range(span, range),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#coversRange(TraceAddressSnapRange)`. Named to match
    /// [`TraceBaseCodeUnitsView::covers_snap_range`].
    fn covers_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool {
        let r = range.get_range();
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(r.space(), false) {
            None => self.false_or_true_undefined(),
            Some(m) => m.covers_snap_range(range),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: &dyn Lifespan, range: &AddressRange) -> bool {
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(range.space(), false) {
            None => self.false_or_true_undefined(),
            Some(m) => m.intersects_range(span, range),
        }
    }

    /// Mirrors `TraceBaseCodeUnitsView#intersectsRange(TraceAddressSnapRange)`. Named to match
    /// [`TraceBaseCodeUnitsView::intersects_snap_range`].
    fn intersects_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool {
        let r = range.get_range();
        let _hold = LockHold::lock(self.read_lock());
        match self.get_for_space(r.space(), false) {
            None => self.false_or_true_undefined(),
            Some(m) => m.intersects_snap_range(range),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::CompilerSpec;
    use std::sync::Mutex;
    use std::collections::BTreeSet;
    
    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    /// A per-space view backed by a sorted set of single-address "units" (their own offset
    /// stands in for the unit value `T = i64`).
    struct MockSpaceView {
        space: Arc<AddressSpace>,
        units: Arc<Mutex<BTreeSet<i64>>>,
    }

    impl AbstractBaseDBTraceCodeUnitsView<i64> for MockSpaceView {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }

        fn size(&self) -> i32 {
            self.units.lock().unwrap().len() as i32
        }

        fn get_floor(&self, _snap: i64, address: &Address) -> Option<i64> {
            self.units.lock().unwrap().range(..=address.offset()).next_back().copied()
        }

        fn get_containing(&self, snap: i64, address: &Address) -> Option<i64> {
            self.get_at(snap, address)
        }

        fn get_at(&self, _snap: i64, address: &Address) -> Option<i64> {
            self.units.lock().unwrap().get(&address.offset()).copied()
        }

        fn get_ceiling(&self, _snap: i64, address: &Address) -> Option<i64> {
            self.units.lock().unwrap().range(address.offset()..).next().copied()
        }

        fn get_in_range(&self, _snap: i64, range: &AddressRange, forward: bool) -> Vec<i64> {
            let lo = range.min_address().offset();
            let hi = range.max_address().offset();
            let mut result: Vec<i64> = self.units.lock().unwrap().range(lo..=hi).copied().collect();
            if !forward {
                result.reverse();
            }
            result
        }

        fn get_intersecting(&self, tasr: &dyn TraceAddressSnapRange) -> Vec<i64> {
            self.get_in_range(0, &tasr.get_range(), true)
        }

        fn get_address_set_view_within(&self, snap: i64, within: &AddressRange) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for offset in self.get_in_range(snap, within, true) {
                set.add_address(&Address::new(self.space.clone(), offset));
            }
            Box::new(set)
        }

        fn get_address_set_view(&self, _snap: i64) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for offset in self.units.lock().unwrap().iter() {
                set.add_address(&Address::new(self.space.clone(), *offset));
            }
            Box::new(set)
        }

        fn contains_address(&self, _snap: i64, address: &Address) -> bool {
            self.units.lock().unwrap().contains(&address.offset())
        }

        fn covers_range(&self, _span: &dyn Lifespan, range: &AddressRange) -> bool {
            let lo = range.min_address().offset();
            let hi = range.max_address().offset();
            (lo..=hi).all(|offset| self.units.lock().unwrap().contains(&offset))
        }

        fn covers_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool {
            self.covers_range(range.get_lifespan().as_ref(), &range.get_range())
        }

        fn intersects_range(&self, _span: &dyn Lifespan, range: &AddressRange) -> bool {
            !self.get_in_range(0, range, true).is_empty()
        }

        fn intersects_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool {
            self.intersects_range(range.get_lifespan().as_ref(), &range.get_range())
        }
    }

    struct MockCodeSpace {
        space: Arc<AddressSpace>,
    }
    impl DBTraceCodeSpace for MockCodeSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    struct MockTrace {
        factory: Arc<DefaultAddressFactory>,
    }
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {}
        fn get_emulator_cache_version(&self) -> i64 {
            0
        }
        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new((*self.factory).clone())
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn crate::trace::seam_stubs::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
        }
        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// The composite view under test: two spaces (`ram`, `ram2`), each backed by a
    /// [`MockSpaceView`], lazily created on first [`DBTraceCodeManager::get_for_space`].
    struct MockMemoryView {
        read_lock: NoopLock,
        write_lock: NoopLock,
        trace: Arc<MockTrace>,
        stores: Mutex<std::collections::HashMap<String, Arc<Mutex<BTreeSet<i64>>>>>,
    }

    impl DBTraceCodeManager for MockMemoryView {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTraceHandle { trace: self.trace.clone() })
        }
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn read_lock(&self) -> &dyn Lock {
            &self.read_lock
        }
        fn write_lock(&self) -> &dyn Lock {
            &self.write_lock
        }
        fn get_for_space(
            &self,
            space: &Arc<AddressSpace>,
            create_if_absent: bool,
        ) -> Option<Arc<dyn DBTraceCodeSpace>> {
            let mut stores = self.stores.lock().unwrap();
            if create_if_absent {
                stores.entry(space.name().to_string()).or_insert_with(|| Arc::new(Mutex::new(BTreeSet::new())));
            }
            if !stores.contains_key(space.name()) {
                return None;
            }
            Some(Arc::new(MockCodeSpace { space: space.clone() }))
        }
        fn get_active_spaces(&self) -> Vec<Arc<dyn DBTraceCodeSpace>> {
            let factory = &self.trace.factory;
            let stores = self.stores.lock().unwrap();
            factory
                .get_address_spaces()
                .into_iter()
                .filter(|s| stores.contains_key(s.name()))
                .map(|s| Arc::new(MockCodeSpace { space: s }) as Arc<dyn DBTraceCodeSpace>)
                .collect()
        }
    }

    /// A thin `Trace` handle that only exists so [`MockMemoryView::get_trace`] can hand out a
    /// fresh `Box<dyn Trace>` each call while sharing the one real `MockTrace`'s address factory.
    struct MockTraceHandle {
        trace: Arc<MockTrace>,
    }
    impl crate::framework::model::DomainObject for MockTraceHandle {}
    impl crate::app::merge::DataTypeManagerOwner for MockTraceHandle {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTraceHandle
    {
    }
    impl Trace for MockTraceHandle {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            self.trace.get_base_language()
        }
        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            self.trace.get_base_compiler_spec()
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {}
        fn get_emulator_cache_version(&self) -> i64 {
            0
        }
        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            self.trace.get_base_address_factory()
        }
        fn get_address_property_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn crate::trace::seam_stubs::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(&self) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::seam_stubs::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
        }
        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl AbstractBaseDBTraceCodeUnitsMemoryView<i64, MockSpaceView> for MockMemoryView {
        fn manager(&self) -> &dyn DBTraceCodeManager {
            self
        }

        fn get_view(&self, space: Arc<dyn DBTraceCodeSpace>) -> MockSpaceView {
            let addr_space = space.get_address_space();
            let mut stores = self.stores.lock().unwrap();
            let units = stores
                .entry(addr_space.name().to_string())
                .or_insert_with(|| Arc::new(Mutex::new(BTreeSet::new())))
                .clone();
            MockSpaceView { space: addr_space, units }
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }
    fn ram2_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram2", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn make_view() -> MockMemoryView {
        let ram = ram_space();
        let ram2 = ram2_space();
        let factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone(), ram2.clone()]));
        MockMemoryView {
            read_lock: NoopLock,
            write_lock: NoopLock,
            trace: Arc::new(MockTrace { factory }),
            stores: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn put_unit(view: &MockMemoryView, space: &Arc<AddressSpace>, offset: i64) {
        AbstractBaseDBTraceCodeUnitsMemoryView::get_for_space(view, space, true);
        view.stores.lock().unwrap()[space.name()].lock().unwrap().insert(offset);
    }

    #[test]
    fn get_floor_crosses_into_the_previous_populated_space() {
        let view = make_view();
        let ram = ram_space();
        let ram2 = ram2_space();
        put_unit(&view, &ram, 0x100);

        // No unit at or below 0x50 in ram2's own space, but ram (which precedes ram2 in the
        // factory's address-space ordering) has one at 0x100: getFloor must cross the space
        // boundary via `DBTraceUtils.getAddressSet` to find it.
        let floor = AbstractBaseDBTraceCodeUnitsMemoryView::get_floor(&view, 0, &Address::new(ram2, 0x50));
        assert_eq!(floor, Some(0x100));
    }

    #[test]
    fn get_ceiling_crosses_into_the_next_populated_space() {
        let view = make_view();
        let ram = ram_space();
        let ram2 = ram2_space();
        put_unit(&view, &ram2, 0x40);

        let ceiling =
            AbstractBaseDBTraceCodeUnitsMemoryView::get_ceiling(&view, 0, &Address::new(ram, 0xFFFF));
        assert_eq!(ceiling, Some(0x40));
    }

    #[test]
    fn get_between_spans_two_spaces_via_the_global_address_set() {
        let view = make_view();
        let ram = ram_space();
        let ram2 = ram2_space();
        put_unit(&view, &ram, 0x10);
        put_unit(&view, &ram2, 0x20);

        let mut units = AbstractBaseDBTraceCodeUnitsMemoryView::get_between(
            &view,
            0,
            &Address::new(ram, 0x0),
            &Address::new(ram2, 0xFFFF),
            true,
        );
        units.sort();
        assert_eq!(units, vec![0x10, 0x20]);
    }

    #[test]
    fn contains_address_is_false_for_a_space_never_populated() {
        let view = make_view();
        let ram = ram_space();
        assert!(!AbstractBaseDBTraceCodeUnitsMemoryView::contains_address(
            &view,
            0,
            &Address::new(ram, 0x10)
        ));
    }

    #[test]
    fn contains_address_and_size_reflect_units_across_active_spaces() {
        let view = make_view();
        let ram = ram_space();
        let ram2 = ram2_space();
        put_unit(&view, &ram, 0x10);
        put_unit(&view, &ram2, 0x20);

        assert!(AbstractBaseDBTraceCodeUnitsMemoryView::contains_address(
            &view,
            0,
            &Address::new(ram.clone(), 0x10)
        ));
        assert!(!AbstractBaseDBTraceCodeUnitsMemoryView::contains_address(
            &view,
            0,
            &Address::new(ram, 0x11)
        ));
        assert_eq!(AbstractBaseDBTraceCodeUnitsMemoryView::size(&view), 2);
    }

    #[test]
    fn get_for_space_only_creates_when_create_if_absent() {
        let view = make_view();
        let ram = ram_space();

        assert!(AbstractBaseDBTraceCodeUnitsMemoryView::get_for_space(&view, &ram, false).is_none());
        assert!(AbstractBaseDBTraceCodeUnitsMemoryView::get_for_space(&view, &ram, true).is_some());
        assert!(AbstractBaseDBTraceCodeUnitsMemoryView::get_for_space(&view, &ram, false).is_some());
    }

    /// Proves the trait is object-safe.
    #[test]
    fn usable_as_trait_object() {
        let view = make_view();
        let obj: &dyn AbstractBaseDBTraceCodeUnitsMemoryView<i64, MockSpaceView> = &view;
        assert_eq!(obj.size(), 0);
        assert_eq!(obj.get_space(), None);
    }
}
