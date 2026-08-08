use std::sync::Arc;

use crate::program::model::address::{AddressSetView, AddressSpace};
use crate::trace::model::listing::trace_code_operations::TraceCodeOperations;
use crate::trace::model::listing::trace_code_space::TraceCodeSpace;
use crate::trace::seam_stubs::{TraceStackFrame, TraceThread};

/// The manager for trace code units, i.e., the equivalent of `Listing`.
///
/// Port of `ghidra.trace.model.listing.TraceCodeManager`.
///
/// This supports a "fluent" interface, which differs from `Listing`. For example, instead of
/// `Listing::get_instruction_containing`, a client would invoke `instructions()` then
/// `TraceInstructionsView::get_containing`. Because traces include register spaces, this chain
/// could be preceded by `get_code_space`/`get_code_register_space`.
///
/// To create an instruction, see `TraceInstructionsView::create`. Since clients do not
/// ordinarily have an instruction prototype in hand, the more common method is to invoke the
/// disassembler on the trace's program view.
///
/// To create a data unit, see `TraceDefinedDataView::create_sized`/`create_unsized`. The method
/// chain to create a data unit in memory is `defined_data()` then `create_sized(...)`. The method
/// chain to create a data unit on a register is `get_code_register_space(...)`, then
/// `TraceCodeSpace::defined_data()`, then `TraceDefinedDataView::create_on_register(...)`.
pub trait TraceCodeManager: TraceCodeOperations {
    /// Get the code space for the memory of the given address space.
    ///
    /// `create_if_absent`: true to create the space if it's not already present.
    ///
    /// Returns the space, or `None` if absent and not created.
    fn get_code_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceCodeSpace>>;

    /// Get the code space for registers of the given thread's innermost frame.
    ///
    /// `create_if_absent`: true to create the space if it's not already present.
    ///
    /// Returns the space, or `None` if absent and not created.
    fn get_code_register_space(
        &self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceCodeSpace>>;

    /// Get the code space for registers of the given thread and frame (0 for innermost).
    ///
    /// `create_if_absent`: true to create the space if it's not already present.
    ///
    /// Returns the space, or `None` if absent and not created.
    fn get_code_register_space_for_frame_level(
        &self,
        thread: &dyn TraceThread,
        frame_level: i32,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceCodeSpace>>;

    /// Get the code space for registers of the given stack frame.
    ///
    /// Note this is simply a shortcut for `get_code_register_space_for_frame_level`, and does not
    /// in any way bind the space to the lifetime of the given frame. Nor, if the frame is moved,
    /// will this space move with it.
    ///
    /// `create_if_absent`: true to create the space if it's not already present.
    ///
    /// Returns the space, or `None` if absent and not created.
    fn get_code_register_space_for_stack_frame(
        &self,
        frame: &dyn TraceStackFrame,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceCodeSpace>>;

    /// Query for the address set where code units have been added between the two given snaps.
    ///
    /// Experimental.
    fn get_code_added(&self, from: i64, to: i64) -> Box<dyn AddressSetView>;

    /// Query for the address set where code units have been removed between the two given snaps.
    ///
    /// Experimental.
    fn get_code_removed(&self, from: i64, to: i64) -> Box<dyn AddressSetView>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressRangeIterator, AddressSet, AddressSpaceType,
        BoxedAddressIterator,
    };
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::{InstructionPrototype, ProcessorContextView, Register};
    use crate::program::seam_stubs::InstructionSet;
    use crate::program::util::code_unit_insertion_exception::CodeUnitInsertionException;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::listing::trace_code_units_view::TraceCodeUnitsView;
    use crate::trace::model::listing::trace_data::TraceData;
    use crate::trace::model::listing::trace_data_view::TraceDataView;
    use crate::trace::model::listing::trace_defined_data_view::TraceDefinedDataView;
    use crate::trace::model::listing::trace_defined_units_view::TraceDefinedUnitsView;
    use crate::trace::model::listing::trace_instruction::TraceInstruction;
    use crate::trace::model::listing::trace_instructions_view::TraceInstructionsView;
    use crate::trace::model::listing::trace_undefined_data_view::TraceUndefinedDataView;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::TracePlatform;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    /// A trivial, empty view usable as any of the base/defined-units views
    /// `TraceCodeOperations`'s methods return -- only realistic enough to prove `TraceCodeManager`
    /// is object-safe and delegates to the right views.
    struct EmptyView;

    impl TraceBaseCodeUnitsView for EmptyView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn size(&self) -> i32 {
            0
        }

        fn get_before(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_floor(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_at(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_ceiling(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_after(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_between(
            &self,
            _snap: i64,
            _min: &Address,
            _max: &Address,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_in_set(
            &self,
            _snap: i64,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_in_range(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_from(&self, _snap: i64, _start: &Address, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_all(&self, _snap: i64, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_intersecting(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_address_set_view(&self, _snap: i64) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn get_address_set_view_within(
            &self,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn contains_address(&self, _snap: i64, _address: &Address) -> bool {
            false
        }

        fn covers_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn intersects_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn intersects_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn get_for_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_containing_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_by_platform_register(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
    }

    impl TraceBaseDefinedUnitsView for EmptyView {
        fn clear(
            &mut self,
            _span: Lifespan,
            _range: &AddressRange,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn clear_register(
            &mut self,
            _span: Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn clear_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            _span: Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    impl TraceDefinedDataView for EmptyView {
        fn create_sized(
            &mut self,
            _lifespan: Lifespan,
            _address: &Address,
            _data_type: &dyn DataType,
            _length: i32,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_sized_on_platform(
            &mut self,
            _lifespan: Lifespan,
            _address: &Address,
            _platform: &dyn TracePlatform,
            _data_type: &dyn DataType,
            _length: i32,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_unsized(
            &mut self,
            _lifespan: Lifespan,
            _address: &Address,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_unsized_on_platform(
            &mut self,
            _lifespan: Lifespan,
            _address: &Address,
            _platform: &dyn TracePlatform,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_on_register(
            &mut self,
            _lifespan: Lifespan,
            _register: &Register,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_on_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            _lifespan: Lifespan,
            _register: &Register,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl TraceUndefinedDataView for EmptyView {}
    impl TraceDefinedUnitsView for EmptyView {}

    impl TraceInstructionsView for EmptyView {
        fn create(
            &mut self,
            _lifespan: Lifespan,
            _address: &Address,
            _platform: &dyn TracePlatform,
            _prototype: &dyn InstructionPrototype,
            _context: &dyn ProcessorContextView,
            _forced_length_override: i32,
        ) -> Result<Box<dyn TraceInstruction>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_on_host(
            &mut self,
            _lifespan: Lifespan,
            _address: &Address,
            _prototype: &dyn InstructionPrototype,
            _context: &dyn ProcessorContextView,
            _forced_length_override: i32,
        ) -> Result<Box<dyn TraceInstruction>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_instruction_set(
            &mut self,
            _lifespan: Lifespan,
            _platform: &dyn TracePlatform,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn add_instruction_set_on_host(
            &mut self,
            _lifespan: Lifespan,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
    }

    struct EmptyAddressRangeIterator;

    impl AddressRangeIterator for EmptyAddressRangeIterator {
        fn has_next(&self) -> bool {
            false
        }

        fn next_range(&mut self) -> Option<AddressRange> {
            None
        }
    }

    /// An address-set view reporting no addresses, standing in for `TraceCodeManager`'s
    /// added/removed queries.
    struct EmptyAddressSetView;

    impl AddressSetView for EmptyAddressSetView {
        fn contains(&self, _address: &Address) -> bool {
            false
        }

        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }

        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn is_empty(&self) -> bool {
            true
        }

        fn min_address(&self) -> Option<Address> {
            None
        }

        fn max_address(&self) -> Option<Address> {
            None
        }

        fn num_address_ranges(&self) -> usize {
            0
        }

        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn address_ranges_ordered(&self, _forward: bool) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn address_ranges_from(&self, _start: &Address, _forward: bool) -> Box<dyn AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }

        fn num_addresses(&self) -> u64 {
            0
        }

        fn addresses(&self, _forward: bool) -> BoxedAddressIterator {
            Box::new(std::iter::empty())
        }

        fn addresses_from(&self, _start: &Address, _forward: bool) -> BoxedAddressIterator {
            Box::new(std::iter::empty())
        }

        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }

        fn intersect(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }

        fn intersect_range(&self, _start: &Address, _end: &Address) -> AddressSet {
            AddressSet::new()
        }

        fn union(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }

        fn subtract(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }

        fn xor(&self, _set: &dyn AddressSetView) -> AddressSet {
            AddressSet::new()
        }

        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            true
        }

        fn first_range(&self) -> Option<AddressRange> {
            None
        }

        fn last_range(&self) -> Option<AddressRange> {
            None
        }

        fn range_containing(&self, _address: &Address) -> Option<AddressRange> {
            None
        }

        fn find_first_address_in_common(&self, _set: &dyn AddressSetView) -> Option<Address> {
            None
        }
    }

    struct MockThread;
    impl TraceThread for MockThread {}

    struct MockStackFrame;
    impl TraceStackFrame for MockStackFrame {}

    /// A minimal implementor proving `TraceCodeManager` is object-safe, extends
    /// `TraceCodeOperations` correctly, and resolves code spaces by address space, thread, frame
    /// level, and stack frame.
    struct MockCodeManager {
        space: Arc<AddressSpace>,
    }

    impl TraceCodeOperations for MockCodeManager {
        fn code_units(&self) -> Box<dyn TraceCodeUnitsView> {
            Box::new(EmptyView)
        }

        fn instructions(&self) -> Box<dyn TraceInstructionsView> {
            Box::new(EmptyView)
        }

        fn data(&self) -> Box<dyn TraceDataView> {
            Box::new(EmptyView)
        }

        fn defined_data(&self) -> Box<dyn TraceDefinedDataView> {
            Box::new(EmptyView)
        }

        fn undefined_data(&self) -> Box<dyn TraceUndefinedDataView> {
            Box::new(EmptyView)
        }

        fn defined_units(&self) -> Box<dyn TraceDefinedUnitsView> {
            Box::new(EmptyView)
        }
    }

    impl TraceCodeManager for MockCodeManager {
        fn get_code_space(
            &self,
            space: &Arc<AddressSpace>,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceCodeSpace>> {
            if Arc::ptr_eq(space, &self.space) || create_if_absent {
                struct MockCodeSpace(Arc<AddressSpace>);
                impl TraceCodeOperations for MockCodeSpace {
                    fn code_units(&self) -> Box<dyn TraceCodeUnitsView> {
                        Box::new(EmptyView)
                    }
                    fn instructions(&self) -> Box<dyn TraceInstructionsView> {
                        Box::new(EmptyView)
                    }
                    fn data(&self) -> Box<dyn TraceDataView> {
                        Box::new(EmptyView)
                    }
                    fn defined_data(&self) -> Box<dyn TraceDefinedDataView> {
                        Box::new(EmptyView)
                    }
                    fn undefined_data(&self) -> Box<dyn TraceUndefinedDataView> {
                        Box::new(EmptyView)
                    }
                    fn defined_units(&self) -> Box<dyn TraceDefinedUnitsView> {
                        Box::new(EmptyView)
                    }
                }
                impl TraceCodeSpace for MockCodeSpace {
                    fn address_space(&self) -> Arc<AddressSpace> {
                        self.0.clone()
                    }
                }
                Some(Box::new(MockCodeSpace(space.clone())))
            } else {
                None
            }
        }

        fn get_code_register_space(
            &self,
            _thread: &dyn TraceThread,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceCodeSpace>> {
            self.get_code_register_space_for_frame_level(_thread, 0, create_if_absent)
        }

        fn get_code_register_space_for_frame_level(
            &self,
            _thread: &dyn TraceThread,
            frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceCodeSpace>> {
            if frame_level == 0 {
                self.get_code_space(&self.space, true)
            } else {
                None
            }
        }

        fn get_code_register_space_for_stack_frame(
            &self,
            _frame: &dyn TraceStackFrame,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceCodeSpace>> {
            self.get_code_register_space_for_frame_level(&MockThread, 0, create_if_absent)
        }

        fn get_code_added(&self, _from: i64, _to: i64) -> Box<dyn AddressSetView> {
            Box::new(EmptyAddressSetView)
        }

        fn get_code_removed(&self, _from: i64, _to: i64) -> Box<dyn AddressSetView> {
            Box::new(EmptyAddressSetView)
        }
    }

    #[test]
    fn usable_as_trait_object_and_resolves_code_spaces() {
        let space = AddressSpace::new("register", 8, 1, AddressSpaceType::Register, 0);
        let manager: Box<dyn TraceCodeManager> = Box::new(MockCodeManager {
            space: space.clone(),
        });

        let code_space = manager.get_code_space(&space, false).unwrap();
        assert_eq!(code_space.address_space().name(), "register");

        let reg_space = manager
            .get_code_register_space(&MockThread, true)
            .unwrap();
        assert_eq!(reg_space.address_space().name(), "register");

        assert!(manager
            .get_code_register_space_for_frame_level(&MockThread, 1, true)
            .is_none());

        let frame_space = manager
            .get_code_register_space_for_stack_frame(&MockStackFrame, true)
            .unwrap();
        assert_eq!(frame_space.address_space().name(), "register");

        assert!(manager.get_code_added(0, 10).is_empty());
        assert!(manager.get_code_removed(0, 10).is_empty());

        // Inherited from `TraceCodeOperations`.
        assert_eq!(manager.code_units().size(), 0);
    }
}
