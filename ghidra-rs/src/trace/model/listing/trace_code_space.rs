use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::listing::trace_code_operations::TraceCodeOperations;

/// A space within a `TraceCodeManager` bound to a specific address space or thread and frame.
///
/// Port of `ghidra.trace.model.listing.TraceCodeSpace`.
///
/// Ordinarily, the manager can operate on all memory address spaces without the client needing to
/// bind to it specifically. However, there may be occasions where it's convenient (and more
/// efficient) to bind to the address space, anyway. Operating on register units requires binding
/// to the space.
///
/// See `TraceCodeManager::get_code_space`/`get_code_register_space`.
pub trait TraceCodeSpace: TraceCodeOperations {
    /// Get the address space of this code space.
    fn address_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpaceType,
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
    /// `TraceCodeOperations`'s methods return -- only realistic enough to prove `TraceCodeSpace`
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

        fn covers_range(&self, _span: &dyn Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn intersects_range(&self, _span: &dyn Lifespan, _range: &AddressRange) -> bool {
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
            _span: &dyn Lifespan,
            _range: &AddressRange,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn clear_register(
            &mut self,
            _span: &dyn Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }

        fn clear_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            _span: &dyn Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    impl TraceDefinedDataView for EmptyView {
        fn create_sized(
            &mut self,
            _lifespan: &dyn Lifespan,
            _address: &Address,
            _data_type: &dyn DataType,
            _length: i32,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_sized_on_platform(
            &mut self,
            _lifespan: &dyn Lifespan,
            _address: &Address,
            _platform: &dyn TracePlatform,
            _data_type: &dyn DataType,
            _length: i32,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_unsized(
            &mut self,
            _lifespan: &dyn Lifespan,
            _address: &Address,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_unsized_on_platform(
            &mut self,
            _lifespan: &dyn Lifespan,
            _address: &Address,
            _platform: &dyn TracePlatform,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_on_register(
            &mut self,
            _lifespan: &dyn Lifespan,
            _register: &Register,
            _data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_on_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            _lifespan: &dyn Lifespan,
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
            _lifespan: &dyn Lifespan,
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
            _lifespan: &dyn Lifespan,
            _address: &Address,
            _prototype: &dyn InstructionPrototype,
            _context: &dyn ProcessorContextView,
            _forced_length_override: i32,
        ) -> Result<Box<dyn TraceInstruction>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_instruction_set(
            &mut self,
            _lifespan: &dyn Lifespan,
            _platform: &dyn TracePlatform,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn add_instruction_set_on_host(
            &mut self,
            _lifespan: &dyn Lifespan,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
    }

    /// A minimal implementor proving `TraceCodeSpace` is object-safe, extends
    /// `TraceCodeOperations` correctly, and exposes its own bound address space.
    struct MockCodeSpace {
        space: Arc<AddressSpace>,
    }

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
            self.space.clone()
        }
    }

    #[test]
    fn usable_as_trait_object_and_reports_its_address_space() {
        let space = AddressSpace::new("register", 8, 1, AddressSpaceType::Register, 0);
        let code_space: Box<dyn TraceCodeSpace> = Box::new(MockCodeSpace {
            space: space.clone(),
        });

        assert_eq!(code_space.address_space().name(), "register");
        assert!(Arc::ptr_eq(&code_space.address_space(), &space));
        // Inherited from `TraceCodeOperations`.
        assert_eq!(code_space.code_units().size(), 0);
    }
}
