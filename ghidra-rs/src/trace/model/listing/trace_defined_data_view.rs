use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::Register;
use crate::program::util::code_unit_insertion_exception::CodeUnitInsertionException;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView;
use crate::trace::model::listing::trace_data::TraceData;
use crate::trace::seam_stubs::TracePlatform;

/// A view of defined data units.
///
/// Port of `ghidra.trace.model.listing.TraceDefinedDataView`.
///
/// This view excludes instructions and default / undefined data units.
///
/// The Java interface's overloaded `create(...)` methods cannot be represented as same-named
/// Rust methods (Rust has no overloading), so each overload is given a distinct, descriptive
/// name below.
pub trait TraceDefinedDataView: TraceBaseDefinedUnitsView {
    /// Create a data unit starting at the given address.
    ///
    /// If the given type is already part of this trace, its platform is used as is. If not,
    /// then it is resolved to the host platform. Mirrors the Java overload
    /// `create(Lifespan, Address, DataType, int)`.
    fn create_sized(
        &mut self,
        lifespan: &dyn Lifespan,
        address: &Address,
        data_type: &dyn DataType,
        length: i32,
    ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException>;

    /// Create a data unit starting at the given address.
    ///
    /// The given type is resolved to the given platform, even if the type already exists in the
    /// trace by another platform. Mirrors the Java overload `create(Lifespan, Address,
    /// TracePlatform, DataType, int)`.
    fn create_sized_on_platform(
        &mut self,
        lifespan: &dyn Lifespan,
        address: &Address,
        platform: &dyn TracePlatform,
        data_type: &dyn DataType,
        length: i32,
    ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException>;

    /// Create a data unit of unspecified length starting at the given address.
    ///
    /// The length will be determined by the data type, possibly by examining the bytes, e.g., a
    /// null-terminated UTF-8 string. If the given type is already part of this trace, its
    /// platform is used as is. If not, then it is resolved to the host platform. Mirrors the
    /// Java overload `create(Lifespan, Address, DataType)`.
    fn create_unsized(
        &mut self,
        lifespan: &dyn Lifespan,
        address: &Address,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException>;

    /// Create a data unit of unspecified length starting at the given address.
    ///
    /// The length will be determined by the data type, possibly by examining the bytes, e.g., a
    /// null-terminated UTF-8 string. The given type is resolved to the given platform, even if
    /// the type already exists in the trace by another platform. Mirrors the Java overload
    /// `create(Lifespan, Address, TracePlatform, DataType)`.
    fn create_unsized_on_platform(
        &mut self,
        lifespan: &dyn Lifespan,
        address: &Address,
        platform: &dyn TracePlatform,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException>;

    /// Create a data unit on the given register, using the trace's host platform.
    ///
    /// If the register is memory mapped, this will delegate to the appropriate space. In those
    /// cases, the assignment affects all threads. The type is resolved to the host platform,
    /// even if it already exists in the trace by another platform. Mirrors the Java default
    /// method `create(Lifespan, Register, DataType)`.
    fn create_on_register(
        &mut self,
        lifespan: &dyn Lifespan,
        register: &Register,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.create_on_platform_register(platform.as_ref(), lifespan, register, data_type)
    }

    /// Create a data unit on the given platform register.
    ///
    /// If the register is memory mapped, this will delegate to the appropriate space. In those
    /// cases, the assignment affects all threads. The type is resolved to the given platform,
    /// even if it already exists in the trace by another platform. Mirrors the Java overload
    /// `create(TracePlatform, Lifespan, Register, DataType)`.
    fn create_on_platform_register(
        &mut self,
        platform: &dyn TracePlatform,
        lifespan: &dyn Lifespan,
        register: &Register,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::docking::settings::settings::Settings;
    use crate::program::model::listing::data::Data;
    use crate::program::model::mem::MemBuffer;
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::guest::trace_platform_manager::TracePlatformManager;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    struct MockPlatform;
    impl TracePlatform for MockPlatform {}

    struct MockPlatformManager;
    impl TracePlatformManager for MockPlatformManager {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            Box::new(MockPlatform)
        }
    }

    struct MockTrace;
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
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
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {}
        fn get_emulator_cache_version(&self) -> i64 {
            0
        }
        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(&self) -> Box<dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            Box::new(MockPlatformManager)
        }
        fn get_memory_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(&self) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(&self) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager> {
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
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A minimal in-memory view backing store, only realistic enough to prove that `create`
    /// inserts units at the requested address/length and that the default
    /// `create_on_register` delegates to `create_on_platform_register` via the host platform.
    struct MockView {
        units: Vec<(Address, i32)>,
    }

    impl TraceBaseCodeUnitsView for MockView {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace)
        }

        fn size(&self) -> i32 {
            self.units.len() as i32
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

        fn contains_address(&self, _snap: i64, address: &Address) -> bool {
            self.units.iter().any(|(a, _)| a == address)
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

    impl TraceBaseDefinedUnitsView for MockView {
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

    impl TraceDefinedDataView for MockView {
        fn create_sized(
            &mut self,
            _lifespan: &dyn Lifespan,
            address: &Address,
            _data_type: &dyn DataType,
            length: i32,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            if self.units.iter().any(|(a, _)| a == address) {
                return Err(CodeUnitInsertionException::new("conflict"));
            }
            self.units.push((address.clone(), length));
            Ok(Box::new(MockData { address: address.clone(), length }))
        }

        fn create_sized_on_platform(
            &mut self,
            lifespan: &dyn Lifespan,
            address: &Address,
            _platform: &dyn TracePlatform,
            data_type: &dyn DataType,
            length: i32,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            self.create_sized(lifespan, address, data_type, length)
        }

        fn create_unsized(
            &mut self,
            lifespan: &dyn Lifespan,
            address: &Address,
            data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            self.create_sized(lifespan, address, data_type, 1)
        }

        fn create_unsized_on_platform(
            &mut self,
            lifespan: &dyn Lifespan,
            address: &Address,
            _platform: &dyn TracePlatform,
            data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            self.create_sized(lifespan, address, data_type, 1)
        }

        fn create_on_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            lifespan: &dyn Lifespan,
            register: &Register,
            data_type: &dyn DataType,
        ) -> Result<Box<dyn TraceData>, CodeUnitInsertionException> {
            self.create_sized(lifespan, register.address(), data_type, register.num_bytes())
        }
    }

    #[derive(Clone)]
    struct MockData {
        address: Address,
        length: i32,
    }

    impl MemBuffer for MockData {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }
    impl crate::program::model::util::PropertySet for MockData {}
    impl Settings for MockData {}
    impl crate::program::model::listing::code_unit::CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<std::sync::Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.add_wrap(self.length as i64 - 1)
        }
        fn get_mnemonic_string(&self) -> String {
            "db".to_string()
        }
        fn get_comment(
            &self,
            _comment_type: crate::program::model::listing::CommentType,
        ) -> Option<String> {
            None
        }
        fn get_comment_as_array(
            &self,
            _comment_type: crate::program::model::listing::CommentType,
        ) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(
            &mut self,
            _comment_type: crate::program::model::listing::CommentType,
            _comment: Option<String>,
        ) {
        }
        fn set_comment_as_array(
            &mut self,
            _comment_type: crate::program::model::listing::CommentType,
            _comment: &[String],
        ) {
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(vec![0u8; self.length as usize])
        }
        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            buffer.fill(0);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_operand_references(
            &self,
            _index: i32,
        ) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_primary_reference(
            &self,
            _index: i32,
        ) -> Option<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_external_reference(
            &self,
            _op_index: i32,
        ) -> Option<std::sync::Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(
            &mut self,
            _reference: std::sync::Arc<dyn crate::program::model::symbol::Reference>,
        ) {
        }
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }
    impl crate::program::model::listing::data::Data for MockData {
        fn get_value(&self) -> Option<Box<dyn std::any::Any>> {
            None
        }
        fn get_value_class(&self) -> Option<std::any::TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_value_references(&self) -> Vec<Box<dyn crate::program::seam_stubs::Reference>> {
            Vec::new()
        }
        fn add_value_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: Box<dyn crate::program::seam_stubs::RefType>,
        ) {
        }
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "mock".to_string()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            false
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn Data> {
            Box::new(self.clone())
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            0
        }
        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(
            &self,
            _options: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }
    impl TraceCodeUnit for MockData {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn crate::trace::seam_stubs::TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), self.address.add_wrap(self.length as i64 - 1))
        }
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start_snap(&self) -> i64 {
            0
        }
        fn set_end_snap(&mut self, _end_snap: i64) {}
        fn get_end_snap(&self) -> i64 {
            0
        }
        fn delete(&mut self) {}
    }
    impl TraceData for MockData {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct DummyLifespan;
    impl Lifespan for DummyLifespan {
        fn lmin(&self) -> i64 {
            0
        }
        fn lmax(&self) -> i64 {
            10
        }
        fn contains(&self, n: i64) -> bool {
            (0..=10).contains(&n)
        }
        fn with_min(&self, _min: i64) -> Box<dyn Lifespan> {
            Box::new(DummyLifespan)
        }
        fn with_max(&self, _max: i64) -> Box<dyn Lifespan> {
            Box::new(DummyLifespan)
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(0..=10)
        }
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    #[test]
    fn usable_as_trait_object_and_creates_at_address() {
        let mut view: Box<dyn TraceDefinedDataView> =
            Box::new(MockView { units: Vec::new() });

        let created = view
            .create_sized(&DummyLifespan, &addr(0x400), &MockDataType, 4)
            .expect("create should succeed for a fresh address");
        assert_eq!(created.get_min_address(), addr(0x400));
        assert_eq!(created.get_length(), 4);
        assert_eq!(view.size(), 1);

        let conflict = view.create_sized(&DummyLifespan, &addr(0x400), &MockDataType, 4);
        assert!(conflict.is_err(), "creating at an already-occupied address must fail");
    }

    #[test]
    fn create_on_register_delegates_to_host_platform_register() {
        let mut view: Box<dyn TraceDefinedDataView> =
            Box::new(MockView { units: Vec::new() });

        let register = Register::no_context();
        let reg = register.borrow();
        let created = view
            .create_on_register(&DummyLifespan, &reg, &MockDataType)
            .expect("create_on_register should succeed");
        assert_eq!(created.get_min_address(), *reg.address());
    }
}
