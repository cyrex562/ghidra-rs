//! Port of `ghidra.trace.database.listing.DBTraceData`.

use crate::trace::seam_stubs::DBTraceDefinedDataAdapter;

/// The implementation for a defined
/// [`TraceData`](crate::trace::model::listing::trace_data::TraceData) for a trace.
///
/// Port of `ghidra.trace.database.listing.DBTraceData`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java class extends the (DB-record-backed) `AbstractDBTraceCodeUnit<DBTraceData>` and
/// implements [`DBTraceDefinedDataAdapter`]. Of its many `@Override` methods, all but one either:
/// - implement a member already declared abstractly by a supertrait reachable from
///   [`DBTraceDefinedDataAdapter`] (`getPlatform`, `delete`, `setEndSnap`, `getLanguage` from
///   `TraceCodeUnit`; `getDataType`, `getBaseDataType`, `getRootOffset`, `getParentOffset`,
///   `getComponentPath`, `getComponentIndex`, `getComponentLevel`, `getFieldName`, `getPathName()`,
///   `getComponentPathName` from `Data`; `getSettingsSpace` from
///   [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter);
///   `getDefaultSettings` from `Settings`), or
/// - exist purely to covariantly narrow an inherited `Data` member's return type (`getParent` to
///   `DBTraceDefinedDataAdapter`, `getRoot` to `DBTraceData` itself), which Rust cannot re-declare
///   (see [`TraceData`](crate::trace::model::listing::trace_data::TraceData)'s docs for the same
///   issue), or
/// - is the abstract `doGetComponentCache()` this class must implement, declared on
///   [`DBTraceDefinedDataAdapter`] rather than here since that's where the Java interface declares
///   it.
///
/// The one exception -- `toString()` -- has no counterpart anywhere in the supertrait chain, so it
/// alone is declared as this trait's own member.
///
/// The static helper `DBTraceData.getBaseDataType(DataType)` and the protected/package-private
/// members (the constructor, `fresh`, `setRecordValue`, `getRecordValue`, `set`,
/// `getDataTypeLength`, the static `tableName`) are DB-record implementation details, not part of
/// the public instance API, so none are reproduced here.
pub trait DBTraceData: DBTraceDefinedDataAdapter {
    /// Mirrors `DBTraceData.toString()` (`doToString()`).
    fn to_string(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::docking::settings::settings_definition::SettingsDefinition;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::Language;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, ReferenceIterator, SourceType as SymSourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType as StubRefType, Reference as StubReference};
    use crate::trace::database::data::db_trace_data_settings_operations::DBTraceDataSettingsOperations;
    use crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::listing::trace_data::TraceData;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{
        AbstractDBTraceDataComponent, DBTraceCodeUnitAdapter, DataAdapterFromDataType, TraceChangeRecord,
        TracePlatform, TraceThread,
    };
    use crate::trace::util::data_adapter_minimal::DataAdapterMinimal;
    use crate::trace::util::trace_change_manager::TraceChangeManager;
    use std::any::Any;
    use std::sync::Arc;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockStubReference;
    impl StubReference for MockStubReference {}

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockReferenceIterator;
    impl ReferenceIterator for MockReferenceIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn next_reference(&mut self) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }
    }

    struct MockChangeManager;
    impl TraceChangeManager for MockChangeManager {
        fn set_changed(&mut self, _event: Box<dyn TraceChangeRecord>) {}
    }

    struct MockTrace;
    impl crate::framework::model::DomainObject for MockTrace {}
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceAddressPropertyManager> {
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
        fn get_platform_manager(&self) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
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
        fn get_register_context_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(&self) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(&self) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
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
        fn create_program_view(&self, _snap: i64) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn crate::trace::model::program::TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(&self) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(&self) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(&mut self, _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_program_view_listener(&mut self, _listener: &dyn crate::trace::model::trace::TraceProgramViewListener) {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_read(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(&self) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A data unit, standing in for `DBTraceData`: an address, a fixed length, a lifespan, and a
    /// name -- enough to prove [`DBTraceData::to_string`]'s behavior and the trait's
    /// object-safety, without wiring up the full DB-backed machinery this stub's real port would
    /// need.
    struct MockDataUnit {
        address: Address,
        length: i32,
        start_snap: i64,
        end_snap: i64,
        name: String,
    }

    impl MemBuffer for MockDataUnit {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
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

    impl PropertySet for MockDataUnit {}

    impl Settings for MockDataUnit {
        fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
            None
        }
    }

    impl CodeUnit for MockDataUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "db".to_string()
        }
        fn get_comment(&self, _comment_type: crate::program::model::listing::CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: crate::program::model::listing::CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x00; self.length as usize])
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            buffer.fill(0x00);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: SymRefType, _source_type: SymSourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: SymRefType, _source_type: SymSourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SymSourceType, _ref_type: SymRefType) {}
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SymSourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Data for MockDataUnit {
        fn get_value(&self) -> Option<Box<dyn Any>> {
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
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn StubReference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn StubRefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            self.name.clone()
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
            unimplemented!("not exercised by these tests")
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
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    impl TraceCodeUnit for MockDataUnit {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace)
        }
        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by these tests")
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by these tests")
        }
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by these tests")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), addr(self.address.offset() + self.length as i64 - 1))
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.start_snap, self.end_snap)
        }
        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }
        fn set_end_snap(&mut self, end_snap: i64) {
            self.end_snap = end_snap;
        }
        fn get_end_snap(&self) -> i64 {
            self.end_snap
        }
        fn delete(&mut self) {}
    }

    impl TraceData for MockDataUnit {}
    impl DataAdapterMinimal for MockDataUnit {}
    impl DataAdapterFromDataType for MockDataUnit {}

    impl DBTraceCodeUnitAdapter for MockDataUnit {
        fn trace_change_manager(&mut self) -> &mut dyn TraceChangeManager {
            unimplemented!("not exercised by these tests")
        }
    }

    impl DBTraceDataAdapter for MockDataUnit {
        fn get_settings_space(&self, _create_if_absent: bool) -> Option<Box<dyn DBTraceDataSettingsOperations>> {
            None
        }
    }

    impl DBTraceDefinedDataAdapter for MockDataUnit {
        fn do_get_component_cache(&self) -> Vec<Box<dyn AbstractDBTraceDataComponent>> {
            Vec::new()
        }

        fn append_path_name(&self, builder: &mut String, include_root_symbol: bool) {
            if include_root_symbol {
                builder.push_str(&self.name);
            }
        }
    }

    impl DBTraceData for MockDataUnit {
        fn to_string(&self) -> String {
            format!("{} {}", Data::get_path_name(self), self.get_length())
        }
    }


    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_data(name: &str) -> MockDataUnit {
        MockDataUnit {
            address: addr(0x400),
            length: 4,
            start_snap: 0,
            end_snap: 10,
            name: name.to_string(),
        }
    }

    #[test]
    fn is_object_safe() {
        fn assert_object_safe(_: &dyn DBTraceData) {}
        assert_object_safe(&make_data("DAT_00000400"));
    }

    #[test]
    fn to_string_combines_path_name_and_length() {
        let data = make_data("DAT_00000400");
        assert_eq!(DBTraceData::to_string(&data), "DAT_00000400 4");
    }

    #[test]
    fn usable_as_trait_object_reaching_every_supertrait() {
        let data: Box<dyn DBTraceData> = Box::new(make_data("my_symbol"));

        // DBTraceData's own member.
        assert_eq!(DBTraceData::to_string(data.as_ref()), "my_symbol 4");

        // DBTraceDefinedDataAdapter (supertrait) member.
        assert!(data.do_get_component_cache().is_empty());
        let mut builder = String::new();
        data.append_path_name(&mut builder, true);
        assert_eq!(builder, "my_symbol");

        // TraceCodeUnit (transitive supertrait) member.
        assert_eq!(data.get_start_snap(), 0);

        // Data (transitive supertrait) member.
        assert_eq!(Data::get_path_name(data.as_ref()), "my_symbol");
    }
}
