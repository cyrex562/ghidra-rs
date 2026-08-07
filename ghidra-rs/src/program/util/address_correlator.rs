use crate::framework::options::Options;
use crate::framework::seam_stubs::ToolOptions;
use crate::program::model::listing::{Data, Function};
use crate::program::util::address_correlation::AddressCorrelation;

/// The default priority. This applies to client-supplied [`DiscoverableAddressCorrelator`](
/// crate::program::util::discoverable_address_correlator::DiscoverableAddressCorrelator)s.
pub const DEFAULT_PRIORITY: i32 = 500;

/// A high priority (low number value) for correlators that should be used before other
/// correlators.
pub const EARLY_PRIORITY: i32 = 100;

/// A low priority (high number value) for correlators that should be used after other
/// correlators.
pub const LATE_CHANCE_PRIORITY: i32 = 1000;

/// A value used to raise or lower priorities.
pub const PRIORITY_OFFSET: i32 = 10;

/// Interface for address correlation algorithms that can generate an address mapping from one
/// set of program addresses to another.
///
/// Port of `ghidra.program.util.AddressCorrelator`.
///
/// This trait supplies a [`get_priority`](AddressCorrelator::get_priority) of
/// [`DEFAULT_PRIORITY`]. `DiscoverableAddressCorrelator` implementors can change this priority to
/// a lower value to be run before the supplied system correlators. Generally, the more specific
/// or restrictive a correlator, the earlier (higher priority) it should be.
///
/// The two Java `correlate` overloads (for `Function` and `Data` sources) are split into
/// [`correlate_functions`](AddressCorrelator::correlate_functions) and
/// [`correlate_data`](AddressCorrelator::correlate_data) since Rust traits do not support method
/// overloading.
///
/// Selected as a dependency-cycle cut-point.
pub trait AddressCorrelator {
    /// Returns an address mapping from one function to another.
    ///
    /// # Arguments
    /// * `source_function` - the source function.
    /// * `destination_function` - the destination function.
    ///
    /// # Returns
    /// An [`AddressCorrelation`] that represents a mapping of the addresses from the source
    /// function to the destination function, or `None` if this correlator could not produce one.
    fn correlate_functions(
        &self,
        source_function: &dyn Function,
        destination_function: &dyn Function,
    ) -> Option<Box<dyn AddressCorrelation>>;

    /// Returns an address mapping from one piece of data to another.
    ///
    /// # Arguments
    /// * `source_data` - the source data.
    /// * `destination_data` - the destination data.
    ///
    /// # Returns
    /// An [`AddressCorrelation`] that represents a mapping of the addresses from the source data
    /// to the destination data, or `None` if this correlator could not produce one.
    fn correlate_data(
        &self,
        source_data: &dyn Data,
        destination_data: &dyn Data,
    ) -> Option<Box<dyn AddressCorrelation>>;

    /// Returns the current option settings for this correlator.
    fn get_options(&self) -> Box<dyn ToolOptions>;

    /// Sets the options to use for this correlator.
    fn set_options(&mut self, options: Box<dyn ToolOptions>);

    /// Returns the options with the default settings for this correlator.
    fn get_default_options(&self) -> Box<dyn Options>;

    /// Returns a number based on an arbitrary number scheme that dictates the order that
    /// correlators should be used. If a correlator returns `None` from one of the `correlate_*`
    /// methods, then the next highest priority correlator will be called, and so on until a
    /// non-`None` correlation is found or all correlators have been called.
    ///
    /// A lower number value is a higher priority. See [`DEFAULT_PRIORITY`].
    fn get_priority(&self) -> i32 {
        DEFAULT_PRIORITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Variable};
    use crate::program::model::symbol::{
        ExternalLocation, ExternalReference, Namespace, Reference, SourceType, Symbol, SymbolType,
    };
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::seam_stubs::{AddressCorrelationRangeLike, RefType as SeamRefType, Reference as SeamReference, StackFrame, VariableFilter};
use crate::program::model::listing::CommentType;
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::util::exception::{CancelledException, InvalidInputException};
    use crate::util::task::TaskMonitor;
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    fn ram_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct StubToolOptions;
    impl ToolOptions for StubToolOptions {}

    struct FixedRange {
        min: Address,
        range: crate::program::model::address::AddressRange,
    }

    impl AddressCorrelationRangeLike for FixedRange {
        fn min_address(&self) -> Address {
            self.min.clone()
        }

        fn range(&self) -> crate::program::model::address::AddressRange {
            self.range.clone()
        }

        fn correlator_name(&self) -> String {
            "PriorityCorrelator".to_string()
        }
    }

    struct ConstantCorrelation {
        space: Arc<AddressSpace>,
    }

    impl AddressCorrelation for ConstantCorrelation {
        fn get_correlated_destination_range(
            &self,
            _source_address: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn AddressCorrelationRangeLike>>, CancelledException> {
            monitor.check_cancelled()?;
            let min = Address::new(self.space.clone(), 0x3000);
            let max = Address::new(self.space.clone(), 0x3010);
            let range = crate::program::model::address::AddressRange::new(min.clone(), max);
            Ok(Some(Box::new(FixedRange { min, range })))
        }
    }

    /// A correlator that only ever matches functions, never data, and reports a
    /// non-default priority -- exercising every trait method with real behavior.
    struct PriorityCorrelator {
        space: Arc<AddressSpace>,
        priority: i32,
    }

    impl AddressCorrelator for PriorityCorrelator {
        fn correlate_functions(
            &self,
            _source_function: &dyn Function,
            _destination_function: &dyn Function,
        ) -> Option<Box<dyn AddressCorrelation>> {
            Some(Box::new(ConstantCorrelation { space: self.space.clone() }))
        }

        fn correlate_data(
            &self,
            _source_data: &dyn Data,
            _destination_data: &dyn Data,
        ) -> Option<Box<dyn AddressCorrelation>> {
            None
        }

        fn get_options(&self) -> Box<dyn ToolOptions> {
            Box::new(StubToolOptions)
        }

        fn set_options(&mut self, _options: Box<dyn ToolOptions>) {}

        fn get_default_options(&self) -> Box<dyn Options> {
            struct EmptyOptions;
            impl Options for EmptyOptions {}
            Box::new(EmptyOptions)
        }

        fn get_priority(&self) -> i32 {
            self.priority
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn trait_object_creation() {
        let corr = PriorityCorrelator { space: test_space(), priority: EARLY_PRIORITY };
        let boxed: Box<dyn AddressCorrelator> = Box::new(corr);
        assert_eq!(boxed.get_priority(), EARLY_PRIORITY);
    }

    #[test]
    fn correlate_functions_returns_mapping_while_data_is_unhandled() {
        let mut corr = PriorityCorrelator { space: test_space(), priority: DEFAULT_PRIORITY };

        let space = test_space();
        let source = Address::new(space, 0x1000);
        let monitor = crate::util::task::DummyMonitor;

        // Function correlation succeeds and yields the constant mapping.
        let mapping = corr
            .correlate_functions(&MockFunction, &MockFunction)
            .expect("function correlation present");
        let range = mapping
            .get_correlated_destination_range(&source, &monitor)
            .expect("not cancelled")
            .expect("range present");
        assert_eq!(range.min_address().offset(), 0x3000);

        // Data correlation is unhandled by this correlator.
        assert!(corr.correlate_data(&MockData, &MockData).is_none());

        // Priority reflects what this correlator was constructed with, not the trait default.
        assert_eq!(corr.get_priority(), DEFAULT_PRIORITY);
        assert_ne!(corr.get_priority(), EARLY_PRIORITY);
        corr.set_options(Box::new(StubToolOptions));
        let _ = corr.get_options();
        let _ = corr.get_default_options();
    }

    // Minimal `Function` stand-in, only used as an opaque `&dyn Function` argument; none of its
    // methods are called by `PriorityCorrelator`.
    struct MockFunction;

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!()
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            ram_address(0x100)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!()
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, _purge_size: i32) {}
        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn is_inline(&self) -> bool {
            false
        }
        fn set_inline(&mut self, _is_inline: bool) {}
        fn has_no_return(&self) -> bool {
            false
        }
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn has_custom_variable_storage(&self) -> bool {
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn is_thunk(&self) -> bool {
            false
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    // Minimal `Data` stand-in, only used as an opaque `&dyn Data` argument; none of its methods
    // are called by `PriorityCorrelator`.
    struct MockData;

    impl crate::program::seam_stubs::MemBuffer for MockData {
        fn get_address(&self) -> Address {
            ram_address(0)
        }
    }
    impl crate::program::model::util::PropertySet for MockData {}

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
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
            ram_address(0)
        }
        fn get_max_address(&self) -> Address {
            ram_address(0)
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
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

    impl crate::docking::settings::settings::Settings for MockData {}

    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
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
            struct MockDataType;
            impl DataType for MockDataType {}
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            struct MockDataType;
            impl DataType for MockDataType {}
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn SeamReference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn SeamRefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            String::new()
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
            Box::new(MockData)
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
}
