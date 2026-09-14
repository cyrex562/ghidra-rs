//! Port of `ghidra.app.plugin.core.functionwindow.FunctionRowObjectToAddressTableRowMapper`.

use crate::app::plugin::core::function_window::FunctionRowObject;
use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::util::seam_stubs::TableRowMapper;
use crate::util::table::ProgramLocationTableRowMapper;

/// Maps a [`FunctionRowObject`] to its function's entry point [`Address`], letting columns
/// designed for address tables be reused by the Function table.
///
/// Port of `ghidra.app.plugin.core.functionwindow.FunctionRowObjectToAddressTableRowMapper`,
/// which `extends ProgramLocationTableRowMapper<FunctionRowObject, Address>`. As with this
/// crate's other row-mapper ports (e.g.
/// [`FunctionToAddressTableRowMapper`](crate::app::plugin::core::function_window::function_to_address_table_row_mapper::FunctionToAddressTableRowMapper)),
/// the Java `extends` becomes implementing [`TableRowMapper`] plus a blanket, field-less impl of
/// [`ProgramLocationTableRowMapper`] to pick up its default methods.
///
/// Java's `map` reads `rowObject.getFunction()` and returns `null` if it is `null` before calling
/// `getEntryPoint()`. [`FunctionRowObject::get_function`] always returns a valid
/// `&Arc<dyn Function>` (there is no null `Function` state to check for in this port), so that
/// defensive null check has no Rust equivalent here -- it was dead code for this port's
/// `FunctionRowObject` regardless, since every `FunctionRowObject` is constructed around a
/// concrete function.
///
/// NOTE: as in the Java original, real implementors' type names must end in `TableRowMapper` for
/// Ghidra's `ClassSearcher` extension-point discovery to find them.
pub struct FunctionRowObjectToAddressTableRowMapper;

impl TableRowMapper<FunctionRowObject, Address> for FunctionRowObjectToAddressTableRowMapper {
    fn map(
        &self,
        row_object: &FunctionRowObject,
        _data: &dyn Program,
        _service_provider: &dyn ServiceProvider,
    ) -> Address {
        row_object.get_function().get_entry_point()
    }
}

impl ProgramLocationTableRowMapper<FunctionRowObject, Address>
    for FunctionRowObjectToAddressTableRowMapper
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::ServiceListener;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockServiceProvider;
    impl ServiceProvider for MockServiceProvider {
        fn get_service(&self, _service_class: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn add_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
        fn remove_service_listener(&mut self, _listener: Box<dyn ServiceListener>) {}
    }

    struct MockSymbol;
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            unimplemented!()
        }
        fn get_name(&self) -> &str {
            "mock_fn"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Function
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockFunction {
        entry_point: Address,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol)
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl crate::program::model::listing::Function for MockFunction {
        fn get_name(&self) -> String {
            "mock_fn".to_string()
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
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
            self.entry_point.clone()
        }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            struct MockSignature;
            impl crate::program::model::listing::FunctionSignature for MockSignature {
                fn get_name(&self) -> String {
                    String::new()
                }

                fn get_prototype_string_with_calling_convention(
                    &self,
                    _include_calling_convention: bool,
                ) -> String {
                    String::new()
                }

                fn get_arguments(
                    &self,
                ) -> Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>>
                {
                    Vec::new()
                }

                fn get_return_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
                    unimplemented!()
                }

                fn get_comment(&self) -> Option<String> {
                    None
                }

                fn has_var_args(&self) -> bool {
                    false
                }

                fn has_no_return(&self) -> bool {
                    false
                }

                fn get_calling_convention(
                    &self,
                ) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
                    None
                }

                fn get_calling_convention_name(&self) -> String {
                    String::new()
                }

                fn is_equivalent_signature(
                    &self,
                    _signature: &dyn crate::program::model::listing::FunctionSignature,
                ) -> bool {
                    false
                }
            }
            Box::new(MockSignature)
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            "mock_fn".to_string()
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            Vec::new()
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }

        fn remove_tag(&mut self, _name: &str) {}

        fn set_stack_purge_size(&mut self, _purge_size: i32) {}

        fn is_stack_purge_size_valid(&self) -> bool {
            false
        }

        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!()
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!()
        }

        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}

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

        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            crate::program::model::listing::function::UNKNOWN_CALLING_CONVENTION_STRING.to_string()
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(
            &self,
            _recursive: bool,
        ) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }

        fn get_function_thunk_addresses(
            &self,
            _recursive: bool,
        ) -> Option<Vec<crate::program::model::address::Address>> {
            None
        }

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn crate::program::model::listing::Function>>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_calling_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            Vec::new()
        }

        fn get_called_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::listing::Function>> {
            Vec::new()
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn function_row_object(entry_point: Address) -> FunctionRowObject {
        let function: Arc<dyn crate::program::model::listing::Function> =
            Arc::new(MockFunction { entry_point });
        FunctionRowObject::new(function)
    }

    #[test]
    fn map_returns_the_functions_entry_point() {
        let mapper = FunctionRowObjectToAddressTableRowMapper;
        let row = function_row_object(ram_address(0x400000));
        let program = MockProgram;
        let provider = MockServiceProvider;

        let mapped = mapper.map(&row, &program, &provider);

        assert_eq!(mapped, ram_address(0x400000));
    }

    #[test]
    fn different_row_objects_map_to_their_own_entry_points() {
        let mapper = FunctionRowObjectToAddressTableRowMapper;
        let program = MockProgram;
        let provider = MockServiceProvider;

        let a = function_row_object(ram_address(0x1000));
        let b = function_row_object(ram_address(0x2000));

        assert_eq!(mapper.map(&a, &program, &provider), ram_address(0x1000));
        assert_eq!(mapper.map(&b, &program, &provider), ram_address(0x2000));
    }
}
