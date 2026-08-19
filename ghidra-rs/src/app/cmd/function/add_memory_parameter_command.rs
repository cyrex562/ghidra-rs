use std::cmp::Ordering;
use std::sync::Arc;

use crate::app::cmd::function::add_parameter_command::{AddParameterCommand, AddParameterCommandBase};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::function::DEFAULT_PARAM_PREFIX;
use crate::program::model::listing::parameter::UNASSIGNED_ORDINAL;
use crate::program::model::listing::parameter_impl::ParameterImpl;
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::variable_impl::{init_fields, VariableImpl};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::{AutoParameterType, Function, Parameter, Program, Variable};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{SourceType, Symbol};
use crate::program::seam_stubs::share_data_type;
use crate::util::exception::InvalidInputException;

/// Mirrors `SymbolUtilities.isDefaultParameterName(String)`, duplicated locally rather than
/// growing the unrelated `symbol_utilities` module, exactly as
/// [`parameter_impl::is_default_parameter_name`](crate::program::model::listing::parameter_impl)
/// (private to that module) already does for the sibling `ParameterImpl` port.
fn has_default_param_name(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return true;
    };
    if name.is_empty() {
        return true;
    }
    match name.strip_prefix(DEFAULT_PARAM_PREFIX) {
        Some(tail) => tail.parse::<i32>().is_ok(),
        None => false,
    }
}

/// Concrete [`Parameter`] with a single memory-address storage element, built by
/// [`AddMemoryParameterCommand::get_parameter`]. Port of the object produced by
/// `new ParameterImpl(name, dataType, memAddr, program)`: an unassigned-ordinal parameter whose
/// storage/data type validation is performed by [`init_fields`], the already-ported
/// `VariableImpl` construction algorithm.
struct MemoryParameter {
    name: Option<String>,
    data_type: Arc<dyn DataType>,
    comment: Option<String>,
    source_type: SourceType,
    storage: Option<Box<dyn VariableStorage>>,
    program: Arc<dyn Program>,
}

impl VariableImpl for MemoryParameter {
    fn stored_name(&self) -> Option<String> {
        self.name.clone()
    }

    fn set_stored_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    fn stored_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.data_type = Arc::from(data_type);
    }

    fn stored_comment(&self) -> Option<String> {
        self.comment.clone()
    }

    fn set_stored_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    fn stored_source_type(&self) -> SourceType {
        self.source_type
    }

    fn set_stored_source_type(&mut self, source_type: SourceType) {
        self.source_type = source_type;
    }

    fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.storage
            .as_ref()
            .map(|s| s.with_varnodes(s.get_varnodes()))
    }

    fn set_stored_variable_storage(&mut self, storage: Option<Box<dyn VariableStorage>>) {
        self.storage = storage;
    }

    fn has_default_name(&self) -> bool {
        has_default_param_name(self.name.as_deref())
    }
}

impl ParameterImpl for MemoryParameter {
    fn stored_ordinal(&self) -> i32 {
        UNASSIGNED_ORDINAL
    }
}

impl Variable for MemoryParameter {
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.parameter_impl_get_data_type()
    }

    fn set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type_with_storage(data_type, storage, force, source)
    }

    fn set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type(data_type, source)
    }

    fn set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        align_stack: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type_aligned(data_type, align_stack, force, source)
    }

    fn get_name(&self) -> Option<String> {
        self.variable_impl_get_name()
    }

    fn get_length(&self) -> i32 {
        self.variable_impl_get_length()
    }

    fn is_valid(&self) -> bool {
        self.variable_impl_is_valid()
    }

    fn get_function(&self) -> Option<Box<dyn Function>> {
        self.variable_impl_get_function()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_source(&self) -> SourceType {
        self.variable_impl_get_source()
    }

    fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
        self.variable_impl_set_name(name, source)
    }

    fn get_comment(&self) -> Option<String> {
        self.variable_impl_get_comment()
    }

    fn set_comment(&mut self, comment: Option<String>) {
        self.variable_impl_set_comment(comment)
    }

    fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.variable_impl_get_variable_storage()
    }

    fn get_first_storage_varnode(&self) -> Option<Varnode> {
        self.variable_impl_get_first_storage_varnode()
    }

    fn get_last_storage_varnode(&self) -> Option<Varnode> {
        self.variable_impl_get_last_storage_varnode()
    }

    fn is_stack_variable(&self) -> bool {
        self.variable_impl_is_stack_variable()
    }

    fn has_stack_storage(&self) -> bool {
        self.variable_impl_has_stack_storage()
    }

    fn is_register_variable(&self) -> bool {
        self.variable_impl_is_register_variable()
    }

    fn get_register(&self) -> Option<RegisterRef> {
        self.variable_impl_get_register()
    }

    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.variable_impl_get_registers()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.variable_impl_get_min_address()
    }

    fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        self.variable_impl_get_stack_offset()
    }

    fn is_memory_variable(&self) -> bool {
        self.variable_impl_is_memory_variable()
    }

    fn is_unique_variable(&self) -> bool {
        self.variable_impl_is_unique_variable()
    }

    fn is_compound_variable(&self) -> bool {
        self.variable_impl_is_compound_variable()
    }

    fn has_assigned_storage(&self) -> bool {
        self.variable_impl_has_assigned_storage()
    }

    fn get_first_use_offset(&self) -> i32 {
        self.parameter_impl_get_first_use_offset()
    }

    fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        None
    }

    fn is_equivalent(&self, variable: &dyn Variable) -> bool {
        self.variable_impl_is_equivalent(variable)
    }

    fn compare_to(&self, other: &dyn Variable) -> Ordering {
        self.variable_impl_compare_to(other)
    }

    fn is_parameter(&self) -> bool {
        true
    }

    fn is_auto_parameter(&self) -> bool {
        self.parameter_impl_is_auto_parameter()
    }

    fn parameter_ordinal(&self) -> Option<i32> {
        Some(self.stored_ordinal())
    }
}

impl Parameter for MemoryParameter {
    fn get_ordinal(&self) -> i32 {
        self.parameter_impl_get_ordinal()
    }

    fn is_auto_parameter(&self) -> bool {
        self.parameter_impl_is_auto_parameter()
    }

    fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
        self.parameter_impl_get_auto_parameter_type()
    }

    fn is_forced_indirect(&self) -> bool {
        self.parameter_impl_is_forced_indirect()
    }

    fn get_formal_data_type(&self) -> Box<dyn DataType> {
        self.parameter_impl_get_formal_data_type()
    }
}

/// A command to create a new function memory parameter.
///
/// Port of `ghidra.app.cmd.function.AddMemoryParameterCommand`.
///
/// # Deprecation
///
/// Function signatures should be modified in their entirety using either
/// `UpdateFunctionCommand` or `ApplyFunctionSignatureCmd`.
#[deprecated(
    since = "11.1",
    note = "use UpdateFunctionCommand or ApplyFunctionSignatureCmd instead"
)]
pub struct AddMemoryParameterCommand {
    #[allow(deprecated)]
    base: AddParameterCommandBase,
    mem_addr: Address,
    name: Option<String>,
    data_type: Arc<dyn DataType>,
}

#[allow(deprecated)]
impl AddMemoryParameterCommand {
    /// Java: the public 6-arg constructor.
    pub fn new(
        function: Arc<dyn Function>,
        mem_addr: Address,
        name: Option<String>,
        data_type: Box<dyn DataType>,
        ordinal: i32,
        source: SourceType,
    ) -> Self {
        AddMemoryParameterCommand {
            base: AddParameterCommandBase::without_parameter(function, ordinal, source),
            mem_addr,
            name,
            data_type: Arc::from(data_type),
        }
    }
}

#[allow(deprecated)]
impl AddParameterCommand for AddMemoryParameterCommand {
    fn base(&self) -> &AddParameterCommandBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut AddParameterCommandBase {
        &mut self.base
    }

    /// Port of `AddMemoryParameterCommand.getName`.
    fn command_name(&self) -> String {
        "Create Memory Parameter".to_string()
    }

    /// Port of `AddMemoryParameterCommand.getParameter`:
    /// `return new ParameterImpl(name, dataType, memAddr, program);`
    fn get_parameter(
        &mut self,
        program: &dyn Program,
    ) -> Result<Box<dyn Parameter>, InvalidInputException> {
        let has_default_name = has_default_param_name(self.name.as_deref());
        let fields = init_fields(
            self.name.clone(),
            share_data_type(&self.data_type),
            None,
            Some(self.mem_addr.clone()),
            None,
            None,
            false,
            program,
            SourceType::UserDefined,
            false,
            has_default_name,
        )?;
        Ok(Box::new(MemoryParameter {
            name: fields.name,
            data_type: Arc::from(fields.data_type),
            comment: None,
            source_type: fields.source_type,
            storage: Some(fields.variable_storage),
            program: self.base.function.get_program(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::cmd::Command;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::listing::function::{FunctionUpdateType, SetFunctionNameError};
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::model::listing::{FunctionSignature, FunctionTag};
    use crate::program::model::symbol::Namespace;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function::FunctionEditError;
    use crate::program::seam_stubs::StackFrame;
    use crate::program::database::OverlappingFunctionException;
    use crate::util::task::TaskMonitor;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            "int".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            None
        }
    }

    #[allow(dead_code)]
    struct MockFunction {
        entry_point: Address,
        program: Arc<dyn Program>,
    }

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
            "mock_function".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            self.entry_point.clone()
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
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
            Ok(())
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            vec![]
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            true
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
            unimplemented!("not exercised by this module's tests")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
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
            vec![]
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            vec![]
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
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
        ) -> Result<(), OverlappingFunctionException> {
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
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    fn function_and_its_program() -> (Arc<dyn Function>, Arc<MockProgram>) {
        let program = Arc::new(MockProgram);
        let function: Arc<dyn Function> = Arc::new(MockFunction {
            entry_point: addr(0x1000),
            program: program.clone(),
        });
        (function, program)
    }

    fn as_mut_program(program: &Arc<MockProgram>) -> &mut (dyn Program + 'static) {
        let ptr = Arc::as_ptr(program) as *mut MockProgram;
        unsafe { &mut *ptr }
    }

    #[test]
    fn name_matches_java_get_name() {
        let (function, _program) = function_and_its_program();
        let cmd = AddMemoryParameterCommand::new(
            function,
            addr(0x2000),
            Some("p1".to_string()),
            Box::new(MockDataType { length: 4 }),
            0,
            SourceType::UserDefined,
        );
        assert_eq!(cmd.name(), "Create Memory Parameter");
    }

    #[test]
    fn get_parameter_builds_memory_storage_at_mem_addr() {
        let (function, program) = function_and_its_program();
        let mut cmd = AddMemoryParameterCommand::new(
            function,
            addr(0x2000),
            Some("p1".to_string()),
            Box::new(MockDataType { length: 4 }),
            0,
            SourceType::UserDefined,
        );
        let parameter = cmd.get_parameter(as_mut_program(&program)).unwrap();
        assert_eq!(parameter.get_name(), Some("p1".to_string()));
        assert_eq!(parameter.get_length(), 4);
        assert!(parameter.is_memory_variable());
        assert_eq!(
            parameter.get_first_storage_varnode().unwrap().get_address(),
            &addr(0x2000)
        );
        assert_eq!(Parameter::get_ordinal(parameter.as_ref()), UNASSIGNED_ORDINAL);
    }

    #[test]
    fn get_parameter_default_name_gets_default_source() {
        let (function, program) = function_and_its_program();
        let mut cmd = AddMemoryParameterCommand::new(
            function,
            addr(0x2000),
            None,
            Box::new(MockDataType { length: 4 }),
            0,
            SourceType::UserDefined,
        );
        let parameter = cmd.get_parameter(as_mut_program(&program)).unwrap();
        assert_eq!(parameter.get_source(), SourceType::Default);
    }
}
