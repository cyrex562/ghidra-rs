use std::sync::Arc;

use crate::framework::cmd::Command;
use crate::program::model::listing::function::FunctionEditError;
use crate::program::model::listing::{Function, Parameter, Program};
use crate::program::model::symbol::SourceType;
use crate::util::exception::InvalidInputException;

/// Shared state and concrete behaviour for [`AddParameterCommand`] implementors.
///
/// Corresponds to the fields and `final applyTo` method of
/// `ghidra.app.cmd.function.AddParameterCommand`, which is itself a concrete, directly
/// instantiable class that `AddRegisterParameterCommand`, `AddStackParameterCommand` and
/// `AddMemoryParameterCommand` extend to override only [`AddParameterCommand::get_parameter`].
///
/// # Deprecation
///
/// Function signatures should be modified in their entirety using either
/// `UpdateFunctionCommand` or `ApplyFunctionSignatureCmd`.
#[deprecated(
    since = "11.1",
    note = "use UpdateFunctionCommand or ApplyFunctionSignatureCmd instead"
)]
pub struct AddParameterCommandBase {
    pub function: Arc<dyn Function>,
    pub ordinal: i32,
    pub source: SourceType,
    parameter: Option<Box<dyn Parameter>>,
    pub status_message: Option<String>,
}

#[allow(deprecated)]
impl AddParameterCommandBase {
    /// Java: the public 4-arg constructor.
    pub fn new(
        function: Arc<dyn Function>,
        parameter: Box<dyn Parameter>,
        ordinal: i32,
        source: SourceType,
    ) -> Self {
        AddParameterCommandBase {
            function,
            ordinal,
            source,
            parameter: Some(parameter),
            status_message: None,
        }
    }

    /// Java: the protected 3-arg constructor, which allows subclasses to use this base
    /// without having already created a `Parameter` (they build one in
    /// [`AddParameterCommand::get_parameter`] instead).
    pub(crate) fn without_parameter(function: Arc<dyn Function>, ordinal: i32, source: SourceType) -> Self {
        AddParameterCommandBase {
            function,
            ordinal,
            source,
            parameter: None,
            status_message: None,
        }
    }
}

/// Overridable hook for producing the parameter to be added.
///
/// Corresponds to `ghidra.app.cmd.function.AddParameterCommand.getParameter`, the only method
/// left non-`final` for subclasses to override.
///
/// # See also
/// `AddRegisterParameterCommand`, `AddStackParameterCommand`, `AddMemoryParameterCommand`.
#[deprecated(
    since = "11.1",
    note = "use UpdateFunctionCommand or ApplyFunctionSignatureCmd instead"
)]
pub trait AddParameterCommand {
    #[allow(deprecated)]
    fn base(&self) -> &AddParameterCommandBase;
    #[allow(deprecated)]
    fn base_mut(&mut self) -> &mut AddParameterCommandBase;

    /// Get the parameter to be added.
    ///
    /// The default implementation returns the parameter supplied at construction time.
    ///
    /// # Errors
    /// Returns `Err` if unable to generate the parameter due to invalid data.
    #[allow(deprecated)]
    fn get_parameter(
        &mut self,
        _program: &dyn Program,
    ) -> Result<Box<dyn Parameter>, InvalidInputException> {
        self.base_mut()
            .parameter
            .take()
            .ok_or_else(|| InvalidInputException::with_message("no parameter available"))
    }

    /// Java: `AddParameterCommand.getName`, not `final` -- overridden by subclasses such as
    /// `AddMemoryParameterCommand` to describe their specific parameter kind.
    fn command_name(&self) -> String {
        "Add Parameter Command".to_string()
    }
}

#[allow(deprecated)]
impl AddParameterCommand for AddParameterCommandBase {
    fn base(&self) -> &AddParameterCommandBase {
        self
    }

    fn base_mut(&mut self) -> &mut AddParameterCommandBase {
        self
    }
}

/// Java: `AddParameterCommand.applyTo`, declared `final` -- every implementor (including
/// subclasses that only override [`AddParameterCommand::get_parameter`]) shares this logic.
#[allow(deprecated)]
impl<T: AddParameterCommand> Command<dyn Program + 'static> for T {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let function = self.base().function.clone();

        let program_ptr = program as *const dyn Program as *const ();
        let function_program = function.get_program();
        let function_program_ptr = function_program.as_ref() as *const dyn Program as *const ();
        assert!(
            std::ptr::eq(program_ptr, function_program_ptr),
            "Program instance mismatch"
        );

        let parameter = match self.get_parameter(program) {
            Ok(parameter) => parameter,
            Err(e) => {
                self.base_mut().status_message = Some(e.to_string());
                return false;
            }
        };
        let name = parameter.get_name();

        let ordinal = self.base().ordinal;
        let source = self.base().source;
        let function_ptr = Arc::as_ptr(&function) as *mut dyn Function;
        #[allow(deprecated)]
        let result = unsafe { (*function_ptr).insert_parameter(ordinal, parameter, source) };

        match result {
            Ok(_) => true,
            Err(FunctionEditError::Duplicate(_)) => {
                self.base_mut().status_message = Some(format!(
                    "Parameter named {} already exists",
                    name.unwrap_or_else(|| "null".to_string())
                ));
                false
            }
            Err(e) => {
                self.base_mut().status_message = Some(e.to_string());
                false
            }
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.base().status_message.clone()
    }

    fn name(&self) -> String {
        self.command_name()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::function::{FunctionUpdateType, SetFunctionNameError};
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::model::listing::{AutoParameterType, FunctionSignature, FunctionTag, Variable};
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{ExternalLocation, Namespace, Symbol};
    use crate::program::seam_stubs::{StackFrame, VariableFilter};
    use crate::program::database::OverlappingFunctionException;
    use crate::util::exception::DuplicateNameException;
    use crate::util::task::TaskMonitor;

    struct MockDataType;
    impl DataType for MockDataType {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockParameter {
        name: Option<String>,
        ordinal: i32,
    }

    impl Variable for MockParameter {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = Some(name.to_string());
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            false
        }
        fn has_stack_storage(&self) -> bool {
            false
        }
        fn is_register_variable(&self) -> bool {
            false
        }
        fn get_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Err(UnsupportedOperationError("not a simple stack variable".to_string()))
        }
        fn is_memory_variable(&self) -> bool {
            false
        }
        fn is_unique_variable(&self) -> bool {
            false
        }
        fn is_compound_variable(&self) -> bool {
            false
        }
        fn has_assigned_storage(&self) -> bool {
            false
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, _variable: &dyn Variable) -> bool {
            false
        }
        fn compare_to(&self, _other: &dyn Variable) -> Ordering {
            Ordering::Equal
        }
        fn is_parameter(&self) -> bool {
            true
        }
    }

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
    }

    #[allow(dead_code)]
    struct MockFunction {
        entry_point: Address,
        program: Arc<dyn Program>,
        insert_result: Option<Result<(), FunctionEditError>>,
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
            var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            match self.insert_result.take() {
                Some(Ok(())) | None => {
                    let name = var.get_name();
                    Ok(Box::new(MockParameter { name, ordinal: 0 }))
                }
                Some(Err(e)) => Err(e),
            }
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
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            vec![]
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
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
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
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

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    fn new_parameter(name: &str) -> Box<dyn Parameter> {
        Box::new(MockParameter {
            name: Some(name.to_string()),
            ordinal: 0,
        })
    }

    /// Builds a `MockFunction` and a `&mut dyn Program` handle that are identity-equal, the way
    /// a real `Function::getProgram()` and the `Program` passed to `applyTo` are the same
    /// object. Mirrors the `Arc::as_ptr` cast-to-`*mut` convention this module (and sibling
    /// `*Cmd` ports) already uses to mutate through a shared `Arc<dyn Function>`.
    fn function_and_its_program(
        insert_result: Option<Result<(), FunctionEditError>>,
    ) -> (Arc<dyn Function>, Arc<MockProgram>) {
        let program = Arc::new(MockProgram);
        let function: Arc<dyn Function> = Arc::new(MockFunction {
            entry_point: addr(0x1000),
            program: program.clone(),
            insert_result,
        });
        (function, program)
    }

    fn as_mut_program(program: &Arc<MockProgram>) -> &mut (dyn Program + 'static) {
        let ptr = Arc::as_ptr(program) as *mut MockProgram;
        unsafe { &mut *ptr }
    }

    #[test]
    fn name_matches_java_get_name() {
        let (function, _program) = function_and_its_program(Some(Ok(())));
        let cmd = AddParameterCommandBase::new(function, new_parameter("p1"), 0, SourceType::UserDefined);
        assert_eq!(cmd.name(), "Add Parameter Command");
    }

    #[test]
    fn status_msg_initially_none() {
        let (function, _program) = function_and_its_program(Some(Ok(())));
        let cmd = AddParameterCommandBase::new(function, new_parameter("p1"), 0, SourceType::UserDefined);
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_succeeds_and_inserts_parameter() {
        let (function, program) = function_and_its_program(Some(Ok(())));
        let mut cmd = AddParameterCommandBase::new(
            function,
            new_parameter("p1"),
            2,
            SourceType::UserDefined,
        );
        assert!(cmd.apply_to(as_mut_program(&program)));
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_reports_duplicate_name_failure() {
        let (function, program) = function_and_its_program(Some(Err(FunctionEditError::Duplicate(
            DuplicateNameException::with_message("p1"),
        ))));
        let mut cmd = AddParameterCommandBase::new(
            function,
            new_parameter("p1"),
            0,
            SourceType::UserDefined,
        );
        assert!(!cmd.apply_to(as_mut_program(&program)));
        assert_eq!(
            cmd.status_msg(),
            Some("Parameter named p1 already exists".to_string())
        );
    }

    #[test]
    fn apply_to_reports_invalid_input_failure() {
        let (function, program) = function_and_its_program(Some(Err(FunctionEditError::InvalidInput(
            InvalidInputException::with_message("bad storage"),
        ))));
        let mut cmd = AddParameterCommandBase::new(
            function,
            new_parameter("p1"),
            0,
            SourceType::UserDefined,
        );
        assert!(!cmd.apply_to(as_mut_program(&program)));
        assert_eq!(cmd.status_msg(), Some("bad storage".to_string()));
    }

    #[test]
    #[should_panic(expected = "Program instance mismatch")]
    fn apply_to_panics_on_program_instance_mismatch() {
        let (function, _program) = function_and_its_program(Some(Ok(())));
        let mut cmd = AddParameterCommandBase::new(
            function,
            new_parameter("p1"),
            0,
            SourceType::UserDefined,
        );
        let mut other_program = MockProgram;
        cmd.apply_to(&mut other_program);
    }

    #[test]
    fn without_parameter_get_parameter_errors_when_unset() {
        let (function, _program) = function_and_its_program(None);
        let mut cmd = AddParameterCommandBase::without_parameter(function, 0, SourceType::UserDefined);
        let program = MockProgram;
        assert!(cmd.get_parameter(&program).is_err());
    }
}
