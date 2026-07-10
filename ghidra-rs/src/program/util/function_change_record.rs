use std::fmt;

use crate::program::model::listing::Function;
use crate::program::util::{ProgramChangeRecord, ProgramEvent};

/// Specific function change types for when the ProgramEvent is FUNCTION_CHANGED.
///
/// Port of `ghidra.program.util.FunctionChangeRecord.FunctionChangeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionChangeType {
    /// A function's purge value changed.
    PurgeChanged,
    /// A function's inline status changed.
    InlineChanged,
    /// A function's no return status changed.
    NoReturnChanged,
    /// A function's call fixup changed.
    CallFixupChanged,
    /// A function's return type changed.
    ReturnTypeChanged,
    /// A function's parameters changed.
    ParametersChanged,
    /// A function's thunk status changed.
    ThunkChanged,
    /// A specific function change was not specified.
    Unspecified,
}

/// Change record generated when a function is modified.
///
/// Port of `ghidra.program.util.FunctionChangeRecord`. Wraps a [`ProgramChangeRecord`]
/// and adds the specific type of function change that occurred.
pub struct FunctionChangeRecord {
    base: ProgramChangeRecord,
    change_type: FunctionChangeType,
}

impl FunctionChangeRecord {
    /// Constructs a new Function change record.
    ///
    /// # Arguments
    /// * `function` - the function that was changed
    /// * `change_type` - the specific type of change that was applied to the function
    pub fn new(function: &dyn Function, change_type: Option<FunctionChangeType>) -> Self {
        let entry_point = function.get_entry_point();
        let change_type = change_type.unwrap_or(FunctionChangeType::Unspecified);
        Self {
            base: ProgramChangeRecord::new(
                ProgramEvent::FunctionChanged,
                Some(entry_point.clone()),
                Some(entry_point),
                None,
                None,
                None,
            ),
            change_type,
        }
    }

    /// Returns the specific type of function change.
    pub fn get_specific_change_type(&self) -> FunctionChangeType {
        self.change_type
    }

    /// Returns true if the specific change was related to the function signature.
    pub fn is_function_signature_change(&self) -> bool {
        matches!(
            self.change_type,
            FunctionChangeType::ParametersChanged | FunctionChangeType::ReturnTypeChanged
        )
    }

    /// Returns true if the specific change was to one of the function's modifier properties.
    pub fn is_function_modifier_change(&self) -> bool {
        matches!(
            self.change_type,
            FunctionChangeType::ThunkChanged
                | FunctionChangeType::InlineChanged
                | FunctionChangeType::NoReturnChanged
                | FunctionChangeType::CallFixupChanged
                | FunctionChangeType::PurgeChanged
        )
    }

    /// Returns a reference to the underlying [`ProgramChangeRecord`].
    pub fn base(&self) -> &ProgramChangeRecord {
        &self.base
    }
}

impl std::ops::Deref for FunctionChangeRecord {
    type Target = ProgramChangeRecord;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl fmt::Display for FunctionChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let change_type_str = match self.change_type {
            FunctionChangeType::PurgeChanged => "PURGE_CHANGED",
            FunctionChangeType::InlineChanged => "INLINE_CHANGED",
            FunctionChangeType::NoReturnChanged => "NO_RETURN_CHANGED",
            FunctionChangeType::CallFixupChanged => "CALL_FIXUP_CHANGED",
            FunctionChangeType::ReturnTypeChanged => "RETURN_TYPE_CHANGED",
            FunctionChangeType::ParametersChanged => "PARAMETERS_CHANGED",
            FunctionChangeType::ThunkChanged => "THUNK_CHANGED",
            FunctionChangeType::Unspecified => "UNSPECIFIED",
        };
        write!(f, "{}, changeType = {}", self.base, change_type_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Program, Variable};
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
    };
    use crate::program::model::symbol::{
        ExternalLocation, Namespace, NamespaceType, SourceType, Symbol,
    };
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::program::database::function::OverlappingFunctionException;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    struct MockFunction {
        entry_point: Address,
    }

    impl MockFunction {
        fn new(offset: i64) -> Self {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            let entry_point = Address::new(space, offset);
            Self { entry_point }
        }
    }

    impl Namespace for MockFunction {
        fn get_name(&self) -> String {
            "mock_function".to_string()
        }

        fn get_id(&self) -> i64 {
            1
        }

        fn get_type(&self) -> NamespaceType {
            NamespaceType::Function
        }

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

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            String::new()
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
        }

        fn get_stack_purge_size(&self) -> i32 {
            -1
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
            false
        }

        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }

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

        fn remove_parameter(&mut self, _ordinal: i32) {}

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

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
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
            _new_body: &dyn AddressSetView,
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
            "default".to_string()
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

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn Function>>,
        ) -> Result<(), String> {
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

    #[test]
    fn new_stores_change_type() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::InlineChanged));
        assert_eq!(
            record.get_specific_change_type(),
            FunctionChangeType::InlineChanged
        );
    }

    #[test]
    fn new_with_none_change_type_becomes_unspecified() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, None);
        assert_eq!(
            record.get_specific_change_type(),
            FunctionChangeType::Unspecified
        );
    }

    #[test]
    fn new_uses_function_entry_point_for_start_and_end() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::PurgeChanged));
        let entry_point = func.get_entry_point();
        assert_eq!(record.start(), Some(&entry_point));
        assert_eq!(record.end(), Some(&entry_point));
    }

    #[test]
    fn new_sets_event_type_to_function_changed() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::ReturnTypeChanged));
        assert_eq!(
            record.change_record().event_type().get_id(),
            ProgramEvent::FunctionChanged.get_id()
        );
    }

    #[test]
    fn is_function_signature_change_true_for_parameters_changed() {
        let func = MockFunction::new(0x1000);
        let record =
            FunctionChangeRecord::new(&func, Some(FunctionChangeType::ParametersChanged));
        assert!(record.is_function_signature_change());
    }

    #[test]
    fn is_function_signature_change_true_for_return_type_changed() {
        let func = MockFunction::new(0x1000);
        let record =
            FunctionChangeRecord::new(&func, Some(FunctionChangeType::ReturnTypeChanged));
        assert!(record.is_function_signature_change());
    }

    #[test]
    fn is_function_signature_change_false_for_other_changes() {
        let func = MockFunction::new(0x1000);
        for change_type in [
            FunctionChangeType::PurgeChanged,
            FunctionChangeType::InlineChanged,
            FunctionChangeType::NoReturnChanged,
            FunctionChangeType::CallFixupChanged,
            FunctionChangeType::ThunkChanged,
            FunctionChangeType::Unspecified,
        ] {
            let record = FunctionChangeRecord::new(&func, Some(change_type));
            assert!(!record.is_function_signature_change());
        }
    }

    #[test]
    fn is_function_modifier_change_true_for_thunk() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::ThunkChanged));
        assert!(record.is_function_modifier_change());
    }

    #[test]
    fn is_function_modifier_change_true_for_inline() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::InlineChanged));
        assert!(record.is_function_modifier_change());
    }

    #[test]
    fn is_function_modifier_change_true_for_no_return() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::NoReturnChanged));
        assert!(record.is_function_modifier_change());
    }

    #[test]
    fn is_function_modifier_change_true_for_call_fixup() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::CallFixupChanged));
        assert!(record.is_function_modifier_change());
    }

    #[test]
    fn is_function_modifier_change_true_for_purge() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::PurgeChanged));
        assert!(record.is_function_modifier_change());
    }

    #[test]
    fn is_function_modifier_change_false_for_non_modifiers() {
        let func = MockFunction::new(0x1000);
        for change_type in [
            FunctionChangeType::ParametersChanged,
            FunctionChangeType::ReturnTypeChanged,
            FunctionChangeType::Unspecified,
        ] {
            let record = FunctionChangeRecord::new(&func, Some(change_type));
            assert!(!record.is_function_modifier_change());
        }
    }

    #[test]
    fn display_includes_change_type() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::InlineChanged));
        let s = format!("{}", record);
        assert!(s.contains("changeType = INLINE_CHANGED"));
    }

    #[test]
    fn display_includes_base_record_info() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::PurgeChanged));
        let s = format!("{}", record);
        assert!(s.contains("DomainObjectChangeRecord"));
    }

    #[test]
    fn deref_exposes_program_change_record_methods() {
        let func = MockFunction::new(0x1000);
        let record = FunctionChangeRecord::new(&func, Some(FunctionChangeType::InlineChanged));
        assert_eq!(
            record.change_record().event_type().get_id(),
            ProgramEvent::FunctionChanged.get_id()
        );
    }
}
