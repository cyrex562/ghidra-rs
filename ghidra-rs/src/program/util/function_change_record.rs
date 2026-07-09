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
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::any::Any;

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

    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_name(&self) -> &str {
            "mock_function"
        }

        fn get_id(&self) -> u64 {
            1
        }

        fn get_address(&self) -> Option<Address> {
            Some(self.entry_point.clone())
        }

        fn get_type(&self) -> crate::program::model::symbol::NamespaceType {
            crate::program::model::symbol::NamespaceType::Function
        }

        fn get_symbol(&self) -> Option<&dyn crate::program::model::symbol::Symbol> {
            None
        }

        fn get_parent_namespace(&self) -> Option<&dyn crate::program::model::symbol::Namespace> {
            None
        }

        fn contains(
            &self,
            _namespace: &dyn crate::program::model::symbol::Namespace,
        ) -> bool {
            false
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl Function for MockFunction {
        fn get_entry_point(&self) -> Address {
            self.entry_point.clone()
        }

        fn get_call_fixup(&self) -> Option<&str> {
            None
        }

        fn get_calling_convention_name(&self) -> &str {
            "default"
        }

        fn get_body(
            &self,
        ) -> crate::program::model::address::AddressSetView {
            crate::program::model::address::AddressSetView::empty()
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(
            &self,
        ) -> Option<crate::program::model::symbol::ExternalLocation> {
            None
        }

        fn has_var_args(&self) -> bool {
            false
        }

        fn get_parameters(&self) -> &[crate::program::model::listing::Parameter] {
            &[]
        }

        fn get_local_variables(
            &self,
        ) -> &[crate::program::model::listing::Variable] {
            &[]
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(
            &mut self,
            _comment: Option<String>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn get_return_type(&self) -> &dyn crate::program::model::data::data_type::DataType {
            unimplemented!()
        }

        fn get_stack_frame(&self) -> &dyn crate::program::seam_stubs::StackFrame {
            unimplemented!()
        }

        fn get_prototype_model(
            &self,
        ) -> Option<&dyn crate::program::seam_stubs::PrototypeModel> {
            None
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self) -> Option<&dyn Function> {
            None
        }

        fn is_inline(&self) -> bool {
            false
        }

        fn is_no_return(&self) -> bool {
            false
        }

        fn get_purge_size(&self) -> i32 {
            -1
        }

        fn as_any(&self) -> &dyn Any {
            self
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
