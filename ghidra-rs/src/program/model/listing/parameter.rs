use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::AutoParameterType;
use crate::program::model::listing::Variable;

/// The name Ghidra assigns to the synthetic return-storage parameter.
pub const RETURN_NAME: &str = "<RETURN>";

/// Ordinal used for the synthetic return-storage parameter.
pub const RETURN_ORDINAL: i32 = -1;

/// Ordinal used for a parameter that has not yet been assigned a position.
pub const UNASSIGNED_ORDINAL: i32 = -2;

/// Interface for function parameters.
pub trait Parameter: Variable {
    /// Returns the ordinal (index) of this parameter within the function signature.
    fn get_ordinal(&self) -> i32;

    /// Returns true if this parameter is automatically generated based upon the associated
    /// function calling convention and function signature. An example of such a parameter
    /// include the "__return_storage_ptr__" parameter.
    fn is_auto_parameter(&self) -> bool;

    /// If this is an auto-parameter this method will indicate its type.
    /// Returns the auto-parameter type, or `None` if not applicable.
    fn get_auto_parameter_type(&self) -> Option<AutoParameterType>;

    /// If this parameter which was forced by the associated calling convention to be passed as
    /// a pointer instead of its original formal type.
    /// Returns true if this parameter was forced to be passed as a pointer instead of its
    /// original formal type.
    fn is_forced_indirect(&self) -> bool;

    /// Get the original formal signature data type before a possible forced indirect was
    /// possibly imposed by the function's calling convention. `get_data_type` (from
    /// [`Variable`]) will always return the effective data type which corresponds to the
    /// allocated variable storage.
    ///
    /// This type will only differ from the effective data type if this parameter
    /// `is_forced_indirect`.
    fn get_formal_data_type(&self) -> Box<dyn DataType>;
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;

    struct MockDataType;

    impl DataType for MockDataType {}

    macro_rules! impl_mock_variable {
        ($ty:ty, $is_param:expr, $is_auto:expr) => {
            impl Variable for $ty {
                fn is_parameter(&self) -> bool {
                    $is_param
                }

                fn is_auto_parameter(&self) -> bool {
                    ($is_auto)(self)
                }

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
                    None
                }

                fn get_length(&self) -> i32 {
                    0
                }

                fn is_valid(&self) -> bool {
                    true
                }

                fn get_function(&self) -> Option<Box<dyn Function>> {
                    None
                }

                fn get_program(&self) -> Arc<dyn Program> {
                    struct MockProgram;
                    impl crate::framework::model::DomainObject for MockProgram {}
                    impl Program for MockProgram {
                        fn get_name(&self) -> String {
                            "mock".to_string()
                        }
                        fn get_language_id(&self) -> String {
                            "mock:LE:32:default".to_string()
                        }
                    }
                    Arc::new(MockProgram)
                }

                fn get_source(&self) -> SourceType {
                    SourceType::UserDefined
                }

                fn set_name(
                    &mut self,
                    _name: &str,
                    _source: SourceType,
                ) -> Result<(), SetVariableNameError> {
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
                    Err(UnsupportedOperationError(
                        "not a simple stack variable".to_string(),
                    ))
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
            }
        };
    }

    struct MockVariable;

    impl_mock_variable!(MockVariable, false, |_v: &MockVariable| false);

    struct MockParameter {
        ordinal: i32,
        auto_parameter_type: Option<AutoParameterType>,
        forced_indirect: bool,
    }

    impl_mock_variable!(MockParameter, true, |v: &MockParameter| v
        .auto_parameter_type
        .is_some());

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }

        fn is_auto_parameter(&self) -> bool {
            self.auto_parameter_type.is_some()
        }

        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            self.auto_parameter_type
        }

        fn is_forced_indirect(&self) -> bool {
            self.forced_indirect
        }

        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
    }

    #[test]
    fn ordinary_parameter_is_not_auto() {
        let param = MockParameter {
            ordinal: 0,
            auto_parameter_type: None,
            forced_indirect: false,
        };
        assert_eq!(param.get_ordinal(), 0);
        assert!(!Parameter::is_auto_parameter(&param));
        assert_eq!(param.get_auto_parameter_type(), None);
        assert!(!param.is_forced_indirect());
    }

    #[test]
    fn auto_parameter_reports_its_type() {
        let param = MockParameter {
            ordinal: RETURN_ORDINAL,
            auto_parameter_type: Some(AutoParameterType::ReturnStoragePtr),
            forced_indirect: true,
        };
        assert!(Parameter::is_auto_parameter(&param));
        assert_eq!(
            param.get_auto_parameter_type(),
            Some(AutoParameterType::ReturnStoragePtr)
        );
        assert!(param.is_forced_indirect());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let param: Box<dyn Parameter> = Box::new(MockParameter {
            ordinal: UNASSIGNED_ORDINAL,
            auto_parameter_type: None,
            forced_indirect: false,
        });
        assert_eq!(param.get_ordinal(), UNASSIGNED_ORDINAL);
        let _formal_type: Box<dyn DataType> = param.get_formal_data_type();
    }
}
