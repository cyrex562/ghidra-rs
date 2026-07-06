use crate::program::model::listing::Variable;

/// Filters variables based on type-specific criteria.
///
/// Mirrors Java's `VariableFilter` interface, providing common filter implementations
/// for categorizing variables by their storage type and parameter status.
pub trait VariableFilter {
    /// Determine if the specified variable matches this filter criteria.
    ///
    /// # Arguments
    /// * `variable` - The variable to test against the filter.
    ///
    /// # Returns
    /// `true` if the variable satisfies the criteria of this filter, `false` otherwise.
    fn matches(&self, variable: &dyn Variable) -> bool;
}

/// Filters for all parameters (includes auto-params).
///
/// A variable is treated as a parameter by this filter if it implements the `Parameter` trait.
pub struct ParameterFilter {
    allow_auto_params: bool,
}

impl ParameterFilter {
    /// Create a new parameter filter.
    ///
    /// # Arguments
    /// * `allow_auto_params` - If `true`, includes auto-parameters; if `false`, excludes them.
    pub fn new(allow_auto_params: bool) -> Self {
        ParameterFilter { allow_auto_params }
    }
}

impl VariableFilter for ParameterFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        if variable.is_parameter() {
            !variable.is_auto_parameter() || self.allow_auto_params
        } else {
            false
        }
    }
}

/// Filters for all simple stack variables.
///
/// A variable is treated as local by this filter if it does not implement the `Parameter` trait.
pub struct LocalVariableFilter;

impl VariableFilter for LocalVariableFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        !variable.is_parameter()
    }
}

/// Filters for all simple stack variables.
pub struct StackVariableFilter;

impl VariableFilter for StackVariableFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        variable.is_stack_variable()
    }
}

/// Filters for all simple or compound variables which utilize a stack storage element.
pub struct CompoundStackVariableFilter;

impl VariableFilter for CompoundStackVariableFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        variable.has_stack_storage()
    }
}

/// Filters for all simple register variables.
pub struct RegisterVariableFilter;

impl VariableFilter for RegisterVariableFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        variable.is_register_variable()
    }
}

/// Filters for all simple memory variables.
pub struct MemoryVariableFilter;

impl VariableFilter for MemoryVariableFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        variable.is_memory_variable()
    }
}

/// Filters for all simple unique variables identified by a hash value.
pub struct UniqueVariableFilter;

impl VariableFilter for UniqueVariableFilter {
    fn matches(&self, variable: &dyn Variable) -> bool {
        variable.is_unique_variable()
    }
}

/// Creates a filter that matches all parameters (includes auto-params).
pub fn parameter_filter() -> Box<dyn VariableFilter> {
    Box::new(ParameterFilter::new(true))
}

/// Creates a filter that matches all parameters which are not auto-params.
pub fn nonauto_parameter_filter() -> Box<dyn VariableFilter> {
    Box::new(ParameterFilter::new(false))
}

/// Creates a filter that matches all local variables.
pub fn local_variable_filter() -> Box<dyn VariableFilter> {
    Box::new(LocalVariableFilter)
}

/// Creates a filter that matches all simple stack variables.
pub fn stack_variable_filter() -> Box<dyn VariableFilter> {
    Box::new(StackVariableFilter)
}

/// Creates a filter that matches all simple or compound variables which utilize
/// a stack storage element.
pub fn compound_stack_variable_filter() -> Box<dyn VariableFilter> {
    Box::new(CompoundStackVariableFilter)
}

/// Creates a filter that matches all simple register variables.
pub fn register_variable_filter() -> Box<dyn VariableFilter> {
    Box::new(RegisterVariableFilter)
}

/// Creates a filter that matches all simple memory variables.
pub fn memory_variable_filter() -> Box<dyn VariableFilter> {
    Box::new(MemoryVariableFilter)
}

/// Creates a filter that matches all simple unique variables identified by a hash value.
pub fn unique_variable_filter() -> Box<dyn VariableFilter> {
    Box::new(UniqueVariableFilter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::SetVariableNameError;
    use crate::program::model::listing::{AutoParameterType, Function, Parameter, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;
    use std::cmp::Ordering;
    use std::sync::Arc;

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockVariable {
        name: Option<String>,
        is_stack: bool,
        has_stack_storage: bool,
        is_register: bool,
        is_memory: bool,
        is_unique: bool,
        is_param: bool,
    }

    impl Variable for MockVariable {
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
            struct MockProgram;
            impl Program for MockProgram {
                fn get_name(&self) -> &str {
                    "mock"
                }
                fn get_language_id(&self) -> &str {
                    "mock:LE:32:default"
                }
            }
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
            self.is_stack
        }

        fn has_stack_storage(&self) -> bool {
            self.has_stack_storage
        }

        fn is_register_variable(&self) -> bool {
            self.is_register
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

        fn get_stack_offset(&self) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Err(crate::program::model::listing::variable::UnsupportedOperationError(
                "not a simple stack variable".to_string(),
            ))
        }

        fn is_memory_variable(&self) -> bool {
            self.is_memory
        }

        fn is_unique_variable(&self) -> bool {
            self.is_unique
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

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
        }

        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }

        fn is_parameter(&self) -> bool {
            false
        }

        fn is_auto_parameter(&self) -> bool {
            false
        }
    }

    struct MockParameter {
        name: Option<String>,
        is_auto: bool,
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
            struct MockProgram;
            impl Program for MockProgram {
                fn get_name(&self) -> &str {
                    "mock"
                }
                fn get_language_id(&self) -> &str {
                    "mock:LE:32:default"
                }
            }
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

        fn get_stack_offset(&self) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Err(crate::program::model::listing::variable::UnsupportedOperationError(
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

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
        }

        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }

        fn is_parameter(&self) -> bool {
            true
        }

        fn is_auto_parameter(&self) -> bool {
            self.is_auto
        }
    }

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            0
        }

        fn is_auto_parameter(&self) -> bool {
            self.is_auto
        }

        fn get_auto_parameter_type(&self) -> Option<crate::program::model::listing::AutoParameterType> {
            None
        }

        fn is_forced_indirect(&self) -> bool {
            false
        }

        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
    }

    #[test]
    fn parameter_filter_matches_regular_parameter() {
        let param = MockParameter {
            name: Some("param1".to_string()),
            is_auto: false,
        };
        let filter = ParameterFilter::new(true);
        assert!(filter.matches(&param));
    }

    #[test]
    fn parameter_filter_matches_auto_parameter_when_allowed() {
        let auto_param = MockParameter {
            name: Some("__return_storage_ptr__".to_string()),
            is_auto: true,
        };
        let filter = ParameterFilter::new(true);
        assert!(filter.matches(&auto_param));
    }

    #[test]
    fn parameter_filter_excludes_auto_parameter_when_not_allowed() {
        let auto_param = MockParameter {
            name: Some("__return_storage_ptr__".to_string()),
            is_auto: true,
        };
        let filter = ParameterFilter::new(false);
        assert!(!filter.matches(&auto_param));
    }

    #[test]
    fn parameter_filter_rejects_non_parameter() {
        let var = MockVariable {
            name: Some("local_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = ParameterFilter::new(true);
        assert!(!filter.matches(&var));
    }

    #[test]
    fn local_variable_filter_rejects_parameter() {
        let param = MockParameter {
            name: Some("param1".to_string()),
            is_auto: false,
        };
        let filter = LocalVariableFilter;
        assert!(!filter.matches(&param));
    }

    #[test]
    fn local_variable_filter_matches_non_parameter() {
        let var = MockVariable {
            name: Some("local_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = LocalVariableFilter;
        assert!(filter.matches(&var));
    }

    #[test]
    fn stack_variable_filter_matches_stack_variable() {
        let var = MockVariable {
            name: Some("stack_var".to_string()),
            is_stack: true,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = StackVariableFilter;
        assert!(filter.matches(&var));
    }

    #[test]
    fn stack_variable_filter_rejects_non_stack_variable() {
        let var = MockVariable {
            name: Some("local_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: true,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = StackVariableFilter;
        assert!(!filter.matches(&var));
    }

    #[test]
    fn compound_stack_variable_filter_matches_compound_stack() {
        let var = MockVariable {
            name: Some("compound_stack".to_string()),
            is_stack: false,
            has_stack_storage: true,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = CompoundStackVariableFilter;
        assert!(filter.matches(&var));
    }

    #[test]
    fn compound_stack_variable_filter_rejects_no_stack_storage() {
        let var = MockVariable {
            name: Some("register_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: true,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = CompoundStackVariableFilter;
        assert!(!filter.matches(&var));
    }

    #[test]
    fn register_variable_filter_matches_register_variable() {
        let var = MockVariable {
            name: Some("reg_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: true,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = RegisterVariableFilter;
        assert!(filter.matches(&var));
    }

    #[test]
    fn register_variable_filter_rejects_non_register_variable() {
        let var = MockVariable {
            name: Some("stack_var".to_string()),
            is_stack: true,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = RegisterVariableFilter;
        assert!(!filter.matches(&var));
    }

    #[test]
    fn memory_variable_filter_matches_memory_variable() {
        let var = MockVariable {
            name: Some("mem_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: false,
            is_memory: true,
            is_unique: false,
            is_param: false,
        };
        let filter = MemoryVariableFilter;
        assert!(filter.matches(&var));
    }

    #[test]
    fn memory_variable_filter_rejects_non_memory_variable() {
        let var = MockVariable {
            name: Some("unique_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: true,
            is_param: false,
        };
        let filter = MemoryVariableFilter;
        assert!(!filter.matches(&var));
    }

    #[test]
    fn unique_variable_filter_matches_unique_variable() {
        let var = MockVariable {
            name: Some("unique_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: true,
            is_param: false,
        };
        let filter = UniqueVariableFilter;
        assert!(filter.matches(&var));
    }

    #[test]
    fn unique_variable_filter_rejects_non_unique_variable() {
        let var = MockVariable {
            name: Some("register_var".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: true,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        let filter = UniqueVariableFilter;
        assert!(!filter.matches(&var));
    }

    #[test]
    fn factory_functions_create_correct_filters() {
        let param_filter = parameter_filter();
        let local_filter = local_variable_filter();
        let stack_filter = stack_variable_filter();
        let register_filter = register_variable_filter();
        let memory_filter = memory_variable_filter();
        let unique_filter = unique_variable_filter();

        let param = MockParameter {
            name: Some("p".to_string()),
            is_auto: false,
        };
        let var = MockVariable {
            name: Some("v".to_string()),
            is_stack: false,
            has_stack_storage: false,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };

        assert!(param_filter.matches(&param));
        assert!(!local_filter.matches(&param));
        assert!(!register_filter.matches(&var));
    }

    #[test]
    fn nonauto_parameter_filter_matches_regular_parameter() {
        let param = MockParameter {
            name: Some("param1".to_string()),
            is_auto: false,
        };
        let filter = nonauto_parameter_filter();
        assert!(filter.matches(&param));
    }

    #[test]
    fn nonauto_parameter_filter_excludes_auto_parameter() {
        let auto_param = MockParameter {
            name: Some("__return_storage_ptr__".to_string()),
            is_auto: true,
        };
        let filter = nonauto_parameter_filter();
        assert!(!filter.matches(&auto_param));
    }

    #[test]
    fn compound_stack_variable_filter_factory() {
        let filter = compound_stack_variable_filter();
        let var = MockVariable {
            name: Some("compound_var".to_string()),
            is_stack: false,
            has_stack_storage: true,
            is_register: false,
            is_memory: false,
            is_unique: false,
            is_param: false,
        };
        assert!(filter.matches(&var));
    }
}
