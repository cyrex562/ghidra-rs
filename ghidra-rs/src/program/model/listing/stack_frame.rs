use thiserror::Error;

use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::{Function, Variable, VariableSizeException};
use crate::program::model::symbol::SourceType;
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Indicator for a Stack that grows negatively.
pub const GROWS_NEGATIVE: i32 = -1;
/// Indicator for a Stack that grows positively.
pub const GROWS_POSITIVE: i32 = 1;
/// Indicator for a unknown stack parameter offset.
pub const UNKNOWN_PARAM_OFFSET: i32 = 128 * 1024;

/// Error produced when [`StackFrame::create_variable`] fails.
///
/// Combines the three checked exceptions declared on the Java method
/// `StackFrame.createVariable(String, int, DataType, SourceType)`.
#[derive(Error, Debug, PartialEq)]
pub enum CreateStackVariableError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    VariableSize(#[from] VariableSizeException),
}

/// Definition of a stack frame.
///
/// All offsets into a stack are from a zero base. Usually negative offsets are parameters and
/// positive offsets are locals. That does not have to be the case, it depends on whether the
/// stack grows positively or negatively. On an a 80x86 architecture, the stack grows negatively.
/// When a value is pushed onto the stack, the stack pointer is decremented by some size.
///
/// Each frame consists of a local sections, parameter section, and save information (return
/// address, saved registers, etc...). A frame is said to grow negative if the parameters are
/// referenced with negative offsets from 0, or positive if the parameters are referenced with
/// negative offsets from 0.
///
/// ```text
///  Negative Growth
///                    -5      local2 (2 bytes)
///                    -3      local1 (4 bytes)
///   frame base        0      stuff (4 bytes)
///   return offset     4      return addr (4 bytes)
///   param offset      8      param2 (4 bytes)
///                    12      param1
///
///  Positive Growth
///                   -15     param offset 1
///                   -11     param offset 2
///   param offset     -8
///   return offset    -7     return address
///                    -3     stuff
///   frame base        0     local 1
///                     4     local 2
///                     8
/// ```
///
/// Port of `ghidra.program.model.listing.StackFrame`.
pub trait StackFrame {
    /// Get the function that this stack belongs to.
    /// This could return `None` if the stack frame isn't part of a function.
    fn get_function(&self) -> Option<Box<dyn Function>>;

    /// Get the size of this stack frame in bytes.
    fn get_frame_size(&self) -> i32;

    /// Get the local portion of the stack frame in bytes.
    fn get_local_size(&self) -> i32;

    /// Get the parameter portion of the stack frame in bytes.
    fn get_parameter_size(&self) -> i32;

    /// Get the offset to the start of the parameters.
    fn get_parameter_offset(&self) -> i32;

    /// Returns true if specified offset could correspond to a parameter.
    fn is_parameter_offset(&self, offset: i32) -> bool;

    /// Set the size of the local stack in bytes.
    fn set_local_size(&mut self, size: i32);

    /// Set the return address stack offset.
    fn set_return_address_offset(&mut self, offset: i32);

    /// Get the return address stack offset.
    fn get_return_address_offset(&self) -> i32;

    /// Get the stack variable containing offset. This may fall in the middle of a defined
    /// variable.
    fn get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>>;

    /// Create a stack variable. It could be a parameter or a local depending on the direction of
    /// the stack.
    ///
    /// **WARNING!** Use of this method to add parameters may force the function to use custom
    /// variable storage. In addition, parameters may be appended even if the current calling
    /// convention does not support them.
    ///
    /// # Errors
    /// Returns `Err` if another variable (parameter or local) already exists in the function
    /// with that name, if the data type is not a fixed length or the variable name is invalid,
    /// or if the data type size is too large based upon storage constraints.
    fn create_variable(
        &mut self,
        name: &str,
        offset: i32,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<Box<dyn Variable>, CreateStackVariableError>;

    /// Clear the stack variable defined at offset.
    fn clear_variable(&mut self, offset: i32);

    /// Get all defined stack variables.
    /// Variables are returned from least offset (-) to greatest offset (+).
    fn get_stack_variables(&self) -> Vec<Box<dyn Variable>>;

    /// Get all defined parameters as stack variables.
    fn get_parameters(&self) -> Vec<Box<dyn Variable>>;

    /// Get all defined local variables.
    fn get_locals(&self) -> Vec<Box<dyn Variable>>;

    /// A stack that grows negative has local references negative and parameter references
    /// positive. A positive growing stack has positive locals and negative parameters.
    ///
    /// Returns true if the stack grows in a negative direction.
    fn grows_negative(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockDataType;

    impl DataType for MockDataType {}

    #[derive(Clone)]
    struct MockVariable {
        name: String,
        offset: i32,
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
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
            Some(self.name.clone())
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

        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
            std::sync::Arc::new(MockProgram)
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_name(
            &mut self,
            name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn get_variable_storage(&self) -> Option<Box<dyn crate::program::seam_stubs::VariableStorage>> {
            None
        }

        fn get_first_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }

        fn get_last_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }

        fn is_stack_variable(&self) -> bool {
            true
        }

        fn has_stack_storage(&self) -> bool {
            true
        }

        fn is_register_variable(&self) -> bool {
            false
        }

        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }

        fn get_min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_stack_offset(
            &self,
        ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Ok(self.offset)
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
            true
        }

        fn get_first_use_offset(&self) -> i32 {
            0
        }

        fn get_symbol(&self) -> Option<std::sync::Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }

        fn compare_to(&self, other: &dyn Variable) -> std::cmp::Ordering {
            self.offset.cmp(&other.get_stack_offset().unwrap_or(0))
        }
    }

    struct MockStackFrame {
        grows_negative: bool,
        local_size: i32,
        variables: RefCell<Vec<MockVariable>>,
    }

    impl StackFrame for MockStackFrame {
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }

        fn get_frame_size(&self) -> i32 {
            self.get_local_size() + self.get_parameter_size()
        }

        fn get_local_size(&self) -> i32 {
            self.local_size
        }

        fn get_parameter_size(&self) -> i32 {
            8
        }

        fn get_parameter_offset(&self) -> i32 {
            if self.grows_negative { 4 } else { -8 }
        }

        fn is_parameter_offset(&self, offset: i32) -> bool {
            if self.grows_negative {
                offset >= self.get_parameter_offset()
            } else {
                offset < 0
            }
        }

        fn set_local_size(&mut self, size: i32) {
            self.local_size = size;
        }

        fn set_return_address_offset(&mut self, _offset: i32) {}

        fn get_return_address_offset(&self) -> i32 {
            4
        }

        fn get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>> {
            self.variables
                .borrow()
                .iter()
                .find(|v| v.offset == offset)
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
        }

        fn create_variable(
            &mut self,
            name: &str,
            offset: i32,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
            if self.variables.borrow().iter().any(|v| v.name == name) {
                return Err(CreateStackVariableError::Duplicate(DuplicateNameException(
                    name.to_string(),
                )));
            }
            let variable = MockVariable {
                name: name.to_string(),
                offset,
            };
            self.variables.borrow_mut().push(variable.clone());
            Ok(Box::new(variable))
        }

        fn clear_variable(&mut self, offset: i32) {
            self.variables.borrow_mut().retain(|v| v.offset != offset);
        }

        fn get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
            self.variables
                .borrow()
                .iter()
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
                .collect()
        }

        fn get_parameters(&self) -> Vec<Box<dyn Variable>> {
            self.variables
                .borrow()
                .iter()
                .filter(|v| self.is_parameter_offset(v.offset))
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
                .collect()
        }

        fn get_locals(&self) -> Vec<Box<dyn Variable>> {
            self.variables
                .borrow()
                .iter()
                .filter(|v| !self.is_parameter_offset(v.offset))
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
                .collect()
        }

        fn grows_negative(&self) -> bool {
            self.grows_negative
        }
    }

    fn new_frame() -> MockStackFrame {
        MockStackFrame {
            grows_negative: true,
            local_size: 0,
            variables: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn constants_match_ghidra_values() {
        assert_eq!(GROWS_NEGATIVE, -1);
        assert_eq!(GROWS_POSITIVE, 1);
        assert_eq!(UNKNOWN_PARAM_OFFSET, 131_072);
    }

    #[test]
    fn frame_size_is_sum_of_local_and_parameter_size() {
        let mut frame = new_frame();
        frame.set_local_size(12);
        assert_eq!(frame.get_frame_size(), 20);
    }

    #[test]
    fn is_parameter_offset_respects_growth_direction() {
        let frame = new_frame();
        assert!(frame.is_parameter_offset(8));
        assert!(!frame.is_parameter_offset(-4));
    }

    #[test]
    fn create_variable_rejects_duplicate_name() {
        let mut frame = new_frame();
        frame
            .create_variable("local_1", -4, Box::new(MockDataType), SourceType::UserDefined)
            .unwrap();

        let err = match frame.create_variable(
            "local_1",
            -8,
            Box::new(MockDataType),
            SourceType::UserDefined,
        ) {
            Err(e) => e,
            Ok(_) => panic!("expected duplicate name error"),
        };
        assert!(matches!(err, CreateStackVariableError::Duplicate(_)));
    }

    #[test]
    fn create_and_clear_variable_round_trip() {
        let mut frame = new_frame();
        frame
            .create_variable("param_1", 8, Box::new(MockDataType), SourceType::UserDefined)
            .unwrap();
        assert_eq!(frame.get_stack_variables().len(), 1);

        frame.clear_variable(8);
        assert!(frame.get_stack_variables().is_empty());
    }

    #[test]
    fn get_variable_containing_finds_matching_offset() {
        let mut frame = new_frame();
        frame
            .create_variable("local_1", -4, Box::new(MockDataType), SourceType::UserDefined)
            .unwrap();

        let found = frame.get_variable_containing(-4);
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_name(), Some("local_1".to_string()));
        assert!(frame.get_variable_containing(-12).is_none());
    }

    #[test]
    fn parameters_and_locals_partition_by_offset() {
        let mut frame = new_frame();
        frame
            .create_variable("param_1", 8, Box::new(MockDataType), SourceType::UserDefined)
            .unwrap();
        frame
            .create_variable("local_1", -4, Box::new(MockDataType), SourceType::UserDefined)
            .unwrap();

        assert_eq!(frame.get_parameters().len(), 1);
        assert_eq!(frame.get_locals().len(), 1);
        assert_eq!(frame.get_stack_variables().len(), 2);
    }

    #[test]
    fn grows_negative_reports_configured_direction() {
        let frame = new_frame();
        assert!(frame.grows_negative());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let frame: Box<dyn StackFrame> = Box::new(new_frame());
        assert_eq!(frame.get_return_address_offset(), 4);
    }
}
