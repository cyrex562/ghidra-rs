use crate::program::model::data::data_type::DataType;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::listing::FunctionSignature;
use crate::program::model::symbol::source_type::SourceType;
use crate::program::seam_stubs::GenericCallingConvention;
use crate::util::exception::InvalidInputException;

/// Defines a function signature for things like function pointers.
///
/// Port of `ghidra.program.model.data.FunctionDefinition`.
///
/// Extends `DataType + FunctionSignature` so existing callers (e.g.
/// [`DataTypeManager::get_all_function_definitions`](crate::program::model::data::data_type_manager::DataTypeManager::get_all_function_definitions))
/// keep compiling unchanged.
pub trait FunctionDefinition: DataType + FunctionSignature {
    /// Set the arguments to this function.
    fn set_arguments(&mut self, args: Vec<Box<dyn ParameterDefinition>>);

    /// Set the return data type for this function.
    ///
    /// # Errors
    /// Returns `Err` if the data type is not a fixed length type, mirroring the
    /// `IllegalArgumentException` thrown by the Java source.
    fn set_return_type(&mut self, data_type: Box<dyn DataType>) -> Result<(), String>;

    /// Set the function comment.
    fn set_comment(&mut self, comment: Option<String>);

    /// Set whether parameters can be passed as a VarArg (variable argument list).
    fn set_var_args(&mut self, has_var_args: bool);

    /// Set whether or not this function has a return.
    fn set_no_return(&mut self, has_no_return: bool);

    /// Set the generic calling convention associated with this function definition.
    ///
    /// The total number of unique calling convention names used within a given `Program` or
    /// `DataTypeManager` may be limited (e.g., 127). When this limit is exceeded an error will
    /// be logged and this setting ignored.
    #[deprecated = "Use of GenericCallingConvention is deprecated since arbitrary calling \
                     convention names are now supported. set_calling_convention should be used."]
    fn set_generic_calling_convention(
        &mut self,
        generic_calling_convention: &dyn GenericCallingConvention,
    );

    /// Set the calling convention associated with this function definition.
    ///
    /// The total number of unique calling convention names used within a given `Program` or
    /// `DataTypeManager` may be limited (e.g., 127). When this limit is exceeded an error will
    /// be logged and this setting ignored.
    ///
    /// `convention_name` is restricted to those defined by `GenericCallingConvention`, the
    /// associated compiler specification. The prototype model declaration name form (e.g.,
    /// "__stdcall") should be specified as it appears in a compiler specification (*.cspec). The
    /// special "unknown" and "default" names are also allowed.
    ///
    /// # Errors
    /// Returns `Err` if the specified `convention_name` is not defined by
    /// `GenericCallingConvention` or the associated compiler specification if the data type
    /// manager has an associated program architecture.
    fn set_calling_convention(
        &mut self,
        convention_name: Option<String>,
    ) -> Result<(), InvalidInputException>;

    /// Replace the given argument with another data type.
    ///
    /// `ordinal` is the index of the argument to be replaced, starting from '0'.
    fn replace_argument(
        &mut self,
        ordinal: i32,
        name: Option<String>,
        dt: Box<dyn DataType>,
        comment: Option<String>,
        source: SourceType,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFunctionDefinition;

    impl DataType for MockFunctionDefinition {}

    impl FunctionSignature for MockFunctionDefinition {
        fn get_name(&self) -> String {
            String::new()
        }

        fn get_prototype_string_with_calling_convention(
            &self,
            _include_calling_convention: bool,
        ) -> String {
            String::new()
        }

        fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            Vec::new()
        }

        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(MockFunctionDefinition)
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
        ) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            String::new()
        }

        fn is_equivalent_signature(&self, _signature: &dyn FunctionSignature) -> bool {
            false
        }
    }

    impl FunctionDefinition for MockFunctionDefinition {
        fn set_arguments(&mut self, _args: Vec<Box<dyn ParameterDefinition>>) {}

        fn set_return_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn set_no_return(&mut self, _has_no_return: bool) {}

        fn set_generic_calling_convention(
            &mut self,
            _generic_calling_convention: &dyn GenericCallingConvention,
        ) {
        }

        fn set_calling_convention(
            &mut self,
            _convention_name: Option<String>,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn replace_argument(
            &mut self,
            _ordinal: i32,
            _name: Option<String>,
            _dt: Box<dyn DataType>,
            _comment: Option<String>,
            _source: SourceType,
        ) {
        }
    }

    struct MockGenericCallingConvention;
    impl GenericCallingConvention for MockGenericCallingConvention {}

    #[test]
    fn usable_as_trait_object() {
        let mut def = MockFunctionDefinition;
        let dyn_def: &mut dyn FunctionDefinition = &mut def;
        dyn_def.set_var_args(true);
        dyn_def.set_no_return(true);
        dyn_def.set_comment(Some("a comment".to_string()));
        assert!(dyn_def.set_return_type(Box::new(MockFunctionDefinition)).is_ok());
        assert!(dyn_def
            .set_calling_convention(Some("__stdcall".to_string()))
            .is_ok());
        dyn_def.replace_argument(
            0,
            Some("arg0".to_string()),
            Box::new(MockFunctionDefinition),
            None,
            SourceType::UserDefined,
        );
    }
}
