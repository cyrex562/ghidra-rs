use crate::program::model::data::data_type::DataType;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::seam_stubs::PrototypeModel;

/// Display string used in a formatted prototype string for a non-returning function.
pub const NORETURN_DISPLAY_STRING: &str = "noreturn";
/// Display string used in a formatted prototype string for a variable argument list.
pub const VAR_ARGS_DISPLAY_STRING: &str = "...";
/// Display string used in a formatted prototype string for a function with no parameters.
pub const VOID_PARAM_DISPLAY_STRING: &str = "void";

/// Interface describing all the things about a function that are portable from one program to
/// another.
///
/// Port of `ghidra.program.model.listing.FunctionSignature`.
pub trait FunctionSignature {
    /// Return the name of this function.
    fn get_name(&self) -> String;

    /// Get string representation of the function signature without the calling convention
    /// specified.
    fn get_prototype_string(&self) -> String {
        self.get_prototype_string_with_calling_convention(false)
    }

    /// Get string representation of the function signature.
    ///
    /// `include_calling_convention`: if true, the prototype will include the call convention
    /// declaration if known, as well as a `noreturn` indicator if applicable.
    fn get_prototype_string_with_calling_convention(&self, include_calling_convention: bool)
        -> String;

    /// Get function signature parameter arguments.
    fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>>;

    /// Get function signature return type.
    fn get_return_type(&self) -> Box<dyn DataType>;

    /// Get descriptive comment for signature.
    fn get_comment(&self) -> Option<String>;

    /// True if this function signature has a variable argument list (VarArgs).
    fn has_var_args(&self) -> bool;

    /// True if this function signature corresponds to a non-returning function.
    fn has_no_return(&self) -> bool;

    /// Gets the calling convention prototype model for this function if associated with a
    /// compiler specification. Always `None` if this signature is not associated with a specific
    /// program architecture.
    fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>>;

    /// Returns the calling convention name associated with this function definition.
    ///
    /// Reserved names may also be returned, e.g. the unknown or default calling convention
    /// names. The "unknown" convention must be returned instead of `None`.
    fn get_calling_convention_name(&self) -> String;

    /// Determine if this signature has an unknown or unrecognized calling convention name.
    fn has_unknown_calling_convention_name(&self) -> bool {
        self.get_calling_convention().is_none()
    }

    /// Returns true if the given signature is equivalent to this signature. The precise meaning
    /// of "equivalent" is dependent upon return/parameter dataTypes.
    fn is_equivalent_signature(&self, signature: &dyn FunctionSignature) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockSignature {
        name: String,
        no_return: bool,
    }

    impl FunctionSignature for MockSignature {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_prototype_string_with_calling_convention(
            &self,
            _include_calling_convention: bool,
        ) -> String {
            format!("void {}(void)", self.name)
        }

        fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            Vec::new()
        }

        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn has_var_args(&self) -> bool {
            false
        }

        fn has_no_return(&self) -> bool {
            self.no_return
        }

        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }

        fn is_equivalent_signature(&self, signature: &dyn FunctionSignature) -> bool {
            self.get_name() == signature.get_name()
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let sig: Box<dyn FunctionSignature> = Box::new(MockSignature {
            name: "foo".to_string(),
            no_return: true,
        });
        assert_eq!(sig.get_name(), "foo");
        assert_eq!(sig.get_prototype_string(), "void foo(void)");
        assert!(sig.has_no_return());
        assert!(sig.has_unknown_calling_convention_name());
        assert!(sig.is_equivalent_signature(sig.as_ref()));
    }
}
