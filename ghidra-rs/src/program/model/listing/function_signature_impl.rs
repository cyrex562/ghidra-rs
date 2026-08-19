//! Port of `ghidra.program.model.listing.FunctionSignatureImpl`.
//!
//! The Java class is `@Deprecated` and does nothing but forward four constructor overloads to
//! [`FunctionDefinitionDataType`]'s own constructors (`FunctionSignatureImpl(String)` ->
//! `super(name)`, `FunctionSignatureImpl(FunctionSignature)` -> `super(signature)`,
//! `FunctionSignatureImpl(Function)`/`FunctionSignatureImpl(Function, boolean)` ->
//! `super(function, formalSignature)`) -- it declares no field and overrides no method. Per the
//! precedent already set in [`FunctionDefinitionDataType`]'s own module documentation (Java
//! constructors are not modeled as trait content -- a concrete implementor's own constructor is
//! expected to populate the backing storage directly), these forwarding constructors are likewise
//! left unmodeled here: there would be nothing left for them to do beyond what
//! [`FunctionDefinitionDataType`]'s documentation already covers.
//!
//! Since the Java class contributes no method beyond what it inherits, this is a pure marker
//! trait extending [`FunctionDefinitionDataType`], preserving the ability to name "the deprecated
//! `FunctionSignatureImpl` subtype" specifically (e.g. a `Box<dyn FunctionSignatureImpl>` call
//! site that still wants the narrower, deprecated type) without adding any new trait methods.

use crate::program::model::data::function_definition_data_type::FunctionDefinitionDataType;

/// Implementation of a Function Signature. All the information about a function that is portable
/// from one program to another.
///
/// Port of `ghidra.program.model.listing.FunctionSignatureImpl`.
///
/// # Deprecated
/// [`FunctionDefinitionDataType`] should be used for defining a function signature.
#[deprecated = "FunctionDefinitionDataType should be used for defining a function signature"]
pub trait FunctionSignatureImpl: FunctionDefinitionDataType {}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::function_definition::FunctionDefinition;
    use crate::program::model::data::parameter_definition::ParameterDefinition;
    use crate::program::model::lang::compiler_spec::CALLING_CONVENTION_UNKNOWN;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function_signature::FunctionSignature;
    use crate::program::model::symbol::source_type::SourceType;
    use crate::program::seam_stubs::GenericCallingConvention as GenericCallingConventionPlaceholder;
    use crate::util::exception::InvalidInputException;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_length() == dt.get_length()
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(*self)
        }
    }

    struct MockSignatureImpl {
        name: String,
        return_type: MockDataType,
        has_no_return: bool,
        calling_convention_name: String,
    }

    impl MockSignatureImpl {
        fn new(name: &str) -> Self {
            MockSignatureImpl {
                name: name.to_string(),
                return_type: MockDataType { length: 4 },
                has_no_return: false,
                calling_convention_name: CALLING_CONVENTION_UNKNOWN.to_string(),
            }
        }
    }

    impl DataType for MockSignatureImpl {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn is_function_definition_type(&self) -> bool {
            true
        }
    }

    impl FunctionSignature for MockSignatureImpl {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_prototype_string_with_calling_convention(
            &self,
            include_calling_convention: bool,
        ) -> String {
            self.function_definition_data_type_impl_prototype_string(include_calling_convention)
        }
        fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            Vec::new()
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(self.return_type)
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn has_no_return(&self) -> bool {
            self.has_no_return
        }
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            self.calling_convention_name.clone()
        }
        fn is_equivalent_signature(&self, signature: &dyn FunctionSignature) -> bool {
            self.function_definition_data_type_impl_is_equivalent_signature(signature)
        }
    }

    impl FunctionDefinition for MockSignatureImpl {
        fn set_arguments(&mut self, _args: Vec<Box<dyn ParameterDefinition>>) {}
        fn set_return_type(&mut self, data_type: Box<dyn DataType>) -> Result<(), String> {
            self.return_type = MockDataType {
                length: data_type.get_length(),
            };
            Ok(())
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn set_no_return(&mut self, has_no_return: bool) {
            self.has_no_return = has_no_return;
        }
        fn set_generic_calling_convention(
            &mut self,
            _generic_calling_convention: &dyn GenericCallingConventionPlaceholder,
        ) {
        }
        fn set_calling_convention(
            &mut self,
            convention_name: Option<String>,
        ) -> Result<(), InvalidInputException> {
            self.calling_convention_name =
                convention_name.unwrap_or_else(|| CALLING_CONVENTION_UNKNOWN.to_string());
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

    impl FunctionDefinitionDataType for MockSignatureImpl {
        fn stored_return_type(&self) -> Box<dyn DataType> {
            Box::new(self.return_type)
        }
        fn set_stored_return_type(&mut self, return_type: Box<dyn DataType>) {
            self.return_type = MockDataType {
                length: return_type.get_length(),
            };
        }
        fn stored_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            Vec::new()
        }
        fn set_stored_arguments(&mut self, _arguments: Vec<Box<dyn ParameterDefinition>>) {}
        fn stored_comment(&self) -> Option<String> {
            None
        }
        fn set_stored_comment(&mut self, _comment: Option<String>) {}
        fn stored_has_var_args(&self) -> bool {
            false
        }
        fn set_stored_has_var_args(&mut self, _has_var_args: bool) {}
        fn stored_has_no_return(&self) -> bool {
            self.has_no_return
        }
        fn set_stored_has_no_return(&mut self, has_no_return: bool) {
            self.has_no_return = has_no_return;
        }
        fn stored_calling_convention_name(&self) -> String {
            self.calling_convention_name.clone()
        }
        fn set_stored_calling_convention_name(&mut self, calling_convention_name: String) {
            self.calling_convention_name = calling_convention_name;
        }
    }

    impl FunctionSignatureImpl for MockSignatureImpl {}

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut sig = MockSignatureImpl::new("foo");
        sig.set_no_return(true);
        let dyn_sig: Box<dyn FunctionSignatureImpl> = Box::new(sig);

        assert_eq!(FunctionSignature::get_name(dyn_sig.as_ref()), "foo");
        assert_eq!(
            dyn_sig.get_prototype_string_with_calling_convention(true),
            "noreturn int foo(void)"
        );
        assert!(dyn_sig.has_no_return());
        assert!(dyn_sig.has_unknown_calling_convention_name());
    }

    #[test]
    fn is_equivalent_signature_delegates_to_function_definition_data_type_impl() {
        let a = MockSignatureImpl::new("foo");
        let mut b = MockSignatureImpl::new("foo");
        assert!(a.is_equivalent_signature(&b));

        b.set_no_return(true);
        assert!(!a.is_equivalent_signature(&b));
    }
}
