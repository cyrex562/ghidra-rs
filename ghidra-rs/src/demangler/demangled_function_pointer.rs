//! Port of `ghidra.app.util.demangler.DemangledFunctionPointer`.
//!
//! A concrete data type representing a demangled function pointer.
//!
//! Java: `class DemangledFunctionPointer extends AbstractDemangledFunctionDefinitionDataType`,
//! which itself `extends DemangledDataType extends DemangledType`. This port composes BOTH
//! bases as fields -- `base: DemangledType` (already ported) and
//! `abstract_base: AbstractDemangledFunctionDefinitionDataTypeBase` (this batch) -- rather than
//! modeling the intermediate `DemangledDataType` layer, which is not ported (see
//! `crate::demangler::seam_stubs::DemangledDataType`'s docs for why).

use crate::demangler::abstract_demangled_function_definition_data_type::AbstractDemangledFunctionDefinitionDataTypeBase;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_type::DemangledType;
use crate::demangler::seam_stubs::{
    AbstractDemangledFunctionDefinitionDataType, DemangledDataType as DemangledDataTypeSeam, DemangledDataTypeLike,
};

/// A concrete demangled function pointer.
///
/// Port of `ghidra.app.util.demangler.DemangledFunctionPointer`. This type represents a
/// function pointer and extends the abstract function definition type.
///
/// The key difference between a function pointer and other function references is the handling
/// of display syntax: function pointers can conditionally display or hide the `(*)` syntax when
/// there is no function name.
pub struct DemangledFunctionPointer {
    /// The underlying demangled type state
    base: DemangledType,
    /// Shared `AbstractDemangledFunctionDefinitionDataType` state (return type, calling
    /// convention, parameters, pointer levels, ...).
    abstract_base: AbstractDemangledFunctionDefinitionDataTypeBase,
    /// Whether to display the `(*)` syntax for function pointers without a name
    display_function_pointer_syntax: bool,
}

impl DemangledFunctionPointer {
    /// Creates a new demangled function pointer.
    ///
    /// Mirrors `DemangledFunctionPointer(String mangled, String originalDemangled)`.
    /// Initializes with default display syntax enabled and increments pointer levels by 1
    /// (since a function pointer is 1 level by default).
    pub fn new(mangled: impl Into<String>, original_demangled: impl Into<String>) -> Self {
        let base = DemangledType::new(mangled, original_demangled, "FuncDef0");
        let mut abstract_base = AbstractDemangledFunctionDefinitionDataTypeBase::new();
        abstract_base.increment_pointer_levels();
        Self {
            base,
            abstract_base,
            display_function_pointer_syntax: true,
        }
    }

    /// Sets whether to display the default function pointer syntax `(*)`
    /// when there is no function name.
    ///
    /// Mirrors `setDisplayDefaultFunctionPointerSyntax(boolean)`.
    pub fn set_display_default_function_pointer_syntax(&mut self, display: bool) {
        self.display_function_pointer_syntax = display;
    }

    /// Returns whether the default function pointer syntax `(*)` is displayed
    /// when there is no function name.
    pub fn get_display_function_pointer_syntax(&self) -> bool {
        self.display_function_pointer_syntax
    }

    /// Returns the type string for this function pointer, which is `*`.
    ///
    /// Mirrors the overridden `getTypeString()` method.
    pub fn get_type_string(&self) -> &str {
        "*"
    }

    /// Adds function pointer parens to the signature string buffer based on the display flag.
    ///
    /// Mirrors the overridden `addFunctionPointerParens(StringBuilder, String)` method.
    /// If `display_function_pointer_syntax` is false, returns the string unchanged.
    /// Otherwise, wraps the string in parentheses: `(s)`.
    pub fn add_function_pointer_parens(&self, s: &str) -> String {
        if !self.display_function_pointer_syntax {
            return s.to_string();
        }
        format!("({})", s)
    }

    /// Returns a reference to the underlying DemangledType.
    pub fn base(&self) -> &DemangledType {
        &self.base
    }

    /// Returns a mutable reference to the underlying DemangledType.
    pub fn base_mut(&mut self) -> &mut DemangledType {
        &mut self.base
    }

    /// Mirrors the inherited `setReturnType(DemangledDataType)`.
    pub fn set_return_type(&mut self, return_type: Box<dyn DemangledDataTypeSeam>) {
        self.abstract_base.set_return_type(return_type);
    }

    /// Mirrors the inherited `getReturnType()`.
    pub fn get_return_type(&self) -> Option<&dyn DemangledDataTypeSeam> {
        self.abstract_base.get_return_type()
    }

    /// Mirrors the inherited `setCallingConvention(String)`.
    pub fn set_calling_convention(&mut self, calling_convention: impl Into<String>) {
        self.abstract_base.set_calling_convention(calling_convention);
    }

    /// Mirrors the inherited `getCallingConvention()`.
    pub fn get_calling_convention(&self) -> Option<&str> {
        self.abstract_base.get_calling_convention()
    }

    /// Mirrors the inherited `addParameter(DemangledDataType)`.
    pub fn add_parameter(&mut self, parameter: Box<dyn DemangledDataTypeSeam>) {
        self.abstract_base.add_parameter(parameter);
    }

    /// Mirrors the inherited `getParameters()`.
    pub fn get_parameters(&self) -> &[Box<dyn DemangledDataTypeSeam>] {
        self.abstract_base.get_parameters()
    }

    /// Mirrors the inherited `getPointerLevels()`.
    pub fn get_pointer_levels(&self) -> i32 {
        self.abstract_base.get_pointer_levels()
    }
}

impl Demangled for DemangledFunctionPointer {
    fn get_mangled_string(&self) -> String {
        self.base.get_mangled_string()
    }

    fn get_original_demangled(&self) -> String {
        self.base.get_original_demangled()
    }

    fn get_name(&self) -> String {
        self.base.get_name()
    }

    fn set_name(&mut self, name: &str) {
        self.base.set_name(name);
    }

    fn get_demangled_name(&self) -> String {
        self.base.get_demangled_name()
    }

    fn get_namespace(&self) -> Option<&dyn Demangled> {
        self.base.get_namespace()
    }

    fn get_namespace_mut(&mut self) -> Option<&mut (dyn Demangled + 'static)> {
        self.base.get_namespace_mut()
    }

    fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
        self.base.set_namespace(namespace);
    }

    fn get_namespace_string(&self) -> String {
        self.base.get_namespace_string()
    }

    fn get_namespace_name(&self) -> String {
        self.base.get_namespace_name()
    }

    /// Mirrors `AbstractDemangledFunctionDefinitionDataType.getSignature()`, which overrides
    /// `DemangledType`'s default (name-only) signature with `toSignature(null)`.
    fn get_signature(&self) -> String {
        AbstractDemangledFunctionDefinitionDataType::to_signature(self, None)
    }
}

impl DemangledDataTypeLike for DemangledFunctionPointer {}

impl AbstractDemangledFunctionDefinitionDataType for DemangledFunctionPointer {
    fn get_type_string(&self) -> String {
        DemangledFunctionPointer::get_type_string(self).to_string()
    }

    fn to_signature(&self, name: Option<&str>) -> String {
        self.abstract_base.to_signature(
            name,
            DemangledFunctionPointer::get_type_string(self),
            self.base.is_const(),
            self.base.is_volatile(),
            |s| self.add_function_pointer_parens(s),
        )
    }
}

impl DemangledDataTypeSeam for DemangledFunctionPointer {
    fn get_signature(&self) -> String {
        Demangled::get_signature(self)
    }

    fn as_function_definition_like(&self) -> Option<&dyn AbstractDemangledFunctionDefinitionDataType> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDataType(&'static str);
    impl DemangledDataTypeSeam for FakeDataType {
        fn get_signature(&self) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn test_create_function_pointer() {
        let fp = DemangledFunctionPointer::new("_Z3fooPFvvE", "foo(void (*)(void))");
        assert_eq!(fp.get_mangled_string(), "_Z3fooPFvvE");
        assert_eq!(fp.get_display_function_pointer_syntax(), true);
        // A function pointer is 1 pointer level by default.
        assert_eq!(fp.get_pointer_levels(), 1);
    }

    #[test]
    fn test_set_display_syntax() {
        let mut fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        fp.set_display_default_function_pointer_syntax(false);
        assert_eq!(fp.get_display_function_pointer_syntax(), false);
    }

    #[test]
    fn test_add_parens_enabled() {
        let fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        assert_eq!(fp.get_type_string(), "*");
        assert_eq!(fp.add_function_pointer_parens("*"), "(*)")
    }

    #[test]
    fn test_add_parens_disabled() {
        let mut fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        fp.set_display_default_function_pointer_syntax(false);
        assert_eq!(fp.add_function_pointer_parens("*"), "*");
    }

    #[test]
    fn test_set_name() {
        let mut fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        fp.set_name("my_func");
        assert_eq!(fp.get_name(), "my_func");
    }

    #[test]
    fn test_type_string() {
        let fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        assert_eq!(fp.get_type_string(), "*");
    }

    #[test]
    fn get_signature_builds_full_function_pointer_signature() {
        // Mirrors `AbstractDemangledFunctionDefinitionDataType.getSignature()`, which is always
        // `toSignature(null)` -- the name (if any) plays no part in `getSignature()`.
        let mut fp = DemangledFunctionPointer::new("_Z3fooPFvvE", "foo(void (*)(void))");
        fp.set_name("myFunc");
        fp.set_return_type(Box::new(FakeDataType("void")));
        fp.set_calling_convention("__cdecl");
        fp.add_parameter(Box::new(FakeDataType("int")));

        let sig = Demangled::get_signature(&fp);
        assert_eq!(sig, "void (__cdecl *)(int)");

        // But `to_signature` (the dyn-dispatchable trait method) DOES honor an explicit name.
        let named = AbstractDemangledFunctionDefinitionDataType::to_signature(&fp, Some("myFunc"));
        assert_eq!(named, "void (__cdecl * myFunc)(int)");
    }

    #[test]
    fn get_signature_without_display_syntax_omits_parens() {
        let mut fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        fp.set_return_type(Box::new(FakeDataType("int")));
        fp.set_display_default_function_pointer_syntax(false);

        let sig = Demangled::get_signature(&fp);
        assert_eq!(sig, "int *()");
    }

    #[test]
    fn as_data_type_reports_as_function_definition_like() {
        let fp = DemangledFunctionPointer::new("_Z3foo", "foo");
        let dt: &dyn DemangledDataTypeSeam = &fp;
        assert!(dt.as_function_definition_like().is_some());
    }
}
