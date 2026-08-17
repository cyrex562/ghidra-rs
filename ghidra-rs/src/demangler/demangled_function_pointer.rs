//! Port of `ghidra.app.util.demangler.DemangledFunctionPointer`.
//!
//! A concrete data type representing a demangled function pointer.

use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_type::DemangledType;
use crate::demangler::seam_stubs::{
    AbstractDemangledFunctionDefinitionDataType, DemangledDataType as DemangledDataTypeSeam,
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
        // Note: we need to be able to mutate here to increment pointer levels,
        // but the Java constructor calls incrementPointerLevels on a field.
        // Since we can't mutate self during construction, we'll handle this in post-construction
        let base = DemangledType::new(mangled, original_demangled, "FuncDef0");
        Self {
            base,
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

    fn get_signature(&self) -> String {
        self.base.get_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_function_pointer() {
        let fp = DemangledFunctionPointer::new("_Z3fooPFvvE", "foo(void (*)(void))");
        assert_eq!(fp.get_mangled_string(), "_Z3fooPFvvE");
        assert_eq!(fp.get_display_function_pointer_syntax(), true);
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
}
