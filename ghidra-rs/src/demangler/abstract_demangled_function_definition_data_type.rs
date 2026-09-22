//! Port of `ghidra.app.util.demangler.AbstractDemangledFunctionDefinitionDataType`.
//!
//! Java is `abstract class AbstractDemangledFunctionDefinitionDataType extends DemangledDataType`
//! with 9 instance fields and 3 in-repo concrete subclasses
//! (`DemangledFunctionPointer`/`DemangledFunctionReference`/`DemangledFunctionIndirect`). Per
//! `scripts/shape_rules.py`'s directive for an abstract class carrying both state and behavior,
//! the shared fields and concrete methods live here on
//! [`AbstractDemangledFunctionDefinitionDataTypeBase`]; only the one truly abstract method
//! (`getTypeString()`) is declared on the
//! [`AbstractDemangledFunctionDefinitionDataType`](crate::demangler::seam_stubs::AbstractDemangledFunctionDefinitionDataType)
//! trait in `seam_stubs.rs`. A concrete subclass composes this base as a field (the same
//! composition-over-inheritance convention `DemangledFunctionPointer` already uses for its own
//! `DemangledType` base) and implements the trait by delegating to it.
//!
//! **Fields inherited from the unported `DemangledDataType`**: Java's `pointerLevels`/
//! `isPointer64`/`isLValueReference`/`isRValueReference` are actually declared on the *parent*
//! class `DemangledDataType` (766 lines, not ported -- see its stub's docs in `seam_stubs.rs`),
//! not on `AbstractDemangledFunctionDefinitionDataType` itself. `toSignature`/
//! `getConventionPointerNameString` are, however, defined HERE and read/write those fields as
//! `this.*` -- i.e. this is their only real consumer among what's ported so far, and none of
//! `DemangledDataType`'s other 20+ fields (isArray/isClass/isComplex/isEnum/isStruct/isUnion/...)
//! are touched by this class's own logic. Rather than block on the full parent class, those four
//! fields are modeled directly on this base struct, documented as "really" belonging to the
//! parent. `isReference()` (`isLValueReference() || isRValueReference()`) is derived, matching
//! Java.
//!
//! **Not ported**: `getDataType(DataTypeManager)` (Java's real-`DataType`-resolution method).
//! It builds a `FunctionDefinitionDataType` via `PointerDataType.getPointer`/
//! `ParameterDefinitionImpl`/`DataTypeNamingUtil` -- `FunctionDefinitionDataType`/`PointerDataType`/
//! `ParameterDefinitionImpl` are all still traits without concrete instantiable singletons in this
//! crate (the same "DWORD singleton" class of gap documented across the PE format ports this same
//! batch), so this cannot be built yet. Left unimplemented rather than stubbed to a wrong answer.

use crate::demangler::seam_stubs::{AbstractDemangledFunctionDefinitionDataType, DemangledDataType};

/// `AbstractDemangledFunctionDefinitionDataType.SPACE`/`CONST`/`VOLATILE`/`UNALIGNED`/`PTR64`/
/// `RESTRICT` are inherited `public static final String` constants declared on the unported
/// `DemangledObject` (the root of the `Demangled` hierarchy). Reproduced directly here (fixed
/// string literals that will never change), matching the `DWORD_LEN`-style convention used
/// elsewhere in this port for a small constant borrowed from an unported ancestor.
const SPACE: char = ' ';
const CONST: &str = "const";
const VOLATILE: &str = "volatile";
const UNALIGNED: &str = "__unaligned";
const PTR64: &str = "__ptr64";
const RESTRICT: &str = "__restrict";

/// Shared state and concrete behavior for [`AbstractDemangledFunctionDefinitionDataType`]
/// implementors. See this module's docs for what is and is not modeled.
pub struct AbstractDemangledFunctionDefinitionDataTypeBase {
    return_type: Option<Box<dyn DemangledDataType>>,
    calling_convention: Option<String>,
    parameters: Vec<Box<dyn DemangledDataType>>,
    modifier: Option<String>,
    is_const_pointer: bool,
    parent_name: Option<String>,
    is_trailing_pointer64: bool,
    is_trailing_unaligned: bool,
    is_trailing_restrict: bool,
    // Really `DemangledDataType` fields -- see module docs.
    pointer_levels: i32,
    is_pointer64: bool,
    is_lvalue_reference: bool,
    is_rvalue_reference: bool,
}

impl AbstractDemangledFunctionDefinitionDataTypeBase {
    /// Port of the package-private `AbstractDemangledFunctionDefinitionDataType(String, String)`
    /// constructor's field initialization (the `mangled`/`originalDemangled`/generated-name
    /// arguments themselves are handled by the concrete subclass's own embedded `DemangledType`,
    /// e.g. `DemangledFunctionPointer::base`).
    pub fn new() -> Self {
        AbstractDemangledFunctionDefinitionDataTypeBase {
            return_type: None,
            calling_convention: None,
            parameters: Vec::new(),
            modifier: None,
            is_const_pointer: false,
            parent_name: None,
            is_trailing_pointer64: false,
            is_trailing_unaligned: false,
            is_trailing_restrict: false,
            pointer_levels: 0,
            is_pointer64: false,
            is_lvalue_reference: false,
            is_rvalue_reference: false,
        }
    }

    /// Mirrors `setReturnType(DemangledDataType)`.
    pub fn set_return_type(&mut self, return_type: Box<dyn DemangledDataType>) {
        self.return_type = Some(return_type);
    }

    /// Mirrors `getReturnType()`.
    pub fn get_return_type(&self) -> Option<&dyn DemangledDataType> {
        self.return_type.as_deref()
    }

    /// Mirrors `setCallingConvention(String)`.
    pub fn set_calling_convention(&mut self, calling_convention: impl Into<String>) {
        self.calling_convention = Some(calling_convention.into());
    }

    /// Mirrors `getCallingConvention()`.
    pub fn get_calling_convention(&self) -> Option<&str> {
        self.calling_convention.as_deref()
    }

    /// Mirrors `setModifier(String)`.
    pub fn set_modifier(&mut self, modifier: impl Into<String>) {
        self.modifier = Some(modifier.into());
    }

    /// Mirrors `setParentName`-equivalent state used by `addParentName`. Not present as a public
    /// Java setter (the `parentName` field has no `setParentName` in the excerpted source, but is
    /// read by `addParentName`); exposed here so a concrete subclass can populate it.
    pub fn set_parent_name(&mut self, parent_name: impl Into<String>) {
        self.parent_name = Some(parent_name.into());
    }

    /// Mirrors `isConstPointer()`.
    pub fn is_const_pointer(&self) -> bool {
        self.is_const_pointer
    }

    /// Mirrors `setConstPointer()`.
    pub fn set_const_pointer(&mut self) {
        self.is_const_pointer = true;
    }

    /// Mirrors `isTrailingPointer64()`.
    pub fn is_trailing_pointer64(&self) -> bool {
        self.is_trailing_pointer64
    }

    /// Mirrors `setTrailingPointer64()`.
    pub fn set_trailing_pointer64(&mut self) {
        self.is_trailing_pointer64 = true;
    }

    /// Mirrors `isTrailingUnaligned()`.
    pub fn is_trailing_unaligned(&self) -> bool {
        self.is_trailing_unaligned
    }

    /// Mirrors `setTrailingUnaligned()`.
    pub fn set_trailing_unaligned(&mut self) {
        self.is_trailing_unaligned = true;
    }

    /// Mirrors `isTrailingRestrict()`.
    pub fn is_trailing_restrict(&self) -> bool {
        self.is_trailing_restrict
    }

    /// Mirrors `setTrailingRestrict()`.
    pub fn set_trailing_restrict(&mut self) {
        self.is_trailing_restrict = true;
    }

    /// Mirrors `addParameter(DemangledDataType)`.
    pub fn add_parameter(&mut self, parameter: Box<dyn DemangledDataType>) {
        self.parameters.push(parameter);
    }

    /// Mirrors `getParameters()` (Java returns a defensive copy; this returns a borrowing slice,
    /// which is equally safe against external mutation since there is no setter that replaces
    /// the whole list).
    pub fn get_parameters(&self) -> &[Box<dyn DemangledDataType>] {
        &self.parameters
    }

    /// Mirrors `getPointerLevels()`. See module docs re: this field really belonging to
    /// `DemangledDataType`.
    pub fn get_pointer_levels(&self) -> i32 {
        self.pointer_levels
    }

    /// Mirrors the inherited `incrementPointerLevels()`.
    pub fn increment_pointer_levels(&mut self) {
        self.pointer_levels += 1;
    }

    /// Mirrors the inherited `isPointer64()`.
    pub fn is_pointer64(&self) -> bool {
        self.is_pointer64
    }

    /// Mirrors the inherited `setPointer64()`.
    pub fn set_pointer64(&mut self) {
        self.is_pointer64 = true;
    }

    /// Mirrors the inherited `isLValueReference()`.
    pub fn is_lvalue_reference(&self) -> bool {
        self.is_lvalue_reference
    }

    /// Mirrors the inherited `setLValueReference()`, which Java defines to also clear
    /// `isRValueReference` (a value reference can't be both).
    pub fn set_lvalue_reference(&mut self) {
        self.is_lvalue_reference = true;
        self.is_rvalue_reference = false;
    }

    /// Mirrors the inherited `isRValueReference()`.
    pub fn is_rvalue_reference(&self) -> bool {
        self.is_rvalue_reference
    }

    /// Mirrors the inherited `setRValueReference()`, symmetric with
    /// [`set_lvalue_reference`](Self::set_lvalue_reference).
    pub fn set_rvalue_reference(&mut self) {
        self.is_rvalue_reference = true;
        self.is_lvalue_reference = false;
    }

    /// Mirrors the inherited `isReference()`.
    pub fn is_reference(&self) -> bool {
        self.is_lvalue_reference() || self.is_rvalue_reference()
    }

    /// Mirrors `toSignature(String)`.
    ///
    /// Java dispatches several pieces virtually on `this`; since this base struct is not itself
    /// the concrete type, those are threaded through as parameters instead:
    /// - `type_string`: `getTypeString()` (the one abstract method).
    /// - `is_const`/`is_volatile`: `isConst()`/`isVolatile()`, inherited from `DemangledType` via
    ///   the concrete subclass's OTHER embedded base (e.g. `DemangledFunctionPointer::base`).
    /// - `wrap_pointer_parens`: `addFunctionPointerParens(StringBuilder, String)`, overridden by
    ///   `DemangledFunctionPointer` to conditionally omit the parens; modeled as a closure
    ///   standing in for that virtual call.
    #[allow(clippy::too_many_arguments)]
    pub fn to_signature(
        &self,
        name: Option<&str>,
        type_string: &str,
        is_const: bool,
        is_volatile: bool,
        wrap_pointer_parens: impl Fn(&str) -> String,
    ) -> String {
        let mut buffer = String::new();
        let s = self.get_convention_pointer_name_string(name, type_string);

        let mut buffer1 = wrap_pointer_parens(&s);

        buffer1.push('(');
        let param_count = self.parameters.len();
        for (i, parameter) in self.parameters.iter().enumerate() {
            buffer1.push_str(&parameter.get_signature());
            if i < param_count - 1 {
                buffer1.push(',');
            }
        }
        buffer1.push(')');

        match self.return_type.as_deref() {
            Some(return_type) => {
                if let Some(function_like) = return_type.as_function_definition_like() {
                    buffer.push_str(&function_like.to_signature(Some(&buffer1)));
                    buffer.push(SPACE);
                }
                else {
                    buffer.push_str(&return_type.get_signature());
                    buffer.push(SPACE);
                    buffer.push_str(&buffer1);
                }
            }
            None => {
                // Java would NPE here (`returnType.getSignature()` on a null field); every
                // real caller sets a return type before calling `toSignature`, so this is
                // treated as "no return type" rather than panicking.
                buffer.push_str(&buffer1);
            }
        }

        if is_const {
            if buffer.len() > 2 {
                buffer.push(SPACE);
            }
            buffer.push_str(CONST);
        }

        if is_volatile {
            if buffer.len() > 2 {
                buffer.push(SPACE);
            }
            buffer.push_str(VOLATILE);
        }

        if self.is_trailing_unaligned {
            if buffer.len() > 2 {
                buffer.push(SPACE);
            }
            buffer.push_str(UNALIGNED);
        }

        if self.is_trailing_pointer64 {
            if buffer.len() > 2 {
                buffer.push(SPACE);
            }
            buffer.push_str(PTR64);
        }

        if self.is_trailing_restrict {
            if buffer.len() > 2 {
                buffer.push(SPACE);
            }
            buffer.push_str(RESTRICT);
        }

        buffer
    }

    /// Mirrors `getConventionPointerNameString(String)`.
    fn get_convention_pointer_name_string(&self, name: Option<&str>, type_string: &str) -> String {
        let mut buffer = String::new();
        buffer.push_str(self.calling_convention.as_deref().unwrap_or(""));

        let mut type_buffer = String::new();
        let pointer_levels = self.get_pointer_levels();
        if pointer_levels > 0 || self.is_reference() {
            self.add_parent_name(&mut type_buffer);

            for _ in 0..pointer_levels {
                type_buffer.push_str(type_string);
            }

            // Kludge for now, matching Java's own comment: the current type-emitting mechanism
            // in the DemangledObject hierarchy lacks a lot and needs revamping.
            if self.is_lvalue_reference() {
                type_buffer.push_str(" &");
            }
            else if self.is_rvalue_reference() {
                type_buffer.push_str(" &&");
            }
        }

        if !type_buffer.trim().is_empty() {
            if let Some(cc) = self.calling_convention.as_deref() {
                if !cc.trim().is_empty() {
                    buffer.push(SPACE);
                }
            }
            buffer.push_str(&type_buffer);
        }

        self.add_modifier(&mut buffer, type_string);

        if self.is_const_pointer {
            buffer.push_str(CONST);
        }

        if self.is_pointer64() {
            if buffer.len() > 2 {
                buffer.push(SPACE);
            }
            buffer.push_str(PTR64);
        }

        if let Some(name) = name {
            if !buffer.is_empty() && !buffer.ends_with(SPACE) {
                buffer.push(SPACE);
            }
            buffer.push_str(name);
        }

        buffer
    }

    /// Mirrors the private `addModifier(StringBuilder)`.
    fn add_modifier(&self, buffer: &mut String, type_string: &str) {
        let Some(modifier) = self.modifier.as_deref() else {
            return;
        };
        if modifier.trim().is_empty() {
            return;
        }

        // Guilty knowledge (Java's own comment): in many cases the 'modifier' is the same as the
        // type string. Further, when printing signatures, the type string is printed if there
        // are pointer levels. To prevent duplication, do not print the modifier when it matches
        // the type string and the type string will be printed (pointer levels > 0).
        if modifier == type_string && self.get_pointer_levels() > 0 {
            return;
        }

        if buffer.len() > 2 {
            buffer.push(SPACE);
        }
        buffer.push_str(modifier);
    }

    /// Mirrors the protected `addParentName(StringBuilder)`.
    fn add_parent_name(&self, buffer: &mut String) {
        let Some(parent_name) = self.parent_name.as_deref() else {
            return;
        };
        if parent_name.starts_with(DEFAULT_NAME_PREFIX) {
            return;
        }

        if buffer.len() > 2 {
            if !buffer.ends_with(SPACE) {
                buffer.push(SPACE);
            }
        }
        buffer.push_str(parent_name);
        buffer.push_str(crate::program::model::symbol::namespace::DELIMITER);
    }
}

impl Default for AbstractDemangledFunctionDefinitionDataTypeBase {
    fn default() -> Self {
        Self::new()
    }
}

/// Mirrors `AbstractDemangledFunctionDefinitionDataType.DEFAULT_NAME_PREFIX`.
const DEFAULT_NAME_PREFIX: &str = "FuncDef";

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDataType {
        signature: String,
    }
    impl DemangledDataType for FakeDataType {
        fn get_signature(&self) -> String {
            self.signature.clone()
        }
    }

    fn fake(signature: &str) -> Box<dyn DemangledDataType> {
        Box::new(FakeDataType { signature: signature.to_string() })
    }

    fn identity_parens(s: &str) -> String {
        format!("({s})")
    }

    #[test]
    fn accessors_round_trip() {
        let mut base = AbstractDemangledFunctionDefinitionDataTypeBase::new();
        assert!(base.get_return_type().is_none());
        base.set_return_type(fake("void"));
        assert_eq!(base.get_return_type().unwrap().get_signature(), "void");

        base.set_calling_convention("__cdecl");
        assert_eq!(base.get_calling_convention(), Some("__cdecl"));

        assert!(!base.is_const_pointer());
        base.set_const_pointer();
        assert!(base.is_const_pointer());

        assert!(!base.is_trailing_pointer64());
        base.set_trailing_pointer64();
        assert!(base.is_trailing_pointer64());

        assert_eq!(base.get_pointer_levels(), 0);
        base.increment_pointer_levels();
        base.increment_pointer_levels();
        assert_eq!(base.get_pointer_levels(), 2);

        base.add_parameter(fake("int"));
        base.add_parameter(fake("char"));
        assert_eq!(base.get_parameters().len(), 2);
    }

    #[test]
    fn lvalue_and_rvalue_reference_are_mutually_exclusive() {
        let mut base = AbstractDemangledFunctionDefinitionDataTypeBase::new();
        assert!(!base.is_reference());

        base.set_lvalue_reference();
        assert!(base.is_lvalue_reference());
        assert!(!base.is_rvalue_reference());
        assert!(base.is_reference());

        base.set_rvalue_reference();
        assert!(!base.is_lvalue_reference());
        assert!(base.is_rvalue_reference());
        assert!(base.is_reference());
    }

    #[test]
    fn to_signature_composes_return_type_calling_convention_and_parameters() {
        let mut base = AbstractDemangledFunctionDefinitionDataTypeBase::new();
        base.set_return_type(fake("void"));
        base.set_calling_convention("__cdecl");
        base.add_parameter(fake("int"));
        base.add_parameter(fake("float"));
        base.increment_pointer_levels();

        // Note: the real algorithm always inserts a space before `name` unless the buffer
        // already ends with one (`getConventionPointerNameString`'s trailing `if` checks the
        // last character of the buffer, not whether it's a "pointer" character), so a pointer
        // level followed by a name reads "__cdecl * myFunc", not "__cdecl *myFunc".
        let sig = base.to_signature(Some("myFunc"), "*", false, false, identity_parens);
        assert_eq!(sig, "void (__cdecl * myFunc)(int,float)");
    }

    #[test]
    fn to_signature_appends_const_and_trailing_qualifiers() {
        let mut base = AbstractDemangledFunctionDefinitionDataTypeBase::new();
        base.set_return_type(fake("int"));
        base.set_trailing_pointer64();
        base.set_trailing_restrict();

        let sig = base.to_signature(None, "*", true, false, identity_parens);
        assert!(sig.contains(CONST));
        assert!(sig.contains(PTR64));
        assert!(sig.contains(RESTRICT));
    }

    #[test]
    fn to_signature_uses_nested_to_signature_for_function_like_return_type() {
        struct FunctionLikeReturn;

        impl crate::demangler::demangled::Demangled for FunctionLikeReturn {
            fn get_mangled_string(&self) -> String {
                String::new()
            }
            fn get_original_demangled(&self) -> String {
                String::new()
            }
            fn get_name(&self) -> String {
                String::new()
            }
            fn set_name(&mut self, _name: &str) {}
            fn get_demangled_name(&self) -> String {
                String::new()
            }
            fn get_namespace(&self) -> Option<&dyn crate::demangler::demangled::Demangled> {
                None
            }
            fn get_namespace_mut(&mut self) -> Option<&mut (dyn crate::demangler::demangled::Demangled + 'static)> {
                None
            }
            fn set_namespace(&mut self, _namespace: Option<Box<dyn crate::demangler::demangled::Demangled>>) {}
            fn get_namespace_string(&self) -> String {
                String::new()
            }
            fn get_namespace_name(&self) -> String {
                String::new()
            }
            fn get_signature(&self) -> String {
                "unused".to_string()
            }
        }
        impl crate::demangler::seam_stubs::DemangledDataTypeLike for FunctionLikeReturn {}
        impl DemangledDataType for FunctionLikeReturn {
            fn get_signature(&self) -> String {
                "unused".to_string()
            }
            fn as_function_definition_like(
                &self,
            ) -> Option<&dyn AbstractDemangledFunctionDefinitionDataType> {
                Some(self)
            }
        }
        impl AbstractDemangledFunctionDefinitionDataType for FunctionLikeReturn {
            fn get_type_string(&self) -> String {
                "*".to_string()
            }
            fn to_signature(&self, name: Option<&str>) -> String {
                format!("nested({})", name.unwrap_or(""))
            }
        }

        let mut base = AbstractDemangledFunctionDefinitionDataTypeBase::new();
        base.set_return_type(Box::new(FunctionLikeReturn));

        let sig = base.to_signature(None, "*", false, false, identity_parens);
        assert!(sig.starts_with("nested("));
    }
}
