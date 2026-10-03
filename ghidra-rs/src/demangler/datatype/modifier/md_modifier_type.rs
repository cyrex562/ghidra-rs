use crate::demangler::seam_stubs::{MdCvModLike, MdMangLike, MdTypeLike};

const VOLATILE: &str = "volatile";
const CONST: &str = "const";

/// Represents a modifier type, whether a pointer, reference, or other special modifier type,
/// within a Microsoft mangled symbol.
///
/// Mirrors `mdemangler.datatype.modifier.MDModifierType`, cut to a trait to break a dependency
/// cycle with `MDMang`/`MDParsableItem`/`MDDataType` (none ported yet) and, transitively, with
/// `MDCVMod`/`MDType`/`MDFunctionType`/`MDArrayReferencedType` (also not ported). The parsing
/// side of the original (`parseInternal`, `parseReferencedType`, driven by the still-unported
/// `MDMang` character reader and the construction of fresh `MDFunctionType`/
/// `MDArrayReferencedType` instances) is intentionally out of scope here, the same as for
/// [`crate::demangler::datatype::modifier::md_based_attribute::MdBasedAttribute`]: it isn't
/// expressible against a not-yet-real driver. This trait models the rest of the public surface --
/// the query/render API callers depend on -- via accessors mirroring the original's protected
/// `cvMod`/`refType` fields and private `isConst`/`isVolatile` fields, plus a default
/// `insert`/`insert_as_arg` implementation mirroring `insertInternal`.
pub trait MdModifierType {
    /// Returns the CV-modifier (pointer/reference/array kind, const/volatile/based/managed
    /// properties) this modifier type wraps.
    ///
    /// Mirrors `getCVMod()`, the raw accessor for the protected `cvMod` field.
    fn cv_mod(&self) -> &dyn MdCvModLike;

    /// Returns the type this modifier refers to (the pointee/referent/element type).
    ///
    /// Mirrors `getReferencedType()`, the raw accessor for the protected `refType` field.
    fn referenced_type(&self) -> &dyn MdTypeLike;

    /// Returns whether this modifier type is `const`.
    ///
    /// Raw accessor mirroring the private `isConst` field (see `isConst()`).
    fn is_const(&self) -> bool;

    /// Sets whether this modifier type is `const`.
    ///
    /// Mirrors `setConst(boolean)`.
    fn set_const(&mut self, is_const: bool);

    /// Returns whether this modifier type is `volatile`.
    ///
    /// Raw accessor mirroring the private `isVolatile` field (see `isVolatile()`).
    fn is_volatile(&self) -> bool;

    /// Sets whether this modifier type is `volatile`.
    ///
    /// Mirrors `setVolatile(boolean)`.
    fn set_volatile(&mut self, is_volatile: bool);

    /// Returns whether the pointer/reference is `__ptr64`.
    ///
    /// Mirrors `isPointer64()`, which delegates to `cvMod.isPointer64()`.
    fn is_pointer64(&self) -> bool {
        self.cv_mod().is_pointer64()
    }

    /// Returns whether the pointer/reference is `__restrict`.
    ///
    /// Mirrors `isRestrict()`, which delegates to `cvMod.isRestricted()`.
    fn is_restrict(&self) -> bool {
        self.cv_mod().is_restricted()
    }

    /// Returns whether the pointer/reference is `__unaligned`.
    ///
    /// Mirrors `isUnaligned()`, which delegates to `cvMod.isUnaligned()`.
    fn is_unaligned(&self) -> bool {
        self.cv_mod().is_unaligned()
    }

    /// Returns the rendered `__based(...)` clause name, if this modifier type is based.
    ///
    /// Mirrors `getBasedName()`, which delegates to `cvMod.getBasedName()`.
    fn based_name(&self) -> Option<&str> {
        self.cv_mod().based_name()
    }

    /// Returns the rendered member-pointer scope qualification, if this modifier type is a
    /// pointer-to-member.
    ///
    /// Mirrors `getMemberScope()`, which delegates to `cvMod.getMemberScope()`.
    fn member_scope(&self) -> Option<&str> {
        self.cv_mod().member_scope()
    }

    /// Inserts this modifier type's rendered text at the front of `builder`.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        self.insert_internal(dmang, builder, false);
    }

    /// Inserts this modifier type's rendered text at the front of `builder`, as though it is a
    /// template or function argument.
    ///
    /// Mirrors `insertAsArg(StringBuilder)`.
    fn insert_as_arg(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        self.insert_internal(dmang, builder, true);
    }

    /// Mirrors the private `insertInternal(StringBuilder, boolean)`, the shared body behind
    /// [`MdModifierType::insert`]/[`MdModifierType::insert_as_arg`].
    fn insert_internal(&self, dmang: &dyn MdMangLike, builder: &mut String, as_arg: bool) {
        let cv_mod = self.cv_mod();
        let ref_type = self.referenced_type();

        if !cv_mod.is_cli_array() {
            if self.is_volatile() {
                dmang.insert_spaced_string(builder, VOLATILE);
            }
            if self.is_const() {
                dmang.insert_spaced_string(builder, CONST);
            }
        }

        if ref_type.is_function_type()
            && (cv_mod.is_pointer_type()
                || cv_mod.is_function_pointer_type()
                || cv_mod.is_reference_type()
                || cv_mod.is_function_reference_type()
                || cv_mod.is_array_type()
                || !builder.is_empty())
        {
            ref_type.mark_from_modifier();
        }

        cv_mod.insert(dmang, builder);
        dmang.clean_output(builder);

        if ref_type.is_array_referenced_type() {
            self.insert_referred_type(dmang, builder, as_arg);
        } else if cv_mod.is_pin_pointer() {
            let mut ref_builder = String::new();
            self.insert_referred_type(dmang, &mut ref_builder, as_arg);
            dmang.append_string(&mut ref_builder, " ");
            if !(cv_mod.is_question_type()
                || (cv_mod.is_pointer_type() && ref_type.is_void_data_type()))
            {
                cv_mod.insert_managed_properties_prefix(dmang, &mut ref_builder);
                cv_mod.insert_managed_properties_suffix(dmang, &mut ref_builder);
            }
            dmang.insert_string(builder, &ref_builder);
        } else if cv_mod.is_cli_array() {
            let mut ref_builder = String::new();
            self.insert_referred_type(dmang, &mut ref_builder, as_arg);
            if !ref_type.is_void_data_type() {
                cv_mod.insert_managed_properties_prefix(dmang, &mut ref_builder);
            }
            cv_mod.insert_managed_properties_suffix(dmang, &mut ref_builder);
            dmang.insert_cli_array_ref_suffix(builder, &ref_builder);
        } else {
            self.insert_referred_type(dmang, builder, as_arg);
        }
    }

    /// Mirrors the protected `insertReferredType(StringBuilder, boolean)`.
    fn insert_referred_type(&self, dmang: &dyn MdMangLike, builder: &mut String, as_arg: bool) {
        let ref_type = self.referenced_type();
        if ref_type.is_data_type() && as_arg {
            ref_type.insert_as_arg(dmang, builder);
        } else {
            ref_type.insert(dmang, builder);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMdMang;

    impl MdMangLike for MockMdMang {
        fn insert_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }

        fn insert_spaced_string(&self, builder: &mut String, s: &str) {
            if builder.is_empty() || s.is_empty() {
                builder.insert_str(0, s);
                return;
            }
            builder.insert(0, ' ');
            builder.insert_str(0, s);
        }
    }

    struct MockCvMod {
        pointer_type: bool,
        cli_array: bool,
        pin_pointer: bool,
    }

    impl MdCvModLike for MockCvMod {
        fn is_pointer64(&self) -> bool {
            false
        }

        fn is_restricted(&self) -> bool {
            false
        }

        fn is_unaligned(&self) -> bool {
            false
        }

        fn based_name(&self) -> Option<&str> {
            None
        }

        fn member_scope(&self) -> Option<&str> {
            None
        }

        fn is_cli_array(&self) -> bool {
            self.cli_array
        }

        fn is_pointer_type(&self) -> bool {
            self.pointer_type
        }

        fn is_function_pointer_type(&self) -> bool {
            false
        }

        fn is_reference_type(&self) -> bool {
            false
        }

        fn is_function_reference_type(&self) -> bool {
            false
        }

        fn is_array_type(&self) -> bool {
            false
        }

        fn is_pin_pointer(&self) -> bool {
            self.pin_pointer
        }

        fn is_question_type(&self) -> bool {
            false
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            if self.pointer_type {
                dmang.insert_spaced_string(builder, "*");
            }
        }

        fn insert_managed_properties_prefix(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}

        fn insert_managed_properties_suffix(&self, _dmang: &dyn MdMangLike, _builder: &mut String) {}
    }

    struct MockRefType {
        name: &'static str,
    }

    impl MdTypeLike for MockRefType {
        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, self.name);
        }

        fn is_data_type(&self) -> bool {
            true
        }

        fn is_function_type(&self) -> bool {
            false
        }

        fn is_array_referenced_type(&self) -> bool {
            false
        }

        fn is_void_data_type(&self) -> bool {
            false
        }
    }

    struct MockModifierType {
        cv_mod: MockCvMod,
        ref_type: MockRefType,
        is_const: bool,
        is_volatile: bool,
    }

    impl MdModifierType for MockModifierType {
        fn cv_mod(&self) -> &dyn MdCvModLike {
            &self.cv_mod
        }

        fn referenced_type(&self) -> &dyn MdTypeLike {
            &self.ref_type
        }

        fn is_const(&self) -> bool {
            self.is_const
        }

        fn set_const(&mut self, is_const: bool) {
            self.is_const = is_const;
        }

        fn is_volatile(&self) -> bool {
            self.is_volatile
        }

        fn set_volatile(&mut self, is_volatile: bool) {
            self.is_volatile = is_volatile;
        }
    }

    #[test]
    fn insert_renders_const_pointer_to_int() {
        let modifier = MockModifierType {
            cv_mod: MockCvMod { pointer_type: true, cli_array: false, pin_pointer: false },
            ref_type: MockRefType { name: "int" },
            is_const: true,
            is_volatile: false,
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        modifier.insert(&dmang, &mut builder);

        assert_eq!(builder, "int* const");
    }

    #[test]
    fn setters_round_trip_through_getters() {
        let mut modifier = MockModifierType {
            cv_mod: MockCvMod { pointer_type: false, cli_array: false, pin_pointer: false },
            ref_type: MockRefType { name: "char" },
            is_const: false,
            is_volatile: false,
        };

        modifier.set_const(true);
        modifier.set_volatile(true);

        assert!(modifier.is_const());
        assert!(modifier.is_volatile());
    }

    #[test]
    fn insert_as_arg_matches_insert_for_plain_data_type() {
        let modifier = MockModifierType {
            cv_mod: MockCvMod { pointer_type: true, cli_array: false, pin_pointer: false },
            ref_type: MockRefType { name: "float" },
            is_const: false,
            is_volatile: true,
        };
        let dmang = MockMdMang;

        let mut via_insert = String::new();
        modifier.insert(&dmang, &mut via_insert);

        let mut via_arg = String::new();
        modifier.insert_as_arg(&dmang, &mut via_arg);

        assert_eq!(via_insert, via_arg);
        assert_eq!(via_insert, "float* volatile");
    }

    #[test]
    fn trait_object_is_usable() {
        let modifier = MockModifierType {
            cv_mod: MockCvMod { pointer_type: true, cli_array: false, pin_pointer: false },
            ref_type: MockRefType { name: "double" },
            is_const: false,
            is_volatile: false,
        };
        let obj: &dyn MdModifierType = &modifier;
        let dmang = MockMdMang;
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "double*");
        assert!(!obj.is_const());
    }
}
