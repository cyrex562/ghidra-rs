use crate::demangler::naming::md_qualified_name::MdQualifiedName;
use crate::demangler::seam_stubs::{MdDataTypeLike, MdMangLike};

/// Represents the base class of a number of "complex" data types (class/struct/union/enum/
/// coclass/cointerface) within a Microsoft mangled symbol. The term "complex" has nothing to do
/// with complex numbers.
///
/// Mirrors `mdemangler.datatype.complex.MDComplexType`, cut to a trait to break a dependency
/// cycle: it is one of the concrete `MDType`s reachable through `MDMangUtils`
/// (`crate::demangler::md_mang_utils::MdMangUtils`, via the [`crate::demangler::seam_stubs::MdComplexTypeLike`]
/// placeholder), while itself needing the still-unported `MDDataType`/`MDMang` chain. The parsing
/// side of the original (`parseInternal`, which just runs `qualifiedName.parse()` against the
/// still-unported `MDMang` character reader) is intentionally out of scope here, matching the
/// treatment of [`MdQualifiedName`] itself. `MDDataType` (the direct superclass) is collapsed
/// onto the [`MdDataTypeLike`] seam rather than the real (but unwired) `MdDataType` port at
/// [`crate::demangler::datatype::md_data_type`], since that port isn't reachable from this crate
/// (see the `MdDataTypeLike` doc comment); only the signedness queries `super.insert`/
/// `super.insertAsArg` need are declared on that seam. `getTypeName()`'s override (always `""`)
/// is given a fixed default here rather than a raw accessor, since no implementor can meaningfully
/// differ from the original's override.
pub trait MdComplexType {
    /// Returns the namespace-qualified name of this complex type.
    ///
    /// Raw accessor mirroring the private `qualifiedName` field; mirrors `getNamespace()`.
    fn namespace(&self) -> &dyn MdQualifiedName;

    /// Returns the inherited `MDDataType` signedness state, needed to mirror
    /// `super.insert(StringBuilder)`/`super.insertAsArg(StringBuilder)`.
    ///
    /// Raw accessor standing in for the `MDDataType` superclass slice of `self`.
    fn data_type(&self) -> &dyn MdDataTypeLike;

    /// Returns the type name text, always empty for a complex type.
    ///
    /// Mirrors the `MDComplexType` override of `getTypeName()`.
    fn type_name(&self) -> &str {
        ""
    }

    /// Returns the rendered namespace-qualified name.
    ///
    /// Mirrors `getTypeNamespace()` (`qualifiedName.toString()`, i.e. inserting the qualified
    /// name and cleaning the result).
    fn type_namespace(&self, dmang: &dyn MdMangLike) -> String {
        let mut builder = String::new();
        self.namespace().insert(dmang, &mut builder);
        dmang.clean_output(&mut builder);
        builder
    }

    /// Inserts the rendered qualified name, space-separated ahead of any existing content,
    /// followed by the inherited `MDDataType` signedness keyword, if any.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if !builder.is_empty() && !builder.starts_with(' ') {
            dmang.insert_string(builder, " ");
        }
        self.namespace().insert(dmang, builder);
        insert_signedness(self.data_type(), dmang, builder);
    }

    /// Inserts the rendered qualified name, space-separated ahead of any existing content,
    /// followed by the inherited `MDDataType` signedness keyword when the UDT argument type tag
    /// output option is enabled.
    ///
    /// Mirrors `insertAsArg(StringBuilder)`.
    fn insert_as_arg(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if !builder.is_empty() && !builder.starts_with(' ') {
            dmang.insert_string(builder, " ");
        }
        self.namespace().insert(dmang, builder);
        if dmang.apply_udt_argument_type_tag() {
            insert_signedness(self.data_type(), dmang, builder);
        }
    }
}

/// Mirrors the effective body of `MDDataType.insert(StringBuilder)` as seen through
/// `MDComplexType`'s override of `getTypeName()`: since that override always returns `""`, the
/// `getTypeName().length() != 0` branch of the original never fires here, leaving only the
/// signedness keyword insertion.
fn insert_signedness(data_type: &dyn MdDataTypeLike, dmang: &dyn MdMangLike, builder: &mut String) {
    if data_type.is_specified_signed() {
        dmang.insert_spaced_string(builder, "signed ");
    }
    if data_type.is_unsigned() {
        dmang.insert_spaced_string(builder, "unsigned ");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::naming::md_qualification::MdQualification;
    use crate::demangler::naming::md_qualifier::MdQualifier;
    use crate::demangler::naming::md_reusable_name::MdReusableName;
    use crate::demangler::seam_stubs::{MdFragmentNameLike, MdTemplateNameAndArgumentsLike};

    struct MockMdMang {
        apply_udt_tag: bool,
    }

    impl MdMangLike for MockMdMang {
        fn insert_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }

        fn insert_spaced_string(&self, builder: &mut String, s: &str) {
            if builder.is_empty() || s.is_empty() {
                builder.insert_str(0, s);
                return;
            }
            if builder.starts_with(' ') {
                if s.ends_with(' ') {
                    builder.remove(0);
                }
            }
            else if !s.ends_with(' ') {
                builder.insert(0, ' ');
            }
            builder.insert_str(0, s);
        }

        fn apply_udt_argument_type_tag(&self) -> bool {
            self.apply_udt_tag
        }
    }

    struct MockReusableName {
        rendered: String,
    }

    impl MdReusableName for MockReusableName {
        fn fragment_name(&self) -> Option<&dyn MdFragmentNameLike> {
            None
        }

        fn template_name(&self) -> Option<&dyn MdTemplateNameAndArgumentsLike> {
            None
        }

        fn special_name(&self) -> Option<&str> {
            Some(&self.rendered)
        }

        fn set_special_name(&mut self, name: Option<String>) {
            self.rendered = name.unwrap_or_default();
        }

        fn set_name(&mut self, _name: &str) {}
    }

    #[derive(Default)]
    struct MockQualification {
        quals: Vec<Box<dyn MdQualifier>>,
    }

    impl MdQualification for MockQualification {
        fn qualifiers(&self) -> &[Box<dyn MdQualifier>] {
            &self.quals
        }
    }

    struct MockQualifiedName {
        name: MockReusableName,
        qualification: MockQualification,
    }

    impl MdQualifiedName for MockQualifiedName {
        fn name_component(&self) -> &dyn MdReusableName {
            &self.name
        }

        fn qualification(&self) -> &dyn MdQualification {
            &self.qualification
        }
    }

    #[derive(Default)]
    struct MockDataType {
        specified_signed: bool,
        unsigned: bool,
    }

    impl MdDataTypeLike for MockDataType {
        fn is_specified_signed(&self) -> bool {
            self.specified_signed
        }

        fn is_unsigned(&self) -> bool {
            self.unsigned
        }
    }

    struct MockComplexType {
        namespace: MockQualifiedName,
        data_type: MockDataType,
    }

    impl MdComplexType for MockComplexType {
        fn namespace(&self) -> &dyn MdQualifiedName {
            &self.namespace
        }

        fn data_type(&self) -> &dyn MdDataTypeLike {
            &self.data_type
        }
    }

    fn mock(name: &str) -> MockComplexType {
        MockComplexType {
            namespace: MockQualifiedName {
                name: MockReusableName { rendered: name.to_string() },
                qualification: MockQualification::default(),
            },
            data_type: MockDataType::default(),
        }
    }

    #[test]
    fn type_name_is_always_empty() {
        let c = mock("MyClass");

        assert_eq!(c.type_name(), "");
    }

    #[test]
    fn type_namespace_renders_the_qualified_name() {
        let c = mock("MyClass");
        let dmang = MockMdMang { apply_udt_tag: true };

        assert_eq!(c.type_namespace(&dmang), "MyClass");
    }

    #[test]
    fn insert_prepends_space_before_nonempty_content_not_starting_with_space() {
        let c = mock("MyClass");
        let dmang = MockMdMang { apply_udt_tag: true };
        let mut builder = "*".to_string();

        c.insert(&dmang, &mut builder);

        assert_eq!(builder, "MyClass *");
    }

    #[test]
    fn insert_omits_leading_space_on_empty_builder() {
        let c = mock("MyClass");
        let dmang = MockMdMang { apply_udt_tag: true };
        let mut builder = String::new();

        c.insert(&dmang, &mut builder);

        assert_eq!(builder, "MyClass");
    }

    #[test]
    fn insert_prepends_unsigned_keyword_from_inherited_data_type() {
        let mut c = mock("MyClass");
        c.data_type.unsigned = true;
        let dmang = MockMdMang { apply_udt_tag: true };
        let mut builder = String::new();

        c.insert(&dmang, &mut builder);

        assert_eq!(builder, "unsigned MyClass");
    }

    #[test]
    fn insert_as_arg_includes_signedness_when_option_enabled() {
        let mut c = mock("MyClass");
        c.data_type.specified_signed = true;
        let dmang = MockMdMang { apply_udt_tag: true };
        let mut builder = String::new();

        c.insert_as_arg(&dmang, &mut builder);

        assert_eq!(builder, "signed MyClass");
    }

    #[test]
    fn insert_as_arg_omits_signedness_when_option_disabled() {
        let mut c = mock("MyClass");
        c.data_type.specified_signed = true;
        let dmang = MockMdMang { apply_udt_tag: false };
        let mut builder = String::new();

        c.insert_as_arg(&dmang, &mut builder);

        assert_eq!(builder, "MyClass");
    }

    #[test]
    fn trait_object_is_usable() {
        let c = mock("Leaf");
        let obj: &dyn MdComplexType = &c;
        let dmang = MockMdMang { apply_udt_tag: true };
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "Leaf");
    }
}
