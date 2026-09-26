use crate::demangler::naming::md_qualification::MdQualification;
use crate::demangler::naming::md_reusable_name::MdReusableName;
use crate::demangler::seam_stubs::MdMangLike;

/// Represents a qualified name (wiki page parlance) within a name of a Microsoft mangled symbol.
/// Note that it is slightly different from `MDQualifiedBasicName` in that it has an
/// [`MdReusableName`] (`MDFragmentName`) as its first component instead of an `MDBasicName`.
///
/// Mirrors `mdemangler.naming.MDQualifiedName`, cut to a trait to break a dependency cycle with
/// `MDMang`/`MDParsableItem` (the still-unported driver and base class). The parsing side of the
/// original (`parseInternal`, driven by the still-unported `MDMang` character reader and the
/// construction of a fresh `MDReusableName`/`MDQualification` pair) is intentionally out of scope
/// here: it isn't expressible against a not-yet-real driver. This trait models the rest of the
/// public surface -- the query/render API callers depend on -- via raw accessors mirroring the
/// original's private `name`/`qualification` fields, the same shape used by
/// [`crate::demangler::naming::md_qualification::MdQualification`].
pub trait MdQualifiedName {
    /// Returns the reusable name that is the innermost (first) component of this qualified name.
    ///
    /// Raw accessor mirroring the private `name` field.
    fn name_component(&self) -> &dyn MdReusableName;

    /// Returns the namespace-qualification component.
    ///
    /// Mirrors `getQualification()`.
    fn qualification(&self) -> &dyn MdQualification;

    /// Returns the rendered innermost name text.
    ///
    /// Mirrors `getName()` (`name.toString()`, i.e. inserting the name component and cleaning the
    /// result).
    fn name(&self, dmang: &dyn MdMangLike) -> String {
        let mut builder = String::new();
        self.name_component().insert(dmang, &mut builder);
        dmang.clean_output(&mut builder);
        builder
    }

    /// Inserts the rendered text of this qualified name into `builder`.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        self.name_component().insert(dmang, builder);
        if self.qualification().has_content() {
            dmang.insert_string(builder, "::");
            self.qualification().insert(dmang, builder);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::naming::md_qualifier::MdQualifier;
    use crate::demangler::seam_stubs::{MdFragmentNameLike, MdTemplateNameAndArgumentsLike};

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

    struct MockQualifier {
        rendered: String,
    }

    impl MdQualifier for MockQualifier {
        fn name(&self) -> Option<&dyn MdReusableName> {
            None
        }

        fn template_name(&self) -> Option<&dyn MdReusableName> {
            None
        }

        fn name_anonymous(&self) -> Option<&dyn MdReusableName> {
            None
        }

        fn name_interface(&self) -> Option<&dyn MdReusableName> {
            None
        }

        fn name_nested(&self) -> Option<&dyn crate::demangler::naming::md_nested_name::MdNestedName> {
            None
        }

        fn name_numbered(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdNumberedNamespaceLike> {
            None
        }

        fn name_q(&self) -> Option<&dyn MdQualification> {
            None
        }

        fn name_c(&self) -> Option<&dyn MdFragmentNameLike> {
            None
        }

        fn is_interface(&self) -> bool {
            false
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
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

    #[test]
    fn name_renders_the_innermost_name_component() {
        let q = MockQualifiedName {
            name: MockReusableName { rendered: "Base".to_string() },
            qualification: MockQualification::default(),
        };
        let dmang = MockMdMang;

        assert_eq!(q.name(&dmang), "Base");
    }

    #[test]
    fn insert_appends_qualification_when_present() {
        let q = MockQualifiedName {
            name: MockReusableName { rendered: "Base".to_string() },
            qualification: MockQualification {
                quals: vec![Box::new(MockQualifier { rendered: "Outer".to_string() })],
            },
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "Outer::Base");
    }

    #[test]
    fn insert_omits_double_colon_when_qualification_is_empty() {
        let q = MockQualifiedName {
            name: MockReusableName { rendered: "Base".to_string() },
            qualification: MockQualification::default(),
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "Base");
    }

    #[test]
    fn trait_object_is_usable() {
        let q = MockQualifiedName {
            name: MockReusableName { rendered: "Leaf".to_string() },
            qualification: MockQualification::default(),
        };
        let obj: &dyn MdQualifiedName = &q;
        let dmang = MockMdMang;

        assert_eq!(obj.name(&dmang), "Leaf");
    }
}
