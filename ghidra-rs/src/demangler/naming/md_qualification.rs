use crate::demangler::naming::md_qualifier::MdQualifier;
use crate::demangler::seam_stubs::MdMangLike;

/// Represents a namespace qualification within a Microsoft mangled symbol. It is composed of
/// individual namespace components ([`MdQualifier`]).
///
/// Mirrors `mdemangler.naming.MDQualification`, cut to a trait to break a dependency cycle with
/// `MDMang`/`MDParsableItem` (the still-unported driver and base class). The parsing side of the
/// original (`parseInternal`, driven by the still-unported `MDMang` character reader and the
/// construction of fresh `MDQualifier` instances) is intentionally out of scope here: it isn't
/// expressible against a not-yet-real driver. This trait models the rest of the public surface --
/// the query/render API callers depend on -- via a raw accessor mirroring the original's private
/// `quals` field, the same shape used by
/// [`crate::demangler::naming::md_qualifier::MdQualifier`].
pub trait MdQualification {
    /// Returns the namespace components, ordered so the last element is the namespace root.
    ///
    /// Raw accessor mirroring the private `quals` field.
    fn qualifiers(&self) -> &[Box<dyn MdQualifier>];

    /// Returns whether this qualification has any components.
    ///
    /// Mirrors `hasContent()`.
    fn has_content(&self) -> bool {
        !self.qualifiers().is_empty()
    }

    /// Returns the innermost (first) qualifier, when this qualification has any components.
    ///
    /// Mirrors `getHead()`.
    fn head(&self) -> Option<&dyn MdQualifier> {
        self.qualifiers().first().map(|q| q.as_ref())
    }

    /// Inserts the rendered text of the innermost (first) qualifier into `builder`.
    ///
    /// Mirrors `insertHeadQualifier(StringBuilder)`.
    fn insert_head_qualifier(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if let Some(head) = self.qualifiers().first() {
            head.insert(dmang, builder);
        }
    }

    /// Inserts the rendered text of this qualification into `builder`, in the base "MD version"
    /// form: an unconditional trailing `[` is appended if the outermost (last) qualifier rendered
    /// is an interface namespace.
    ///
    /// Mirrors `insert_MdVersion(StringBuilder)`.
    fn insert_md_version(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        let quals = self.qualifiers();
        let last = quals.len().wrapping_sub(1);
        let mut is_interface = false;
        for (i, qual) in quals.iter().enumerate() {
            // Results in brackets as follows:
            //   "Namespace[::InterfaceNameSpace]::BaseName"
            //   "InterfaceNamespace]::NameSpace::BaseName" --Note that MSFT does not include
            //     opening bracket here.
            if is_interface {
                dmang.insert_string(builder, "[");
            }
            is_interface = qual.is_interface();
            if is_interface {
                dmang.insert_string(builder, "]");
            }
            qual.insert(dmang, builder);
            if i != last {
                dmang.insert_string(builder, "::");
            }
        }
        if is_interface {
            dmang.insert_string(builder, "[");
        }
    }

    /// Inserts the rendered text of this qualification into `builder`, in the VS2015-style "all"
    /// form: unlike [`MdQualification::insert_md_version`], no unconditional trailing `[` is
    /// appended.
    ///
    /// Mirrors `insert_VSAll(StringBuilder)`.
    fn insert_vs_all(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        let quals = self.qualifiers();
        let last = quals.len().wrapping_sub(1);
        let mut is_interface = false;
        for (i, qual) in quals.iter().enumerate() {
            if is_interface {
                dmang.insert_string(builder, "[");
            }
            is_interface = qual.is_interface();
            if is_interface {
                dmang.insert_string(builder, "]");
            }
            qual.insert(dmang, builder);
            if i != last {
                dmang.insert_string(builder, "::");
            }
        }
    }

    /// Inserts the rendered text of this qualification into `builder`.
    ///
    /// Mirrors `insert(StringBuilder)`. The original dispatches via `MDMANG SPECIALIZATION`
    /// (`dmang.insert(builder, this)`, which the base `MDMang` implements by calling
    /// [`MdQualification::insert_md_version`] and which `MDMangVS2015` overrides to call
    /// [`MdQualification::insert_vs_all`] instead); here that choice is exposed directly as
    /// [`MdMangLike::use_vs_all_qualification`].
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if dmang.use_vs_all_qualification() {
            self.insert_vs_all(dmang, builder);
        }
        else {
            self.insert_md_version(dmang, builder);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMdMang {
        vs_all: bool,
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
            builder.insert(0, ' ');
            builder.insert_str(0, s);
        }

        fn use_vs_all_qualification(&self) -> bool {
            self.vs_all
        }
    }

    fn md_version_dmang() -> MockMdMang {
        MockMdMang { vs_all: false }
    }

    struct MockQualifier {
        rendered: String,
        is_interface: bool,
    }

    impl MdQualifier for MockQualifier {
        fn name(&self) -> Option<&dyn crate::demangler::naming::md_reusable_name::MdReusableName> {
            None
        }

        fn template_name(
            &self,
        ) -> Option<&dyn crate::demangler::naming::md_reusable_name::MdReusableName> {
            None
        }

        fn name_anonymous(
            &self,
        ) -> Option<&dyn crate::demangler::naming::md_reusable_name::MdReusableName> {
            None
        }

        fn name_interface(
            &self,
        ) -> Option<&dyn crate::demangler::naming::md_reusable_name::MdReusableName> {
            None
        }

        fn name_nested(
            &self,
        ) -> Option<&dyn crate::demangler::naming::md_nested_name::MdNestedName> {
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

        fn name_c(&self) -> Option<&dyn crate::demangler::seam_stubs::MdFragmentNameLike> {
            None
        }

        fn is_interface(&self) -> bool {
            self.is_interface
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    fn qual(rendered: &str) -> Box<dyn MdQualifier> {
        Box::new(MockQualifier { rendered: rendered.to_string(), is_interface: false })
    }

    fn interface_qual(rendered: &str) -> Box<dyn MdQualifier> {
        Box::new(MockQualifier { rendered: rendered.to_string(), is_interface: true })
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

    #[test]
    fn empty_qualification_has_no_content_and_no_head() {
        let q = MockQualification::default();

        assert!(!q.has_content());
        assert!(q.head().is_none());
    }

    #[test]
    fn insert_md_version_joins_qualifiers_root_first() {
        // quals[0] is innermost, quals[last] is the namespace root.
        let q = MockQualification { quals: vec![qual("Base"), qual("Sub"), qual("Root")] };
        let dmang = md_version_dmang();
        let mut builder = String::new();

        assert!(q.has_content());
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "Root::Sub::Base");
    }

    #[test]
    fn insert_md_version_adds_extra_leading_bracket_for_interface_root() {
        let q = MockQualification { quals: vec![qual("Base"), interface_qual("Iface")] };
        let dmang = md_version_dmang();
        let mut builder = String::new();

        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "[Iface]::Base");
    }

    #[test]
    fn insert_vs_all_omits_extra_leading_bracket_for_interface_root() {
        let q = MockQualification { quals: vec![qual("Base"), interface_qual("Iface")] };
        let dmang = MockMdMang { vs_all: true };
        let mut builder = String::new();

        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "Iface]::Base");
    }

    #[test]
    fn insert_head_qualifier_renders_only_the_innermost_qualifier() {
        let q = MockQualification { quals: vec![qual("Base"), qual("Root")] };
        let dmang = md_version_dmang();
        let mut builder = String::new();

        q.insert_head_qualifier(&dmang, &mut builder);

        assert_eq!(builder, "Base");
        assert_eq!(q.head().unwrap().is_interface(), false);
    }

    #[test]
    fn trait_object_is_usable() {
        let q = MockQualification { quals: vec![qual("Root")] };
        let obj: &dyn MdQualification = &q;
        let dmang = md_version_dmang();
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "Root");
        assert!(obj.has_content());
    }
}
