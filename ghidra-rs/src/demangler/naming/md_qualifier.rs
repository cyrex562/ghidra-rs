use crate::demangler::naming::md_nested_name::MdNestedName;
use crate::demangler::naming::md_qualification::MdQualification;
use crate::demangler::naming::md_reusable_name::MdReusableName;
use crate::demangler::seam_stubs::{MdFragmentNameLike, MdMangLike, MdNumberedNamespaceLike};

const ANONYMOUS_NAMESPACE: &str = "`anonymous namespace'";
const UNKNOWN_NAMESPACE: &str = "MDMANG_UNK_QUALIFICATION";

/// Represents one component of a namespace qualification (see `MDQualification`) within a
/// Microsoft mangled symbol.
///
/// Mirrors `mdemangler.naming.MDQualifier`, cut to a trait to break a dependency cycle with
/// `MDMang`/`MDParsableItem` (the still-unported driver and base class). The parsing side of the
/// original (`parseInternal`, driven by the still-unported `MDMang` character reader and the
/// construction of fresh `MDNestedName`/`MDReusableName`/`MDNumberedNamespace`/
/// `MDQualification`/`MDFragmentName` instances) is intentionally out of scope here: it isn't
/// expressible against a not-yet-real driver. This trait models the rest of the public surface --
/// the query/render API callers depend on -- via raw accessors mirroring the original's private
/// fields (of which exactly one is ever populated on a given instance), the same shape used by
/// [`crate::demangler::naming::md_reusable_name::MdReusableName`]. Unlike
/// [`MdNumberedNamespaceLike`] (still a placeholder), no placeholder stub is needed for
/// `MDQualification`: it is already ported as
/// [`MdQualification`](crate::demangler::naming::md_qualification::MdQualification).
pub trait MdQualifier {
    /// Returns the plain reusable name, when this qualifier is a simple name.
    ///
    /// Raw accessor mirroring the private `name` field (see `getName()`).
    fn name(&self) -> Option<&dyn MdReusableName>;

    /// Returns the template name, when this qualifier is a template.
    ///
    /// Raw accessor mirroring the private `templateName` field (see `getTemplate()`).
    fn template_name(&self) -> Option<&dyn MdReusableName>;

    /// Returns the anonymous-namespace name source, when this qualifier is an anonymous
    /// namespace.
    ///
    /// Raw accessor mirroring the private `nameAnonymous` field. The original exposes no direct
    /// getter for the field itself, only [`MdQualifier::is_anon`]/[`MdQualifier::anonymous_name`]
    /// (`isAnon()`/`getAnonymousName()`).
    fn name_anonymous(&self) -> Option<&dyn MdReusableName>;

    /// Returns the interface name, when this qualifier is an interface namespace.
    ///
    /// Raw accessor mirroring the private `nameInterface` field (see `getInterface()`).
    fn name_interface(&self) -> Option<&dyn MdReusableName>;

    /// Returns the nested name, when this qualifier is a nested name.
    ///
    /// Raw accessor mirroring the private `nameNested` field (see `getNested()`).
    fn name_nested(&self) -> Option<&dyn MdNestedName>;

    /// Returns the numbered namespace, when this qualifier is a numbered (local) namespace.
    ///
    /// Raw accessor mirroring the private `nameNumbered` field (see `getNameNumbered()`).
    fn name_numbered(&self) -> Option<&dyn MdNumberedNamespaceLike>;

    /// Returns the qualified interface name, when this qualifier came from a `?Q`-prefixed
    /// qualified name.
    ///
    /// Raw accessor mirroring the private `nameQ` field (see `getNameQ()`).
    fn name_q(&self) -> Option<&dyn MdQualification>;

    /// Returns the Windows-10-specific fragment name, when this qualifier is a `?C`-prefixed
    /// fragment.
    ///
    /// Raw accessor mirroring the private `nameC` field (see `getNameC()`).
    fn name_c(&self) -> Option<&dyn MdFragmentNameLike>;

    /// Returns whether this qualifier is a plain name.
    ///
    /// Mirrors `isName()`.
    fn is_name(&self) -> bool {
        self.name().is_some()
    }

    /// Returns whether this qualifier is a template.
    ///
    /// Mirrors `isTemplate()`.
    fn is_template(&self) -> bool {
        self.template_name().is_some()
    }

    /// Returns whether this qualifier is an anonymous namespace.
    ///
    /// Mirrors `isAnon()`.
    fn is_anon(&self) -> bool {
        self.name_anonymous().is_some()
    }

    /// Returns whether this qualifier is an interface namespace.
    ///
    /// Mirrors `isInterface()`.
    fn is_interface(&self) -> bool {
        self.name_interface().is_some()
    }

    /// Returns whether this qualifier is a nested name.
    ///
    /// Mirrors `isNested()`.
    fn is_nested(&self) -> bool {
        self.name_nested().is_some()
    }

    /// Returns whether this qualifier is a numbered (local) namespace.
    ///
    /// Mirrors `isLocalNamespace()`. Per the original's comment, this possibly duplicates
    /// [`MdQualifier::is_name_numbered`] and could be removed in favor of it.
    fn is_local_namespace(&self) -> bool {
        self.name_numbered().is_some()
    }

    /// Returns whether this qualifier is a numbered (local) namespace.
    ///
    /// Mirrors `isNameNumbered()`.
    fn is_name_numbered(&self) -> bool {
        self.name_numbered().is_some()
    }

    /// Returns whether this qualifier came from a `?Q`-prefixed qualified name.
    ///
    /// Mirrors `isNameQ()`.
    fn is_name_q(&self) -> bool {
        self.name_q().is_some()
    }

    /// Returns whether this qualifier is a Windows-10-specific `?C`-prefixed fragment.
    ///
    /// Mirrors `isNameC()`.
    fn is_name_c(&self) -> bool {
        self.name_c().is_some()
    }

    /// Returns the underlying name of the anonymous namespace.
    ///
    /// Mirrors `getAnonymousName()`. Returns an empty string in the (parse-error-only) case the
    /// original would have thrown a `NullPointerException`: this qualifier is not an anonymous
    /// namespace.
    fn anonymous_name(&self) -> String {
        self.name_anonymous().map(|n| n.name()).unwrap_or_default()
    }

    /// Returns the underlying name of the numbered (local) namespace.
    ///
    /// Mirrors `getLocalNamespace()`. Returns an empty string in the (parse-error-only) case the
    /// original would have thrown a `NullPointerException`: this qualifier is not a numbered
    /// namespace.
    fn local_namespace(&self) -> String {
        self.name_numbered().map(|n| n.name()).unwrap_or_default()
    }

    /// Returns the rendered encoded number of the numbered (local) namespace.
    ///
    /// Mirrors `getLocalNamespaceNumber()`. Returns an empty string in the (parse-error-only)
    /// case the original would have thrown a `NullPointerException`: this qualifier is not a
    /// numbered namespace.
    fn local_namespace_number(&self) -> String {
        self.name_numbered().map(|n| n.number_string()).unwrap_or_default()
    }

    /// Inserts the rendered text of this qualifier into `builder`. Exactly one of the underlying
    /// variants is expected to be present; if none are, a fixed placeholder is inserted instead.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if let Some(name) = self.name() {
            name.insert(dmang, builder);
        }
        else if let Some(template) = self.template_name() {
            template.insert(dmang, builder);
        }
        else if let Some(anon) = self.name_anonymous() {
            if dmang.use_encoded_anonymous_namespace() {
                let node = standard_anonymous_namespace_node(&anon.name());
                dmang.insert_string(builder, &node);
            }
            else {
                dmang.insert_string(builder, ANONYMOUS_NAMESPACE);
            }
        }
        else if let Some(interface) = self.name_interface() {
            interface.insert(dmang, builder);
        }
        else if let Some(nested) = self.name_nested() {
            nested.insert(dmang, builder);
        }
        else if let Some(numbered) = self.name_numbered() {
            numbered.insert(dmang, builder);
        }
        else if let Some(name_q) = self.name_q() {
            let mut name_q_builder = String::new();
            name_q.insert(dmang, &mut name_q_builder);
            dmang.insert_string(&mut name_q_builder, "[");
            dmang.append_string(&mut name_q_builder, "]");
            dmang.insert_string(builder, &name_q_builder);
        }
        else if let Some(name_c) = self.name_c() {
            name_c.insert(dmang, builder);
        }
        else {
            dmang.insert_string(builder, UNKNOWN_NAMESPACE);
        }
    }
}

/// Standardizes an anonymous-namespace name into the `_anon_XXXXXXXX` form.
///
/// Mirrors the static `MDMangUtils.createStandardAnonymousNamespaceNode(String)` helper (a pure
/// function of its input, so ported directly rather than placed behind a seam). Unlike the
/// original, which throws `NumberFormatException` on a malformed hex suffix, this returns the
/// input unchanged -- consistent with this crate's preference for graceful fallback over panics
/// in non-parsing helper code.
fn standard_anonymous_namespace_node(anon: &str) -> String {
    let stripped = if let Some(rest) = anon.strip_prefix("A0x") {
        rest
    }
    else if let Some(rest) = anon.strip_prefix('`') {
        rest
    }
    else {
        return anon.to_string();
    };
    match u64::from_str_radix(stripped, 16) {
        Ok(num) => format!("_anon_{num:08X}"),
        Err(_) => anon.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::object::md_object_cpp::MdObjectCpp;

    struct MockMdMang {
        encoded_anon: bool,
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

        fn use_encoded_anonymous_namespace(&self) -> bool {
            self.encoded_anon
        }
    }

    fn plain_dmang() -> MockMdMang {
        MockMdMang { encoded_anon: false }
    }

    struct MockReusableName {
        rendered: String,
    }

    impl MdReusableName for MockReusableName {
        fn fragment_name(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdFragmentNameLike> {
            None
        }

        fn template_name(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdTemplateNameAndArgumentsLike> {
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

    struct MockNested {
        rendered: String,
    }

    impl MdNestedName for MockNested {
        fn nested_object(&self) -> &dyn MdObjectCpp {
            panic!("not needed: insert is overridden for this mock");
        }

        fn mangled(&self) -> &str {
            "?mocked@@"
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    struct MockNumberedNamespace {
        number: String,
    }

    impl MdNumberedNamespaceLike for MockNumberedNamespace {
        fn name(&self) -> String {
            format!("`{}'", self.number)
        }

        fn number_string(&self) -> String {
            self.number.clone()
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.name());
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

    struct MockFragmentName {
        rendered: String,
    }

    impl MdFragmentNameLike for MockFragmentName {
        fn get_name(&self) -> String {
            self.rendered.clone()
        }

        fn set_name(&mut self, name: String) {
            self.rendered = name;
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    #[derive(Default)]
    struct MockQualifier {
        name: Option<MockReusableName>,
        template_name: Option<MockReusableName>,
        name_anonymous: Option<MockReusableName>,
        name_interface: Option<MockReusableName>,
        name_nested: Option<MockNested>,
        name_numbered: Option<MockNumberedNamespace>,
        name_q: Option<MockQualification>,
        name_c: Option<MockFragmentName>,
    }

    impl MdQualifier for MockQualifier {
        fn name(&self) -> Option<&dyn MdReusableName> {
            self.name.as_ref().map(|n| n as &dyn MdReusableName)
        }

        fn template_name(&self) -> Option<&dyn MdReusableName> {
            self.template_name.as_ref().map(|n| n as &dyn MdReusableName)
        }

        fn name_anonymous(&self) -> Option<&dyn MdReusableName> {
            self.name_anonymous.as_ref().map(|n| n as &dyn MdReusableName)
        }

        fn name_interface(&self) -> Option<&dyn MdReusableName> {
            self.name_interface.as_ref().map(|n| n as &dyn MdReusableName)
        }

        fn name_nested(&self) -> Option<&dyn MdNestedName> {
            self.name_nested.as_ref().map(|n| n as &dyn MdNestedName)
        }

        fn name_numbered(&self) -> Option<&dyn MdNumberedNamespaceLike> {
            self.name_numbered.as_ref().map(|n| n as &dyn MdNumberedNamespaceLike)
        }

        fn name_q(&self) -> Option<&dyn MdQualification> {
            self.name_q.as_ref().map(|n| n as &dyn MdQualification)
        }

        fn name_c(&self) -> Option<&dyn MdFragmentNameLike> {
            self.name_c.as_ref().map(|n| n as &dyn MdFragmentNameLike)
        }
    }

    #[test]
    fn name_variant_reports_state_and_renders() {
        let q = MockQualifier {
            name: Some(MockReusableName { rendered: "Foo".to_string() }),
            ..Default::default()
        };
        let dmang = plain_dmang();
        let mut builder = String::new();

        assert!(q.is_name());
        assert!(!q.is_template());
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "Foo");
    }

    #[test]
    fn anonymous_variant_renders_standard_text_by_default() {
        let q = MockQualifier {
            name_anonymous: Some(MockReusableName { rendered: "A0xdeadbeef".to_string() }),
            ..Default::default()
        };
        let dmang = plain_dmang();
        let mut builder = String::new();

        assert!(q.is_anon());
        assert_eq!(q.anonymous_name(), "A0xdeadbeef");
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "`anonymous namespace'");
    }

    #[test]
    fn anonymous_variant_renders_encoded_text_when_option_enabled() {
        let q = MockQualifier {
            name_anonymous: Some(MockReusableName { rendered: "A0xdeadbeef".to_string() }),
            ..Default::default()
        };
        let dmang = MockMdMang { encoded_anon: true };
        let mut builder = String::new();

        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "_anon_DEADBEEF");
    }

    #[test]
    fn nested_variant_delegates_to_nested_name() {
        let q = MockQualifier {
            name_nested: Some(MockNested { rendered: "`Nested'".to_string() }),
            ..Default::default()
        };
        let dmang = plain_dmang();
        let mut builder = String::new();

        assert!(q.is_nested());
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "`Nested'");
    }

    #[test]
    fn numbered_variant_reports_local_namespace_accessors() {
        let q = MockQualifier {
            name_numbered: Some(MockNumberedNamespace { number: "2".to_string() }),
            ..Default::default()
        };
        let dmang = plain_dmang();
        let mut builder = String::new();

        assert!(q.is_local_namespace());
        assert!(q.is_name_numbered());
        assert_eq!(q.local_namespace(), "`2'");
        assert_eq!(q.local_namespace_number(), "2");
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "`2'");
    }

    #[test]
    fn name_q_variant_wraps_rendered_qualification_in_brackets() {
        let inner = MockQualifier {
            name: Some(MockReusableName { rendered: "Foo::Bar".to_string() }),
            ..Default::default()
        };
        let q = MockQualifier {
            name_q: Some(MockQualification { quals: vec![Box::new(inner)] }),
            ..Default::default()
        };
        let dmang = plain_dmang();
        let mut builder = String::new();

        assert!(q.is_name_q());
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "[Foo::Bar]");
    }

    #[test]
    fn name_c_variant_delegates_to_fragment_name() {
        let q = MockQualifier {
            name_c: Some(MockFragmentName { rendered: "Frag".to_string() }),
            ..Default::default()
        };
        let dmang = plain_dmang();
        let mut builder = String::new();

        assert!(q.is_name_c());
        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "Frag");
    }

    #[test]
    fn no_variant_set_falls_back_to_unknown_placeholder() {
        let q = MockQualifier::default();
        let dmang = plain_dmang();
        let mut builder = String::new();

        q.insert(&dmang, &mut builder);

        assert_eq!(builder, "MDMANG_UNK_QUALIFICATION");
    }

    #[test]
    fn trait_object_is_usable() {
        let q = MockQualifier {
            name: Some(MockReusableName { rendered: "Bar".to_string() }),
            ..Default::default()
        };
        let obj: &dyn MdQualifier = &q;
        let dmang = plain_dmang();
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "Bar");
        assert!(obj.is_name());
    }
}
