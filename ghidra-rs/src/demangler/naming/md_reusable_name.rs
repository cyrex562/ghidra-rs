use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::seam_stubs::{MdFragmentNameLike, MdMangLike, MdTemplateNameAndArgumentsLike};

/// Represents a reusable name (whether a fragment, template name, or backreference index of a
/// previous reusable name)--where one is allowed--within a Microsoft mangled symbol.
///
/// Mirrors `mdemangler.naming.MDReusableName`, cut to a trait to break a dependency cycle with
/// `MDMang`/`MDParsableItem`/`MDFragmentName`/`MDTemplateNameAndArguments` (none are ported yet).
/// The parsing side of the original (`parseInternal`, driven by the still-unported `MDMang`
/// character reader and backreference table) is intentionally out of scope here: it only
/// constructs and assigns fresh `MDFragmentName`/`MDTemplateNameAndArguments` instances, which
/// isn't expressible against a not-yet-real type. This trait models the rest of the public
/// surface -- the query/render/special-name API callers and `insert` depend on.
pub trait MdReusableName {
    /// Returns the fragment name, if this reusable name is a fragment.
    ///
    /// Mirrors `getFragmentName()`.
    fn fragment_name(&self) -> Option<&dyn MdFragmentNameLike>;

    /// Returns the template name and arguments, if this reusable name is a template.
    ///
    /// Mirrors `getTemplateName()`.
    fn template_name(&self) -> Option<&dyn MdTemplateNameAndArgumentsLike>;

    /// Returns the special name interpretation of a fragment name, if any.
    ///
    /// Mirrors `getSpecialName()`.
    fn special_name(&self) -> Option<&str>;

    /// Sets the special name interpretation of a fragment name.
    ///
    /// Rust-side plumbing standing in for direct assignment to the private `specialName` field
    /// in `processSpecialName`.
    fn set_special_name(&mut self, name: Option<String>);

    /// Sets the name, delegating to the fragment name when this reusable name is a fragment.
    ///
    /// Mirrors `setName(String)`. Per the original's comment, this is currently unreachable from
    /// any caller, but is kept as part of the ported public API.
    fn set_name(&mut self, name: &str);

    /// Returns whether the name is a fragment name. Note that there can still be a special name
    /// interpretation of a fragment, so both can be true.
    ///
    /// Mirrors `isFragment()`.
    fn is_fragment(&self) -> bool {
        self.fragment_name().is_some()
    }

    /// Returns whether the name is a template name with arguments. This is exclusive; if `true`
    /// the other two tests on name will be `false`.
    ///
    /// Mirrors `isTemplate()`.
    fn is_template(&self) -> bool {
        self.template_name().is_some()
    }

    /// Returns whether the name has a special name representation. This is the interpretation of
    /// a fragment, so if `true` then [`MdReusableName::is_fragment`] is also `true`.
    ///
    /// Mirrors `isSpecialName()`.
    fn is_special_name(&self) -> bool {
        self.special_name().is_some()
    }

    /// Returns the rendered name: the special name if set, else the fragment's name, else the
    /// template's name, else an empty string.
    ///
    /// Mirrors `getName()`.
    fn name(&self) -> String {
        if let Some(special) = self.special_name() {
            return special.to_string();
        }
        if let Some(fragment) = self.fragment_name() {
            return fragment.get_name();
        }
        if let Some(template) = self.template_name() {
            return template.get_name();
        }
        String::new()
    }

    /// Inserts the rendered text of this reusable name into `builder`, preferring the special
    /// name, then the fragment, then the template.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if let Some(special) = self.special_name() {
            dmang.insert_string(builder, special);
        } else if let Some(fragment) = self.fragment_name() {
            fragment.insert(dmang, builder);
        } else if let Some(template) = self.template_name() {
            template.insert(dmang, builder);
        }
    }

    /// Interprets a fragment name as one of a fixed set of special (non-MSFT, non-LLVM) names,
    /// setting the special name when `input_name` matches one of the recognized prefixes.
    ///
    /// Mirrors `processSpecialName(String)`.
    fn process_special_name(&mut self, input_name: &str) -> Result<(), DemangledException> {
        if let Some(guard_number) = input_name.strip_prefix("$TSS") {
            validate_number_string(guard_number)?;
            self.set_special_name(Some(format!("`thread safe static guard{{{guard_number}}}'")));
        } else if input_name == "$S1" {
            self.set_special_name(Some("`nonvisible static guard{1}'".to_string()));
        } else if let Some(mangling_number) = input_name.strip_prefix("$RT") {
            validate_number_string(mangling_number)?;
            self.set_special_name(Some(format!("`reference temporary{{{mangling_number}}}'")));
        }
        Ok(())
    }
}

/// Validates that `number_string` contains only digit characters.
///
/// Mirrors the private `validateNumberString(String)` helper.
fn validate_number_string(number_string: &str) -> Result<(), DemangledException> {
    for c in number_string.chars() {
        if !c.is_ascii_digit() {
            return Err(DemangledException::from_message(format!(
                "Illegal character in Number: {c}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFragmentName {
        name: String,
    }

    impl MdFragmentNameLike for MockFragmentName {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: String) {
            self.name = name;
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.name);
        }
    }

    struct MockTemplateName {
        name: String,
    }

    impl MdTemplateNameAndArgumentsLike for MockTemplateName {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.name);
        }
    }

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

    #[derive(Default)]
    struct MockReusableName {
        fragment: Option<MockFragmentName>,
        template: Option<MockTemplateName>,
        special_name: Option<String>,
    }

    impl MdReusableName for MockReusableName {
        fn fragment_name(&self) -> Option<&dyn MdFragmentNameLike> {
            self.fragment.as_ref().map(|f| f as &dyn MdFragmentNameLike)
        }

        fn template_name(&self) -> Option<&dyn MdTemplateNameAndArgumentsLike> {
            self.template.as_ref().map(|t| t as &dyn MdTemplateNameAndArgumentsLike)
        }

        fn special_name(&self) -> Option<&str> {
            self.special_name.as_deref()
        }

        fn set_special_name(&mut self, name: Option<String>) {
            self.special_name = name;
        }

        fn set_name(&mut self, name: &str) {
            if let Some(fragment) = self.fragment.as_mut() {
                fragment.set_name(name.to_string());
            }
        }
    }

    #[test]
    fn fragment_reports_fragment_state_and_name() {
        let r = MockReusableName {
            fragment: Some(MockFragmentName { name: "foo".to_string() }),
            ..Default::default()
        };

        assert!(r.is_fragment());
        assert!(!r.is_template());
        assert!(!r.is_special_name());
        assert_eq!(r.name(), "foo");
    }

    #[test]
    fn template_reports_template_state_and_name() {
        let r = MockReusableName {
            template: Some(MockTemplateName { name: "bar<int>".to_string() }),
            ..Default::default()
        };

        assert!(!r.is_fragment());
        assert!(r.is_template());
        assert_eq!(r.name(), "bar<int>");
    }

    #[test]
    fn set_name_delegates_to_fragment() {
        let mut r = MockReusableName {
            fragment: Some(MockFragmentName { name: "old".to_string() }),
            ..Default::default()
        };

        r.set_name("new");

        assert_eq!(r.name(), "new");
    }

    #[test]
    fn set_name_without_fragment_is_a_no_op() {
        let mut r = MockReusableName::default();

        r.set_name("ignored");

        assert_eq!(r.name(), "");
    }

    #[test]
    fn process_special_name_thread_safe_static_guard() {
        let mut r = MockReusableName {
            fragment: Some(MockFragmentName { name: "$TSS0".to_string() }),
            ..Default::default()
        };

        r.process_special_name("$TSS0").unwrap();

        assert!(r.is_special_name());
        assert_eq!(r.name(), "`thread safe static guard{0}'");
    }

    #[test]
    fn process_special_name_nonvisible_static_guard() {
        let mut r = MockReusableName::default();

        r.process_special_name("$S1").unwrap();

        assert_eq!(r.name(), "`nonvisible static guard{1}'");
    }

    #[test]
    fn process_special_name_reference_temporary() {
        let mut r = MockReusableName::default();

        r.process_special_name("$RT12").unwrap();

        assert_eq!(r.name(), "`reference temporary{12}'");
    }

    #[test]
    fn process_special_name_unrecognized_prefix_leaves_no_special_name() {
        let mut r = MockReusableName {
            fragment: Some(MockFragmentName { name: "plainFragment".to_string() }),
            ..Default::default()
        };

        r.process_special_name("plainFragment").unwrap();

        assert!(!r.is_special_name());
        assert_eq!(r.name(), "plainFragment");
    }

    #[test]
    fn process_special_name_rejects_non_digit_number() {
        let mut r = MockReusableName::default();

        let err = r.process_special_name("$RT1a").unwrap_err();

        assert!(err.to_string().contains("Illegal character in Number"));
        assert!(!r.is_special_name());
    }

    #[test]
    fn insert_prefers_special_name_over_fragment() {
        let mut r = MockReusableName {
            fragment: Some(MockFragmentName { name: "frag".to_string() }),
            ..Default::default()
        };
        r.set_special_name(Some("`special{1}'".to_string()));
        let dmang = MockMdMang;
        let mut builder = String::new();

        r.insert(&dmang, &mut builder);

        assert_eq!(builder, "`special{1}'");
    }

    #[test]
    fn insert_falls_back_to_template_when_no_fragment_or_special() {
        let r = MockReusableName {
            template: Some(MockTemplateName { name: "tmpl<T>".to_string() }),
            ..Default::default()
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        r.insert(&dmang, &mut builder);

        assert_eq!(builder, "tmpl<T>");
    }

    #[test]
    fn trait_object_is_usable() {
        let r = MockReusableName {
            fragment: Some(MockFragmentName { name: "x".to_string() }),
            ..Default::default()
        };
        let obj: &dyn MdReusableName = &r;

        assert!(obj.is_fragment());
        assert_eq!(obj.name(), "x");
    }
}
