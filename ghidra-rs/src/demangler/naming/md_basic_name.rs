use crate::demangler::naming::md_name_modifier::MdNameModifier;
use crate::demangler::naming::md_qualifier::MdQualifier;
use crate::demangler::naming::md_reusable_name::MdReusableName;
use crate::demangler::object::md_object_cpp::MdObjectCpp;
use crate::demangler::seam_stubs::{
    MdDataTypeLike, MdMangLike, MdSpecialNameLike, MdStringLike, MdTemplateNameAndArgumentsLike,
};

/// Represents the "Basic" part of a qualified name (following wiki page naming convention for
/// Microsoft Demangler) within a Microsoft mangled symbol.
///
/// Mirrors `mdemangler.naming.MDBasicName`, cut to a trait to break a dependency cycle: it is
/// embedded inside `MDObjectCPP` (via the not-yet-ported `MDQualifiedBasicName`) as
/// `embeddedObject`, while itself embedding an `MDObjectCPP` (already ported as [`MdObjectCpp`])
/// as `embeddedObject`/`getEmbeddedObject()`. The parsing side of the original (`parseInternal`,
/// driven by the still-unported `MDMang` character reader and the construction of fresh
/// `MDSpecialName`/`MDTemplateNameAndArguments`/`MDObjectCPP`/`MDQualification`/`MDReusableName`
/// instances) is intentionally out of scope here: it isn't expressible against a not-yet-real
/// driver. This trait models the rest of the public surface -- the query/render API callers
/// depend on -- via raw accessors mirroring the original's private fields (of which at most one of
/// `special_name`/`template_name_and_arguments`/`reusable_name` is ever populated on a given
/// instance). The `embeddedObjectQualification` field is omitted: the original only ever parses
/// and discards it ("Value not used, but must be parsed"), never reading it back through any
/// ported member.
pub trait MdBasicName {
    /// Returns the special-name interpretation, when this basic name is a special name (an
    /// operator, constructor/destructor, or RTTI-derived name).
    ///
    /// Raw accessor mirroring the private `specialName` field.
    fn special_name(&self) -> Option<&dyn MdSpecialNameLike>;

    /// Returns the template name and arguments, when this basic name is a template.
    ///
    /// Raw accessor mirroring the private `templateNameAndArguments` field.
    fn template_name_and_arguments(&self) -> Option<&dyn MdTemplateNameAndArgumentsLike>;

    /// Returns the plain reusable name, when this basic name is neither a special name nor a
    /// template.
    ///
    /// Raw accessor mirroring the private `reusableName` field.
    fn reusable_name(&self) -> Option<&dyn MdReusableName>;

    /// Returns the embedded object (essentially what could stand on its own as a mangled symbol)
    /// that is used as part of the name of the mangled object, when this basic name was parsed
    /// from a `???`-prefixed embedded-object sequence.
    ///
    /// Raw accessor mirroring the private `embeddedObject` field (see `getEmbeddedObject()`).
    fn embedded_object(&self) -> Option<&dyn MdObjectCpp>;

    /// Returns the name modifier applied on top of this basic name, if any.
    ///
    /// Raw accessor mirroring the private `nameModifier` field.
    fn name_modifier(&self) -> Option<&dyn MdNameModifier>;

    /// Sets the name, delegating to the special name or the template name and arguments,
    /// whichever is present.
    ///
    /// Mirrors `setName(String)`. Per the original's comment, this should only ever be called for
    /// a constructor or destructor, which come from `MDSpecialName` or
    /// `MDTemplateNameAndArguments`; when neither is present, the original logs a warning instead
    /// of setting anything. Left abstract (no default body) since delegating a mutation into a
    /// `special_name()`/`template_name_and_arguments()` result isn't expressible through their
    /// immutable accessors; implementors hold the concrete sub-objects and mutate them directly.
    fn set_name(&mut self, name: &str);

    /// Sets the constructor/destructor qualifier, delegating to the special name or the template
    /// name and arguments, whichever is present.
    ///
    /// Mirrors `setXtorQual(MDQualifier)`. See [`MdBasicName::set_name`] for why this is left
    /// abstract.
    fn set_xtor_qual(&mut self, qual: Box<dyn MdQualifier>);

    /// Sets the type-cast target's rendered text, delegating to the special name or the template
    /// name and arguments, whichever is present.
    ///
    /// Mirrors `setCastTypeString(String)`. See [`MdBasicName::set_name`] for why this is left
    /// abstract.
    fn set_cast_type_string(&mut self, cast_type_string: &str);

    /// Sets the type-cast target type, delegating to the special name or the template name and
    /// arguments, whichever is present.
    ///
    /// Mirrors `setCastType(MDDataType)`. See [`MdBasicName::set_name`] for why this is left
    /// abstract.
    fn set_cast_type(&mut self, cast_type: Box<dyn MdDataTypeLike>);

    /// Sets the name modifier applied on top of this basic name.
    ///
    /// Mirrors `setNameModifier(MDNameModifier)`.
    fn set_name_modifier(&mut self, name_modifier: Box<dyn MdNameModifier>);

    /// Returns whether this basic name represents a constructor.
    ///
    /// Mirrors `isConstructor()`.
    fn is_constructor(&self) -> bool {
        if let Some(special) = self.special_name() {
            return special.is_constructor();
        }
        if let Some(template) = self.template_name_and_arguments() {
            return template.is_constructor();
        }
        false
    }

    /// Returns whether this basic name represents a destructor.
    ///
    /// Mirrors `isDestructor()`.
    fn is_destructor(&self) -> bool {
        if let Some(special) = self.special_name() {
            return special.is_destructor();
        }
        if let Some(template) = self.template_name_and_arguments() {
            return template.is_destructor();
        }
        false
    }

    /// Returns whether this basic name represents a type-cast operator.
    ///
    /// Mirrors `isTypeCast()`.
    fn is_type_cast(&self) -> bool {
        if let Some(special) = self.special_name() {
            return special.is_type_cast();
        }
        if let Some(template) = self.template_name_and_arguments() {
            return template.is_type_cast();
        }
        false
    }

    /// Returns the RTTI number: `{0-4, or -1 if not an RTTI}`.
    ///
    /// Mirrors `getRTTINumber()`.
    fn rtti_number(&self) -> i32 {
        match self.special_name() {
            Some(special) => special.rtti_number(),
            None => -1,
        }
    }

    /// Returns whether this basic name is a string literal.
    ///
    /// Mirrors `isString()`.
    fn is_string(&self) -> bool {
        match self.special_name() {
            Some(special) => special.is_string(),
            None => false,
        }
    }

    /// Returns the string literal, when [`MdBasicName::is_string`] is `true`.
    ///
    /// Mirrors `getMDString()`.
    fn md_string(&self) -> Option<&dyn MdStringLike> {
        let special = self.special_name()?;
        if special.is_string() { special.md_string() } else { None }
    }

    /// Returns the rendered name: the special name if set, else the template name, else the
    /// reusable name, else an empty string.
    ///
    /// Mirrors `getName()`.
    fn name(&self) -> String {
        if let Some(special) = self.special_name() {
            return special.name();
        }
        if let Some(template) = self.template_name_and_arguments() {
            return template.get_name();
        }
        if let Some(reusable) = self.reusable_name() {
            return reusable.name();
        }
        String::new()
    }

    /// Inserts the rendered text of this basic name into `builder`, preferring the reusable name,
    /// then the special name, then the embedded object, then the template name and arguments;
    /// followed by the rendered name modifier, if any, appended (not prepended) directly onto the
    /// end of `builder`.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if let Some(reusable) = self.reusable_name() {
            reusable.insert(dmang, builder);
        }
        else if let Some(special) = self.special_name() {
            special.insert(dmang, builder);
        }
        else if let Some(embedded) = self.embedded_object() {
            embedded.insert(dmang, builder);
        }
        else if let Some(template) = self.template_name_and_arguments() {
            template.insert(dmang, builder);
        }
        if let Some(modifier) = self.name_modifier() {
            builder.push_str(&modifier.get_modifier());
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

    #[derive(Default)]
    struct MockSpecialName {
        constructor: bool,
        destructor: bool,
        type_cast: bool,
        rtti: i32,
        string_literal: Option<MockMdString>,
        rendered: String,
    }

    struct MockMdString;
    impl MdStringLike for MockMdString {}

    impl MdSpecialNameLike for MockSpecialName {
        fn is_constructor(&self) -> bool {
            self.constructor
        }

        fn is_destructor(&self) -> bool {
            self.destructor
        }

        fn is_type_cast(&self) -> bool {
            self.type_cast
        }

        fn rtti_number(&self) -> i32 {
            self.rtti
        }

        fn is_string(&self) -> bool {
            self.string_literal.is_some()
        }

        fn md_string(&self) -> Option<&dyn MdStringLike> {
            self.string_literal.as_ref().map(|s| s as &dyn MdStringLike)
        }

        fn name(&self) -> String {
            self.rendered.clone()
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    #[derive(Default)]
    struct MockTemplateName {
        constructor: bool,
        destructor: bool,
        type_cast: bool,
        rendered: String,
    }

    impl MdTemplateNameAndArgumentsLike for MockTemplateName {
        fn get_name(&self) -> String {
            self.rendered.clone()
        }

        fn is_constructor(&self) -> bool {
            self.constructor
        }

        fn is_destructor(&self) -> bool {
            self.destructor
        }

        fn is_type_cast(&self) -> bool {
            self.type_cast
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    struct MockReusableName {
        rendered: String,
    }

    impl MdReusableName for MockReusableName {
        fn fragment_name(&self) -> Option<&dyn crate::demangler::seam_stubs::MdFragmentNameLike> {
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

    struct MockObjectCpp {
        rendered: String,
    }

    impl MdObjectCpp for MockObjectCpp {
        fn qualified_name(
            &self,
        ) -> Option<&dyn crate::demangler::seam_stubs::MdQualifiedBasicNameLike> {
            None
        }

        fn type_info(&self) -> Option<&dyn crate::demangler::seam_stubs::MdTypeInfoLike> {
            None
        }

        fn hashed_object(
            &self,
        ) -> Option<&dyn crate::demangler::object::md_object_cpp::MdHashedObject> {
            None
        }

        fn embedded_object_flag(&self) -> bool {
            false
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    struct MockNameModifier {
        modifier: String,
    }

    impl MdNameModifier for MockNameModifier {
        fn get_modifier(&self) -> String {
            self.modifier.clone()
        }
    }

    #[derive(Default)]
    struct MockBasicName {
        special_name: Option<MockSpecialName>,
        template_name_and_arguments: Option<MockTemplateName>,
        reusable_name: Option<MockReusableName>,
        embedded_object: Option<MockObjectCpp>,
        name_modifier: Option<MockNameModifier>,
    }

    impl MdBasicName for MockBasicName {
        fn special_name(&self) -> Option<&dyn MdSpecialNameLike> {
            self.special_name.as_ref().map(|s| s as &dyn MdSpecialNameLike)
        }

        fn template_name_and_arguments(&self) -> Option<&dyn MdTemplateNameAndArgumentsLike> {
            self.template_name_and_arguments.as_ref().map(|t| t as &dyn MdTemplateNameAndArgumentsLike)
        }

        fn reusable_name(&self) -> Option<&dyn MdReusableName> {
            self.reusable_name.as_ref().map(|r| r as &dyn MdReusableName)
        }

        fn embedded_object(&self) -> Option<&dyn MdObjectCpp> {
            self.embedded_object.as_ref().map(|e| e as &dyn MdObjectCpp)
        }

        fn name_modifier(&self) -> Option<&dyn MdNameModifier> {
            self.name_modifier.as_ref().map(|n| n as &dyn MdNameModifier)
        }

        fn set_name(&mut self, name: &str) {
            if let Some(special) = self.special_name.as_mut() {
                special.rendered = name.to_string();
            }
            else if let Some(template) = self.template_name_and_arguments.as_mut() {
                template.rendered = name.to_string();
            }
        }

        fn set_xtor_qual(&mut self, _qual: Box<dyn MdQualifier>) {
            // Mock does not need to render the qualifier; presence is enough for these tests.
        }

        fn set_cast_type_string(&mut self, cast_type_string: &str) {
            if let Some(special) = self.special_name.as_mut() {
                special.rendered = format!("{} {}", special.rendered, cast_type_string);
            }
        }

        fn set_cast_type(&mut self, _cast_type: Box<dyn MdDataTypeLike>) {}

        fn set_name_modifier(&mut self, name_modifier: Box<dyn MdNameModifier>) {
            self.name_modifier = Some(MockNameModifier { modifier: name_modifier.get_modifier() });
        }
    }

    #[test]
    fn reusable_name_reports_name_and_renders() {
        let b = MockBasicName {
            reusable_name: Some(MockReusableName { rendered: "MyClass".to_string() }),
            ..Default::default()
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        assert_eq!(b.name(), "MyClass");
        assert!(!b.is_constructor());
        b.insert(&dmang, &mut builder);

        assert_eq!(builder, "MyClass");
    }

    #[test]
    fn special_name_constructor_reports_state_and_renders() {
        let b = MockBasicName {
            special_name: Some(MockSpecialName {
                constructor: true,
                rendered: "MyClass".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        assert!(b.is_constructor());
        assert!(!b.is_destructor());
        assert_eq!(b.name(), "MyClass");
        b.insert(&dmang, &mut builder);

        assert_eq!(builder, "MyClass");
    }

    #[test]
    fn template_name_destructor_delegates_through_template() {
        let b = MockBasicName {
            template_name_and_arguments: Some(MockTemplateName {
                destructor: true,
                rendered: "~Tmpl<T>".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(b.is_destructor());
        assert!(!b.is_constructor());
        assert_eq!(b.name(), "~Tmpl<T>");
    }

    #[test]
    fn rtti_number_defaults_to_negative_one_without_special_name() {
        let b = MockBasicName::default();

        assert_eq!(b.rtti_number(), -1);
        assert!(!b.is_string());
        assert!(b.md_string().is_none());
    }

    #[test]
    fn rtti_number_and_string_delegate_to_special_name() {
        let b = MockBasicName {
            special_name: Some(MockSpecialName {
                rtti: 2,
                string_literal: Some(MockMdString),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(b.rtti_number(), 2);
        assert!(b.is_string());
        assert!(b.md_string().is_some());
    }

    #[test]
    fn insert_prefers_embedded_object_over_template() {
        let b = MockBasicName {
            embedded_object: Some(MockObjectCpp { rendered: "Embedded".to_string() }),
            template_name_and_arguments: Some(MockTemplateName {
                rendered: "Tmpl<T>".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        b.insert(&dmang, &mut builder);

        assert_eq!(builder, "Embedded");
    }

    #[test]
    fn insert_appends_name_modifier_directly_to_end_of_builder() {
        let b = MockBasicName {
            reusable_name: Some(MockReusableName { rendered: "MyClass".to_string() }),
            name_modifier: Some(MockNameModifier { modifier: "::modifier".to_string() }),
            ..Default::default()
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        b.insert(&dmang, &mut builder);

        assert_eq!(builder, "MyClass::modifier");
    }

    #[test]
    fn set_name_delegates_to_special_name() {
        let mut b = MockBasicName {
            special_name: Some(MockSpecialName::default()),
            ..Default::default()
        };

        b.set_name("ctor");

        assert_eq!(b.name(), "ctor");
    }

    #[test]
    fn set_name_modifier_updates_accessor() {
        let mut b = MockBasicName::default();

        b.set_name_modifier(Box::new(MockNameModifier { modifier: "mod".to_string() }));

        assert_eq!(b.name_modifier().unwrap().get_modifier(), "mod");
    }

    #[test]
    fn trait_object_is_usable() {
        let b = MockBasicName {
            reusable_name: Some(MockReusableName { rendered: "Root".to_string() }),
            ..Default::default()
        };
        let obj: &dyn MdBasicName = &b;
        let dmang = MockMdMang;
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "Root");
        assert_eq!(obj.name(), "Root");
    }
}
