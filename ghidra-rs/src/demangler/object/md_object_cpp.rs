use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::seam_stubs::{
    MdMangLike, MdQualificationLike, MdQualifiedBasicNameLike, MdStringLike, MdTypeInfoLike,
};

/// Represents a Microsoft-mangled C++ object symbol: either a qualified name (optionally
/// decorated with RTTI-derived type info) or an MD5-hashed symbol.
///
/// Mirrors `mdemangler.object.MDObjectCPP`, cut to a trait to break a dependency cycle: it is a
/// cut-point between `MDMang`/`MDObject`/`MDParsableItem` (the still-unported driver and base
/// class), `MDQualifiedBasicName`/`MDBasicName`/`MDQualification`/`MDString`
/// (`mdemangler.naming`), and `MDTypeInfo`/`MDTypeInfoParser` (`mdemangler.typeinfo`) -- none of
/// which are ported yet. The parsing side of the original (`parseInternal`,
/// `processHashedObject`, and the private `applyFunctionReturnTypeToTypeCastOperatorName` helper)
/// is intentionally out of scope here: each only constructs or dispatches through fresh instances
/// of those not-yet-real types (and, for the type-cast helper, `MDFunctionType`), which isn't
/// expressible against placeholder traits. This trait models the rest of the public surface -- the
/// query/render API callers depend on -- plus `processHashedObjectMSVC`, whose behavior (always
/// throwing) doesn't depend on any unported type.
pub trait MdObjectCpp {
    /// Returns the qualified name, when this object is not a hashed object.
    ///
    /// Raw accessor mirroring the private `qualifiedName` field (see `getQualifiedName()`).
    fn qualified_name(&self) -> Option<&dyn MdQualifiedBasicNameLike>;

    /// Returns the parsed type info, when this object is not a hashed object and RTTI-derived
    /// type info was present.
    ///
    /// Raw accessor mirroring the private `typeInfo` field (see `getTypeInfo()`).
    fn type_info(&self) -> Option<&dyn MdTypeInfoLike>;

    /// Returns the MD5-hashed representation, when this object is a hashed object.
    ///
    /// Raw accessor mirroring the private `hashedObject` field.
    fn hashed_object(&self) -> Option<&dyn MdHashedObject>;

    /// Returns whether this is an embedded object (a `???`-prefixed symbol), i.e. whether
    /// [`MdObjectCpp::embedded_object`] should delegate to the basic name's embedded object.
    ///
    /// Raw accessor mirroring the private `embeddedObjectFlag` field, set only during parsing
    /// (out of scope here).
    fn embedded_object_flag(&self) -> bool;

    /// Returns whether the object was a hashed object.
    ///
    /// Mirrors `isHashObject()`.
    fn is_hash_object(&self) -> bool {
        self.hashed_object().is_some()
    }

    /// Returns the embedded object if there is one, else itself.
    ///
    /// Mirrors `getEmbeddedObject()`. Requires `Self: Sized` (unlike the rest of this trait) so
    /// the "return itself" branch can coerce `&Self` to `&dyn MdObjectCpp`; call this only
    /// through a concrete type, not through a `dyn MdObjectCpp`.
    fn embedded_object(&self) -> &dyn MdObjectCpp
    where
        Self: Sized,
    {
        if self.embedded_object_flag() {
            if let Some(qualified_name) = self.qualified_name() {
                return qualified_name.basic_name().embedded_object();
            }
        }
        self
    }

    /// Returns the name of the symbol, minus any namespace component.
    ///
    /// Mirrors `getName()`. Returns an empty string in the (parse-error-only) case the original
    /// would have thrown a `NullPointerException`: neither a hashed object nor a qualified name
    /// present.
    fn name(&self) -> String {
        if let Some(hashed) = self.hashed_object() {
            return hashed.name();
        }
        match self.qualified_name() {
            Some(qualified_name) => qualified_name.basic_name().to_display_string(),
            None => String::new(),
        }
    }

    /// Returns the namespace-qualification component.
    ///
    /// Mirrors `getQualification()`.
    fn qualification(&self) -> Option<&dyn MdQualificationLike> {
        if let Some(hashed) = self.hashed_object() {
            return Some(hashed.qualification());
        }
        self.qualified_name().map(|qualified_name| qualified_name.qualification())
    }

    /// Returns `true` if the symbol's basic name is an [`MdStringLike`] literal.
    ///
    /// Mirrors `isString()`.
    fn is_string(&self) -> bool {
        match self.qualified_name() {
            Some(qualified_name) => qualified_name.is_string(),
            None => false,
        }
    }

    /// Returns the string literal from the basic name if it is a symbol of that type; else
    /// returns `None`.
    ///
    /// Mirrors `getMDString()`.
    fn md_string(&self) -> Option<&dyn MdStringLike> {
        if self.is_string() {
            self.qualified_name().and_then(|qualified_name| qualified_name.md_string())
        }
        else {
            None
        }
    }

    /// Inserts the rendered text of this object into `builder`.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if let Some(hashed) = self.hashed_object() {
            hashed.insert(dmang, builder);
        }
        else if let Some(qualified_name) = self.qualified_name() {
            qualified_name.insert(dmang, builder);
            if let Some(type_info) = self.type_info() {
                type_info.insert(dmang, builder);
            }
        }
    }

    /// Always fails, mimicking the MSFT "failure" behavior, which cuts the parsing process short.
    /// This is one of two choice methods that can be used (see [`MdObjectCpp::hashed_object`]'s
    /// doc for the other, `processHashedObject`, which is out of scope here).
    ///
    /// Mirrors `processHashedObjectMSVC()`.
    fn process_hashed_object_msvc(&self) -> Result<(), DemangledException> {
        Err(DemangledException::from_message("cannot parse hashed symbol"))
    }
}

/// Represents the MD5-hashed representation of the internals of an [`MdObjectCpp`]. It takes the
/// place of the [`MdQualifiedBasicNameLike`].
///
/// Mirrors the `MDObjectCPP.MDHashedObject` inner class. Declared alongside [`MdObjectCpp`]
/// (rather than in `seam_stubs`) because it is part of `MDObjectCPP.java` itself, not a reference
/// to a separate not-yet-ported file. As with [`MdObjectCpp`], the parsing side (`parseInternal`)
/// is out of scope: it is driven entirely by the still-unported `MDMang` character reader.
pub trait MdHashedObject {
    /// Returns the hashed string.
    ///
    /// Raw accessor mirroring the private `hashString` field (see `getHashString()`).
    fn hash_string(&self) -> &str;

    /// Returns an empty [`MdQualificationLike`] that represents the namespace of the symbol.
    ///
    /// Mirrors `getQualification()`.
    fn qualification(&self) -> &dyn MdQualificationLike;

    /// Returns the name representation: the hash string wrapped in the tick-mark convention used
    /// elsewhere in this crate's demangled output.
    ///
    /// Mirrors `getName()`.
    fn name(&self) -> String {
        format!("`{}'", self.hash_string())
    }

    /// Inserts the rendered name into `builder`.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        dmang.insert_string(builder, &self.name());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::seam_stubs::MdBasicNameLike;

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

    struct MockQualification;
    impl MdQualificationLike for MockQualification {}

    struct MockMdString;
    impl MdStringLike for MockMdString {}

    struct MockBasicName {
        text: String,
    }

    impl MdBasicNameLike for MockBasicName {
        fn embedded_object(&self) -> &dyn MdObjectCpp {
            panic!("not embedded in this test");
        }

        fn to_display_string(&self) -> String {
            self.text.clone()
        }
    }

    struct MockTypeInfo {
        rendered: String,
    }

    impl MdTypeInfoLike for MockTypeInfo {
        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.rendered);
        }
    }

    struct MockQualifiedBasicName {
        basic_name: MockBasicName,
        qualification: MockQualification,
        string_literal: Option<MockMdString>,
    }

    impl MdQualifiedBasicNameLike for MockQualifiedBasicName {
        fn basic_name(&self) -> &dyn MdBasicNameLike {
            &self.basic_name
        }

        fn qualification(&self) -> &dyn MdQualificationLike {
            &self.qualification
        }

        fn is_string(&self) -> bool {
            self.string_literal.is_some()
        }

        fn md_string(&self) -> Option<&dyn MdStringLike> {
            self.string_literal.as_ref().map(|s| s as &dyn MdStringLike)
        }

        fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
            dmang.insert_string(builder, &self.basic_name.text);
        }
    }

    struct MockHashedObject {
        hash: String,
        qualification: MockQualification,
    }

    impl MdHashedObject for MockHashedObject {
        fn hash_string(&self) -> &str {
            &self.hash
        }

        fn qualification(&self) -> &dyn MdQualificationLike {
            &self.qualification
        }
    }

    #[derive(Default)]
    struct MockObjectCpp {
        qualified_name: Option<MockQualifiedBasicName>,
        type_info: Option<MockTypeInfo>,
        hashed_object: Option<MockHashedObject>,
        embedded_object_flag: bool,
    }

    impl MdObjectCpp for MockObjectCpp {
        fn qualified_name(&self) -> Option<&dyn MdQualifiedBasicNameLike> {
            self.qualified_name.as_ref().map(|q| q as &dyn MdQualifiedBasicNameLike)
        }

        fn type_info(&self) -> Option<&dyn MdTypeInfoLike> {
            self.type_info.as_ref().map(|t| t as &dyn MdTypeInfoLike)
        }

        fn hashed_object(&self) -> Option<&dyn MdHashedObject> {
            self.hashed_object.as_ref().map(|h| h as &dyn MdHashedObject)
        }

        fn embedded_object_flag(&self) -> bool {
            self.embedded_object_flag
        }
    }

    fn named_object(name: &str) -> MockObjectCpp {
        MockObjectCpp {
            qualified_name: Some(MockQualifiedBasicName {
                basic_name: MockBasicName { text: name.to_string() },
                qualification: MockQualification,
                string_literal: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn name_delegates_to_qualified_basic_name() {
        let obj = named_object("MyClass");

        assert!(!obj.is_hash_object());
        assert_eq!(obj.name(), "MyClass");
    }

    #[test]
    fn hashed_object_reports_hash_derived_name_and_ignores_qualified_name() {
        let obj = MockObjectCpp {
            hashed_object: Some(MockHashedObject {
                hash: "0123456789ABCDEF0123456789ABCDEF".to_string(),
                qualification: MockQualification,
            }),
            ..Default::default()
        };

        assert!(obj.is_hash_object());
        assert_eq!(obj.name(), "`0123456789ABCDEF0123456789ABCDEF'");
    }

    #[test]
    fn is_string_and_md_string_reflect_basic_name_literal_state() {
        let mut obj = named_object("literal");
        obj.qualified_name.as_mut().unwrap().string_literal = Some(MockMdString);

        assert!(obj.is_string());
        assert!(obj.md_string().is_some());
    }

    #[test]
    fn is_string_false_when_basic_name_not_a_literal() {
        let obj = named_object("NotAString");

        assert!(!obj.is_string());
        assert!(obj.md_string().is_none());
    }

    #[test]
    fn insert_renders_qualified_name_then_type_info() {
        let mut obj = named_object("MyClass");
        obj.type_info = Some(MockTypeInfo { rendered: "(void)".to_string() });
        let dmang = MockMdMang;
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        // Each insert prepends, matching MDMang's builder convention (see MdMangLike/insert).
        assert_eq!(builder, "(void)MyClass");
    }

    #[test]
    fn insert_delegates_entirely_to_hashed_object_when_hashed() {
        let obj = MockObjectCpp {
            hashed_object: Some(MockHashedObject {
                hash: "0123456789ABCDEF0123456789ABCDEF".to_string(),
                qualification: MockQualification,
            }),
            ..Default::default()
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "`0123456789ABCDEF0123456789ABCDEF'");
    }

    #[test]
    fn process_hashed_object_msvc_always_fails() {
        let obj = named_object("Anything");

        let err = obj.process_hashed_object_msvc().unwrap_err();

        assert!(err.to_string().contains("cannot parse hashed symbol"));
    }

    #[test]
    fn embedded_object_returns_self_when_flag_unset() {
        let obj = named_object("MyClass");

        let embedded = obj.embedded_object();

        assert_eq!(embedded.name(), "MyClass");
    }

    #[test]
    fn trait_object_is_usable() {
        let obj = named_object("MyClass");
        let dyn_obj: &dyn MdObjectCpp = &obj;

        assert_eq!(dyn_obj.name(), "MyClass");
        assert!(!dyn_obj.is_hash_object());
    }
}
