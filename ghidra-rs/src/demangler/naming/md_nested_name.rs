use crate::demangler::object::md_object_cpp::MdObjectCpp;
use crate::demangler::seam_stubs::MdMangLike;

/// Represents a nested name (wiki page parlance) within a name of a Microsoft mangled symbol.
///
/// Mirrors `mdemangler.naming.MDNestedName`, cut to a trait to break a dependency cycle with
/// `MDMang`/`MDParsableItem` (the still-unported driver and base class). The parsing side of the
/// original (`parseInternal`, driven by the still-unported `MDMang` character reader and
/// `MDObjectCPP` construction) is intentionally out of scope here: it isn't expressible against a
/// not-yet-real driver. This trait models the rest of the public surface -- the query/render API
/// callers depend on. Unlike sibling seams in this package, no placeholder stub is needed for
/// `MDObjectCPP`: it is already ported as [`MdObjectCpp`].
pub trait MdNestedName {
    /// Returns the nested object.
    ///
    /// Raw accessor mirroring the private `objectCPP` field (see `getNestedObject()`).
    fn nested_object(&self) -> &dyn MdObjectCpp;

    /// Returns the portion of the original mangled string this nested name was parsed from.
    ///
    /// Raw accessor mirroring the private `mangled` field (see `getMangled()`).
    fn mangled(&self) -> &str;

    /// Inserts the rendered text of this nested name into `builder`, wrapping the nested object's
    /// rendering in the backtick/quote nested-name convention.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        let mut nested = String::new();
        self.nested_object().insert(dmang, &mut nested);
        dmang.insert_string(builder, "'");
        dmang.insert_string(builder, &nested);
        dmang.insert_string(builder, "`");
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

    struct MockNestedName {
        object: MockObjectCpp,
        mangled: String,
    }

    impl MdNestedName for MockNestedName {
        fn nested_object(&self) -> &dyn MdObjectCpp {
            &self.object
        }

        fn mangled(&self) -> &str {
            &self.mangled
        }
    }

    #[test]
    fn insert_wraps_nested_object_in_backtick_quote_convention() {
        let n = MockNestedName {
            object: MockObjectCpp { rendered: "MyClass".to_string() },
            mangled: "?MyClass@@".to_string(),
        };
        let dmang = MockMdMang;
        let mut builder = String::new();

        n.insert(&dmang, &mut builder);

        assert_eq!(builder, "`MyClass'");
    }

    #[test]
    fn mangled_returns_the_original_substring() {
        let n = MockNestedName {
            object: MockObjectCpp { rendered: "Foo".to_string() },
            mangled: "?Foo@@".to_string(),
        };

        assert_eq!(n.mangled(), "?Foo@@");
    }

    #[test]
    fn trait_object_is_usable() {
        let n = MockNestedName {
            object: MockObjectCpp { rendered: "Bar".to_string() },
            mangled: "?Bar@@".to_string(),
        };
        let obj: &dyn MdNestedName = &n;
        let dmang = MockMdMang;
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "`Bar'");
        assert_eq!(obj.mangled(), "?Bar@@");
    }
}
