use crate::demangler::seam_stubs::MdMangLike;

const PREFIX_EMIT_CLAUSE_BASED: &str = "__based(";
const SUFFIX_EMIT_CLAUSE_BASED: &str = ")";

/// Represents a based property of a modifier type within a Microsoft mangled symbol.
///
/// Mirrors `mdemangler.datatype.modifier.MDBasedAttribute`, cut to a trait to break a dependency
/// cycle with `MDMang`/`MDParsableItem` (the still-unported driver and base class). The parsing
/// side of the original (`parseInternal`, driven by the still-unported `MDMang` character reader
/// and the construction of fresh `MDQualifiedName`/`MDBasicName` instances) is intentionally out
/// of scope here: it isn't expressible against a not-yet-real driver. This trait models the rest
/// of the public surface -- the query/render API callers depend on -- via raw accessors mirroring
/// the original's private `basedName`/`basedPtrBased`/`parsed` fields.
pub trait MdBasedAttribute {
    /// Returns the rendered based-clause name (e.g. `"void"`, a qualified name, or a
    /// `__segmname("...")` clause), when this attribute is not based on a based-pointer.
    ///
    /// Raw accessor mirroring the private `basedName` field.
    fn based_name(&self) -> Option<&str>;

    /// Returns whether this attribute represents the "based on basedptr" case, which the
    /// original notes is invalid in the Microsoft model (see the "based5 bug" comment on the
    /// original Java source) and is rendered as a lone NUL character rather than a clause.
    ///
    /// Mirrors `isBasedPtrBased()`, also the raw accessor for the private `basedPtrBased` field.
    fn is_based_ptr_based(&self) -> bool;

    /// Returns whether this attribute has been parsed yet.
    ///
    /// Raw accessor mirroring the private `parsed` field. [`MdBasedAttribute::insert`] and
    /// [`MdBasedAttribute::append`] are no-ops while this is `false`.
    fn is_parsed(&self) -> bool;

    /// Inserts the rendered based-clause at the front of `builder`, in the form
    /// `"__based(<name>) "`.
    ///
    /// Mirrors `insert(StringBuilder)`. When [`MdBasedAttribute::is_based_ptr_based`] is `true`,
    /// per the "based5 bug" mimicked from the Microsoft demangler, `builder` is instead truncated
    /// to a lone NUL character.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if !self.is_parsed() {
            return;
        }
        if self.is_based_ptr_based() {
            builder.clear();
            builder.push('\0');
            return;
        }
        dmang.insert_spaced_string(builder, SUFFIX_EMIT_CLAUSE_BASED);
        dmang.insert_string(builder, self.based_name().unwrap_or_default());
        dmang.insert_string(builder, PREFIX_EMIT_CLAUSE_BASED);
    }

    /// Appends the rendered based-clause to the end of `builder`, in the form
    /// `" __based(<name>)"`.
    ///
    /// Mirrors `append(StringBuilder)`. When [`MdBasedAttribute::is_based_ptr_based`] is `true`,
    /// per the "based5 bug" mimicked from the Microsoft demangler, `builder` is instead truncated
    /// to a lone NUL character.
    fn append(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if !self.is_parsed() {
            return;
        }
        if self.is_based_ptr_based() {
            builder.clear();
            builder.push('\0');
            return;
        }
        dmang.append_string(builder, " ");
        dmang.append_string(builder, PREFIX_EMIT_CLAUSE_BASED);
        dmang.append_string(builder, self.based_name().unwrap_or_default());
        dmang.append_string(builder, SUFFIX_EMIT_CLAUSE_BASED);
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

    struct MockBasedAttribute {
        based_name: Option<String>,
        based_ptr_based: bool,
        parsed: bool,
    }

    impl MdBasedAttribute for MockBasedAttribute {
        fn based_name(&self) -> Option<&str> {
            self.based_name.as_deref()
        }

        fn is_based_ptr_based(&self) -> bool {
            self.based_ptr_based
        }

        fn is_parsed(&self) -> bool {
            self.parsed
        }
    }

    #[test]
    fn unparsed_insert_and_append_are_no_ops() {
        let a = MockBasedAttribute { based_name: Some("void".to_string()), based_ptr_based: false, parsed: false };
        let dmang = MockMdMang;
        let mut builder = "unchanged".to_string();

        a.insert(&dmang, &mut builder);
        assert_eq!(builder, "unchanged");

        a.append(&dmang, &mut builder);
        assert_eq!(builder, "unchanged");
    }

    #[test]
    fn insert_wraps_based_name_in_based_clause() {
        let a = MockBasedAttribute { based_name: Some("void".to_string()), based_ptr_based: false, parsed: true };
        let dmang = MockMdMang;
        let mut builder = String::new();

        a.insert(&dmang, &mut builder);

        assert_eq!(builder, "__based(void)");
    }

    #[test]
    fn append_wraps_based_name_in_based_clause_with_leading_space() {
        let a = MockBasedAttribute { based_name: Some("void".to_string()), based_ptr_based: false, parsed: true };
        let dmang = MockMdMang;
        let mut builder = "int".to_string();

        a.append(&dmang, &mut builder);

        assert_eq!(builder, "int __based(void)");
    }

    #[test]
    fn based_ptr_based_truncates_builder_to_nul_on_insert() {
        let a = MockBasedAttribute { based_name: None, based_ptr_based: true, parsed: true };
        let dmang = MockMdMang;
        let mut builder = "some prior content".to_string();

        a.insert(&dmang, &mut builder);

        assert_eq!(builder, "\0");
    }

    #[test]
    fn based_ptr_based_truncates_builder_to_nul_on_append() {
        let a = MockBasedAttribute { based_name: None, based_ptr_based: true, parsed: true };
        let dmang = MockMdMang;
        let mut builder = "some prior content".to_string();

        a.append(&dmang, &mut builder);

        assert_eq!(builder, "\0");
    }

    #[test]
    fn trait_object_is_usable() {
        let a = MockBasedAttribute { based_name: Some("__segmname(\"Foo\")".to_string()), based_ptr_based: false, parsed: true };
        let obj: &dyn MdBasedAttribute = &a;
        let dmang = MockMdMang;
        let mut builder = String::new();

        obj.insert(&dmang, &mut builder);

        assert_eq!(builder, "__based(__segmname(\"Foo\"))");
        assert!(!obj.is_based_ptr_based());
    }
}
